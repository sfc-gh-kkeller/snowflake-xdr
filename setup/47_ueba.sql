-- ============================================================================
-- Snowflake XDR - Phase 5.7: behavioural baselines (UEBA)
-- ============================================================================
-- Per-entity and peer-group profiles over the last 30 days (excluding the last
-- 24 hours), and explained anomalies for the last 24 hours against them:
--
--   new_country        sign-in from a country this user never used (and, scored higher,
--                      no one in their peer group used)
--   new_source_ip      successful sign-in from an address this user never used
--   off_hours          sign-in at an hour this user is almost never active
--   volume_spike       rows read today far above this user's own daily norm
--   peer_outlier       rows read today far above everyone else in the same role
--   new_lineage        a parent -> child process pair this host never ran, rare fleet-wide
--   new_cloud_action   a cloud API action this identity never called and peers rarely do
--
-- Anomalies are SIGNALS, not alerts: they raise a finding's calibrated confidence
-- (factor "behaviour anomaly" in SCORE_CONFIDENCE, setup/29_confidence.sql), feed
-- auto-investigation, and show on Entity 360. Cold start is explicit: an entity
-- needs enough baseline days / events before a kind of anomaly can fire.
--
-- Cortex ML: entities with 14+ active days also get a SNOWFLAKE.ML.ANOMALY_DETECTION
-- model on daily activity (RUN_UEBA_ML). With less history the step reports that it
-- was skipped and why; RUN_UEBA_ML('selftest') proves the integration on a synthetic
-- series with a known spike.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES (
    entity_type  VARCHAR(20),     -- user | host | peer_group
    entity       VARCHAR(500),
    peer_group   VARCHAR(255),
    metric       VARCHAR(60),
    value        VARIANT,
    sample_count NUMBER,
    days_seen    NUMBER,
    built_at     TIMESTAMP_LTZ
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.UEBA_ANOMALIES (
    anomaly_id   VARCHAR DEFAULT UUID_STRING(),
    entity_type  VARCHAR(20),
    entity       VARCHAR(500),
    kind         VARCHAR(40),
    score        FLOAT,           -- 0..1, how unusual
    detail       VARCHAR(1000),   -- plain-language explanation
    evidence     VARIANT,
    method       VARCHAR(20),     -- profile | cortex_ml
    event_time   TIMESTAMP_LTZ,
    detected_at  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    dedupe_key   VARCHAR(1000)
);

-- ---------------------------------------------------------------------------
-- 1. Profiles
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.BUILD_UEBA_PROFILES()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_n NUMBER;
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE XDR_UEBA_NEW AS
    WITH auth AS (
        SELECT LOWER(user_name) AS entity, _time, src, geo_country, HOUR(_time) AS hr, user_role
        FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
        WHERE action = 'success' AND user_name IS NOT NULL
          AND _time BETWEEN DATEADD('day', -30, CURRENT_TIMESTAMP()) AND DATEADD('day', -1, CURRENT_TIMESTAMP())
    ),
    roles AS (   -- peer group = the role a user most often works in
        SELECT entity, peer_group FROM (
            SELECT LOWER(user_name) AS entity, user_role AS peer_group, COUNT(*) AS n
            FROM (SELECT user_name, user_role FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY
                  WHERE user_role IS NOT NULL AND _time > DATEADD('day', -30, CURRENT_TIMESTAMP())
                  UNION ALL
                  SELECT user_name, user_role FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
                  WHERE user_role IS NOT NULL AND _time > DATEADD('day', -30, CURRENT_TIMESTAMP()))
            GROUP BY 1, 2)
        QUALIFY ROW_NUMBER() OVER (PARTITION BY entity ORDER BY n DESC) = 1
    ),
    auth_prof AS (
        SELECT entity, COUNT(*) AS n, COUNT(DISTINCT DATE_TRUNC('day', _time)) AS days,
               ARRAY_AGG(DISTINCT UPPER(geo_country)) AS countries, ARRAY_AGG(DISTINCT src) AS srcs
        FROM auth GROUP BY 1
    ),
    hours AS (   -- hours carrying at least 2% of this user's sign-ins
        SELECT entity, ARRAY_AGG(hr) WITHIN GROUP (ORDER BY hr) AS active_hours
        FROM (SELECT entity, hr, COUNT(*) / SUM(COUNT(*)) OVER (PARTITION BY entity) AS share FROM auth GROUP BY 1, 2)
        WHERE share >= 0.02 GROUP BY 1
    ),
    reads AS (
        SELECT LOWER(user_name) AS entity, DATE_TRUNC('day', _time) AS d, SUM(COALESCE(rows_affected, 0)) AS rows_read
        FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY
        WHERE user_name IS NOT NULL AND action IN ('select', 'unload', 'read')
          AND _time BETWEEN DATEADD('day', -30, CURRENT_TIMESTAMP()) AND DATEADD('day', -1, CURRENT_TIMESTAMP())
        GROUP BY 1, 2
    ),
    read_prof AS (
        SELECT entity, COUNT(*) AS days, AVG(rows_read) AS mean_rows, COALESCE(STDDEV(rows_read), 0) AS sd_rows,
               MAX(rows_read) AS max_rows
        FROM reads GROUP BY 1
    ),
    cloud AS (
        SELECT LOWER(user_name) AS entity, ARRAY_AGG(DISTINCT action) AS actions, COUNT(*) AS n,
               COUNT(DISTINCT DATE_TRUNC('day', _time)) AS days
        FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
        WHERE user_name IS NOT NULL AND action IS NOT NULL
          AND _time BETWEEN DATEADD('day', -30, CURRENT_TIMESTAMP()) AND DATEADD('day', -1, CURRENT_TIMESTAMP())
        GROUP BY 1
    ),
    lineage AS (
        SELECT UPPER(dest) AS entity,
               ARRAY_AGG(DISTINCT LOWER(COALESCE(parent_process_name, '?')) || '>' || LOWER(process_name)) AS pairs,
               COUNT(*) AS n, COUNT(DISTINCT DATE_TRUNC('day', _time)) AS days
        FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
        WHERE dest IS NOT NULL AND process_name IS NOT NULL
          AND _time BETWEEN DATEADD('day', -30, CURRENT_TIMESTAMP()) AND DATEADD('day', -1, CURRENT_TIMESTAMP())
        GROUP BY 1
    )
    SELECT 'user' AS entity_type, a.entity, r.peer_group, 'auth' AS metric,
           OBJECT_CONSTRUCT('countries', a.countries, 'srcs', ARRAY_SLICE(a.srcs, 0, 200), 'active_hours', h.active_hours) AS value,
           a.n AS sample_count, a.days AS days_seen
    FROM auth_prof a LEFT JOIN hours h ON h.entity = a.entity LEFT JOIN roles r ON r.entity = a.entity
    UNION ALL
    SELECT 'user', p.entity, r.peer_group, 'reads',
           OBJECT_CONSTRUCT('mean_rows', ROUND(p.mean_rows), 'sd_rows', ROUND(p.sd_rows), 'max_rows', p.max_rows), p.days, p.days
    FROM read_prof p LEFT JOIN roles r ON r.entity = p.entity
    UNION ALL
    SELECT 'user', c.entity, r.peer_group, 'cloud', OBJECT_CONSTRUCT('actions', ARRAY_SLICE(c.actions, 0, 500)), c.n, c.days
    FROM cloud c LEFT JOIN roles r ON r.entity = c.entity
    UNION ALL
    SELECT 'host', l.entity, NULL, 'lineage', OBJECT_CONSTRUCT('pairs', ARRAY_SLICE(l.pairs, 0, 1000)), l.n, l.days
    FROM lineage l
    UNION ALL   -- peer groups: daily reads across all members, and every country any member used
    SELECT 'peer_group', r.peer_group, r.peer_group, 'reads',
           OBJECT_CONSTRUCT('mean_rows', ROUND(AVG(x.rows_read)), 'sd_rows', ROUND(COALESCE(STDDEV(x.rows_read), 0)),
                            'p95_rows', APPROX_PERCENTILE(x.rows_read, 0.95), 'members', COUNT(DISTINCT x.entity)),
           COUNT(*), COUNT(DISTINCT x.d)
    FROM reads x JOIN roles r ON r.entity = x.entity GROUP BY r.peer_group
    UNION ALL
    SELECT 'peer_group', r.peer_group, r.peer_group, 'auth',
           OBJECT_CONSTRUCT('countries', ARRAY_AGG(DISTINCT UPPER(a.geo_country)), 'members', COUNT(DISTINCT a.entity)),
           COUNT(*), COUNT(DISTINCT DATE_TRUNC('day', a._time))
    FROM auth a JOIN roles r ON r.entity = a.entity GROUP BY r.peer_group;

    BEGIN TRANSACTION;
    DELETE FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES;
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES
        (entity_type, entity, peer_group, metric, value, sample_count, days_seen, built_at)
    SELECT entity_type, entity, peer_group, metric, value, sample_count, days_seen, CURRENT_TIMESTAMP() FROM XDR_UEBA_NEW;
    v_n := SQLROWCOUNT;
    COMMIT;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'profiles', :v_n);
END;
$$;

-- ---------------------------------------------------------------------------
-- 2. Anomalies (last 24h vs profile). Minimum history per kind avoids cold-start noise.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_UEBA_ANOMALIES()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_n NUMBER;
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE XDR_UEBA_CAND AS
    WITH up AS (SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES WHERE entity_type = 'user'),
    pp AS (SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES WHERE entity_type = 'peer_group'),
    auth_now AS (
        SELECT LOWER(user_name) AS entity, _time, src, UPPER(geo_country) AS country, HOUR(_time) AS hr
        FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
        WHERE action = 'success' AND user_name IS NOT NULL AND _time > DATEADD('day', -1, CURRENT_TIMESTAMP())
    ),
    reads_now AS (
        SELECT LOWER(user_name) AS entity, SUM(COALESCE(rows_affected, 0)) AS rows_read, MAX(_time) AS last_time
        FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY
        WHERE user_name IS NOT NULL AND action IN ('select', 'unload', 'read') AND _time > DATEADD('day', -1, CURRENT_TIMESTAMP())
        GROUP BY 1
    ),
    pair_hosts AS (   -- how many hosts ran each parent>child pair in their baseline
        SELECT f.value::VARCHAR AS pair, COUNT(DISTINCT h.entity) AS hosts
        FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES h, LATERAL FLATTEN(INPUT => h.value:pairs) f
        WHERE h.entity_type = 'host' AND h.metric = 'lineage'
        GROUP BY 1
    ),
    peer_actions AS (   -- how many identities in each peer group called each cloud action
        SELECT u.peer_group, f.value::VARCHAR AS action, ARRAY_AGG(DISTINCT u.entity) AS users
        FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES u, LATERAL FLATTEN(INPUT => u.value:actions) f
        WHERE u.entity_type = 'user' AND u.metric = 'cloud'
        GROUP BY 1, 2
    ),
    proc_now AS (
        SELECT p.*, LOWER(COALESCE(p.parent_process_name, '?')) || '>' || LOWER(p.process_name) AS pair
        FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES p
        WHERE p._time > DATEADD('day', -1, CURRENT_TIMESTAMP()) AND p.dest IS NOT NULL AND p.process_name IS NOT NULL
    )
    -- new_country: 5+ baseline days
    SELECT 'user' AS entity_type, a.entity, 'new_country' AS kind,
           IFF(ARRAY_CONTAINS(a.country::VARIANT, COALESCE(g.value:countries, ARRAY_CONSTRUCT())), 0.6, 0.85) AS score,
           'Signed in from ' || a.country || ', a country this user has not used in ' || u.days_seen || ' days of history'
               || IFF(ARRAY_CONTAINS(a.country::VARIANT, COALESCE(g.value:countries, ARRAY_CONSTRUCT())), '',
                      ' and no one in their peer group (' || COALESCE(u.peer_group, '?') || ') has') AS detail,
           OBJECT_CONSTRUCT('country', a.country, 'src', a.src, 'usual', u.value:countries) AS evidence,
           a._time AS event_time, a.entity || '|new_country|' || a.country AS dedupe_key
    FROM auth_now a JOIN up u ON u.entity = a.entity AND u.metric = 'auth'
    LEFT JOIN pp g ON g.entity = u.peer_group AND g.metric = 'auth'
    WHERE a.country IS NOT NULL AND u.days_seen >= 5 AND NOT ARRAY_CONTAINS(a.country::VARIANT, u.value:countries)
    QUALIFY ROW_NUMBER() OVER (PARTITION BY a.entity, a.country ORDER BY a._time) = 1
    UNION ALL
    -- new_source_ip: 20+ baseline sign-ins
    SELECT 'user', a.entity, 'new_source_ip', 0.3,
           'Signed in from ' || a.src || ', an address not seen for this user in ' || u.sample_count || ' sign-ins',
           OBJECT_CONSTRUCT('src', a.src, 'known_addresses', ARRAY_SIZE(u.value:srcs)), a._time, a.entity || '|new_source_ip|' || a.src
    FROM auth_now a JOIN up u ON u.entity = a.entity AND u.metric = 'auth'
    WHERE a.src IS NOT NULL AND u.sample_count >= 20 AND NOT ARRAY_CONTAINS(a.src::VARIANT, u.value:srcs)
    QUALIFY ROW_NUMBER() OVER (PARTITION BY a.entity, a.src ORDER BY a._time) = 1
    UNION ALL
    -- off_hours: 30+ baseline sign-ins
    SELECT 'user', a.entity, 'off_hours', 0.4,
           'Signed in at ' || LPAD(a.hr, 2, '0') || ':00, outside the hours this user is normally active ('
               || ARRAY_TO_STRING(u.value:active_hours, ', ') || ')',
           OBJECT_CONSTRUCT('hour', a.hr, 'active_hours', u.value:active_hours), a._time,
           a.entity || '|off_hours|' || DATE_TRUNC('day', a._time)::DATE
    FROM auth_now a JOIN up u ON u.entity = a.entity AND u.metric = 'auth'
    WHERE u.sample_count >= 30 AND u.value:active_hours IS NOT NULL AND NOT ARRAY_CONTAINS(a.hr::VARIANT, u.value:active_hours)
    QUALIFY ROW_NUMBER() OVER (PARTITION BY a.entity ORDER BY a._time) = 1
    UNION ALL
    -- volume_spike: 3+ baseline days; above mean + max(3 sd, 2 x mean) and at least 10k rows
    SELECT 'user', r.entity, 'volume_spike',
           LEAST(0.95, 0.5 + LN(r.rows_read / GREATEST(u.value:mean_rows::NUMBER, 1)) / 20),
           'Read ' || TO_VARCHAR(r.rows_read, 'FM999,999,999,999') || ' rows in 24h; this user''s daily norm is about '
               || TO_VARCHAR(u.value:mean_rows::NUMBER, 'FM999,999,999,999') || ' (max ' || TO_VARCHAR(u.value:max_rows::NUMBER, 'FM999,999,999,999') || ')',
           OBJECT_CONSTRUCT('rows_24h', r.rows_read, 'mean_rows', u.value:mean_rows, 'sd_rows', u.value:sd_rows), r.last_time,
           r.entity || '|volume_spike|' || DATE_TRUNC('day', r.last_time)::DATE
    FROM reads_now r JOIN up u ON u.entity = r.entity AND u.metric = 'reads'
    WHERE u.days_seen >= 3 AND r.rows_read >= 10000
      AND r.rows_read > u.value:mean_rows::NUMBER + GREATEST(3 * u.value:sd_rows::NUMBER, 2 * u.value:mean_rows::NUMBER)
    UNION ALL
    -- peer_outlier: above 3x the peer group's p95 day (3+ members), regardless of own history
    SELECT 'user', r.entity, 'peer_outlier', 0.55,
           'Read ' || TO_VARCHAR(r.rows_read, 'FM999,999,999,999') || ' rows in 24h, over 3x what members of '
               || g.entity || ' read on a busy day (p95 ' || TO_VARCHAR(g.value:p95_rows::NUMBER, 'FM999,999,999,999') || ')',
           OBJECT_CONSTRUCT('rows_24h', r.rows_read, 'peer_group', g.entity, 'peer_p95', g.value:p95_rows, 'members', g.value:members),
           r.last_time, r.entity || '|peer_outlier|' || DATE_TRUNC('day', r.last_time)::DATE
    FROM reads_now r
    JOIN up u ON u.entity = r.entity
    JOIN pp g ON g.entity = u.peer_group AND g.metric = 'reads'
    WHERE g.value:members::NUMBER >= 3 AND r.rows_read >= 10000 AND r.rows_read > 3 * g.value:p95_rows::NUMBER
    QUALIFY ROW_NUMBER() OVER (PARTITION BY r.entity ORDER BY u.metric) = 1
    UNION ALL
    -- new_lineage: 3+ baseline days on the host, pair seen on fewer than 2 hosts fleet-wide
    SELECT 'host', UPPER(p.dest), 'new_lineage', 0.5,
           'Ran ' || REPLACE(p.pair, '>', ' -> ')
               || ' for the first time on this host (' || h.days_seen || ' days of history); rare across the fleet',
           OBJECT_CONSTRUCT('parent', p.parent_process_name, 'process', p.process_name, 'cmd', LEFT(p.process, 300),
                            'hosts_with_pair', COALESCE(ph.hosts, 0)),
           p._time, UPPER(p.dest) || '|new_lineage|' || p.pair
    FROM proc_now p
    JOIN SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES h ON h.entity_type = 'host' AND h.entity = UPPER(p.dest) AND h.metric = 'lineage'
    LEFT JOIN pair_hosts ph ON ph.pair = p.pair
    WHERE h.days_seen >= 3 AND NOT ARRAY_CONTAINS(p.pair::VARIANT, h.value:pairs) AND COALESCE(ph.hosts, 0) < 2
    QUALIFY ROW_NUMBER() OVER (PARTITION BY UPPER(p.dest), p.pair ORDER BY p._time) = 1
    UNION ALL
    -- new_cloud_action: 3+ baseline days, action used by at most one other peer
    SELECT 'user', LOWER(c.user_name), 'new_cloud_action', 0.4,
           'Called ' || c.action || ' for the first time (' || u.days_seen || ' days of cloud history)',
           OBJECT_CONSTRUCT('action', c.action, 'known_actions', ARRAY_SIZE(u.value:actions)), c._time,
           LOWER(c.user_name) || '|new_cloud_action|' || c.action
    FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API c
    JOIN up u ON u.entity = LOWER(c.user_name) AND u.metric = 'cloud'
    LEFT JOIN peer_actions pa ON pa.peer_group = u.peer_group AND pa.action = c.action
    WHERE c._time > DATEADD('day', -1, CURRENT_TIMESTAMP()) AND u.days_seen >= 3 AND c.action IS NOT NULL
      AND NOT ARRAY_CONTAINS(c.action::VARIANT, u.value:actions)
      AND COALESCE(ARRAY_SIZE(ARRAY_REMOVE(pa.users, u.entity::VARIANT)), 0) <= 1
    QUALIFY ROW_NUMBER() OVER (PARTITION BY LOWER(c.user_name), c.action ORDER BY c._time) = 1;

    -- canary / probe entities are not behaviour
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.UEBA_ANOMALIES
        (entity_type, entity, kind, score, detail, evidence, method, event_time, dedupe_key)
    SELECT c.entity_type, c.entity, c.kind, ROUND(c.score, 2), LEFT(c.detail, 1000), c.evidence, 'profile', c.event_time, c.dedupe_key
    FROM XDR_UEBA_CAND c
    WHERE NOT CONTAINS(LOWER(c.entity), 'xdrcanary')
      AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_ANOMALIES a WHERE a.dedupe_key = c.dedupe_key);
    v_n := SQLROWCOUNT;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'new_anomalies', :v_n);
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Cortex ML anomaly detection on daily activity (entities with 14+ active days)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_UEBA_ML(P_MODE VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import json

DB = "SNOWFLAKE_XDR"
MIN_DAYS = 14


def one(s, sql, params=None):
    r = s.sql(sql, params=params).collect()
    return r[0].as_dict() if r else None


def train_and_detect(s, train, test):
    """Fit SNOWFLAKE.ML.ANOMALY_DETECTION per entity series; return flagged rows of `test`."""
    s.sql(f"""CREATE OR REPLACE SNOWFLAKE.ML.ANOMALY_DETECTION XDR_UEBA_MODEL(
                INPUT_DATA => TABLE({train}), SERIES_COLNAME => 'ENTITY', TIMESTAMP_COLNAME => 'TS',
                TARGET_COLNAME => 'N', LABEL_COLNAME => '')""").collect()
    s.sql(f"""CALL XDR_UEBA_MODEL!DETECT_ANOMALIES(
                INPUT_DATA => TABLE({test}), SERIES_COLNAME => 'ENTITY', TIMESTAMP_COLNAME => 'TS',
                TARGET_COLNAME => 'N')""").collect()
    out = [r.as_dict() for r in s.sql("""SELECT series::VARCHAR AS entity, ts, y, forecast, upper_bound, percentile
                                          FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE is_anomaly""").collect()]
    s.sql("DROP SNOWFLAKE.ML.ANOMALY_DETECTION IF EXISTS XDR_UEBA_MODEL").collect()
    return out


def main(s, P_MODE):
    mode = (P_MODE or "run").lower()
    if mode == "selftest":
        # 3 synthetic series, 21 days of steady activity, one with a 10x spike on the scored day
        s.sql("""CREATE OR REPLACE TEMPORARY TABLE XDR_UEBA_ML_ALL AS
                 SELECT 'selftest_' || e.v AS entity,
                        DATEADD('day', d.i, DATEADD('day', -22, CURRENT_DATE()))::TIMESTAMP_NTZ AS ts,
                        IFF(e.v = 'b' AND d.i = 21, 1000, 100 + MOD(d.i * 7 + e.k, 11))::FLOAT AS n
                 FROM (SELECT column1 AS v, column2 AS k FROM VALUES ('a', 1), ('b', 2), ('c', 3)) e,
                      (SELECT ROW_NUMBER() OVER (ORDER BY SEQ4()) - 1 AS i FROM TABLE(GENERATOR(ROWCOUNT => 22))) d""").collect()
    else:
        # daily activity per user: sign-ins + database statements (30 days)
        s.sql(f"""CREATE OR REPLACE TEMPORARY TABLE XDR_UEBA_ML_ALL AS
                  SELECT entity, ts, COUNT(*)::FLOAT AS n FROM (
                      SELECT LOWER(user_name) AS entity, DATE_TRUNC('day', _time)::TIMESTAMP_NTZ AS ts
                      FROM {DB}.RAW_LOGS.AUTHENTICATION WHERE user_name IS NOT NULL AND _time > DATEADD('day', -30, CURRENT_TIMESTAMP())
                      UNION ALL
                      SELECT LOWER(user_name), DATE_TRUNC('day', _time)::TIMESTAMP_NTZ
                      FROM {DB}.RAW_LOGS.DATABASE_ACTIVITY WHERE user_name IS NOT NULL AND _time > DATEADD('day', -30, CURRENT_TIMESTAMP()))
                  WHERE NOT CONTAINS(entity, 'xdrcanary')
                  GROUP BY 1, 2""").collect()
    s.sql(f"""CREATE OR REPLACE TEMPORARY TABLE XDR_UEBA_ML_ELIGIBLE AS
              SELECT entity FROM XDR_UEBA_ML_ALL GROUP BY 1 HAVING COUNT(*) >= {MIN_DAYS + 1}""").collect()
    eligible = one(s, "SELECT COUNT(*) AS n FROM XDR_UEBA_ML_ELIGIBLE")["N"]
    if not eligible:
        most = one(s, "SELECT MAX(c) AS m FROM (SELECT COUNT(*) AS c FROM XDR_UEBA_ML_ALL GROUP BY entity)")["M"] or 0
        return {"ok": True, "skipped": True, "message": f"Cortex ML skipped: no entity has {MIN_DAYS}+ active days yet "
                                                       f"(most: {most}); profile-based anomalies still run"}
    s.sql("""CREATE OR REPLACE TEMPORARY TABLE XDR_UEBA_ML_TRAIN AS
             SELECT a.* FROM XDR_UEBA_ML_ALL a JOIN XDR_UEBA_ML_ELIGIBLE e ON e.entity = a.entity
             QUALIFY ROW_NUMBER() OVER (PARTITION BY a.entity ORDER BY a.ts DESC) > 1""").collect()
    s.sql("""CREATE OR REPLACE TEMPORARY TABLE XDR_UEBA_ML_TEST AS
             SELECT a.* FROM XDR_UEBA_ML_ALL a JOIN XDR_UEBA_ML_ELIGIBLE e ON e.entity = a.entity
             QUALIFY ROW_NUMBER() OVER (PARTITION BY a.entity ORDER BY a.ts DESC) = 1""").collect()
    flagged = train_and_detect(s, "XDR_UEBA_ML_TRAIN", "XDR_UEBA_ML_TEST")
    if mode == "selftest":
        ok = [f["ENTITY"] for f in flagged] == ["selftest_b"]
        return {"ok": ok, "selftest": True, "flagged": flagged,
                "message": "Cortex ML anomaly detection flagged exactly the injected spike" if ok
                           else f"unexpected result: flagged {[f['ENTITY'] for f in flagged]}"}
    added = 0
    for f in flagged:
        key = f"{f['ENTITY']}|ml_daily_activity|{str(f['TS'])[:10]}"
        added += s.sql(f"""INSERT INTO {DB}.DETECTIONS.UEBA_ANOMALIES
                              (entity_type, entity, kind, score, detail, evidence, method, event_time, dedupe_key)
                           SELECT 'user', ?, 'ml_daily_activity', LEAST(0.9, GREATEST(0.4, ?)), ?, PARSE_JSON(?), 'cortex_ml',
                                  ?::TIMESTAMP_NTZ, ?
                           WHERE NOT EXISTS (SELECT 1 FROM {DB}.DETECTIONS.UEBA_ANOMALIES WHERE dedupe_key = ?)""",
                        params=[f["ENTITY"], float(f["PERCENTILE"] or 0.9),
                                f"{int(f['Y'])} events on {str(f['TS'])[:10]}; Cortex ML expected about {int(f['FORECAST'])} "
                                f"(upper bound {int(f['UPPER_BOUND'])})",
                                json.dumps({k.lower(): v for k, v in f.items()}, default=str), str(f["TS"]), key, key]).collect()[0][0]
    return {"ok": True, "eligible_entities": eligible, "flagged": len(flagged), "added": added}
$$;

-- ---------------------------------------------------------------------------
-- 4. Orchestration
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_UEBA()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_age NUMBER;
    p VARIANT := NULL;
    d VARIANT;
    m VARIANT;
BEGIN
    SELECT DATEDIFF('hour', MAX(built_at), CURRENT_TIMESTAMP()) INTO :v_age FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_PROFILES;
    IF (v_age IS NULL OR v_age >= 20) THEN
        CALL SNOWFLAKE_XDR.DETECTIONS.BUILD_UEBA_PROFILES() INTO :p;
    END IF;
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_UEBA_ANOMALIES() INTO :d;
    IF (v_age IS NULL OR v_age >= 20) THEN   -- daily: the ML step trains a model
        CALL SNOWFLAKE_XDR.DETECTIONS.RUN_UEBA_ML('run') INTO :m;
    END IF;
    RETURN OBJECT_CONSTRUCT('profiles', :p, 'anomalies', :d, 'ml', :m);
END;
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_UEBA
    WAREHOUSE = XDR_WH
    SCHEDULE = '60 MINUTE'
    COMMENT = 'UEBA: rebuild 30-day profiles daily, score the last 24h hourly, Cortex ML daily'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_UEBA();
ALTER TASK SNOWFLAKE_XDR.DETECTIONS.TASK_UEBA RESUME;

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_UEBA_ENTITY AS
SELECT entity, entity_type, COUNT(*) AS anomalies_7d, MAX(score) AS max_score,
       ARRAY_AGG(DISTINCT kind) AS kinds, MAX(event_time) AS last_anomaly
FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_ANOMALIES
WHERE event_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY 1, 2;

-- ---------------------------------------------------------------------------
-- 5. Demo: an analyst with 12 days of normal behaviour (and two peers in the same
--    role) signs in at 03:00 from a new country and reads 1.5M rows. SF-006 fires;
--    UEBA explains why it is unusual for this person and raises its confidence.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SEED_UEBA_DEMO()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    acct VARCHAR := CURRENT_ACCOUNT_NAME();
    v_at TIMESTAMP_LTZ;
    v_tm BOOLEAN;
    p VARIANT;
    d VARIANT;
    c VARCHAR;
    v_finding VARIANT;
    v_anoms VARIANT;
BEGIN
    DELETE FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION WHERE source = 'ueba_demo';
    DELETE FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY WHERE source = 'ueba_demo';
    DELETE FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_ANOMALIES WHERE entity LIKE 'ueba_demo%';
    DELETE FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE user_name = 'UEBA_DEMO_ANALYST' AND rule_id = 'SF-006';
    -- Baseline: days -13..-2, 8 sign-ins between 09:00 and 16:00 from the office, ~5k rows read a day
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (event_id, _time, action, app, authentication_method, dest, signature,
        src, user_name, user_role, geo_country, vendor_account, vendor_product, source, sourcetype, index_name)
    SELECT 'ueba:' || UUID_STRING(),
           DATEADD('hour', 9 + MOD(n.i, 8), DATE_TRUNC('day', DATEADD('day', -2 - d.i, CURRENT_TIMESTAMP()))),
           'success', 'snowflake', 'PASSWORD', :acct, 'LOGIN', '10.20.0.' || (5 + MOD(n.i, 2)), u.name, 'ANALYST_ROLE',
           'US', :acct, 'snowflake', 'ueba_demo', 'snowflake:login', 'demo'
    FROM (SELECT column1 AS name FROM VALUES ('UEBA_DEMO_ANALYST'), ('UEBA_DEMO_PEER1'), ('UEBA_DEMO_PEER2')) u,
         (SELECT SEQ4() AS i FROM TABLE(GENERATOR(ROWCOUNT => 12))) d,
         (SELECT SEQ4() AS i FROM TABLE(GENERATOR(ROWCOUNT => 8))) n;
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY (event_id, _time, action, user_name, user_role, src, dest, app,
        query_type, query_text, object, result, rows_affected, warehouse, vendor_account, vendor_product, source, sourcetype, index_name)
    SELECT 'ueba:' || UUID_STRING(), DATEADD('hour', 11, DATE_TRUNC('day', DATEADD('day', -2 - d.i, CURRENT_TIMESTAMP()))),
           'select', u.name, 'ANALYST_ROLE', '10.20.0.5', :acct, 'Snowsight', 'SELECT',
           'SELECT * FROM SNOWFLAKE_XDR.DEMO_FINANCE.CUSTOMERS WHERE region = ''west''', 'SNOWFLAKE_XDR.DEMO_FINANCE',
           'success', 4000 + MOD(d.i * 379, 2000), 'XDR_WH', :acct, 'snowflake', 'ueba_demo', 'snowflake:query', 'demo'
    FROM (SELECT column1 AS name FROM VALUES ('UEBA_DEMO_ANALYST'), ('UEBA_DEMO_PEER1'), ('UEBA_DEMO_PEER2')) u,
         (SELECT SEQ4() AS i FROM TABLE(GENERATOR(ROWCOUNT => 12))) d;
    -- Today, ~40 minutes ago (inside SF-006's 3-hour lookback): a sign-in from a new country and address,
    -- then a 1.5M-row read. If that lands outside office hours, off_hours fires too.
    v_at := DATEADD('minute', -40, CURRENT_TIMESTAMP());
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (event_id, _time, action, app, authentication_method, dest, signature,
        src, user_name, user_role, geo_country, vendor_account, vendor_product, source, sourcetype, index_name)
    SELECT 'ueba:' || UUID_STRING(), :v_at, 'success', 'snowflake', 'PASSWORD', :acct, 'LOGIN', '185.220.101.90',
           'UEBA_DEMO_ANALYST', 'ANALYST_ROLE', 'RO', :acct, 'snowflake', 'ueba_demo', 'snowflake:login', 'demo';
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY (event_id, _time, action, user_name, user_role, src, dest, app,
        query_type, query_text, object, result, rows_affected, warehouse, vendor_account, vendor_product, source, sourcetype, index_name)
    SELECT 'ueba:' || UUID_STRING(), DATEADD('minute', 5, :v_at), 'select', 'UEBA_DEMO_ANALYST', 'ANALYST_ROLE',
           '185.220.101.90', :acct, 'PythonConnector', 'SELECT', 'SELECT * FROM SNOWFLAKE_XDR.DEMO_FINANCE.CUSTOMERS',
           'SNOWFLAKE_XDR.DEMO_FINANCE', 'success', 1500000, 'XDR_WH', :acct, 'snowflake', 'ueba_demo', 'snowflake:query', 'demo';
    -- The real pack rule fires (evaluated live even while it is in shadow, like the other demo stories)
    SELECT MAX(test_mode) INTO :v_tm FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE rule_id = 'SF-006';
    UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES SET test_mode = FALSE WHERE rule_id = 'SF-006';
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_SQL('SF-006', FALSE) INTO :c;
    UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES SET test_mode = :v_tm WHERE rule_id = 'SF-006';
    CALL SNOWFLAKE_XDR.DETECTIONS.BUILD_UEBA_PROFILES() INTO :p;
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_UEBA_ANOMALIES() INTO :d;
    CALL SNOWFLAKE_XDR.DETECTIONS.SCORE_CONFIDENCE() INTO :c;
    SELECT OBJECT_CONSTRUCT('finding_id', MAX(finding_id), 'conf_score', MAX(conf_score), 'conf_band', MAX(conf_band),
                            'factors', ANY_VALUE(conf_factors)) INTO :v_finding
    FROM (SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE rule_id = 'SF-006' AND user_name = 'UEBA_DEMO_ANALYST' ORDER BY detection_time DESC LIMIT 1);
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('kind', kind, 'score', score, 'detail', detail)) INTO :v_anoms
    FROM SNOWFLAKE_XDR.DETECTIONS.UEBA_ANOMALIES WHERE entity = 'ueba_demo_analyst';
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'anomalies', :v_anoms, 'finding', :v_finding, 'profiles', :p, 'detect', :d);
END;
$$;
