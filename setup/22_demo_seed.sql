-- ============================================================================
-- Snowflake XDR - 22: Demo Seed State
-- ============================================================================
-- Scripted versions of the demo state that was originally applied by hand:
--   SEED_DEMO_GEO()             geolocation for auth events (Threat Map)
--   SEED_ANALYST_DISPOSITIONS() prior analyst verdicts the FP model learns from
-- Both only touch rows that are still unset, so re-running is harmless.
-- The runner calls them at the right phase: geo after data generation,
-- dispositions after detections and before TRAIN_FP_MODEL.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SEED_DEMO_GEO()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_rows NUMBER;
BEGIN
    -- Deterministic city per event so the map is stable across re-runs
    UPDATE SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION a
    SET a.geo_lat = c.lat,
        a.geo_lon = c.lon,
        a.geo_city = c.city,
        a.geo_country = c.country
    FROM (
        SELECT column1 AS idx, column2 AS city, column3 AS country,
               column4::FLOAT AS lat, column5::FLOAT AS lon
        FROM VALUES
            (0, 'Frankfurt', 'Germany',   50.11,   8.68),
            (1, 'London',    'UK',        51.51,  -0.13),
            (2, 'New York',  'USA',       40.71, -74.01),
            (3, 'Singapore', 'Singapore',  1.35, 103.82),
            (4, 'Sao Paulo', 'Brazil',   -23.55, -46.63),
            (5, 'Moscow',    'Russia',    55.76,  37.62),
            (6, 'Beijing',   'China',     39.90, 116.41),
            (7, 'Mumbai',    'India',     19.08,  72.88)
    ) c
    WHERE a.geo_lat IS NULL
      AND c.idx = ABS(HASH(COALESCE(a.src, a.event_id))) % 8;

    v_rows := SQLROWCOUNT;
    RETURN 'Geo seeded on ' || :v_rows || ' auth events.';
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SEED_ANALYST_DISPOSITIONS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_fp NUMBER;
    v_benign NUMBER;
BEGIN
    -- DET-021 on the scheduled vulnerability scanner: analysts have marked it
    -- a false positive repeatedly. The 2 newest findings per entity stay open
    -- so SCORE_FINDINGS_FP has something to auto-suppress in the demo.
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    SET f.disposition = 'false_positive',
        f.status = 'dismissed',
        f.triage_notes = 'Analyst: vulnerability scanner scheduled scan',
        f.triaged_at = CURRENT_TIMESTAMP()
    FROM (
        SELECT finding_id
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE rule_id = 'DET-021'
        QUALIFY ROW_NUMBER() OVER (
            PARTITION BY COALESCE(user_name, src, dest)
            ORDER BY event_time DESC) > 2
    ) older
    WHERE f.finding_id = older.finding_id
      AND f.disposition IS NULL;
    v_fp := SQLROWCOUNT;

    -- ML-ANOMALY-001 volume spikes on admin accounts: authorized admin work
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    SET f.disposition = 'benign',
        f.status = 'resolved',
        f.triage_notes = 'Analyst: authorized admin activity',
        f.triaged_at = CURRENT_TIMESTAMP()
    FROM (
        SELECT finding_id
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE rule_id = 'ML-ANOMALY-001'
        QUALIFY ROW_NUMBER() OVER (
            PARTITION BY user_name ORDER BY event_time DESC) > 1
    ) older
    WHERE f.finding_id = older.finding_id
      AND f.disposition IS NULL;
    v_benign := SQLROWCOUNT;

    RETURN 'Seeded dispositions: ' || :v_fp || ' false_positive, '
        || :v_benign || ' benign.';
END;
$$;
