-- ============================================================================
-- Snowflake XDR - 30: OpenTelemetry ingestion (phase 2)
-- ============================================================================
-- Out-of-the-box ingestion: any OpenTelemetry Collector or OTLP sender ships
-- logs to the XDR_OTLP_RECEIVER service (31_otel_receiver.sql), which lands
-- them in RAW_LOGS.OTEL_LOGS. CIM mappings turn each source into the existing
-- CIM tables (AUTHENTICATION, CLOUD_API, ...) so every built-in rule, custom
-- rule and the Detection Autopilot work on new sources unchanged.
--
--   OTLP/HTTP -> receiver -> INGEST_OTLP_LOGS -> OTEL_LOGS
--             -> APPLY_CIM_MAPPINGS (watermark per mapping) -> CIM tables
--
-- Sources are identified by a per-source token (X-XDR-Source-Token header) or,
-- when none is sent, by the resource attribute service.name. Unknown sources
-- are auto-registered as 'unmapped'; the Detection Autopilot proposes a
-- mapping for them (change_type new_parser) under the same policy and
-- approval flow as detections.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Landing table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS (
    otel_id          VARCHAR DEFAULT UUID_STRING(),
    received_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    source_id        VARCHAR(100),
    event_time       TIMESTAMP_LTZ,
    observed_time    TIMESTAMP_LTZ,
    severity_text    VARCHAR(50),
    severity_number  NUMBER,
    body             VARIANT,        -- string, or parsed JSON when the body is JSON text
    attributes       VARIANT,        -- log record attributes, flattened to key -> value
    resource         VARIANT,        -- resource attributes (service.name, host.name, ...)
    scope            VARIANT,
    trace_id         VARCHAR(64),
    span_id          VARCHAR(32)
)
CLUSTER BY (source_id, TO_DATE(received_at))
COMMENT = 'Raw OpenTelemetry log records (OTLP), one row per log record';

-- ---------------------------------------------------------------------------
-- 2. Sources, tokens, mappings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES (
    source_id      VARCHAR(100) PRIMARY KEY,
    name           VARCHAR(200),
    kind           VARCHAR(50),       -- okta, linux_auth, cloudtrail, unknown, ...
    token_hash     VARCHAR(64),       -- SHA2 of the source token; NULL = identified by service.name
    status         VARCHAR(20),       -- unmapped | mapping_proposed | mapped | paused
    owner          VARCHAR(255),
    created_at     TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    first_seen     TIMESTAMP_LTZ,
    last_seen      TIMESTAMP_LTZ,
    notes          VARCHAR(1000)
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS (
    mapping_id     VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    source_id      VARCHAR(100),
    target_table   VARCHAR(50),       -- a RAW_LOGS CIM table
    mapping_sql    VARCHAR,           -- SELECT ... FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE source_id = '<id>'
    status         VARCHAR(20),       -- draft | live | paused | retired
    version        NUMBER DEFAULT 1,
    created_by     VARCHAR(255),
    created_at     TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at     TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    watermark      TIMESTAMP_LTZ,     -- max received_at already mapped
    rows_mapped    NUMBER DEFAULT 0,
    last_run_at    TIMESTAMP_LTZ,
    last_error     VARCHAR(2000),
    validation     VARIANT
);

-- ---------------------------------------------------------------------------
-- 3. OTLP helpers
-- ---------------------------------------------------------------------------
-- OTLP AnyValue -> plain VARIANT ({"stringValue": "x"} -> "x", kvlistValue -> object, ...)
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.RAW_LOGS.OTLP_ANYVALUE(V VARIANT)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'conv'
AS
$$
def conv(v):
    if not isinstance(v, (dict, str, int, float, bool, list)):    # SQL NULL
        return None
    if not isinstance(v, dict):
        return v
    if "stringValue" in v:
        return v["stringValue"]
    if "boolValue" in v:
        return v["boolValue"]
    if "intValue" in v:
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return v["intValue"]
    if "doubleValue" in v:
        return v["doubleValue"]
    if "bytesValue" in v:
        return v["bytesValue"]
    if "arrayValue" in v:
        return [conv(x) for x in (v["arrayValue"] or {}).get("values", [])]
    if "kvlistValue" in v:
        return {kv.get("key"): conv(kv.get("value")) for kv in (v["kvlistValue"] or {}).get("values", [])}
    return None
$$;

-- OTLP KeyValue list -> object
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.RAW_LOGS.OTLP_ATTRS(KV VARIANT)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'conv'
AS
$$
def any_(v):
    if not isinstance(v, dict):
        return v
    for k in ("stringValue", "boolValue", "doubleValue", "bytesValue"):
        if k in v:
            return v[k]
    if "intValue" in v:
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return v["intValue"]
    if "arrayValue" in v:
        return [any_(x) for x in (v["arrayValue"] or {}).get("values", [])]
    if "kvlistValue" in v:
        return {kv.get("key"): any_(kv.get("value")) for kv in (v["kvlistValue"] or {}).get("values", [])}
    return None

def conv(kv):
    if not isinstance(kv, list):    # absent attributes arrive as SQL NULL
        return {}
    return {x.get("key"): any_(x.get("value")) for x in kv if isinstance(x, dict)}
$$;

-- Nanoseconds since epoch (string or number) -> timestamp
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.RAW_LOGS.OTLP_TIME(NS VARIANT)
RETURNS TIMESTAMP_LTZ
AS
$$
    IFF(TRY_CAST(NS::VARCHAR AS NUMBER(38, 0)) IS NULL OR TRY_CAST(NS::VARCHAR AS NUMBER(38, 0)) = 0, NULL,
        TO_TIMESTAMP_LTZ(TRY_CAST(NS::VARCHAR AS NUMBER(38, 0)), 9))
$$;

-- ---------------------------------------------------------------------------
-- 4. Ingest one OTLP/JSON ExportLogsServiceRequest
--    Called by the receiver (protobuf is converted to OTLP JSON first) and
--    usable directly from SQL for tests and backfills.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.RAW_LOGS.INGEST_OTLP_LOGS(
    P_PAYLOAD VARCHAR, P_SOURCE_TOKEN VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_token_source VARCHAR;
    v_n NUMBER;
    v_new_sources NUMBER;
BEGIN
    -- A presented token must match a registered source; a wrong token is rejected
    IF (NULLIF(TRIM(:P_SOURCE_TOKEN), '') IS NOT NULL) THEN
        SELECT MAX(source_id) INTO :v_token_source FROM SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES
        WHERE token_hash = SHA2(TRIM(:P_SOURCE_TOKEN), 256) AND status <> 'paused';
        IF (v_token_source IS NULL) THEN
            RETURN OBJECT_CONSTRUCT('accepted', 0, 'rejected', 'unknown or paused source token');
        END IF;
    END IF;

    CREATE OR REPLACE TEMPORARY TABLE XDR_OTLP_BATCH AS
    WITH req AS (SELECT TRY_PARSE_JSON(:P_PAYLOAD) AS j),
    recs AS (
        SELECT SNOWFLAKE_XDR.RAW_LOGS.OTLP_ATTRS(rl.value:resource:attributes) AS resource,
               sl.value:scope AS scope,
               lr.value AS r
        FROM req,
             LATERAL FLATTEN(INPUT => req.j:resourceLogs) rl,
             LATERAL FLATTEN(INPUT => rl.value:scopeLogs) sl,
             LATERAL FLATTEN(INPUT => sl.value:logRecords) lr
    )
    SELECT COALESCE(:v_token_source,
                    LOWER(REGEXP_REPLACE(COALESCE(resource:"xdr.source"::VARCHAR, resource:"service.name"::VARCHAR, 'unknown'),
                                         '[^A-Za-z0-9_.-]', '_'))) AS source_id,
           COALESCE(SNOWFLAKE_XDR.RAW_LOGS.OTLP_TIME(r:timeUnixNano), SNOWFLAKE_XDR.RAW_LOGS.OTLP_TIME(r:observedTimeUnixNano),
                    CURRENT_TIMESTAMP()) AS event_time,
           SNOWFLAKE_XDR.RAW_LOGS.OTLP_TIME(r:observedTimeUnixNano) AS observed_time,
           r:severityText::VARCHAR AS severity_text,
           TRY_CAST(r:severityNumber::VARCHAR AS NUMBER) AS severity_number,
           -- JSON text bodies (Okta, CloudTrail) are parsed so mappings can address fields
           COALESCE(TRY_PARSE_JSON(SNOWFLAKE_XDR.RAW_LOGS.OTLP_ANYVALUE(r:body)::VARCHAR),
                    SNOWFLAKE_XDR.RAW_LOGS.OTLP_ANYVALUE(r:body)) AS body,
           SNOWFLAKE_XDR.RAW_LOGS.OTLP_ATTRS(r:attributes) AS attributes,
           resource, scope,
           NULLIF(r:traceId::VARCHAR, '') AS trace_id,
           NULLIF(r:spanId::VARCHAR, '') AS span_id
    FROM recs;

    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
        (source_id, event_time, observed_time, severity_text, severity_number, body, attributes, resource, scope,
         trace_id, span_id)
    SELECT source_id, event_time, observed_time, severity_text, severity_number, body, attributes, resource, scope,
           trace_id, span_id
    FROM XDR_OTLP_BATCH;
    v_n := SQLROWCOUNT;

    -- Register sources seen for the first time; keep last_seen fresh
    MERGE INTO SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES t
    USING (SELECT source_id, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
           FROM XDR_OTLP_BATCH GROUP BY 1) s
    ON t.source_id = s.source_id
    WHEN MATCHED THEN UPDATE SET t.last_seen = GREATEST(COALESCE(t.last_seen, s.last_seen), s.last_seen)
    WHEN NOT MATCHED THEN INSERT (source_id, name, kind, status, first_seen, last_seen, notes)
        VALUES (s.source_id, s.source_id, 'unknown', 'unmapped', s.first_seen, s.last_seen,
                'auto-registered on first OTLP batch');
    v_new_sources := SQLROWCOUNT;

    RETURN OBJECT_CONSTRUCT('accepted', :v_n, 'source', :v_token_source);
END;
$$;

-- Register a source and issue its token (returned once; only the hash is stored)
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.REGISTER_OTEL_SOURCE(
    P_SOURCE_ID VARCHAR, P_NAME VARCHAR, P_KIND VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_id VARCHAR := LOWER(REGEXP_REPLACE(TRIM(:P_SOURCE_ID), '[^A-Za-z0-9_.-]', '_'));
    v_token VARCHAR := 'xdr_' || REPLACE(UUID_STRING(), '-', '') || REPLACE(UUID_STRING(), '-', '');
BEGIN
    IF (v_id IS NULL OR v_id = '') THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'source id required');
    END IF;
    MERGE INTO SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES t
    USING (SELECT :v_id AS source_id) s ON t.source_id = s.source_id
    WHEN MATCHED THEN UPDATE SET t.token_hash = SHA2(:v_token, 256), t.name = COALESCE(NULLIF(:P_NAME, ''), t.name),
        t.kind = COALESCE(NULLIF(:P_KIND, ''), t.kind)
    WHEN NOT MATCHED THEN INSERT (source_id, name, kind, token_hash, status, owner)
        VALUES (:v_id, COALESCE(NULLIF(:P_NAME, ''), :v_id), COALESCE(NULLIF(:P_KIND, ''), 'unknown'),
                SHA2(:v_token, 256), 'unmapped', CURRENT_USER());
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'source_id', :v_id, 'token', :v_token,
                            'message', 'Store this token now; it is not shown again.');
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. Mapping validation and the mapping engine
-- ---------------------------------------------------------------------------
-- Mapping SQL may only read OTEL_LOGS (the shared rule guard checks the rest)
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.REFERENCE.MAPPING_SQL_VIOLATION(S VARCHAR)
RETURNS VARCHAR
AS
$$
    -- String literals (hostnames like 'cloudtrail.amazonaws.com') are blanked before the object checks
    COALESCE(SNOWFLAKE_XDR.DASHBOARDS.RULE_SQL_VIOLATION(REGEXP_REPLACE(S, '\'[^\']*\'', '\'\'')),
             IFF(REGEXP_COUNT(REGEXP_REPLACE(S, '\'[^\']*\'', '\'\''), 'SNOWFLAKE_XDR\\.RAW_LOGS\\.[A-Za-z_][A-Za-z0-9_$]*', 1, 'i')
                 <> REGEXP_COUNT(S, 'SNOWFLAKE_XDR\\.RAW_LOGS\\.OTEL_LOGS\\b', 1, 'i'),
                 'may only read SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS', NULL))
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.VALIDATE_CIM_MAPPING(
    P_TARGET VARCHAR, P_SQL VARCHAR, P_SOURCE_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import re

REQUIRED = {"AUTHENTICATION": ["_TIME", "ACTION", "USER_NAME"], "CLOUD_API": ["_TIME", "ACTION", "USER_NAME"],
            "NETWORK_TRAFFIC": ["_TIME", "SRC", "DEST"], "DNS_ACTIVITY": ["_TIME", "SRC", "QUERY"],
            "WEB_ACTIVITY": ["_TIME", "SRC", "URL"], "ENDPOINT_PROCESSES": ["_TIME", "DEST", "PROCESS"],
            "ENDPOINT_FILESYSTEM": ["_TIME", "DEST", "FILE_PATH"], "ENDPOINT_REGISTRY": ["_TIME", "DEST", "REGISTRY_PATH"],
            "ENDPOINT_SERVICES": ["_TIME", "DEST", "SERVICE_NAME"], "INTRUSION_DETECTION": ["_TIME", "SRC", "SIGNATURE"],
            "DATABASE_ACTIVITY": ["_TIME", "ACTION", "USER_NAME"]}


def main(s, target, sql, source_id):
    target = (target or "").upper()
    if target not in REQUIRED:
        return {"ok": False, "error": f"target must be one of {sorted(REQUIRED)}"}
    sql = re.sub(r";\s*$", "", (sql or "").strip())
    v = s.sql("SELECT SNOWFLAKE_XDR.REFERENCE.MAPPING_SQL_VIOLATION(?) AS v", params=[sql]).collect()[0]["V"]
    if v:
        return {"ok": False, "error": "mapping SQL " + v}
    cols = {r["COLUMN_NAME"]: r["DATA_TYPE"] for r in s.sql(
        "SELECT column_name, data_type FROM SNOWFLAKE_XDR.INFORMATION_SCHEMA.COLUMNS "
        "WHERE table_schema = 'RAW_LOGS' AND table_name = ?", params=[target]).collect()}
    try:
        df = s.sql(f"SELECT * FROM ({sql}) LIMIT 500")
        names = [f.name.strip('"').upper() for f in df.schema.fields]
        data = [r.as_dict() for r in df.collect()]
    except Exception as e:
        return {"ok": False, "error": "mapping SQL failed: " + str(e)[:600]}
    unknown = [n for n in names if n not in cols]
    if unknown:
        return {"ok": False, "error": f"columns not in {target}: {', '.join(unknown)}", "target_columns": sorted(cols)}
    missing = [c for c in REQUIRED[target] if c not in names]
    if missing:
        return {"ok": False, "error": f"required columns missing: {', '.join(missing)}"}
    src_rows = s.sql("SELECT COUNT(*) AS n FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE source_id = ?",
                     params=[source_id]).collect()[0]["N"]
    if not data:
        return {"ok": False, "error": "mapping returned no rows from the source sample", "source_rows": src_rows}
    fill = {c: round(sum(1 for r in data if r.get(c) not in (None, "")) / len(data), 2) for c in names}
    weak = {c: f for c, f in fill.items() if c in REQUIRED[target] and f < 0.95}
    sample = [{k: (str(v)[:80] if v is not None else None) for k, v in r.items()} for r in data[:5]]
    return {"ok": not weak, "error": (f"required columns under 95% filled: {weak}" if weak else None),
            "rows_sampled": len(data), "source_rows": src_rows, "coverage": fill, "sample": sample,
            "columns": names}
$$;

-- Apply every live mapping incrementally (watermark on received_at)
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.APPLY_CIM_MAPPINGS()
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import re

TARGETS = ("AUTHENTICATION", "CLOUD_API", "NETWORK_TRAFFIC", "DNS_ACTIVITY", "WEB_ACTIVITY", "ENDPOINT_PROCESSES",
           "ENDPOINT_FILESYSTEM", "ENDPOINT_REGISTRY", "ENDPOINT_SERVICES", "INTRUSION_DETECTION", "DATABASE_ACTIVITY")


def main(s):
    out = {}
    for m in s.sql("SELECT * FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS WHERE status = 'live'").collect():
        m = m.as_dict()
        mid, tgt = m["MAPPING_ID"], (m["TARGET_TABLE"] or "").upper()
        try:
            if tgt not in TARGETS:
                raise ValueError("invalid target table " + tgt)
            sql = re.sub(r";\s*$", "", m["MAPPING_SQL"].strip())
            v = s.sql("SELECT SNOWFLAKE_XDR.REFERENCE.MAPPING_SQL_VIOLATION(?) AS v", params=[sql]).collect()[0]["V"]
            if v:
                raise ValueError("mapping SQL " + v)
            hi = s.sql("SELECT MAX(received_at) AS t FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE source_id = ?",
                       params=[m["SOURCE_ID"]]).collect()[0]["T"]
            if hi is None or (m["WATERMARK"] is not None and hi <= m["WATERMARK"]):
                # Nothing new; a passing guard check means any earlier error is resolved
                s.sql("""UPDATE SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS SET last_run_at = CURRENT_TIMESTAMP(), last_error = NULL
                         WHERE mapping_id = ?""", params=[mid]).collect()
                out[m["SOURCE_ID"] + "->" + tgt] = 0
                continue
            # Restrict the mapping to new rows: OTEL_LOGS is re-scoped through a CTE of the same name
            lo = m["WATERMARK"]
            win = ("WITH OTEL_WINDOW AS (SELECT * FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE source_id = ? "
                   "AND received_at <= ?" + (" AND received_at > ?" if lo is not None else "") + ") ")
            inner = re.sub(r"SNOWFLAKE_XDR\.RAW_LOGS\.OTEL_LOGS\b", "OTEL_WINDOW", sql, flags=re.I)
            if inner.lstrip().upper().startswith("WITH "):
                inner = inner.lstrip()[5:]
                body = win[:-1] + ", " + inner
            else:
                body = win + inner
            cols = [f.name.strip('"').upper() for f in
                    s.sql(f"SELECT * FROM ({sql}) LIMIT 0").schema.fields]
            # Cast each mapped column to the target column's type (VARIANT, TIMESTAMP, NUMBER, ...)
            types = {r["COLUMN_NAME"]: r["DATA_TYPE"] for r in s.sql(
                "SELECT column_name, data_type FROM SNOWFLAKE_XDR.INFORMATION_SCHEMA.COLUMNS "
                "WHERE table_schema = 'RAW_LOGS' AND table_name = ?", params=[tgt]).collect()}
            cast = {"VARIANT": "TRY_PARSE_JSON(TO_VARCHAR({c}))", "OBJECT": "TRY_PARSE_JSON(TO_VARCHAR({c}))",
                    "ARRAY": "TRY_PARSE_JSON(TO_VARCHAR({c}))", "NUMBER": "TRY_TO_NUMBER(TO_VARCHAR({c}))",
                    "FLOAT": "TRY_TO_DOUBLE(TO_VARCHAR({c}))", "BOOLEAN": "TRY_TO_BOOLEAN(TO_VARCHAR({c}))",
                    "TIMESTAMP_LTZ": "TRY_TO_TIMESTAMP_LTZ(TO_VARCHAR({c}))", "TIMESTAMP_NTZ": "TRY_TO_TIMESTAMP_NTZ(TO_VARCHAR({c}))",
                    "TIMESTAMP_TZ": "TRY_TO_TIMESTAMP_TZ(TO_VARCHAR({c}))", "TEXT": "TO_VARCHAR({c})"}
            col_list = ", ".join(cols)
            sel_list = ", ".join(cast.get(types.get(c, "TEXT"), "{c}").format(c=f'"{c}"') for c in cols)
            params = [m["SOURCE_ID"], str(hi)] + ([str(lo)] if lo is not None else [])
            n = s.sql(f"""INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.{tgt} ({col_list}, INDEX_NAME, SOURCE, INGESTION_TIME)
                          SELECT {sel_list}, 'otel', ?, CURRENT_TIMESTAMP() FROM ({body})""",
                      params=["otel:" + m["SOURCE_ID"]] + params).collect()[0][0]
            s.sql("""UPDATE SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS SET watermark = ?, rows_mapped = rows_mapped + ?,
                       last_run_at = CURRENT_TIMESTAMP(), last_error = NULL WHERE mapping_id = ?""",
                  params=[str(hi), n, mid]).collect()
            out[m["SOURCE_ID"] + "->" + tgt] = n
        except Exception as e:
            s.sql("""UPDATE SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS SET last_run_at = CURRENT_TIMESTAMP(), last_error = ?
                     WHERE mapping_id = ?""", params=[str(e)[:2000], mid]).collect()
            out[m["SOURCE_ID"] + "->" + tgt] = "error: " + str(e)[:200]
    return out
$$;

-- Go live with a validated mapping (replaces the source's live mapping for that target)
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.ACTIVATE_CIM_MAPPING(P_MAPPING_ID VARCHAR, P_BACKFILL BOOLEAN)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_src VARCHAR;
    v_tgt VARCHAR;
    v_sql VARCHAR;
    v_val VARIANT;
BEGIN
    SELECT MAX(source_id), MAX(target_table), MAX(mapping_sql) INTO :v_src, :v_tgt, :v_sql
    FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS WHERE mapping_id = :P_MAPPING_ID;
    IF (v_src IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'mapping not found');
    END IF;
    CALL SNOWFLAKE_XDR.REFERENCE.VALIDATE_CIM_MAPPING(:v_tgt, :v_sql, :v_src) INTO :v_val;
    IF (NOT COALESCE(v_val:ok::BOOLEAN, FALSE)) THEN
        UPDATE SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS SET validation = :v_val, updated_at = CURRENT_TIMESTAMP()
        WHERE mapping_id = :P_MAPPING_ID;
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'validation failed: ' || v_val:error::VARCHAR);
    END IF;
    UPDATE SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS SET status = 'retired', updated_at = CURRENT_TIMESTAMP()
    WHERE source_id = :v_src AND target_table = :v_tgt AND status = 'live' AND mapping_id <> :P_MAPPING_ID;
    -- Backfill = map everything already landed; otherwise only data from now on
    UPDATE SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS
    SET status = 'live', validation = :v_val, updated_at = CURRENT_TIMESTAMP(),
        watermark = IFF(COALESCE(:P_BACKFILL, TRUE), NULL,
                        (SELECT MAX(received_at) FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE source_id = :v_src))
    WHERE mapping_id = :P_MAPPING_ID;
    UPDATE SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES SET status = 'mapped' WHERE source_id = :v_src;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', 'mapping live for ' || v_src || ' -> ' || v_tgt);
END;
$$;

-- Undo a mapping: stop it and delete the CIM rows it produced
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.RETIRE_CIM_MAPPING(P_MAPPING_ID VARCHAR, P_DELETE_ROWS BOOLEAN)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
TARGETS = ("AUTHENTICATION", "CLOUD_API", "NETWORK_TRAFFIC", "DNS_ACTIVITY", "WEB_ACTIVITY", "ENDPOINT_PROCESSES",
           "ENDPOINT_FILESYSTEM", "ENDPOINT_REGISTRY", "ENDPOINT_SERVICES", "INTRUSION_DETECTION", "DATABASE_ACTIVITY")


def main(s, mid, delete_rows):
    r = s.sql("SELECT source_id, target_table FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS WHERE mapping_id = ?",
              params=[mid]).collect()
    if not r:
        return {"ok": False, "message": "mapping not found"}
    src, tgt = r[0]["SOURCE_ID"], (r[0]["TARGET_TABLE"] or "").upper()
    s.sql("UPDATE SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS SET status = 'retired', updated_at = CURRENT_TIMESTAMP() "
          "WHERE mapping_id = ?", params=[mid]).collect()
    n = 0
    if delete_rows and tgt in TARGETS:
        n = s.sql(f"DELETE FROM SNOWFLAKE_XDR.RAW_LOGS.{tgt} WHERE index_name = 'otel' AND source = ?",
                  params=["otel:" + src]).collect()[0][0]
    live = s.sql("SELECT COUNT(*) AS n FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS WHERE source_id = ? AND status = 'live'",
                 params=[src]).collect()[0]["N"]
    if not live:
        s.sql("UPDATE SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES SET status = 'unmapped' WHERE source_id = ?",
              params=[src]).collect()
    return {"ok": True, "message": f"mapping retired; {n} mapped rows removed from {tgt}"}
$$;

-- ---------------------------------------------------------------------------
-- 6. Shipped mappings for common sources
-- ---------------------------------------------------------------------------
-- Okta System Log (Collector: Okta receiver or a forwarder posting the System Log JSON as the body)
MERGE INTO SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES t
USING (SELECT * FROM VALUES
    ('okta', 'Okta System Log', 'okta'),
    ('linux_auth', 'Linux auth.log / sshd (filelog receiver)', 'linux_auth'),
    ('aws_cloudtrail', 'AWS CloudTrail (awss3 receiver)', 'cloudtrail')
    AS v(source_id, name, kind)) s ON t.source_id = s.source_id
WHEN NOT MATCHED THEN INSERT (source_id, name, kind, status, owner, notes)
    VALUES (s.source_id, s.name, s.kind, 'mapped', 'setup', 'shipped mapping');

DELETE FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS WHERE created_by = 'setup' AND status <> 'live';
INSERT INTO SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS (source_id, target_table, mapping_sql, status, created_by)
SELECT v.source_id, v.target_table, v.mapping_sql, 'live', 'setup'
FROM (SELECT * FROM VALUES
('okta', 'AUTHENTICATION', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:published::VARCHAR), event_time) AS _time,
       CASE WHEN UPPER(body:outcome:result::VARCHAR) = 'SUCCESS' THEN 'success'
            WHEN UPPER(body:outcome:result::VARCHAR) IN ('FAILURE', 'DENY') THEN 'failure'
            ELSE LOWER(body:outcome:result::VARCHAR) END AS action,
       'okta' AS app,
       body:authenticationContext:credentialType::VARCHAR AS authentication_method,
       'okta' AS authentication_service,
       COALESCE(body:target[0]:displayName::VARCHAR, 'okta') AS dest,
       body:outcome:reason::VARCHAR AS reason,
       body:displayMessage::VARCHAR AS signature,
       body:eventType::VARCHAR AS signature_id,
       body:client:ipAddress::VARCHAR AS src,
       SPLIT_PART(body:actor:alternateId::VARCHAR, '@', 1) AS user_name,
       body:actor:id::VARCHAR AS user_id,
       body:client:userAgent:rawUserAgent::VARCHAR AS user_agent,
       body:client:geographicalContext:city::VARCHAR AS geo_city,
       body:client:geographicalContext:country::VARCHAR AS geo_country,
       'Okta' AS vendor_product, 'okta' AS host, 'okta:system_log' AS sourcetype,
       body::VARCHAR AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'okta' AND body:eventType::VARCHAR LIKE 'user.session.%'$$),
('linux_auth', 'AUTHENTICATION', $$SELECT event_time AS _time,
       IFF(body::VARCHAR ILIKE '%Accepted %', 'success', 'failure') AS action,
       'sshd' AS app,
       IFF(body::VARCHAR ILIKE '%publickey%', 'publickey', 'password') AS authentication_method,
       COALESCE(resource:"host.name"::VARCHAR, attributes:"host.name"::VARCHAR) AS dest,
       REGEXP_SUBSTR(body::VARCHAR, '(Failed|Accepted|Invalid) [a-z]+') AS reason,
       REGEXP_SUBSTR(body::VARCHAR, 'from ([0-9a-fA-F.:]+)', 1, 1, 'e', 1) AS src,
       REGEXP_SUBSTR(body::VARCHAR, 'for (invalid user )?([A-Za-z0-9._-]+) from', 1, 1, 'e', 2) AS user_name,
       'OpenSSH' AS vendor_product, COALESCE(resource:"host.name"::VARCHAR, 'linux') AS host,
       'linux_secure' AS sourcetype, body::VARCHAR AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'linux_auth' AND (body::VARCHAR ILIKE '%Failed password%' OR body::VARCHAR ILIKE '%Accepted %'
                                   OR body::VARCHAR ILIKE '%Invalid user%')$$),
('aws_cloudtrail', 'CLOUD_API', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:eventTime::VARCHAR), event_time) AS _time,
       body:eventName::VARCHAR AS action,
       body:eventSource::VARCHAR || ':' || body:eventName::VARCHAR AS command,
       COALESCE(body:userIdentity:userName::VARCHAR, SPLIT_PART(body:userIdentity:arn::VARCHAR, '/', -1)) AS user_name,
       body:userIdentity:type::VARCHAR AS user_type,
       body:sourceIPAddress::VARCHAR AS src,
       body:eventSource::VARCHAR AS dest,
       COALESCE(body:requestParameters:bucketName::VARCHAR, body:requestParameters:roleName::VARCHAR,
                body:requestParameters:userName::VARCHAR) AS object,
       IFF(body:errorCode IS NULL, 'success', 'failure') AS result,
       body:errorMessage::VARCHAR AS reason,
       SPLIT_PART(body:eventSource::VARCHAR, '.', 1) AS app,
       body:recipientAccountId::VARCHAR AS vendor_account,
       body:awsRegion::VARCHAR AS vendor_region,
       'aws' AS vendor_product, body:requestParameters AS request_parameters,
       'cloudtrail.amazonaws.com' AS host, 'aws:cloudtrail' AS sourcetype, body::VARCHAR AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'aws_cloudtrail' AND body:eventName IS NOT NULL$$)
AS x(source_id, target_table, mapping_sql)) v
WHERE NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS m
                  WHERE m.source_id = v.source_id AND m.target_table = v.target_table AND m.status = 'live');

-- ---------------------------------------------------------------------------
-- 7. Status, schedule
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_OTEL_SOURCE_HEALTH AS
SELECT s.source_id, s.name, s.kind, s.status, s.owner, s.token_hash IS NOT NULL AS has_token,
       s.first_seen, s.last_seen,
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS o WHERE o.source_id = s.source_id
          AND o.received_at > DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS records_24h,
       (SELECT MAX(received_at) FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS o WHERE o.source_id = s.source_id) AS last_received,
       (SELECT ROUND(AVG(DATEDIFF('millisecond', o.event_time, o.received_at)) / 1000, 1)
          FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS o WHERE o.source_id = s.source_id
           AND o.received_at > DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS avg_lag_seconds,
       (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('mapping_id', m.mapping_id, 'target', m.target_table, 'status', m.status,
                 'rows', m.rows_mapped, 'last_run', m.last_run_at, 'error', m.last_error, 'created_by', m.created_by))
          FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS m
          WHERE m.source_id = s.source_id AND m.status IN ('live', 'draft', 'paused')) AS mappings
FROM SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES s;

CREATE TASK IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.TASK_APPLY_CIM_MAPPINGS
    WAREHOUSE = XDR_WH
    SCHEDULE = '1 MINUTE'
    COMMENT = 'Map new OpenTelemetry records into the CIM tables'
AS
    CALL SNOWFLAKE_XDR.REFERENCE.APPLY_CIM_MAPPINGS();

-- Summary for the XDR Analyst agent (tool data_sources_status) and the digest
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.DATA_SOURCES_STATUS()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sources VARIANT;
    v_pending VARIANT;
    v_totals VARIANT;
BEGIN
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('source_id', source_id, 'name', name, 'status', status,
                                      'records_24h', records_24h, 'last_received', last_received,
                                      'avg_lag_seconds', avg_lag_seconds, 'mappings', mappings))
               WITHIN GROUP (ORDER BY records_24h DESC)
    INTO :v_sources FROM SNOWFLAKE_XDR.REFERENCE.V_OTEL_SOURCE_HEALTH;
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('change_id', change_id, 'title', title,
                                      'source_id', evidence:source_id::VARCHAR, 'target_table', evidence:target_table::VARCHAR,
                                      'validated_on_rows', evidence:validation:rows_sampled))
    INTO :v_pending FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
    WHERE change_type = 'new_parser' AND status = 'proposed';
    SELECT OBJECT_CONSTRUCT('records_24h', COUNT(*), 'sources_sending_24h', COUNT(DISTINCT source_id))
    INTO :v_totals FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE received_at > DATEADD('hour', -24, CURRENT_TIMESTAMP());
    RETURN OBJECT_CONSTRUCT('totals', :v_totals, 'sources', COALESCE(:v_sources, []),
                            'pending_mapping_proposals', COALESCE(:v_pending, []),
                            'how_to_add_a_source', 'Point an OpenTelemetry Collector otlphttp exporter at the XDR receiver /v1/logs with a Snowflake PAT (role XDR_OTLP_SENDER). The source registers itself; the Detection Autopilot proposes its CIM mapping (approve with decide_autopilot_change).');
END;
$$;

-- ---------------------------------------------------------------------------
-- 8. Demo seed: three OTel stories through the real ingest path (no container needed)
--    okta       password spray on tlee from Lagos, then a success  -> DET-001
--    linux_auth SSH brute force on bastion-01, then an accepted login -> DET-001
--    edge-fw    a firewall XDR has never seen -> autopilot new_parser proposal
-- scripts/otel_replay.py sends the same stories over HTTPS to the receiver.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.RAW_LOGS.SEED_OTEL_DEMO()
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import json
import random
import time


def kv(k, v):
    return {"key": k, "value": {"stringValue": str(v)}}


def req(service, host, records):
    return {"resourceLogs": [{"resource": {"attributes": [kv("service.name", service), kv("host.name", host)]},
                              "scopeLogs": [{"scope": {"name": "xdr-demo-seed"}, "logRecords": records}]}]}


def rec(t, sev, body):
    return {"timeUnixNano": str(int(t * 1e9)), "severityText": sev, "body": {"stringValue": body}}


def okta_event(t, result):
    return json.dumps({
        "published": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t)),
        "eventType": "user.session.start", "displayMessage": "User login to Okta",
        "outcome": {"result": result, "reason": "INVALID_CREDENTIALS" if result == "FAILURE" else None},
        "actor": {"id": "00u1tlee", "alternateId": "tlee@corp.example"},
        "client": {"ipAddress": "198.51.100.77", "userAgent": {"rawUserAgent": "python-requests/2.31"},
                   "geographicalContext": {"city": "Lagos", "country": "Nigeria"}},
        "authenticationContext": {"credentialType": "PASSWORD"}, "target": [{"displayName": "Okta Dashboard"}]})


def main(s):
    now = s.sql("SELECT DATE_PART(EPOCH_SECOND, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AS t").collect()[0]["T"]
    rnd = random.Random(7)
    okta = [rec(now - 600 + i * 30, "WARN", okta_event(now - 600 + i * 30, "FAILURE")) for i in range(12)]
    okta.append(rec(now - 200, "INFO", okta_event(now - 200, "SUCCESS")))
    users = ["root", "admin", "ubuntu", "deploy", "root", "oracle", "root", "git", "admin", "root", "postgres", "root"]
    sshd = [rec(now - 500 + i * 20, "WARN",
                f"sshd[{2100 + i}]: Failed password for {'' if u in ('root', 'deploy') else 'invalid user '}{u} "
                f"from 203.0.113.45 port {40000 + i} ssh2") for i, u in enumerate(users)]
    sshd.append(rec(now - 120, "INFO", "sshd[2200]: Accepted password for deploy from 203.0.113.45 port 40999 ssh2"))
    fw = [rec(now - 300 + i * 15, "INFO", json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 300 + i * 15)),
        "fw_action": rnd.choice(["ALLOW", "DENY", "DENY"]), "src_addr": f"10.1.4.{20 + i}",
        "dst_addr": "45.33.32.156", "dst_port": rnd.choice([22, 443, 3389, 445, 8080]), "proto": "TCP",
        "bytes_out": rnd.randint(200, 90000), "rule": "egress-default"})) for i in range(10)]
    out = {}
    for name, payload in (("okta", req("okta", "okta", okta)), ("linux_auth", req("linux_auth", "bastion-01", sshd)),
                          ("edge-fw", req("edge-fw", "fw-edge-01", fw))):
        r = s.call("SNOWFLAKE_XDR.RAW_LOGS.INGEST_OTLP_LOGS", json.dumps(payload), None)
        out[name] = json.loads(r) if isinstance(r, str) else r
    mapped = s.call("SNOWFLAKE_XDR.REFERENCE.APPLY_CIM_MAPPINGS")
    out["mapped"] = json.loads(mapped) if isinstance(mapped, str) else mapped
    return out
$$;
