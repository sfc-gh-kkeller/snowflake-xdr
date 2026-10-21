-- ============================================================================
-- Snowflake XDR - 00b: CTF Demo Dataset load (runs after `snow stage copy`)
-- ============================================================================
-- COPY INTO skips files already loaded, so re-running is harmless.
-- ON_ERROR = CONTINUE matches the original Splunk_Connect workbook: a few
-- source rows are malformed and are skipped rather than failing the load.
-- ============================================================================

USE SCHEMA CTF.PUBLIC;
USE WAREHOUSE XDR_WH;

COPY INTO ACCESS_LOGS
    FROM @CTF_UPLOAD_STAGE
    PATTERN = '.*access_logs[.]csv[.]gz'
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';

COPY INTO ASSET_INVENTORY (ID, OS, MEMORY_GB, CPU_CORES, DISK_GB, LOCATION, OWNER, PROVIDER, STATUS, LAST_UPDATED, TAGS)
    FROM (
        SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRY_PARSE_JSON($11)
        FROM @CTF_UPLOAD_STAGE
    )
    PATTERN = '.*asset_inventory[.]csv[.]gz'
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';

COPY INTO VULNERABILITIES
    FROM @CTF_UPLOAD_STAGE
    PATTERN = '.*vulnerabilities[.]csv[.]gz'
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';

COPY INTO SECURITY_FINDINGS
    FROM @CTF_UPLOAD_STAGE
    PATTERN = '.*security_findings[.]csv[.]gz'
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';

SELECT 'ACCESS_LOGS' AS table_name, COUNT(*) AS row_count FROM ACCESS_LOGS
UNION ALL SELECT 'ASSET_INVENTORY', COUNT(*) FROM ASSET_INVENTORY
UNION ALL SELECT 'VULNERABILITIES', COUNT(*) FROM VULNERABILITIES
UNION ALL SELECT 'SECURITY_FINDINGS', COUNT(*) FROM SECURITY_FINDINGS
ORDER BY table_name;
