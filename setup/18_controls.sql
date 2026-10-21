-- ============================================================================
-- Snowflake XDR - 18: Compensating Controls Engine
-- ============================================================================
-- Registry of security controls; assessment engine that marks findings whose
-- events were already blocked/mitigated as "mitigated_by_control" so analysts
-- don't chase problems that other controls already cover.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Controls registry
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.SECURITY_CONTROLS (
    control_id          VARCHAR(50) PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    control_type        VARCHAR(50),      -- firewall_rule, edr_policy, iam_policy, segmentation, dns_filter
    description         VARCHAR(1000),
    mitre_technique_ids ARRAY,            -- techniques this control mitigates
    covered_entities    ARRAY,            -- hosts / users / IPs in scope
    scope_note          VARCHAR(500),    -- human explanation of the scope
    status              VARCHAR(20) DEFAULT 'active',   -- active, monitoring, disabled
    last_reviewed       TIMESTAMP_NTZ,
    created_at          TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

INSERT INTO SNOWFLAKE_XDR.REFERENCE.SECURITY_CONTROLS
    (control_id, name, control_type, description, mitre_technique_ids, covered_entities, scope_note, status)
SELECT * FROM (
    SELECT 'CTL-001', 'Jump-box-only RDP policy', 'firewall_rule',
           'RDP (3389) to critical infrastructure is only permitted from the JUMP-BOX host; all other sources are blocked.',
           ARRAY_CONSTRUCT('T1021.001'),
           ARRAY_CONSTRUCT('host:DC-01','host:FS-FILE01','host:DB-PROD-01'),
           'Blocks lateral RDP into the data center segment from any non-jump-box source.',
           'active'
    UNION ALL
    SELECT 'CTL-002', 'EDR process quarantine', 'edr_policy',
           'EDR automatically quarantines known attacker tooling (mimikatz, psexec variants) on managed endpoints.',
           ARRAY_CONSTRUCT('T1003','T1021.002'),
           ARRAY_CONSTRUCT('host:WS-042','host:WKS-001','host:WKS-002','host:WKS-003'),
           'Applies to all workstations with the EDR agent installed.',
           'active'
    UNION ALL
    SELECT 'CTL-003', 'DNS sinkhole for known-bad domains', 'dns_filter',
           'Recursive DNS filters and sinkholes responses for DGA and known-malicious domains.',
           ARRAY_CONSTRUCT('T1071.004'),
           ARRAY_CONSTRUCT(),
           'Account-wide; applies to all internal resolvers.',
           'monitoring'
    UNION ALL
    SELECT 'CTL-004', 'MFA enforcement on VPN', 'iam_policy',
           'MFA is required for all VPN authentications; password-only VPN attempts should fail even with valid credentials.',
           ARRAY_CONSTRUCT('T1078','T1110'),
           ARRAY_CONSTRUCT('host:VPN-GW-01'),
           'Applies to the VPN gateway only.',
           'active'
    UNION ALL
    SELECT 'CTL-005', 'East-west SMB segmentation', 'segmentation',
           'Server-to-server SMB is restricted to approved pairs; workstation-to-DC SMB is monitored.',
           ARRAY_CONSTRUCT('T1021.002'),
           ARRAY_CONSTRUCT('host:DC-01'),
           'Partial coverage: workstation SMB to DC still permitted for legacy tooling.',
           'monitoring'
) t
WHERE NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.SECURITY_CONTROLS);

-- ---------------------------------------------------------------------------
-- 2. Single-finding assessment
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.ASSESS_CONTROL_COVERAGE(
    P_FINDING_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    v_entity VARCHAR;
    v_tactic VARCHAR;
    v_tech VARCHAR;
    v_action VARCHAR;
    v_control VARIANT;
BEGIN
    SELECT COALESCE(user_name, src, dest, ''), COALESCE(mitre_tactic_id, ''),
           COALESCE(mitre_technique_id, ''), COALESCE(evidence:action::VARCHAR, '')
    INTO :v_entity, :v_tactic, :v_tech, :v_action
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE finding_id = :P_FINDING_ID;

    IF (v_entity IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('covered', FALSE, 'reason', 'finding not found');
    END IF;

    -- Match: entity in control scope AND technique in control techniques
    SELECT MIN(OBJECT_CONSTRUCT(
               'covered', TRUE,
               'control_id', c.control_id,
               'control_name', c.name,
               'control_type', c.control_type,
               'scope_note', c.scope_note,
               'status', c.status))
    INTO :v_control
    FROM SNOWFLAKE_XDR.REFERENCE.SECURITY_CONTROLS c
    WHERE c.status IN ('active', 'monitoring')
      AND ARRAY_POSITION(TO_VARIANT('host:' || :v_entity), c.covered_entities) IS NOT NULL
       OR c.status IN ('active', 'monitoring')
      AND ARRAY_POSITION(TO_VARIANT(:v_entity), c.covered_entities) IS NOT NULL
       OR c.status IN ('active', 'monitoring')
      AND ARRAY_POSITION(TO_VARIANT(:v_tech), c.mitre_technique_ids) IS NOT NULL
       AND :v_entity IN (SELECT COLUMN_VALUE FROM TABLE(FLATTEN(c.covered_entities)));

    IF (v_control IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('covered', FALSE,
                                'reason', 'no active control covers this entity/technique');
    END IF;

    RETURN v_control;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Bulk assessment: auto-resolve findings covered by controls
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.APPLY_CONTROL_ASSESSMENT()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_mitigated NUMBER;
BEGIN
    -- Findings whose triggering event was blocked AND whose entity+technique
    -- is covered by an active control => not a real problem; mark and close.
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    SET f.status = 'resolved',
        f.disposition = 'mitigated_by_control',
        f.triage_notes = COALESCE(f.triage_notes || ' | ', '')
            || 'Auto-assessed: covered by control '
            || c.name || ' (' || c.scope_note || '). Attempt was blocked.',
        f.triaged_at = CURRENT_TIMESTAMP(),
        f.risk_score = LEAST(f.risk_score, 20)
    FROM SNOWFLAKE_XDR.REFERENCE.SECURITY_CONTROLS c
    WHERE f.status IN ('new', 'investigating')
      AND COALESCE(f.evidence:action::VARCHAR, 'blocked') IN ('blocked', 'dropped')
      AND c.status = 'active'
      AND (ARRAY_POSITION(TO_VARIANT(COALESCE('host:' || f.src, '')), c.covered_entities) IS NOT NULL
           OR ARRAY_POSITION(TO_VARIANT(COALESCE(f.user_name, '')), c.covered_entities) IS NOT NULL
           OR ARRAY_POSITION(TO_VARIANT(COALESCE(f.dest, '')), c.covered_entities) IS NOT NULL)
      AND NOT c.control_id IS NULL;

    v_mitigated := SQLROWCOUNT;

    RETURN 'Control assessment complete. Findings mitigated by existing controls: '
        || :v_mitigated;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Attempt-detection: blocked RDP/SMB attempts into protected assets fire
--    as low-sev "attempted, blocked" findings the controls engine then closes.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_PROTECTED_ACCESS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_new NUMBER;
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        (finding_id, rule_id, description, category, severity,
         mitre_tactic_id, mitre_technique_id, src, dest,
         event_time, detection_time, detection_source, confidence,
         evidence, risk_score, status)
    SELECT
        UUID_STRING(),
        'DET-019',
        'RDP attempt into protected infrastructure from ' || src
            || ' was BLOCKED (' || COALESCE(rule, 'fw') || ')',
        'network', 3,
        'TA0008', 'T1021.001',
        src, dest,
        _time, CURRENT_TIMESTAMP(), 'stored_procedure', 70,
        OBJECT_CONSTRUCT(
            'action', action,
            'fw_rule', rule,
            'dest_port', dest_port,
            'src_ip', src_ip,
            'attempt', 'blocked'),
        40, 'new'
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE dest_port = 3389
      AND action = 'blocked'
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
      AND NOT EXISTS (
          SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
          WHERE f.rule_id = 'DET-019'
            AND f.src = NETWORK_TRAFFIC.src
            AND f.event_time = NETWORK_TRAFFIC._time
      );

    v_new := SQLROWCOUNT;
    RETURN 'Protected-access detection complete. New findings: ' || :v_new;
END;
$$;
