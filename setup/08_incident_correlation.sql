-- ============================================================================
-- Snowflake XDR/SIEM - Incident Correlation Engine
-- ============================================================================
-- Correlates individual detection findings into incidents by:
--   1. Grouping findings by entity overlap within time windows
--   2. Identifying kill chain progression
--   3. Building entity relationship graphs
--   4. Creating attacker timelines
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA INCIDENTS;

-- ---------------------------------------------------------------------------
-- Main Correlation Procedure
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.CORRELATE_INCIDENTS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    new_incidents NUMBER DEFAULT 0;
BEGIN
    -- Step 1: Find groups of related findings (same entity, within 24h window)
    -- that are not already assigned to an incident
    CREATE OR REPLACE TEMPORARY TABLE incident_candidates AS
    WITH unlinked_findings AS (
        SELECT *
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE incident_id IS NULL
          AND status != 'dismissed'
    ),
    entity_groups AS (
        SELECT
            COALESCE(user_name, src, dest) AS primary_entity,
            CASE
                WHEN user_name IS NOT NULL THEN 'user'
                WHEN src IS NOT NULL THEN 'ip'
                ELSE 'host'
            END AS entity_type,
            ARRAY_AGG(finding_id) AS finding_ids,
            ARRAY_AGG(DISTINCT mitre_tactic_id) AS tactics,
            COUNT(*) AS finding_count,
            MAX(severity) AS max_severity,
            MIN(event_time) AS first_seen,
            MAX(event_time) AS last_seen
        FROM unlinked_findings
        WHERE COALESCE(user_name, src, dest) IS NOT NULL
        GROUP BY COALESCE(user_name, src, dest),
                 CASE WHEN user_name IS NOT NULL THEN 'user'
                      WHEN src IS NOT NULL THEN 'ip' ELSE 'host' END
        HAVING COUNT(*) >= 2  -- Need at least 2 findings to create an incident
           AND DATEDIFF('hour', MIN(event_time), MAX(event_time)) <= 48
    )
    SELECT * FROM entity_groups;

    -- Step 2: Create incidents from candidates
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENTS (
        title, description, severity, priority, risk_score,
        kill_chain_stages_observed, tactics_observed,
        first_seen, last_seen, duration_hours,
        primary_entity, entity_type,
        affected_host_count, affected_user_count, status
    )
    SELECT
        CASE
            WHEN max_severity >= 5 THEN 'Critical: Multi-stage attack involving ' || primary_entity
            WHEN max_severity >= 4 THEN 'High: Suspicious activity cluster for ' || primary_entity
            ELSE 'Medium: Correlated findings for ' || primary_entity
        END AS title,
        'Auto-correlated incident with ' || finding_count::VARCHAR || ' findings across ' ||
        ARRAY_SIZE(tactics)::VARCHAR || ' MITRE tactics' AS description,
        LEAST(max_severity + CASE WHEN ARRAY_SIZE(tactics) >= 3 THEN 1 ELSE 0 END, 5),
        CASE LEAST(max_severity + CASE WHEN ARRAY_SIZE(tactics) >= 3 THEN 1 ELSE 0 END, 5)
            WHEN 5 THEN 'P1' WHEN 4 THEN 'P2' WHEN 3 THEN 'P3' ELSE 'P4'
        END,
        max_severity * finding_count * ARRAY_SIZE(tactics)::FLOAT,
        tactics, tactics,
        first_seen, last_seen,
        DATEDIFF('minute', first_seen, last_seen) / 60.0,
        primary_entity, entity_type,
        1, 1, 'open'
    FROM incident_candidates;

    SELECT COUNT(*) INTO :new_incidents FROM incident_candidates;

    -- Step 3: Link findings to their incidents
    -- One incident per finding: a finding can match several new incidents
    -- (e.g. its user AND its source IP are both primary entities); take the
    -- highest-risk one so the MERGE never sees duplicate source rows.
    MERGE INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    USING (
        SELECT finding_id, incident_id
        FROM (
            SELECT
                f2.finding_id,
                i.incident_id,
                ROW_NUMBER() OVER (
                    PARTITION BY f2.finding_id
                    ORDER BY i.risk_score DESC NULLS LAST, i.incident_id) AS rn
            FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
            JOIN incident_candidates ic
              ON i.primary_entity = ic.primary_entity
              AND i.entity_type = ic.entity_type
              AND i.first_seen = ic.first_seen
            JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f2
              ON f2.incident_id IS NULL
              AND (f2.user_name = ic.primary_entity
                   OR f2.src = ic.primary_entity
                   OR f2.dest = ic.primary_entity)
            WHERE i.created_at > DATEADD('minute', -5, CURRENT_TIMESTAMP())
        )
        WHERE rn = 1
    ) matched
    ON f.finding_id = matched.finding_id
    WHEN MATCHED THEN UPDATE SET f.incident_id = matched.incident_id;

    -- Step 4: Insert into incident_findings junction
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_FINDINGS (incident_id, finding_id)
    SELECT incident_id, finding_id
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE incident_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_FINDINGS iff
          WHERE iff.incident_id = DETECTION_FINDINGS.incident_id
            AND iff.finding_id = DETECTION_FINDINGS.finding_id
      );

    -- Step 5: Build kill chain progression for new incidents
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.KILL_CHAIN_PROGRESSION (
        incident_id, stage_order, tactic_id, tactic_name,
        first_finding_id, finding_count, first_observed, last_observed
    )
    SELECT
        f.incident_id,
        t.tactic_order,
        f.mitre_tactic_id,
        t.tactic_name,
        MIN(f.finding_id),
        COUNT(*),
        MIN(f.event_time),
        MAX(f.event_time)
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    JOIN SNOWFLAKE_XDR.REFERENCE.MITRE_TACTICS t ON f.mitre_tactic_id = t.tactic_id
    WHERE f.incident_id IS NOT NULL
      AND f.incident_id IN (SELECT incident_id FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE created_at > DATEADD('minute', -5, CURRENT_TIMESTAMP()))
    GROUP BY f.incident_id, t.tactic_order, f.mitre_tactic_id, t.tactic_name;

    -- Step 6: Build entity graph edges
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.ENTITY_GRAPH (
        incident_id, src_entity_type, src_entity_value,
        dst_entity_type, dst_entity_value,
        relationship_type, first_seen, last_seen, event_count,
        finding_ids, mitre_technique
    )
    SELECT
        incident_id,
        CASE WHEN src IS NOT NULL THEN 'ip' ELSE 'user' END,
        COALESCE(src, user_name),
        CASE WHEN dest IS NOT NULL THEN 'host' ELSE 'service' END,
        COALESCE(dest, 'unknown'),
        CASE category
            WHEN 'identity' THEN 'authenticated_to'
            WHEN 'network' THEN 'communicated_with'
            WHEN 'endpoint' THEN 'executed_on'
            WHEN 'cloud' THEN 'accessed'
            ELSE 'related_to'
        END,
        MIN(event_time),
        MAX(event_time),
        COUNT(*),
        ARRAY_AGG(finding_id),
        ANY_VALUE(mitre_technique_id)
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE incident_id IS NOT NULL
      AND incident_id IN (SELECT incident_id FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE created_at > DATEADD('minute', -5, CURRENT_TIMESTAMP()))
      AND COALESCE(src, user_name) IS NOT NULL
    GROUP BY incident_id, COALESCE(src, user_name),
             CASE WHEN src IS NOT NULL THEN 'ip' ELSE 'user' END,
             COALESCE(dest, 'unknown'),
             CASE WHEN dest IS NOT NULL THEN 'host' ELSE 'service' END,
             category;

    -- Step 7: Build attacker timeline
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.ATTACKER_TIMELINE (
        incident_id, event_time, action_summary,
        tactic_id, technique_id,
        actor_entity, actor_type, target_entity, target_type,
        finding_id
    )
    SELECT
        incident_id,
        event_time,
        description,
        mitre_tactic_id,
        mitre_technique_id,
        COALESCE(src, user_name),
        CASE WHEN src IS NOT NULL THEN 'ip' ELSE 'user' END,
        dest,
        'host',
        finding_id
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE incident_id IS NOT NULL
      AND incident_id IN (SELECT incident_id FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE created_at > DATEADD('minute', -5, CURRENT_TIMESTAMP()))
    ORDER BY event_time;

    DROP TABLE IF EXISTS incident_candidates;

    RETURN 'Correlation complete. New incidents created: ' || :new_incidents::VARCHAR;
END;
$$;
