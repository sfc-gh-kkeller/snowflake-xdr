/** Overview (persona: SOC analyst / SOC lead). Ported from 1_soc_overview.py. */

import { rows, one, scalar, type Row } from "@/lib/xdr"

export const overview = {
  "overview.kpis": async () =>
    one(`
      SELECT
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE status = 'open') AS open_incidents,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS findings_24h,
        (SELECT COALESCE(AVG(DATEDIFF('minute', created_at, closed_at)), 0)
          FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE closed_at IS NOT NULL) AS mttr_minutes,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE severity >= 4 AND status = 'new') AS critical_untriaged,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE detection_source IN ('ai_detection_agent', 'ai_hunting_agent')
            AND detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS ai_findings_24h,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE disposition = 'mitigated_by_control') AS mitigated_by_control,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE triage_notes LIKE '%Auto-suppressed by FP model%') AS auto_suppressed`),

  /** Hourly findings by severity, bucketed by when the activity happened (event time), pivoted to one row per hour for a stacked chart. */
  "overview.timeline": async () => {
    const r = await rows(`
      SELECT DATE_TRUNC('hour', COALESCE(event_time, detection_time)) AS hour, severity, COUNT(*) AS count
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE COALESCE(event_time, detection_time) > DATEADD('day', -7, CURRENT_TIMESTAMP())
      GROUP BY 1, 2 ORDER BY 1`)
    return pivotBySeverity(r)
  },

  "overview.bySeverity": async () =>
    rows(`
      SELECT CASE severity WHEN 5 THEN 'Critical' WHEN 4 THEN 'High' WHEN 3 THEN 'Medium'
                           WHEN 2 THEN 'Low' ELSE 'Info' END AS label,
             severity, COUNT(*) AS count
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
      GROUP BY 1, 2 ORDER BY severity DESC`),

  "overview.byCategory": async () =>
    rows(`
      SELECT COALESCE(category, 'other') AS category, COUNT(*) AS count
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
      GROUP BY 1 ORDER BY 2 DESC`),

  "overview.recentIncidents": async () =>
    rows(`
      SELECT incident_id, title, severity, priority, status, primary_entity, entity_type,
             first_seen, last_seen, duration_hours
      FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
      ORDER BY created_at DESC LIMIT 10`),

  "overview.topEntities": async () =>
    rows(`
      SELECT COALESCE(user_name, src, dest) AS entity, COUNT(*) AS finding_count,
             MAX(severity) AS max_severity
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
        AND COALESCE(user_name, src, dest) IS NOT NULL
      GROUP BY 1 ORDER BY 2 DESC LIMIT 10`),

  "overview.briefing": async () => {
    const r = await scalar<{ briefing?: string }>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.AI_DAILY_BRIEFING()", [], { long: true })
    return { text: r?.briefing ?? "" }
  },
}

/** [{hour, severity, count}] -> [{hour, sev1..sev5}] for a stacked bar chart. */
export function pivotBySeverity(r: Row[]): Row[] {
  const byHour = new Map<string, Row>()
  for (const row of r) {
    const hour = String(row.hour)
    const entry = byHour.get(hour) ?? { hour, sev1: 0, sev2: 0, sev3: 0, sev4: 0, sev5: 0 }
    const sev = Math.min(5, Math.max(1, Number(row.severity) || 1))
    entry[`sev${sev}`] = (Number(entry[`sev${sev}`]) || 0) + (Number(row.count) || 0)
    byHour.set(hour, entry)
  }
  return [...byHour.values()]
}
