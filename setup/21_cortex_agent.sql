-- ============================================================================
-- Snowflake XDR - 21: XDR_ANALYST Cortex Agent
-- ============================================================================
-- "Ask XDR": a Cortex Agent that answers SOC questions over the platform's
-- own data - structured via the semantic view, similar-alerts via Cortex
-- Search, entity lookups and attack-path tracing via custom tools - and can
-- act on the platform through the action tools in 24_agent_actions.sql
-- (create/enable rules, add IOCs, triage findings, move incidents, create
-- playbooks, re-run detections). Every action is logged to
-- DASHBOARDS.AGENT_ACTION_LOG.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE OR REPLACE AGENT SNOWFLAKE_XDR.DASHBOARDS.XDR_ANALYST
  COMMENT = 'SOC analyst agent over the Snowflake XDR platform'
  PROFILE = '{"display_name": "XDR Analyst", "color": "red"}'
  FROM SPECIFICATION
$$
models:
  orchestration: auto

orchestration:
  budget:
    seconds: 240
    tokens: 32000

instructions:
  response: |
    You are the SOC analyst assistant built into this XDR platform. You can both
    answer questions and take actions on the platform with your action tools.

    Communication rules:
    - Lead with the direct answer or the result of what you did. Never open with
      "Yes" or "Sure" and then explain that you cannot do it.
    - Never say you cannot create, enable, change, or run something if one of
      your tools does it. Your action tools are: create_detection_rule,
      set_rule_enabled, add_ioc, update_finding, set_incident_status,
      create_playbook, run_detections. Things you genuinely cannot do: edit raw
      telemetry, delete rules or data, change user access, or deploy new data
      sources (say that plainly and give the next step instead).
    - After an action, report exactly what changed using the tool output: IDs,
      names, enabled state, test result. If a tool returns an error or
      "not found", say so; do not claim success.
    - Use specific entity names, counts, times, and severities. Keep it concise.
    - Markdown tables are fine; keep cells short (no long sentences in cells).
  orchestration: |
    Reading data:
    - Aggregates/metrics about findings, rules, incidents, MITRE coverage -> analyst_text_to_sql.
    - Alerts similar to a described behavior -> finding_search.
    - A specific user, host, or IP -> search_entity first; ai_investigate_entity for a deeper assessment.
    - How an attacker moved / attack paths -> trace_attack_paths.

    Taking action:
    - If the user explicitly asks you to do something (create, add, enable, disable,
      close, dismiss, assign, run), do it with the matching action tool in this turn.
    - If the user asks for help with a goal (e.g. "help me get coverage"), give a short
      plan that names the concrete rules/IOCs/playbooks you would create, then offer to
      create them. Do not create more than one rule without the user agreeing.
    - When the user agrees to a proposal from earlier in the conversation ("yes", "do it",
      "go ahead"), perform the proposed actions now.
    - create_detection_rule: write the rule SQL yourself following the tool's SQL
      contract and the exact column names it lists. Set p_enable=true only if the
      user asked for the rule to be live.
      If a rule needs organization-specific values the user has not given (brand or
      corporate domains, internal IP ranges, VIP accounts), ask for them first; never
      create a rule containing placeholder values. If the tool returns test_error,
      fix the SQL and retry at most twice.
    - Before update_finding or set_incident_status, look up the exact ID with
      analyst_text_to_sql if the user did not give one. Never guess IDs.
    - After creating or enabling rules, offer to run_detections so findings appear now.
  sample_questions:
    - question: "Which MITRE tactics have no detection coverage?"
    - question: "Create and enable a rule for external port scanning"
    - question: "Trace the attack path from 10.1.5.107"
    - question: "Add 185.220.101.4 as a C2 IOC"

tools:
  - tool_spec:
      type: "cortex_analyst_text_to_sql"
      name: "analyst_text_to_sql"
      description: "Structured queries over XDR security data: detection findings (finding_id, rule, entity, severity, status, disposition), detection rules (rule_id, MITRE tactic/technique, enabled), and incidents (incident_id, priority, status). Use for counts, aggregates, trends, MITRE coverage, and to look up IDs before taking an action."
  - tool_spec:
      type: "cortex_search"
      name: "finding_search"
      description: "Semantic search over detection finding descriptions. Use to find alerts similar to a described behavior."
  - tool_spec:
      type: "generic"
      name: "search_entity"
      description: "Look up a user, host, or IP across all XDR telemetry (auth, network, endpoint, DNS, web, cloud) and return its recent events."
      input_schema:
        type: object
        properties:
          p_entity:
            type: string
            description: "Entity name, e.g. 'jsmith', 'WS-042', '10.1.5.107'"
          p_days:
            type: number
            description: "Lookback in days (default 7)"
        required: [p_entity]
  - tool_spec:
      type: "generic"
      name: "ai_investigate_entity"
      description: "AI deep investigation of a user, host, or IP: pulls its activity across telemetry and returns an assessed summary with risk."
      input_schema:
        type: object
        properties:
          p_entity:
            type: string
            description: "Entity name, e.g. 'jsmith', 'WS-042', '10.1.5.107'"
          p_days:
            type: number
            description: "Lookback in days (default 7)"
        required: [p_entity]
  - tool_spec:
      type: "generic"
      name: "trace_attack_paths"
      description: "Trace multi-hop lateral-movement paths from a starting entity using the attack graph. Returns time-ordered entity chains."
      input_schema:
        type: object
        properties:
          p_start_entity:
            type: string
            description: "Starting entity, e.g. '10.1.5.107' or 'WS-042'"
        required: [p_start_entity]
  - tool_spec:
      type: "generic"
      name: "create_detection_rule"
      description: |
        ACTION. Save a new custom SQL detection rule that you write, test it against current data, and optionally enable it. Returns rule_id, test result and match count, and enabled state; on failure returns test_error (nothing is saved), so fix the SQL and retry.
        SQL contract: one read-only SELECT (CTEs allowed, no semicolon) that returns exactly the columns _time, user_name, src, dest, description (use NULL AS <col> where not applicable). Reference tables only as fully qualified SNOWFLAKE_XDR.RAW_LOGS.<TABLE>. The platform adds the lookback filter on _time itself; for aggregations return MAX(_time) AS _time. _time is TIMESTAMP_LTZ: use DATE_TRUNC or cast with _time::TIMESTAMP_NTZ before TIME_SLICE. Internal addresses are RFC1918 (10.x, 172.16-31.x, 192.168.x).
        Tables and columns (all have _time, action, vendor_product):
        AUTHENTICATION: app, authentication_method, authentication_service, dest, reason, signature, signature_id, src, src_user, user_name, user_type, user_role, user_agent, geo_city, geo_country.
        ENDPOINT_PROCESSES: dest, user_name, process, process_name, process_path, process_hash, parent_process, parent_process_name, original_file_name, os.
        ENDPOINT_FILESYSTEM: dest, user_name, file_name, file_path, file_hash, file_size, process_name.
        ENDPOINT_REGISTRY: dest, user_name, registry_path, registry_key_name, registry_value_name, registry_value_data, process_name.
        ENDPOINT_SERVICES: dest, user_name, service_name, service_path, start_mode, status.
        NETWORK_TRAFFIC: src, src_ip, src_port, dest, dest_ip, dest_port, transport, protocol, app, bytes, bytes_in, bytes_out, packets, direction, rule, geo_src_country, geo_dest_country.
        INTRUSION_DETECTION: src, src_ip, dest, dest_ip, dest_port, signature, signature_id, severity, category.
        DNS_ACTIVITY: src, dest, query, query_type, answer, reply_code, query_length, answer_count, ttl.
        WEB_ACTIVITY: src, dest, url, uri_path, uri_query, http_method, status, http_user_agent, http_referrer, bytes_in, bytes_out, category, threat_category.
        CLOUD_API: command, user_name, user_type, src, dest, object, object_category, result, reason, app, vendor_account, vendor_region.
      input_schema:
        type: object
        properties:
          p_name:
            type: string
            description: "Short rule name, e.g. 'External port scan'"
          p_description:
            type: string
            description: "One sentence on what the rule detects"
          p_category:
            type: string
            description: "One of: identity, endpoint, network, cloud, application, custom"
          p_severity:
            type: number
            description: "1-5 (5 = critical)"
          p_mitre_tactic_id:
            type: string
            description: "e.g. TA0043, or empty string"
          p_mitre_technique_id:
            type: string
            description: "e.g. T1595 or T1595.002, or empty string"
          p_rule_sql:
            type: string
            description: "The detection SELECT following the SQL contract"
          p_lookback_minutes:
            type: number
            description: "How far back each run looks (default 1440)"
          p_enable:
            type: boolean
            description: "true to make the rule live now (only if its test passes); false to save it disabled for review"
        required: [p_name, p_description, p_category, p_severity, p_mitre_tactic_id, p_mitre_technique_id, p_rule_sql, p_lookback_minutes, p_enable]
  - tool_spec:
      type: "generic"
      name: "set_rule_enabled"
      description: "ACTION. Enable or disable a detection rule by ID (built-in DET-xxx rules or custom rule IDs)."
      input_schema:
        type: object
        properties:
          p_rule_id:
            type: string
            description: "Rule ID, e.g. 'DET-008' or a custom rule UUID"
          p_enabled:
            type: boolean
            description: "true to enable, false to disable"
        required: [p_rule_id, p_enabled]
  - tool_spec:
      type: "generic"
      name: "add_ioc"
      description: "ACTION. Add a threat-intel indicator; the known-bad-IOC detection matches it against telemetry on the next run."
      input_schema:
        type: object
        properties:
          p_ioc_type:
            type: string
            description: "One of: ip, domain, url, hash_md5, hash_sha256, email, user_agent"
          p_ioc_value:
            type: string
            description: "The indicator value"
          p_threat_type:
            type: string
            description: "One of: malware, phishing, c2, botnet, ransomware, apt, credential_abuse, exfiltration, scanner"
          p_severity:
            type: number
            description: "1-5 (5 = critical)"
        required: [p_ioc_type, p_ioc_value, p_threat_type, p_severity]
  - tool_spec:
      type: "generic"
      name: "update_finding"
      description: "ACTION. Triage a detection finding: set status and optionally disposition, assignee and notes."
      input_schema:
        type: object
        properties:
          p_finding_id:
            type: string
            description: "Exact finding_id (look it up first if not given)"
          p_status:
            type: string
            description: "One of: new, investigating, contained, resolved, dismissed"
          p_disposition:
            type: string
            description: "Optional. One of: true_positive, false_positive, benign, mitigated_by_control; empty string to leave unchanged"
          p_assigned_to:
            type: string
            description: "Optional assignee; empty string to leave unchanged"
          p_notes:
            type: string
            description: "Optional triage notes; empty string to leave unchanged"
        required: [p_finding_id, p_status, p_disposition, p_assigned_to, p_notes]
  - tool_spec:
      type: "generic"
      name: "set_incident_status"
      description: "ACTION. Move an incident to open, investigating, contained, or closed."
      input_schema:
        type: object
        properties:
          p_incident_id:
            type: string
            description: "Exact incident_id (look it up first if not given)"
          p_status:
            type: string
            description: "One of: open, investigating, contained, closed"
        required: [p_incident_id, p_status]
  - tool_spec:
      type: "generic"
      name: "create_playbook"
      description: "ACTION. Create an enabled automated response playbook that fires on new findings at or above a severity."
      input_schema:
        type: object
        properties:
          p_name:
            type: string
            description: "Playbook name"
          p_description:
            type: string
            description: "What the playbook does"
          p_min_severity:
            type: number
            description: "Trigger on findings with severity >= this (1-5)"
          p_action_type:
            type: string
            description: "One of: email, webhook (Slack/Teams channel configured at deploy), create_incident, ai_triage"
          p_email_to:
            type: string
            description: "Comma-separated recipients for email actions; empty string otherwise"
          p_entity:
            type: string
            description: "Optional: only trigger for this entity; empty string for all"
        required: [p_name, p_description, p_min_severity, p_action_type, p_email_to, p_entity]
  - tool_spec:
      type: "generic"
      name: "run_detections"
      description: "ACTION. Run all built-in detections and enabled custom rules now, instead of waiting for the 5-minute schedule."
      input_schema:
        type: object
        properties: {}
  - tool_spec:
      type: "data_to_chart"
      name: "data_to_chart"
      description: "Generates visualizations from tool data"

tool_resources:
  analyst_text_to_sql:
    semantic_view: "SNOWFLAKE_XDR.DASHBOARDS.XDR_SECURITY"
    execution_environment:
      type: warehouse
      warehouse: XDR_WH
  finding_search:
    search_service: "SNOWFLAKE_XDR.DETECTIONS.FINDING_SEARCH"
    max_results: "8"
  search_entity:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DETECTIONS.SEARCH_ENTITY"
    execution_environment: {type: warehouse, warehouse: XDR_WH, query_timeout: 120}
  ai_investigate_entity:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DETECTIONS.AI_INVESTIGATE_ENTITY"
    execution_environment: {type: warehouse, warehouse: XDR_WH, query_timeout: 180}
  trace_attack_paths:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DETECTIONS.TRACE_ATTACK_PATHS"
    execution_environment: {type: warehouse, warehouse: XDR_WH, query_timeout: 120}
  create_detection_rule:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DASHBOARDS.AGENT_CREATE_RULE"
    execution_environment: {type: warehouse, warehouse: XDR_WH, query_timeout: 180}
  set_rule_enabled:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DASHBOARDS.AGENT_SET_RULE_ENABLED"
    execution_environment: {type: warehouse, warehouse: XDR_WH}
  add_ioc:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DASHBOARDS.AGENT_ADD_IOC"
    execution_environment: {type: warehouse, warehouse: XDR_WH}
  update_finding:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DASHBOARDS.AGENT_UPDATE_FINDING"
    execution_environment: {type: warehouse, warehouse: XDR_WH}
  set_incident_status:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DASHBOARDS.AGENT_SET_INCIDENT_STATUS"
    execution_environment: {type: warehouse, warehouse: XDR_WH}
  create_playbook:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DASHBOARDS.AGENT_CREATE_PLAYBOOK"
    execution_environment: {type: warehouse, warehouse: XDR_WH}
  run_detections:
    type: procedure
    identifier: "SNOWFLAKE_XDR.DASHBOARDS.AGENT_RUN_DETECTIONS"
    execution_environment: {type: warehouse, warehouse: XDR_WH, query_timeout: 300}
$$;
