-- ============================================================================
-- Snowflake XDR - 21: XDR_ANALYST Cortex Agent
-- ============================================================================
-- "Ask XDR": a Cortex Agent that answers SOC questions over the platform's
-- own data - structured via the semantic view, similar-alerts via Cortex
-- Search, entity lookups and attack-path tracing via custom tools.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. The agent
-- ---------------------------------------------------------------------------
CREATE OR REPLACE AGENT SNOWFLAKE_XDR.DASHBOARDS.XDR_ANALYST
  COMMENT = 'SOC analyst agent over the Snowflake XDR platform'
  PROFILE = '{"display_name": "XDR Analyst", "color": "red"}'
  FROM SPECIFICATION
$$
models:
  orchestration: auto

instructions:
  response: "You are a SOC analyst assistant embedded in an XDR platform. Answer with specifics: entity names, counts, times, severities. When numbers come from a tool, state them plainly. Keep answers concise and actionable for a security analyst."
  orchestration: "Route questions as follows: aggregate/metric questions about findings, rules, or incidents -> use analyst_text_to_sql. Questions about similar alerts or alert descriptions -> use finding_search. Questions about a specific user, host, or IP entity -> use search_entity first, and ai_investigate_entity for a deeper investigation. Questions about how an attacker moved or attack paths -> use trace_attack_paths. Questions about attack campaigns or narratives -> use analyst_text_to_sql for the incident data, then summarize."
  sample_questions:
    - question: "How many high severity findings are there this week?"
    - question: "What happened with the user jsmith?"
    - question: "Trace the attack path from 10.1.5.107"
    - question: "Which MITRE tactics have no detection coverage?"

tools:
  - tool_spec:
      type: "cortex_analyst_text_to_sql"
      name: "analyst_text_to_sql"
      description: "Structured queries over XDR security data: detection findings, detection rules, and incidents. Use for counts, aggregates, trends, severity breakdowns, MITRE tactic coverage, and incident metrics."
  - tool_spec:
      type: "cortex_search"
      name: "finding_search"
      description: "Semantic search over detection finding descriptions. Use to find alerts similar to a described behavior, or to find alerts by describing the activity."
  - tool_spec:
      type: "generic"
      name: "search_entity"
      description: "Look up any user, host, or IP entity across all XDR telemetry (auth, network, endpoint, DNS, web, cloud). Returns the entity's recent events. Inputs: entity name (e.g. 'jsmith', 'WS-042', '10.1.5.107') and optional lookback days (default 7)."
  - tool_spec:
      type: "generic"
      name: "ai_investigate_entity"
      description: "AI-driven deep investigation of a user, host, or IP: pulls the entity's activity across telemetry and produces an assessed summary. Inputs: entity name and optional lookback days (default 7)."
  - tool_spec:
      type: "generic"
      name: "trace_attack_paths"
      description: "Trace multi-hop attack paths (lateral movement) starting from an entity using the attack graph. Returns time-ordered entity chains with edge details. Input: the starting entity (user, host, or IP, e.g. '10.1.5.107' or 'host:WS-042')."
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
    type: function
    user-defined-function-argument: "P_ENTITY"
    execution_environment:
      type: warehouse
      warehouse: XDR_WH
  ai_investigate_entity:
    type: function
    user-defined-function-argument: "P_ENTITY"
    execution_environment:
      type: warehouse
      warehouse: XDR_WH
  trace_attack_paths:
    type: function
    user-defined-function-argument: "P_START_ENTITY"
    execution_environment:
      type: warehouse
      warehouse: XDR_WH
$$;
