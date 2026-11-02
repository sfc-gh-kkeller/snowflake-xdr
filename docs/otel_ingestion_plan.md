# Phase 2 plan: out-of-the-box ingestion with OpenTelemetry

Status: plan, not built. Phase 1 (the Detection Autopilot) is in `setup/26_autopilot.sql`.

## Goal

A customer points an existing OpenTelemetry Collector (or any OTLP sender) at the XDR
and gets security telemetry flowing into the CIM tables without writing a parser. New
sources are recognised and mapped by the Detection Autopilot under the same policy
and approval flow as detections (`change_type = 'new_parser'`).

Why OTLP: it is the vendor-neutral standard that collectors, agents and SaaS
forwarders already speak, so one receiver replaces a long tail of per-vendor adapters.
Snowflake's Observe is OTel-native as well, so staying on plain OTLP keeps a path open
to that stack instead of inventing a private format.

## Architecture

```
 OTel Collector / agents / SaaS forwarders
        │  OTLP/HTTP (protobuf or JSON), bearer token
        ▼
 SPCS service: XDR_OTLP_RECEIVER  (public endpoint, autoscaled)
   - /v1/logs, /v1/traces, /v1/metrics
   - auth: per-source token -> source_id; payload size + rate limits
   - batches records, writes with Snowpipe Streaming (row-level, seconds latency)
        ▼
 RAW_LOGS.OTEL_LOGS / OTEL_SPANS / OTEL_METRICS   (append-only, VARIANT attributes)
        │  Dynamic tables or streams + tasks, one mapping per source
        ▼
 RAW_LOGS.AUTHENTICATION, NETWORK_TRAFFIC, CLOUD_API, ...  (existing CIM tables)
        ▼
 Built-in rules, custom rules, Detection Autopilot (unchanged)
```

## Work items

1. **Landing tables** (`setup/28_otel_ingest.sql`)
   - `RAW_LOGS.OTEL_LOGS`: `received_at`, `source_id`, `time_unix_nano`, `observed_time`,
     `severity_text`, `body` VARIANT, `resource` VARIANT, `scope` VARIANT, `attributes`
     VARIANT, `trace_id`, `span_id`; clustered by `TO_DATE(received_at)`, `source_id`.
   - `OTEL_SPANS`, `OTEL_METRICS` with the matching OTLP fields (lower priority for security).
   - `REFERENCE.OTEL_SOURCES`: `source_id`, name, token hash, `detected_kind`
     (okta, cloudtrail, sysmon, linux_auth, k8s_audit, ...), mapping status, owner.

2. **SPCS OTLP receiver** (`otel-receiver/`)
   - Small service (Go or Python) that decodes OTLP protobuf/JSON and writes rows with
     the Snowpipe Streaming SDK into `OTEL_LOGS`; flush on size or ~1 s.
   - Public endpoint behind per-source bearer tokens stored as Snowflake secrets;
     reject unknown tokens, cap request size, return OTLP-conformant partial-success
     responses so collectors retry correctly.
   - Health and lag metrics into `PLATFORM.INGEST_HEALTH` so the existing Health view
     and data-freshness checks cover OTel sources.
   - Compute pool sized for the demo (1 node, autoscale to 3); document sizing per
     events/second.

3. **Source catalog and mappings**
   - `REFERENCE.CIM_MAPPINGS`: per source: target CIM table, mapping SQL (a SELECT from
     `OTEL_LOGS` producing CIM columns), version, status (`draft`, `shadow`, `live`).
   - Shipped mappings for the common cases: Okta System Log, AWS CloudTrail, Windows
     Security / Sysmon (via the Collector's windowseventlog receiver), Linux auth/syslog,
     Kubernetes audit, GitHub audit.
   - Each live mapping is materialised as a Dynamic Table (target lag ~1 minute)
     unioned into the CIM table views, so detections need no change.

4. **Autopilot `new_parser` loop** (extends `AUTOPILOT`)
   - Assess: sources in `OTEL_LOGS` with no live mapping, or a mapping whose
     null-rate / parse-error rate jumped (schema drift).
   - Propose: Cortex reads a sample of `body` / `attributes`, picks the target CIM
     table and writes the mapping SELECT.
   - Validate: guard (read-only, `RAW_LOGS.OTEL_*` only), required CIM columns
     non-null for at least 95% of the sample, timestamps parse, cardinality checks,
     and a dry run of the detections that read the target table.
   - Decide: policy row `new_parser` (default `propose_only`); in shadow the mapping
     writes to a `*_SHADOW` copy so field coverage can be compared before go-live.
   - Same change feed, approvals, rollback, digest and agent tools as detections.

5. **Starter Collector configs** (`otel-receiver/collector-examples/`)
   - `otlphttp` exporter to the SPCS endpoint with the bearer token header.
   - Examples: filelog for Linux auth, windowseventlog for Security/Sysmon,
     an Okta forwarder using the Okta System Log API, CloudTrail via S3 + awss3 receiver.
   - Latency note per source (poll interval + ~1 s receiver flush + Dynamic Table lag).

6. **SaaS sources without a Collector**
   - Pull: External Access Integration + a scheduled Python procedure per API
     (the README's Okta example, generalised), writing to `OTEL_LOGS` with the same
     `source_id` model so mapping and autopilot handling are identical.
   - Openflow connectors where a managed connector exists.

7. **Console and agent**
   - Sources page: per-source volume, lag, mapping status, and a "connect a source"
     panel that issues a token and shows the Collector snippet.
   - Agent tools: `list_sources`, `source_health`, and approval of `new_parser` changes
     through the existing `decide_autopilot_change`.

8. **Tests and demo**
   - Replay generator that sends the existing synthetic campaigns as OTLP, so the same
     ground truth validates both ingestion and detection end to end.
   - Unit tests for OTLP decoding, token checks and mapping validation.

## Open decisions

- Receiver language: Go (official OTLP libraries, small image) vs Python (same stack as
  the procedures). Leaning Go for throughput.
- Raw retention for `OTEL_*` tables vs the CIM tables, and whether to land raw data in
  Iceberg tables for open access.
- Whether traces and metrics are in scope for security use cases in the first cut, or
  logs only.
