"""
Shared helper for the XDR forwarders: send JSON records to the XDR OTLP receiver as
OTLP/HTTP JSON log records (one record per log body, which is what the CIM mappings
expect), and keep a small state file per forwarder.

  export XDR_ENDPOINT=https://<ingress>.snowflakecomputing.app/v1/logs
  export XDR_PAT=...                  # PAT of a user granted XDR_OTLP_SENDER
  export XDR_SOURCE_TOKEN=...         # optional: pins records to a registered source

Needs: pip install requests
"""

import json
import os
import time

import requests

BATCH = 500


def send(service_name, records, scope="xdr-forwarder"):
    """records: list of (epoch_seconds, dict). Raises on a rejected batch so the caller keeps its state."""
    headers = {"Authorization": f'Snowflake Token="{os.environ["XDR_PAT"]}"', "Content-Type": "application/json"}
    if os.getenv("XDR_SOURCE_TOKEN"):
        headers["X-XDR-Source-Token"] = os.environ["XDR_SOURCE_TOKEN"]
    for i in range(0, len(records), BATCH):
        chunk = records[i:i + BATCH]
        payload = {"resourceLogs": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": service_name}}]},
            "scopeLogs": [{"scope": {"name": scope}, "logRecords": [
                {"timeUnixNano": str(int(ts * 1e9)), "severityText": "INFO",
                 "body": {"stringValue": json.dumps(body, default=str)}} for ts, body in chunk]}]}]}
        for attempt in range(5):
            r = requests.post(os.environ["XDR_ENDPOINT"], data=json.dumps(payload), headers=headers, timeout=60)
            if r.status_code == 200:
                break
            if r.status_code in (429, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"XDR rejected batch: HTTP {r.status_code} {r.text[:200]}")
        else:
            raise RuntimeError("XDR receiver unavailable after retries")


def load_state(path, default):
    return open(path).read().strip() if os.path.exists(path) else default


def save_state(path, value):
    with open(path, "w") as f:
        f.write(str(value))
