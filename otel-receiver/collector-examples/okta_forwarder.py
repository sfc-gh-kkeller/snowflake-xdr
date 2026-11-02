#!/usr/bin/env python3
"""
Okta System Log -> Snowflake XDR (OTLP/HTTP).

There is no Okta receiver in the OpenTelemetry Collector, so this small poller
reads the Okta System Log API (GET /api/v1/logs, polled with `since` and the
`next` link) and sends each event as an OTLP log record whose body is the event
JSON. The shipped `okta` mapping turns user.session.* events into
AUTHENTICATION rows. Send to the XDR receiver directly, or to a local
Collector's OTLP receiver (localhost:4318) to add batching and retry.

  export OKTA_DOMAIN=acme.okta.com OKTA_API_TOKEN=...      # read-only admin token
  export XDR_ENDPOINT=https://<ingress>.snowflakecomputing.app/v1/logs
  export XDR_PAT=...                                        # user granted XDR_OTLP_SENDER
  python3 okta_forwarder.py          # runs forever; state in ./okta_forwarder.state

Needs: pip install requests
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import requests

STATE = os.getenv("OKTA_STATE_FILE", "okta_forwarder.state")
POLL_SECONDS = int(os.getenv("OKTA_POLL_SECONDS", "60"))


def otlp(events):
    """OTLP/JSON ExportLogsServiceRequest with one log record per Okta event."""
    records = []
    for e in events:
        ts = datetime.fromisoformat(e["published"].replace("Z", "+00:00"))
        records.append({
            "timeUnixNano": str(int(ts.timestamp() * 1e9)),
            "severityText": e.get("severity", "INFO"),
            "body": {"stringValue": json.dumps(e)},
        })
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "okta"}}]},
        "scopeLogs": [{"scope": {"name": "okta-forwarder"}, "logRecords": records}],
    }]}


def main():
    okta = f"https://{os.environ['OKTA_DOMAIN']}/api/v1/logs"
    okta_h = {"Authorization": f"SSWS {os.environ['OKTA_API_TOKEN']}", "Accept": "application/json"}
    xdr_h = {"Authorization": f'Snowflake Token="{os.environ["XDR_PAT"]}"', "Content-Type": "application/json"}
    if os.getenv("XDR_SOURCE_TOKEN"):
        xdr_h["X-XDR-Source-Token"] = os.environ["XDR_SOURCE_TOKEN"]
    since = open(STATE).read().strip() if os.path.exists(STATE) else \
        (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    while True:
        url, params = okta, {"since": since, "limit": 1000, "sortOrder": "ASCENDING"}
        while url:
            r = requests.get(url, headers=okta_h, params=params, timeout=60)
            if r.status_code == 429:  # Okta rate limit: wait for the reset
                time.sleep(max(1, int(r.headers.get("X-Rate-Limit-Reset", time.time() + 30)) - int(time.time())))
                continue
            r.raise_for_status()
            events = r.json()
            if events:
                resp = requests.post(os.environ["XDR_ENDPOINT"], data=json.dumps(otlp(events)), headers=xdr_h, timeout=60)
                if resp.status_code != 200:
                    print(f"XDR rejected batch: HTTP {resp.status_code} {resp.text[:200]}; retrying next poll")
                    break
                since = events[-1]["published"]
                open(STATE, "w").write(since)
                print(f"forwarded {len(events)} events up to {since}")
            nxt = r.links.get("next", {}).get("url")
            url, params = (nxt, None) if nxt and events else (None, None)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
