#!/usr/bin/env python3
"""
SentinelOne Singularity -> Snowflake XDR (`sentinelone` source).

  * Cloud Funnel (Deep Visibility telemetry) lands as gzipped JSON lines in your S3 bucket;
    this forwarder reads new objects under S1_FUNNEL_PREFIX and sends Process Creation,
    IP Connect, DNS Resolved and File Creation events.
  * Threats come from the management API (/web/api/v2.1/threats), polled every S1_POLL_SECONDS.

  export S1_BUCKET=... S1_FUNNEL_PREFIX=cloud_funnel/ AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
  export S1_CONSOLE=https://<tenant>.sentinelone.net S1_API_TOKEN=...
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 sentinelone_funnel.py

Needs: pip install boto3 requests
"""
import gzip
import json
import os
import time

import requests

from xdr_otlp import load_state, save_state, send

KEEP = {"Process Creation", "IP Connect", "IP Listen", "DNS Resolved", "DNS Unresolved",
        "File Creation", "File Modification", "File Rename"}
STATE = os.getenv("S1_STATE_FILE", "sentinelone_funnel.state")
POLL = int(os.getenv("S1_POLL_SECONDS", "120"))


def ts(ev):
    try:
        return int(ev.get("event.time")) / 1000
    except (TypeError, ValueError):
        return time.time()


def funnel(s3, after_key):
    bucket, prefix = os.environ["S1_BUCKET"], os.getenv("S1_FUNNEL_PREFIX", "")
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix, StartAfter=after_key or prefix)
    last = after_key
    for page in pages:
        for obj in page.get("Contents", []):
            raw = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            lines = (gzip.decompress(raw) if obj["Key"].endswith(".gz") else raw).splitlines()
            batch = [(ts(e), e) for e in (json.loads(x) for x in lines if x.strip()) if e.get("event.type") in KEEP]
            if batch:
                send("sentinelone", batch, scope="sentinelone-funnel")
            last = obj["Key"]
    return last


def threats(since):
    r = requests.get(f"{os.environ['S1_CONSOLE']}/web/api/v2.1/threats",
                     headers={"Authorization": f"ApiToken {os.environ['S1_API_TOKEN']}"},
                     params={"createdAt__gt": since, "limit": 500, "sortBy": "createdAt"}, timeout=60)
    r.raise_for_status()
    data = r.json().get("data", [])
    if data:
        send("sentinelone", [(time.time(), t) for t in data], scope="sentinelone-threats")
        return data[-1]["threatInfo"]["createdAt"]
    return since


def main():
    import boto3
    s3 = boto3.client("s3")
    state = json.loads(load_state(STATE, '{"key": "", "since": "1970-01-01T00:00:00Z"}'))
    while True:
        state["key"] = funnel(s3, state["key"])
        state["since"] = threats(state["since"])
        save_state(STATE, json.dumps(state))
        time.sleep(POLL)


if __name__ == "__main__":
    main()
