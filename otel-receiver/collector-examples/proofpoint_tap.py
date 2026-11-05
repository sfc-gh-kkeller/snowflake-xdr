#!/usr/bin/env python3
"""
Proofpoint TAP SIEM API -> Snowflake XDR (`proofpoint` source).

Polls /v2/siem/all every TAP_POLL_SECONDS and sends messagesDelivered, messagesBlocked,
clicksPermitted and clicksBlocked records, each tagged with "_type" so the mapping can tell
them apart.

  export TAP_PRINCIPAL=... TAP_SECRET=...      # TAP service credential
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 proofpoint_tap.py

Needs: pip install requests
"""
import os
import time
from datetime import datetime, timedelta, timezone

import requests

from xdr_otlp import load_state, save_state, send

STATE = os.getenv("TAP_STATE_FILE", "proofpoint_tap.state")
POLL = int(os.getenv("TAP_POLL_SECONDS", "300"))
TYPES = ("messagesDelivered", "messagesBlocked", "clicksPermitted", "clicksBlocked")


def epoch(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return time.time()


def main():
    auth = (os.environ["TAP_PRINCIPAL"], os.environ["TAP_SECRET"])
    while True:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        # The SIEM API serves at most 1 hour per call, from up to 7 days back
        since = load_state(STATE, (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        end = min(now, datetime.fromisoformat(since.replace("Z", "+00:00")) + timedelta(hours=1))
        interval = f"{since}/{end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        r = requests.get("https://tap-api-v2.proofpoint.com/v2/siem/all", auth=auth, timeout=120,
                         params={"format": "json", "interval": interval})
        r.raise_for_status()
        d = r.json()
        for t in TYPES:
            recs = [(epoch(x.get("clickTime") or x.get("messageTime")), {**x, "_type": t}) for x in d.get(t, [])]
            if recs:
                send("proofpoint", recs, scope="proofpoint-tap")
        save_state(STATE, end.strftime("%Y-%m-%dT%H:%M:%SZ"))
        time.sleep(POLL if end >= now else 1)


if __name__ == "__main__":
    main()
