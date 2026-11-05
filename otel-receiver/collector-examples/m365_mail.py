#!/usr/bin/env python3
"""
Microsoft 365 mail -> Snowflake XDR (`m365_messagetrace` and `m365_audit` sources).

  * Message trace: the Reporting web service MessageTrace endpoint (Exchange Online), every
    M365_POLL_SECONDS, for the window since the last run.
  * Audit: the Office 365 Management Activity API, Audit.Exchange content (inbox rules and
    mailbox forwarding: New-InboxRule, Set-InboxRule, UpdateInboxRules, Set-Mailbox).
    Start the subscription once:  POST .../subscriptions/start?contentType=Audit.Exchange

App registration needs ReportingWebService.Read.All (Exchange) and ActivityFeed.Read
(Office 365 Management APIs), with admin consent.

  export M365_TENANT_ID=... M365_CLIENT_ID=... M365_CLIENT_SECRET=...
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 m365_mail.py

Needs: pip install requests
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import requests

from xdr_otlp import load_state, save_state, send

TENANT = os.getenv("M365_TENANT_ID", "")
STATE = os.getenv("M365_STATE_FILE", "m365_mail.state")
POLL = int(os.getenv("M365_POLL_SECONDS", "300"))
AUDIT_OPS = {"New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox"}


def token(scope):
    r = requests.post(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token", timeout=30, data={
        "grant_type": "client_credentials", "client_id": os.environ["M365_CLIENT_ID"],
        "client_secret": os.environ["M365_CLIENT_SECRET"], "scope": scope})
    r.raise_for_status()
    return r.json()["access_token"]


def epoch(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return time.time()


def message_trace(start, end):
    t = token("https://outlook.office365.com/.default")
    url = ("https://reports.office365.com/ecp/reportingwebservice/reporting.svc/MessageTrace"
           f"?$format=json&$filter=StartDate eq datetime'{start}' and EndDate eq datetime'{end}'")
    while url:
        r = requests.get(url, headers={"Authorization": f"Bearer {t}"}, timeout=120)
        r.raise_for_status()
        d = r.json().get("d", {})
        rows = d.get("results", [])
        if rows:
            send("m365_messagetrace", [(epoch(x.get("Received")), x) for x in rows], scope="m365-messagetrace")
        url = d.get("__next")


def audit(start, end):
    t = token("https://manage.office.com/.default")
    h = {"Authorization": f"Bearer {t}"}
    base = f"https://manage.office.com/api/v1.0/{TENANT}/activity/feed"
    r = requests.get(f"{base}/subscriptions/content", headers=h, timeout=60,
                     params={"contentType": "Audit.Exchange", "startTime": start, "endTime": end})
    r.raise_for_status()
    for blob in r.json():
        events = requests.get(blob["contentUri"], headers=h, timeout=60).json()
        keep = [(epoch(e.get("CreationTime")), e) for e in events if e.get("Operation") in AUDIT_OPS]
        if keep:
            send("m365_audit", keep, scope="m365-audit")


def main():
    while True:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        start = load_state(STATE, (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S"))
        end = now.strftime("%Y-%m-%dT%H:%M:%S")
        message_trace(start, end)
        audit(start, end)
        save_state(STATE, end)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
