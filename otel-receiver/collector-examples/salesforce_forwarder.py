#!/usr/bin/env python3
"""
Salesforce event monitoring and Setup Audit Trail -> Snowflake XDR.

Polls the Real-Time Event Monitoring objects (LoginEvent, ReportEvent, ApiEvent, needs
Shield / Event Monitoring) and SetupAuditTrail with SOQL, tags each record with its
EventType, and sends it to the `salesforce` source (DATABASE_ACTIVITY).

  export SF_USERNAME=... SF_PASSWORD=... SF_TOKEN=...   # integration user with View Event Log Files / View Setup
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 salesforce_forwarder.py

Needs: pip install simple-salesforce requests
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

from simple_salesforce import Salesforce

from xdr_otlp import load_state, save_state, send

STATE = os.getenv("SF_STATE_FILE", "salesforce_forwarder.state")
POLL_SECONDS = int(os.getenv("SF_POLL_SECONDS", "120"))
OBJECTS = {
    "LoginEvent": ("EventDate", "EventDate, Username, SourceIp, Status, LoginType, Application, Country, SessionKey"),
    "ReportEvent": ("EventDate", "EventDate, Username, SourceIp, Operation, ReportId, RowsProcessed, QueriedEntities, SessionKey"),
    "ApiEvent": ("EventDate", "EventDate, Username, SourceIp, Operation, RowsProcessed, Query, QueriedEntities, Client, SessionKey"),
    "SetupAuditTrail": ("CreatedDate", "CreatedDate, CreatedBy.Username, Action, Section, Display"),
}


def main():
    sf = Salesforce(username=os.environ["SF_USERNAME"], password=os.environ["SF_PASSWORD"],
                    security_token=os.environ["SF_TOKEN"])
    default = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    state = json.loads(load_state(STATE, "{}"))
    while True:
        for obj, (tcol, cols) in OBJECTS.items():
            since = state.get(obj, default)
            res = sf.query_all(f"SELECT {cols} FROM {obj} WHERE {tcol} > {since} ORDER BY {tcol} LIMIT 2000")
            recs = []
            for r in res["records"]:
                r.pop("attributes", None)
                if obj == "SetupAuditTrail":
                    r["CreatedByUsername"] = (r.pop("CreatedBy") or {}).get("Username")
                r["EventType"] = obj
                ts = datetime.strptime(r[tcol][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                recs.append((ts.timestamp(), r))
            if recs:
                send("salesforce", recs, scope="salesforce-forwarder")
                state[obj] = res["records"][-1][tcol][:19] + "Z"
                save_state(STATE, json.dumps(state))
                print(f"{obj}: forwarded {len(recs)} up to {state[obj]}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
