#!/usr/bin/env python3
"""
Databricks audit logs -> Snowflake XDR.

Reads the system table system.access.audit incrementally (by event_time) through a SQL
warehouse and sends each row as an audit record with the field names of the Databricks
audit log delivery format (serviceName, actionName, userIdentity, requestParams, response),
which the shipped `databricks` mapping turns into DATABASE_ACTIVITY.

  export DATABRICKS_HOST=adb-123.azuredatabricks.net DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/abc
  export DATABRICKS_TOKEN=...       # service principal with SELECT on system.access.audit
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 databricks_forwarder.py

Needs: pip install databricks-sql-connector requests
"""

import os
import time
from datetime import datetime, timedelta, timezone

from databricks import sql

from xdr_otlp import load_state, save_state, send

STATE = os.getenv("DBX_STATE_FILE", "databricks_forwarder.state")
POLL_SECONDS = int(os.getenv("DBX_POLL_SECONDS", "120"))
QUERY = """
SELECT event_time, workspace_id, account_id, service_name, action_name, user_identity.email AS email,
       source_ip_address, user_agent, request_params, response.status_code AS status_code,
       response.error_message AS error_message
FROM system.access.audit
WHERE event_time > :since
ORDER BY event_time
LIMIT 5000
"""


def main():
    since = load_state(STATE, (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
    with sql.connect(server_hostname=os.environ["DATABRICKS_HOST"], http_path=os.environ["DATABRICKS_HTTP_PATH"],
                     access_token=os.environ["DATABRICKS_TOKEN"]) as conn:
        while True:
            with conn.cursor() as cur:
                cur.execute(QUERY, {"since": since})
                rows = cur.fetchall()
            if rows:
                records = [(r.event_time.timestamp(), {
                    "timestamp": int(r.event_time.timestamp() * 1000), "workspaceId": str(r.workspace_id),
                    "accountId": r.account_id, "serviceName": r.service_name, "actionName": r.action_name,
                    "userIdentity": {"email": r.email}, "sourceIPAddress": r.source_ip_address,
                    "userAgent": r.user_agent, "requestParams": dict(r.request_params or {}),
                    "response": {"statusCode": r.status_code, "errorMessage": r.error_message}}) for r in rows]
                send("databricks", records, scope="databricks-forwarder")
                since = rows[-1].event_time.isoformat()
                save_state(STATE, since)
                print(f"forwarded {len(rows)} audit events up to {since}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
