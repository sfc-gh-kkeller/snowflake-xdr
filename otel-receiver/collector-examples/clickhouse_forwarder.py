#!/usr/bin/env python3
"""
ClickHouse system.query_log -> Snowflake XDR.

Polls system.query_log (QueryFinish and exception rows) by event_time and sends each
row as JSON, which the shipped `clickhouse` mapping turns into DATABASE_ACTIVITY.
Run with a read-only user granted SELECT on system.query_log.

  export CLICKHOUSE_HOST=ch.internal CLICKHOUSE_USER=xdr_reader CLICKHOUSE_PASSWORD=...
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 clickhouse_forwarder.py

Needs: pip install clickhouse-connect requests
"""

import os
import time
from datetime import datetime, timedelta

import clickhouse_connect

from xdr_otlp import load_state, save_state, send

STATE = os.getenv("CH_STATE_FILE", "clickhouse_forwarder.state")
POLL_SECONDS = int(os.getenv("CH_POLL_SECONDS", "60"))
QUERY = """
SELECT toString(event_time_microseconds) AS event_time, toString(type) AS type, user, toString(address) AS address,
       query_kind, query, read_rows, read_bytes, result_rows, written_rows, exception, client_name, query_id,
       tables, databases
FROM system.query_log
WHERE type != 'QueryStart' AND event_time_microseconds > parseDateTime64BestEffort({since:String}, 6)
  AND user != currentUser()
ORDER BY event_time_microseconds
LIMIT 5000
"""


def main():
    client = clickhouse_connect.get_client(host=os.environ["CLICKHOUSE_HOST"], username=os.environ["CLICKHOUSE_USER"],
                                           password=os.environ["CLICKHOUSE_PASSWORD"], secure=True)
    since = load_state(STATE, (datetime.utcnow() - timedelta(hours=1)).isoformat())
    while True:
        res = client.query(QUERY, parameters={"since": since})
        rows = [dict(zip(res.column_names, r)) for r in res.result_rows]
        if rows:
            send("clickhouse", [(datetime.fromisoformat(r["event_time"]).timestamp(), r) for r in rows],
                 scope="clickhouse-forwarder")
            since = rows[-1]["event_time"]
            save_state(STATE, since)
            print(f"forwarded {len(rows)} queries up to {since}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
