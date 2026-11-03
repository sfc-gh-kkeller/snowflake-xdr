#!/usr/bin/env python3
"""
Entra ID sign-in / audit logs and the Azure Activity log -> Snowflake XDR.

Azure exports all three through a diagnostic setting to Event Hubs. Each Event Hubs
message is {"records": [...]}; this forwarder splits the records and routes them by
category to the sources the rule pack expects:

  SignInLogs (and *SignInLogs)  -> service.name entra_signin   -> AUTHENTICATION
  AuditLogs                     -> service.name entra_audit    -> CLOUD_API
  Administrative / Policy / ... -> service.name azure_activity -> CLOUD_API

  export EVENTHUB_CONNECTION_STRING='Endpoint=sb://...;EntityPath=insights-logs'
  export EVENTHUB_CONSUMER_GROUP='$Default'
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 entra_azure_forwarder.py

Needs: pip install azure-eventhub requests
"""

import json
import os
from datetime import datetime

from azure.eventhub import EventHubConsumerClient

from xdr_otlp import send


def route(category):
    c = (category or "").lower()
    if c.endswith("signinlogs"):
        return "entra_signin"
    if c == "auditlogs":
        return "entra_audit"
    return "azure_activity"


def ts(rec):
    try:
        return datetime.fromisoformat(rec["time"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError):
        return datetime.now().timestamp()


def on_event(partition, event):
    if event is None:
        return
    try:
        records = json.loads(event.body_as_str()).get("records", [])
    except ValueError:
        return
    by_source = {}
    for rec in records:
        by_source.setdefault(route(rec.get("category")), []).append((ts(rec), rec))
    for source, recs in by_source.items():
        send(source, recs, scope="entra-azure-forwarder")
    partition.update_checkpoint(event)   # in-memory unless a checkpoint store is configured


def main():
    client = EventHubConsumerClient.from_connection_string(
        os.environ["EVENTHUB_CONNECTION_STRING"], consumer_group=os.getenv("EVENTHUB_CONSUMER_GROUP", "$Default"))
    with client:
        client.receive(on_event=on_event, starting_position="@latest")


if __name__ == "__main__":
    main()
