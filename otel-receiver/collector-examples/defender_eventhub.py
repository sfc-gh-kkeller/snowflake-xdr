#!/usr/bin/env python3
"""
Microsoft Defender for Endpoint (Advanced Hunting streaming) -> Snowflake XDR (`defender` source).

In Microsoft Defender XDR: Settings > Microsoft Defender XDR > Streaming API > Add, forward
DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents and AlertInfo /
AlertEvidence to Event Hubs. Each message is {"records": [{"time", "category", "properties"}]};
this forwarder splits the batch so every record is one log body, as the mappings expect.

  export EVENTHUB_CONNECTION_STRING='Endpoint=sb://...;EntityPath=mde-streaming'
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 defender_eventhub.py

Needs: pip install azure-eventhub requests
"""
import json
import os
from datetime import datetime

from azure.eventhub import EventHubConsumerClient

from xdr_otlp import send

CATEGORIES = {"AdvancedHunting-DeviceProcessEvents", "AdvancedHunting-DeviceNetworkEvents",
              "AdvancedHunting-DeviceFileEvents", "AdvancedHunting-DeviceEvents",
              "AdvancedHunting-AlertInfo", "AdvancedHunting-AlertEvidence"}


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
    keep = [(ts(r), r) for r in records if r.get("category") in CATEGORIES]
    if keep:
        send("defender", keep, scope="defender-eventhub")
    partition.update_checkpoint(event)   # in-memory unless a checkpoint store is configured


def main():
    client = EventHubConsumerClient.from_connection_string(
        os.environ["EVENTHUB_CONNECTION_STRING"], consumer_group=os.getenv("EVENTHUB_CONSUMER_GROUP", "$Default"))
    with client:
        client.receive(on_event=on_event, starting_position="@latest")


if __name__ == "__main__":
    main()
