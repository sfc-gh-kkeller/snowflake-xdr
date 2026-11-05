#!/usr/bin/env python3
"""
CrowdStrike Falcon Data Replicator (FDR) -> Snowflake XDR (`crowdstrike` source).

FDR drops gzipped newline-delimited JSON into an S3 bucket and announces each batch on an
SQS queue. This forwarder reads the queue, downloads each file and sends the events that
the XDR mappings use (ProcessRollup2, NetworkConnectIP4, DnsRequest, *Written) over OTLP.
Event Streams detections (DetectionSummaryEvent) can be sent the same way from the
Falcon SIEM connector output file: python3 crowdstrike_fdr.py --siem-file <path>.

  export FDR_SQS_URL=... AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-west-1
  export XDR_ENDPOINT=... XDR_PAT=...
  python3 crowdstrike_fdr.py

Needs: pip install boto3 requests
"""
import gzip
import json
import os
import sys
import time

from xdr_otlp import send

KEEP = {"ProcessRollup2", "SyntheticProcessRollup2", "NetworkConnectIP4", "NetworkListenIP4", "DnsRequest",
        "NewExecutableWritten", "PeFileWritten", "ScriptFileWritten"}


def ts(ev):
    """FDR 'timestamp' and Event Streams 'eventCreationTime' are epoch milliseconds."""
    v = ev.get("timestamp") or (ev.get("metadata") or {}).get("eventCreationTime")
    try:
        return int(v) / 1000
    except (TypeError, ValueError):
        return time.time()


def forward_fdr():
    import boto3
    sqs, s3 = boto3.client("sqs"), boto3.client("s3")
    queue = os.environ["FDR_SQS_URL"]
    while True:
        msgs = sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=20).get("Messages", [])
        for m in msgs:
            note = json.loads(m["Body"])
            for f in note.get("files", []):
                obj = s3.get_object(Bucket=note["bucket"], Key=f["path"])
                batch = []
                for line in gzip.decompress(obj["Body"].read()).splitlines():
                    ev = json.loads(line)
                    if ev.get("event_simpleName") in KEEP:
                        batch.append((ts(ev), ev))
                    if len(batch) >= 500:
                        send("crowdstrike", batch, scope="crowdstrike-fdr")
                        batch = []
                if batch:
                    send("crowdstrike", batch, scope="crowdstrike-fdr")
            sqs.delete_message(QueueUrl=queue, ReceiptHandle=m["ReceiptHandle"])


def forward_siem_file(path):
    with open(path) as fh:
        batch = [json.loads(line) for line in fh if line.strip()]
    send("crowdstrike", [(ts(e), e) for e in batch
                          if e.get("metadata", {}).get("eventType", "").endswith("DetectionSummaryEvent")],
         scope="crowdstrike-siem")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--siem-file":
        forward_siem_file(sys.argv[2])
    else:
        forward_fdr()
