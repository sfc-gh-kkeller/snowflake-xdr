#!/usr/bin/env python3
"""
Replay demo attack telemetry to the XDR OTLP receiver as real OpenTelemetry (OTLP/HTTP protobuf).

  python3 scripts/otel_replay.py --endpoint https://<ingress>/v1/logs --pat-file pat.txt [--story all]

Stories:
  okta      password spray on one account from an unusual country, then a success (DET-001 brute force)
  sshd      SSH brute force against a bastion host, then an accepted login
  firewall  a source XDR has never seen (JSON bodies) - the autopilot proposes its CIM mapping

Needs: pip install opentelemetry-proto requests
Auth: a Snowflake Programmatic Access Token for a user granted XDR_OTLP_SENDER.
"""

import argparse
import gzip
import json
import random
import sys
import time

import requests
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord, ResourceLogs, ScopeLogs


def kv(k, v):
    return KeyValue(key=k, value=AnyValue(string_value=str(v)))


def batch(service, host, records, scope="xdr-replay"):
    req = ExportLogsServiceRequest()
    rl = ResourceLogs()
    rl.resource.attributes.extend([kv("service.name", service), kv("host.name", host)])
    sl = ScopeLogs()
    sl.scope.name = scope
    for t, sev, body, attrs in records:
        lr = LogRecord(time_unix_nano=int(t * 1e9), observed_time_unix_nano=int(time.time() * 1e9),
                       severity_text=sev, body=AnyValue(string_value=body))
        lr.attributes.extend([kv(k, v) for k, v in (attrs or {}).items()])
        sl.log_records.append(lr)
    rl.scope_logs.append(sl)
    req.resource_logs.append(rl)
    return req


def okta(now):
    recs = []
    ip, user = "198.51.100.77", "tlee@corp.example"
    for i in range(12):
        recs.append((now - 600 + i * 30, "WARN", json.dumps({
            "published": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now - 600 + i * 30)),
            "eventType": "user.session.start", "displayMessage": "User login to Okta",
            "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            "actor": {"id": "00u1tlee", "alternateId": user},
            "client": {"ipAddress": ip, "userAgent": {"rawUserAgent": "python-requests/2.31"},
                       "geographicalContext": {"city": "Lagos", "country": "Nigeria"}},
            "authenticationContext": {"credentialType": "PASSWORD"},
            "target": [{"displayName": "Okta Dashboard"}]}), None))
    recs.append((now - 200, "INFO", json.dumps({
        "published": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now - 200)),
        "eventType": "user.session.start", "displayMessage": "User login to Okta",
        "outcome": {"result": "SUCCESS"}, "actor": {"id": "00u1tlee", "alternateId": user},
        "client": {"ipAddress": ip, "userAgent": {"rawUserAgent": "python-requests/2.31"},
                   "geographicalContext": {"city": "Lagos", "country": "Nigeria"}},
        "authenticationContext": {"credentialType": "PASSWORD"}, "target": [{"displayName": "Okta Dashboard"}]}),
        None))
    return batch("okta", "okta", recs, "okta-systemlog")


def sshd(now):
    recs = []
    src = "203.0.113.45"
    users = ["root", "admin", "ubuntu", "deploy", "root", "oracle", "root", "git", "admin", "root", "postgres", "root"]
    for i, u in enumerate(users):
        msg = (f"Failed password for invalid user {u} from {src} port {40000 + i} ssh2" if u not in ("root", "deploy")
               else f"Failed password for {u} from {src} port {40000 + i} ssh2")
        recs.append((now - 500 + i * 20, "WARN", f"sshd[{2100 + i}]: {msg}", {"log.file.name": "auth.log"}))
    recs.append((now - 120, "INFO", f"sshd[2200]: Accepted password for deploy from {src} port 40999 ssh2",
                 {"log.file.name": "auth.log"}))
    return batch("linux_auth", "bastion-01", recs, "filelog")


def firewall(now):
    recs = []
    for i in range(10):
        dst_port = random.choice([22, 443, 3389, 445, 8080])
        recs.append((now - 300 + i * 15, "INFO", json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 300 + i * 15)),
            "fw_action": random.choice(["ALLOW", "DENY", "DENY"]),
            "src_addr": f"10.1.4.{20 + i}", "dst_addr": "45.33.32.156", "dst_port": dst_port,
            "proto": "TCP", "bytes_out": random.randint(200, 90000), "rule": "egress-default"}), None))
    return batch("edge-fw", "fw-edge-01", recs, "syslog")


STORIES = {"okta": okta, "sshd": sshd, "firewall": firewall}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True, help="https://<ingress>/v1/logs")
    ap.add_argument("--pat-file", required=True)
    ap.add_argument("--story", default="all", choices=["all", *STORIES])
    ap.add_argument("--source-token", help="X-XDR-Source-Token for a registered source")
    a = ap.parse_args()
    pat = open(a.pat_file).read().strip()
    headers = {"Authorization": f'Snowflake Token="{pat}"', "Content-Type": "application/x-protobuf",
               "Content-Encoding": "gzip"}
    if a.source_token:
        headers["X-XDR-Source-Token"] = a.source_token
    now = time.time()
    ok = True
    for name in (STORIES if a.story == "all" else [a.story]):
        req = STORIES[name](now)
        n = sum(len(sl.log_records) for rl in req.resource_logs for sl in rl.scope_logs)
        r = requests.post(a.endpoint, data=gzip.compress(req.SerializeToString()), headers=headers, timeout=60)
        print(f"{name:9s} {n:3d} records -> HTTP {r.status_code} {r.text[:120] if r.status_code != 200 else ''}")
        ok &= r.status_code == 200
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
