"""
XDR OTLP/HTTP receiver (Snowpark Container Services).

Accepts OpenTelemetry logs on POST /v1/logs (protobuf or JSON, optional gzip),
converts protobuf to OTLP/JSON and hands each export batch to
SNOWFLAKE_XDR.RAW_LOGS.INGEST_OTLP_LOGS, which lands it in RAW_LOGS.OTEL_LOGS.

Auth: the SPCS public endpoint authenticates every caller with Snowflake
(Programmatic Access Token in `Authorization: Snowflake Token="..."`). The optional
X-XDR-Source-Token header pins records to a registered source.

POST /v1/webhooks/{connection} takes ticket changes pushed by Jira Automation
("Send web request") or a ServiceNow outbound REST message and hands them to
SNOWFLAKE_XDR.INCIDENTS.INGEST_TICKET_WEBHOOK. If XDR_WEBHOOK_SECRET_<CONNECTION>
is set, the body must also carry a matching X-Hub-Signature: sha256=<hmac>.
"""

import gzip
import hashlib
import hmac
import json
import re
import logging
import os
import threading
import time

import snowflake.connector
from fastapi import FastAPI, Request, Response
from google.protobuf.json_format import MessageToJson
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("xdr-otlp")

MAX_BODY = int(os.getenv("XDR_MAX_BODY_BYTES", str(8 * 1024 * 1024)))
WAREHOUSE = os.getenv("XDR_WAREHOUSE", "XDR_WH")
PROC = "CALL SNOWFLAKE_XDR.RAW_LOGS.INGEST_OTLP_LOGS(%s, %s)"
WEBHOOK_PROC = "CALL SNOWFLAKE_XDR.INCIDENTS.INGEST_TICKET_WEBHOOK(%s, %s)"
CONNECTION_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
MAX_WEBHOOK_BODY = 1024 * 1024

app = FastAPI(title="XDR OTLP receiver")
_local = threading.local()
_stats = {"requests": 0, "records": 0, "errors": 0, "rejected": 0, "started": time.time()}


def _connect():
    """Inside SPCS the service authenticates with the OAuth token Snowflake mounts into the container."""
    token_file = "/snowflake/session/token"
    if os.path.exists(token_file):
        return snowflake.connector.connect(
            host=os.environ["SNOWFLAKE_HOST"], account=os.environ["SNOWFLAKE_ACCOUNT"],
            authenticator="oauth", token=open(token_file).read(), warehouse=WAREHOUSE,
            database="SNOWFLAKE_XDR", schema="RAW_LOGS", client_session_keep_alive=True)
    # Local development: a named connection from connections.toml
    return snowflake.connector.connect(connection_name=os.getenv("SNOWFLAKE_CONNECTION_NAME", "default"),
                                       warehouse=WAREHOUSE)


def _cursor():
    conn = getattr(_local, "conn", None)
    if conn is None or conn.is_closed():
        _local.conn = conn = _connect()
    return conn.cursor()


def _ingest(payload_json: str, source_token: str | None, proc: str = PROC) -> dict:
    for attempt in (1, 2):
        try:
            cur = _cursor()
            args = (source_token, payload_json) if proc == WEBHOOK_PROC else (payload_json, source_token)
            cur.execute(proc, args)
            row = cur.fetchone()
            return json.loads(row[0]) if row and row[0] else {}
        except snowflake.connector.errors.Error:
            # Token refresh or dropped session: reconnect once
            _local.conn = None
            if attempt == 2:
                raise
    return {}


def _otlp_response(json_mode: bool, rejected: int = 0, message: str = "") -> Response:
    if json_mode:
        body = {} if not rejected else {"partialSuccess": {"rejectedLogRecords": str(rejected), "errorMessage": message}}
        return Response(json.dumps(body), media_type="application/json")
    resp = ExportLogsServiceResponse()
    if rejected:
        resp.partial_success.rejected_log_records = rejected
        resp.partial_success.error_message = message
    return Response(resp.SerializeToString(), media_type="application/x-protobuf")


@app.get("/healthz")
def healthz():
    return {"ok": True, **_stats, "uptime_s": round(time.time() - _stats["started"])}


@app.post("/v1/logs")
async def logs(request: Request):
    _stats["requests"] += 1
    raw = await request.body()
    if len(raw) > MAX_BODY:
        return Response("payload too large", status_code=413)
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except OSError:
            return Response("invalid gzip body", status_code=400)
        if len(raw) > MAX_BODY * 4:
            return Response("payload too large", status_code=413)

    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    json_mode = ctype == "application/json"
    try:
        if json_mode:
            payload = raw.decode("utf-8")
            json.loads(payload)  # reject malformed JSON before it reaches Snowflake
        else:
            req = ExportLogsServiceRequest()
            req.ParseFromString(raw)
            # OTLP/JSON encoding: camelCase field names, 64-bit ints as strings, hex trace ids
            payload = MessageToJson(req, preserving_proto_field_name=False, indent=None)
    except Exception as e:  # noqa: BLE001 - any decode failure is a client error
        return Response(f"invalid OTLP payload: {e}", status_code=400)

    token = request.headers.get("x-xdr-source-token") or None
    try:
        res = _ingest(payload, token)
    except Exception as e:  # noqa: BLE001
        _stats["errors"] += 1
        log.exception("ingest failed")
        # 503 tells collectors to retry with backoff
        return Response(f"ingest temporarily unavailable: {str(e)[:200]}", status_code=503)

    if res.get("rejected"):
        _stats["rejected"] += 1
        return Response(res["rejected"], status_code=401)
    _stats["records"] += int(res.get("accepted", 0))
    return _otlp_response(json_mode)


@app.post("/v1/webhooks/{connection}")
async def ticket_webhook(connection: str, request: Request):
    """Ticket changes pushed from Jira / ServiceNow; applied to the XDR incident by the next ticket sync."""
    if not CONNECTION_RE.match(connection):
        return Response("invalid connection", status_code=404)
    raw = await request.body()
    if len(raw) > MAX_WEBHOOK_BODY:
        return Response("payload too large", status_code=413)
    secret = os.getenv(f"XDR_WEBHOOK_SECRET_{connection.upper().replace('-', '_')}")
    if secret:
        sent = request.headers.get("x-hub-signature", "")
        method, _, sig = sent.partition("=")
        expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        if method != "sha256" or not hmac.compare_digest(sig, expected):
            return Response("bad signature", status_code=401)
    try:
        json.loads(raw)
    except ValueError:
        return Response("body must be JSON", status_code=400)
    try:
        res = _ingest(raw.decode("utf-8"), connection, WEBHOOK_PROC)
    except Exception:  # noqa: BLE001
        log.exception("webhook ingest failed")
        return Response("temporarily unavailable", status_code=503)
    if not res.get("ok"):
        return Response(str(res.get("message", "rejected")), status_code=404)
    return {"ok": True, "queued": res.get("queued", 0)}
