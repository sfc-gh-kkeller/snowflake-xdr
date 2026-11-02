#!/usr/bin/env bash
# Build and deploy the XDR OTLP receiver to Snowpark Container Services.
#   scripts/deploy_otel_receiver.sh [-c connection]
# Prints the public endpoint when ready. Idempotent: re-running pushes a new
# image and restarts the service on it.
set -euo pipefail

CONN="${SNOWFLAKE_CONNECTION:-aws_demo_kevin}"
while getopts "c:" o; do case $o in c) CONN="$OPTARG" ;; *) exit 1 ;; esac; done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="v$(date +%Y%m%d%H%M%S)"

sql() { snow sql -c "$CONN" --enable-templating NONE "$@"; }
scalar() { snow sql -c "$CONN" --format json -q "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d[-1] if d and isinstance(d[0], list) else d; print(list(d[0].values())[0] if d else "")'; }

echo "== infrastructure"
sql -f "$ROOT/setup/31_otel_receiver.sql" > /dev/null

REPO_URL=$(snow sql -c "$CONN" --format json -q "SHOW IMAGE REPOSITORIES LIKE 'XDR_IMAGES' IN SCHEMA SNOWFLAKE_XDR.RAW_LOGS" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["repository_url"])')
IMAGE="$REPO_URL/xdr-otlp-receiver:$TAG"

echo "== build $IMAGE"
docker build --platform linux/amd64 -t "$IMAGE" "$ROOT/otel-receiver" > /dev/null
snow spcs image-registry login -c "$CONN" > /dev/null
docker push "$IMAGE" > /dev/null

echo "== service"
IMAGE_PATH="/snowflake_xdr/raw_logs/xdr_images/xdr-otlp-receiver:$TAG"
SPEC=$(cat <<EOF
spec:
  containers:
  - name: receiver
    image: $IMAGE_PATH
    env:
      XDR_WAREHOUSE: XDR_WH
    readinessProbe:
      port: 4318
      path: /healthz
    resources:
      requests: {cpu: 0.5, memory: 1Gi}
      limits: {cpu: 1, memory: 2Gi}
  endpoints:
  - name: otlp
    port: 4318
    public: true
serviceRoles:
- name: sender
  endpoints: [otlp]
EOF
)
EXISTS=$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.INFORMATION_SCHEMA.SERVICES WHERE service_name = 'XDR_OTLP_RECEIVER'" || echo 0)
if [[ "$EXISTS" == "0" ]]; then
  sql -q "USE ROLE XDR_INGEST_ROLE; CREATE SERVICE SNOWFLAKE_XDR.RAW_LOGS.XDR_OTLP_RECEIVER
            IN COMPUTE POOL XDR_OTEL_POOL QUERY_WAREHOUSE = XDR_WH MIN_INSTANCES = 1 MAX_INSTANCES = 2
            FROM SPECIFICATION \$\$
$SPEC
\$\$;" > /dev/null
else
  sql -q "USE ROLE XDR_INGEST_ROLE; ALTER SERVICE SNOWFLAKE_XDR.RAW_LOGS.XDR_OTLP_RECEIVER FROM SPECIFICATION \$\$
$SPEC
\$\$;" > /dev/null
fi
sql -q "USE ROLE XDR_INGEST_ROLE; GRANT SERVICE ROLE SNOWFLAKE_XDR.RAW_LOGS.XDR_OTLP_RECEIVER!SENDER TO ROLE XDR_OTLP_SENDER;" > /dev/null

echo "== waiting for the endpoint"
for _ in $(seq 1 60); do
  URL=$(snow sql -c "$CONN" --format json -q "USE ROLE XDR_INGEST_ROLE; SHOW ENDPOINTS IN SERVICE SNOWFLAKE_XDR.RAW_LOGS.XDR_OTLP_RECEIVER" 2>/dev/null \
    | python3 -c 'import json,sys
d=json.load(sys.stdin); d=d[-1]
u=[r.get("ingress_url","") for r in d if r.get("name")=="otlp"]
print(u[0] if u and u[0].endswith(".snowflakecomputing.app") else "")' 2>/dev/null || true)
  STATUS=$(scalar "SELECT SYSTEM\$GET_SERVICE_STATUS('SNOWFLAKE_XDR.RAW_LOGS.XDR_OTLP_RECEIVER')" 2>/dev/null | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())[0]["status"])' 2>/dev/null || echo "?")
  if [[ -n "$URL" && "$STATUS" == "READY" ]]; then
    echo "Receiver ready: https://$URL/v1/logs"
    exit 0
  fi
  sleep 10
done
echo "Service not ready yet (status $STATUS); check SYSTEM\$GET_SERVICE_LOGS" >&2
exit 1
