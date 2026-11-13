#!/usr/bin/env bash
# Vendored Sigma baseline: refresh rule-packs/sigma/ from SigmaHQ and import it.
#
#   bash scripts/sync_sigma.sh                 # upload the vendored baseline + compiler, import
#   bash scripts/sync_sigma.sh --refresh       # first re-vendor from a fresh SigmaHQ clone
#
# Only rules that compile to CIM SQL and pass the default filter (status stable/test,
# level high/critical) are vendored. The live path (SIGMA_IMPORT('github')) needs no
# script: TASK_SIGMA_SYNC pulls each new SigmaHQ release.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONN="${CONN:-${SNOWFLAKE_CONNECTION:-default}}"
SNOW="${SNOW:-snow}"
PY="${PY:-python3}"
OUT="$REPO_ROOT/rule-packs/sigma"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "${1:-}" == "--refresh" ]]; then
    git clone -q --depth 1 https://github.com/SigmaHQ/sigma.git "$WORK/sigma"
    rm -rf "$OUT/rules"
    "$PY" - "$WORK/sigma" "$OUT" "$REPO_ROOT/sigma" <<'EOF'
import glob, os, shutil, subprocess, sys
src, out, mod = sys.argv[1:4]
sys.path.insert(0, mod)
from sigma_compiler import compile_rule
n = 0
for d in ("rules", "rules-emerging-threats"):
    for f in glob.glob(f"{src}/{d}/**/*.yml", recursive=True):
        r = compile_rule(open(f, encoding="utf-8").read())
        if r["ok"] and r.get("status") in ("stable", "test") and r.get("level") in ("high", "critical"):
            dst = os.path.join(out, "rules", os.path.relpath(f, src))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy(f, dst)
            n += 1
shutil.copy(f"{src}/LICENSE", f"{out}/LICENSE")
sha = subprocess.check_output(["git", "-C", src, "rev-parse", "HEAD"], text=True).strip()
open(f"{out}/SOURCE", "w").write(f"https://github.com/SigmaHQ/sigma @ {sha}\n{n} rules vendored\n")
print(f"vendored {n} rules")
EOF
fi

(cd "$OUT" && zip -qr "$WORK/sigma_bundle.zip" rules LICENSE)
"$SNOW" sql -c "$CONN" --enable-templating NONE -q \
    "PUT file://$REPO_ROOT/sigma/sigma_compiler.py @SNOWFLAKE_XDR.REFERENCE.SIGMA_STAGE AUTO_COMPRESS = FALSE OVERWRITE = TRUE" >/dev/null
"$SNOW" sql -c "$CONN" --enable-templating NONE -q \
    "PUT file://$WORK/sigma_bundle.zip @SNOWFLAKE_XDR.REFERENCE.SIGMA_STAGE AUTO_COMPRESS = FALSE OVERWRITE = TRUE" >/dev/null
"$SNOW" sql -c "$CONN" --enable-templating NONE --format json -q \
    "CALL SNOWFLAKE_XDR.REFERENCE.SIGMA_IMPORT('stage')"
