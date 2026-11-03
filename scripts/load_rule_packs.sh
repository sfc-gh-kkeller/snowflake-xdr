#!/usr/bin/env bash
# Load every rule pack in rule-packs/*/pack.yaml into SNOWFLAKE_XDR and run a
# coverage-aware install (rules whose data source has no rows wait for data).
#
#   scripts/load_rule_packs.sh [connection] [pack_id ...]
set -euo pipefail
CONN="${1:-${SNOWFLAKE_CONNECTION:-aws_demo_kevin}}"
shift || true
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SQL="$(mktemp -t xdr_packs.XXXXXX).sql"

python3 - "$ROOT" "$SQL" "$@" <<'EOF'
import pathlib, sys
root, out, only = pathlib.Path(sys.argv[1]), sys.argv[2], set(sys.argv[3:])
stmts = []
for f in sorted(root.glob("rule-packs/*/pack.yaml")):
    if only and f.parent.name not in only:
        continue
    body = f.read_text()
    if "$$" in body:
        sys.exit(f"{f}: '$$' is not allowed in pack files")
    stmts.append(f"CALL SNOWFLAKE_XDR.REFERENCE.LOAD_RULE_PACK($${body}$$);")
stmts.append("CALL SNOWFLAKE_XDR.REFERENCE.INSTALL_RULE_PACK('all', FALSE);")
pathlib.Path(out).write_text("\n".join(stmts) + "\n")
print(f"{len(stmts) - 1} pack(s) staged")
EOF

snow sql -c "$CONN" --enable-templating NONE -f "$SQL"
rm -f "$SQL"
