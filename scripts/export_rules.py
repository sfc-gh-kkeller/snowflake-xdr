#!/usr/bin/env python3
"""Detection-as-code: Snowflake <-> git.

  python3 scripts/export_rules.py export            write detections/<managed_by>/<rule_id>.yml from Snowflake
  python3 scripts/export_rules.py verify [files...]  CI: lint + compile + canary-verify rule YAMLs in Snowflake
  python3 scripts/export_rules.py apply  [files...]  merge: apply changed detections/*.yml to Snowflake

Pack rules live in rule-packs/*/pack.yaml (and Sigma in rule-packs/sigma/) and are not exported here.
Uses the snow CLI (connection from $CONN, default $SNOWFLAKE_CONNECTION or "default"; CI passes a temporary connection).
Needs pyyaml.
"""
import glob
import json
import os
import subprocess
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "detections")
SNOW = os.environ.get("SNOW", "snow")


def snow_args():
    if os.environ.get("SNOWFLAKE_CI") == "1":  # GitHub Actions: SNOWFLAKE_* env vars, key-pair auth
        return ["-x"]
    return ["-c", os.environ.get("CONN") or os.environ.get("SNOWFLAKE_CONNECTION", "default")]


def sql(query, *binds):
    """Run one statement; binds are inlined as escaped string literals (the CLI has no bind support)."""
    def lit(v):
        return "NULL" if v is None else "'" + str(v).replace("\\", "\\\\").replace("'", "''") + "'"
    parts = query.split("?")
    if len(parts) - 1 != len(binds):
        raise ValueError("placeholder count does not match binds")
    q = parts[0] + "".join(lit(b) + rest for b, rest in zip(binds, parts[1:]))
    r = subprocess.run([SNOW, "sql", *snow_args(), "--format", "json", "--enable-templating", "NONE", "-q", q],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("snow sql failed: " + (r.stderr or r.stdout)[-2000:])
    return json.loads(r.stdout)


def scalar(query, *binds):
    row = sql(query, *binds)[0]
    v = list(row.values())[0]
    return json.loads(v) if isinstance(v, str) else v


class Literal(str):
    pass


yaml.add_representer(Literal, lambda d, v: d.represent_scalar("tag:yaml.org,2002:str", v, style="|"))


def export():
    rows = sql("""SELECT c.rule_id, c.name, c.description, c.severity, c.mitre_tactic_id, c.mitre_technique_id,
                         c.source_table, c.code, c.threshold_count, c.threshold_window_minutes, c.lookback_minutes,
                         c.enabled, c.test_mode, c.version, c.managed_by, c.created_by, c.pinned, f.fixtures
                  FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c
                  LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.V_CANARY_FIXTURES f ON f.rule_id = c.rule_id
                  WHERE c.language = 'sql' AND c.managed_by <> 'pack' AND c.managed_by <> 'autopilot_candidate'
                  ORDER BY c.rule_id""")
    keep = set()
    for r in rows:
        doc = {"id": r["RULE_ID"], "name": r["NAME"], "description": r["DESCRIPTION"],
               "severity": int(r["SEVERITY"] or 3), "tactic": r["MITRE_TACTIC_ID"], "technique": r["MITRE_TECHNIQUE_ID"],
               "table": r["SOURCE_TABLE"], "threshold": int(r["THRESHOLD_COUNT"] or 1),
               "window_minutes": int(r["THRESHOLD_WINDOW_MINUTES"] or 60), "lookback_minutes": int(r["LOOKBACK_MINUTES"] or 60),
               "enabled": bool(r["ENABLED"]), "shadow": bool(r["TEST_MODE"]), "pinned": bool(r["PINNED"]),
               "version": int(r["VERSION"] or 1), "managed_by": r["MANAGED_BY"], "created_by": r["CREATED_BY"]}
        if r["FIXTURES"]:
            doc["fixtures"] = json.loads(r["FIXTURES"]) if isinstance(r["FIXTURES"], str) else r["FIXTURES"]
        doc["sql"] = Literal((r["CODE"] or "").strip() + "\n")
        sub = os.path.join(OUT, r["MANAGED_BY"] or "human")
        os.makedirs(sub, exist_ok=True)
        path = os.path.join(sub, f"{r['RULE_ID']}.yml")
        with open(path, "w") as f:
            f.write("# Exported from Snowflake by scripts/export_rules.py - edit and open a pull request;\n"
                    "# CI verifies it and the merge applies it (setup/42_detection_as_code.sql).\n")
            yaml.dump({k: v for k, v in doc.items() if v is not None}, f, sort_keys=False, allow_unicode=True, width=120)
        keep.add(path)
    removed = 0
    for path in glob.glob(os.path.join(OUT, "*", "*.yml")):
        if path not in keep:  # rule deleted in Snowflake
            os.remove(path)
            removed += 1
    print(f"exported {len(keep)} rules to {os.path.relpath(OUT, ROOT)}/ ({removed} removed)")


def bundle(files):
    files = files or sorted(glob.glob(os.path.join(OUT, "*", "*.yml")))
    return json.dumps([{"path": os.path.relpath(p, ROOT), "text": open(p).read()} for p in files if p.endswith((".yml", ".yaml"))])


def verify(files):
    r = scalar("CALL SNOWFLAKE_XDR.DETECTIONS.CI_VERIFY_RULES(?)", bundle(files))
    for x in r.get("results", []):
        print(f"{x['status']:7} {x.get('path')} {x.get('rule') or ''}: {x.get('message', '')}")
    print(f"{r.get('rules', 0)} rule(s) checked, {r.get('failed', 0)} failed")
    sys.exit(0 if r.get("ok") else 1)


def apply(files):
    ref = os.environ.get("GITHUB_SHA", subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                                      capture_output=True, text=True).stdout.strip())
    r = scalar("CALL SNOWFLAKE_XDR.DETECTIONS.APPLY_RULES_FROM_GIT(?, ?)", bundle(files), ref)
    print(json.dumps(r, indent=2))
    sys.exit(0 if r.get("ok") else 1)


if __name__ == "__main__":
    cmd, rest = (sys.argv[1] if len(sys.argv) > 1 else "export"), sys.argv[2:]
    {"export": lambda: export(), "verify": lambda: verify(rest), "apply": lambda: apply(rest)}[cmd]()
