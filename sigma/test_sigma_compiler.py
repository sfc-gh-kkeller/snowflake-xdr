"""Unit tests for the Sigma compiler: python3 -m pytest sigma/ (needs pyyaml + pytest)."""
import json

import pytest

from sigma_compiler import COMPILER_VERSION, compile_rule, evaluate, sql_lit, sigma_tokens, like_pattern

PROC = """
title: Suspicious Encoded PowerShell
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    - Image|endswith: '\\\\powershell.exe'
    - OriginalFileName: PowerShell.EXE
  selection_cli:
    CommandLine|contains|windash: ' -enc '
  filter_main:
    ParentImage|startswith: 'C:\\\\Program Files\\\\'
  condition: all of selection_* and not filter_main
"""


def rule(text=PROC):
    r = compile_rule(text, "SIG-00001")
    assert r["ok"], r["reason"]
    return r


def test_compiles_with_attack_mapping():
    r = rule()
    x = r["rule"]
    assert x["table"] == "ENDPOINT_PROCESSES" and x["severity"] == 4
    assert x["technique"] == "T1059.001" and x["tactic"] == "TA0002"
    assert "FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES" in x["sql"]
    assert "ESCAPE '!'" in x["sql"]


def test_one_positive_fixture_per_branch_and_a_negative():
    r = rule()
    fx = r["rule"]["fixtures"]
    # two image branches x windash variants collapse to distinct rows, capped at 6
    assert 2 <= len(fx["positive"]) <= 6
    assert r["fixture_branches"] == len(fx["positive"])
    assert fx["negative"], "a must-not-fire fixture is synthesised"
    for p in fx["positive"]:
        assert p["row"]["user_name"] == "{{entity}}"


def test_fixtures_agree_with_the_condition():
    # Rebuild the tree via a second compile and evaluate synthesised rows in Python
    import sigma_compiler as sc
    import yaml
    doc = yaml.safe_load(PROC)
    src = sc.resolve_source(doc["logsource"])
    det = dict(doc["detection"])
    cond = det.pop("condition")
    tree = sc.parse_condition(cond, {k: sc.selection(v, src) for k, v in det.items()})
    fx = rule()["rule"]["fixtures"]
    assert all(evaluate(tree, p["row"]) for p in fx["positive"])
    assert not any(evaluate(tree, n["row"]) for n in fx["negative"])


def test_backslashes_and_quotes_are_escaped():
    assert sql_lit("C:\\Windows\\it's") == "'C:\\\\Windows\\\\it''s'"
    assert like_pattern(sigma_tokens("100%_a!*")) == "100!%!_a!!%"
    assert like_pattern(sigma_tokens("lit\\*eral")) == "lit*eral"


def test_cloud_fields_read_the_original_record():
    r = rule("""
title: AWS root console login
id: 22222222-2222-2222-2222-222222222222
status: stable
level: critical
logsource: {product: aws, service: cloudtrail}
detection:
  sel: {eventName: ConsoleLogin, userIdentity.type: Root}
  condition: sel
""")
    x = r["rule"]
    assert "GET_PATH(_raw, 'userIdentity.type')" in x["sql"] and "vendor_product ILIKE 'aws'" in x["sql"]
    row = x["fixtures"]["positive"][0]["row"]
    assert row["_raw"]["userIdentity"]["type"] == "Root" and row["vendor_product"] == "aws"


@pytest.mark.parametrize("snippet,reason", [
    ("logsource: {product: zeek, service: dns}", "logsource"),
    ("logsource: {category: process_creation}\ndetection:\n  sel: {CommandLine|base64offset|contains: x}\n  condition: sel", "modifier"),
    ("logsource: {category: process_creation}\ndetection:\n  sel: {CommandLine|re: '(?<=a)b'}\n  condition: sel", "PCRE"),
    ("logsource: {category: process_creation}\ndetection:\n  sel: {Image: x}\n  condition: sel | count() > 5", "aggregation"),
])
def test_unsupported_rules_fail_with_a_reason(snippet, reason):
    text = "title: t\nid: 33333333-3333-3333-3333-333333333333\n" + snippet
    if "detection" not in snippet:
        text += "\ndetection:\n  sel: {Image: x}\n  condition: sel"
    r = compile_rule(text)
    assert not r["ok"] and reason in r["reason"]


def test_compiler_version_is_set():
    assert COMPILER_VERSION and json.dumps(COMPILER_VERSION)
