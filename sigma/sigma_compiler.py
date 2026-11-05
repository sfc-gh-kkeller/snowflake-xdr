"""Sigma -> Snowflake XDR rule compiler.

Deterministic (no LLM): parses a Sigma rule, maps its logsource to a CIM table and
its fields to CIM columns (or to the original vendor record in `_raw`), compiles
the detection to SQL, and synthesises canary fixtures - one positive per branch of
the condition (so a narrowed rule is caught) and a negative that breaks one clause.

Used in two places with the same code:
  * locally / CI:  python3 sigma/sigma_compiler.py <rule.yml>   (and tests)
  * in Snowflake:  SNOWFLAKE_XDR.REFERENCE.SIGMA_IMPORT imports this file from a stage

compile_rule(yaml_text) -> {"ok": bool, "reason": str, "rule": {...pack rule...}}
"""
import ipaddress
import itertools
import json
import re

import yaml

DB = "SNOWFLAKE_XDR"
CANARY_ENTITY = "{{entity}}"

# ---------------------------------------------------------------------------
# Logsource -> CIM table.  Each source: which table, a vendor filter, the CIM
# columns Sigma fields map to, where the canary marker goes, and the output
# projection every XDR rule must return (_time, user_name, src, dest, description).
# Unmapped fields read from the original record: GET_PATH(_raw, '<field>').
# ---------------------------------------------------------------------------
WIN_PROC = {
    "image": "process_path", "commandline": "process", "parentimage": "parent_process_path",
    "parentcommandline": "parent_process", "originalfilename": "original_file_name",
    "user": "user_name", "integritylevel": "process_integrity_level",
    "currentdirectory": "process_current_directory", "hashes": "process_hash",
    "processid": "process_id", "parentprocessid": "parent_process_id", "computer": "dest",
    "processguid": "process_guid", "parentprocessguid": "parent_process_guid",
}
REG_PATH = ("REPLACE(REPLACE(REPLACE(REPLACE(registry_path, 'HKEY_LOCAL_MACHINE', 'HKLM'), "
            "'HKEY_CURRENT_USER', 'HKCU'), 'HKEY_USERS', 'HKU'), 'HKEY_CLASSES_ROOT', 'HKCR')")
SOURCES = [
    {"id": "process_creation", "match": {"category": "process_creation"}, "table": "ENDPOINT_PROCESSES",
     "fields": WIN_PROC, "marker": "user_name", "src": "process_name", "detail": "process"},
    {"id": "registry", "match": {"category": ("registry_set", "registry_add", "registry_delete", "registry_event")},
     "table": "ENDPOINT_REGISTRY", "marker": "user_name", "src": "image", "detail": "registry_path",
     "fields": {"targetobject": REG_PATH, "details": "registry_value_data", "image": "image",
                "eventtype": "action", "user": "user_name", "computer": "dest"}},
    {"id": "file", "match": {"category": ("file_event", "file_creation", "file_delete", "file_access", "file_rename")},
     "table": "ENDPOINT_FILESYSTEM", "marker": "user_name", "src": "image", "detail": "file_path",
     "fields": {"targetfilename": "file_path", "image": "image", "user": "user_name", "computer": "dest"}},
    {"id": "network", "match": {"category": "network_connection"}, "table": "NETWORK_TRAFFIC",
     "marker": "src", "user": "src", "src": "src", "detail": "dest_ip",
     "fields": {"destinationip": "dest_ip", "destinationport": "dest_port", "sourceip": "src_ip",
                "sourceport": "src_port", "destinationhostname": "dest", "protocol": "transport",
                "initiated": "direction", "computer": "src"}},
    {"id": "dns", "match": {"category": "dns_query"}, "table": "DNS_ACTIVITY",
     "marker": "src", "user": "src", "src": "src", "detail": "query",
     "fields": {"queryname": "query", "queryresults": "answer", "computer": "src"}},
    {"id": "proxy", "match": {"category": "proxy"}, "table": "WEB_ACTIVITY",
     "marker": "src", "user": "src", "src": "src", "detail": "url",
     "fields": {"c-uri": "url", "c-uri-query": "uri_query", "c-useragent": "http_user_agent",
                "cs-method": "http_method", "sc-status": "status", "cs-host": "dest", "r-dns": "dest",
                "cs-referrer": "http_referrer", "c-ip": "src"}},
    # Cloud / SaaS: the original vendor record is kept in _raw, so Sigma's native field names apply
    {"id": "aws", "match": {"product": "aws", "service": "cloudtrail"}, "table": "CLOUD_API", "vendor": "aws",
     "marker": "user_name", "src": "src", "detail": "action", "raw": True},
    {"id": "okta", "match": {"product": "okta"}, "table": "CLOUD_API", "vendor": "Okta",
     "marker": "user_name", "src": "src", "detail": "action", "raw": True,
     "aliases": {"eventtype": "eventType", "displaymessage": "displayMessage"}},
    {"id": "azure_activity", "match": {"product": "azure", "service": "activitylogs"}, "table": "CLOUD_API",
     "vendor": "azure", "marker": "user_name", "src": "src", "detail": "action", "raw": True, "props": True},
    {"id": "azure_audit", "match": {"product": "azure", "service": "auditlogs"}, "table": "CLOUD_API",
     "vendor": "Entra ID", "marker": "user_name", "src": "src", "detail": "action", "raw": True, "props": True},
    {"id": "azure_signin", "match": {"product": "azure", "service": ("signinlogs", "riskdetection")},
     "table": "AUTHENTICATION", "vendor": "Entra ID", "marker": "user_name", "src": "src",
     "detail": "signature", "raw": True, "props": True},
]
LEVEL_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
TACTICS = {
    "reconnaissance": "TA0043", "resource_development": "TA0042", "initial_access": "TA0001",
    "execution": "TA0002", "persistence": "TA0003", "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005", "credential_access": "TA0006", "discovery": "TA0007",
    "lateral_movement": "TA0008", "collection": "TA0009", "command_and_control": "TA0011",
    "exfiltration": "TA0010", "impact": "TA0040",
}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "cidr", "windash", "exists",
                  "gt", "gte", "lt", "lte", "cased", "i", "m", "s"}
MAX_BRANCHES = 6
COMPILER_VERSION = "3"   # bump when compiled SQL/fixtures change: forces re-import of every rule
MAX_SQL = 10000          # CUSTOM_RULES.CODE length


class Unsupported(Exception):
    pass


# ---------------------------------------------------------------------------
# Logsource and field resolution
# ---------------------------------------------------------------------------
def resolve_source(logsource):
    ls = {k: str(v).lower() for k, v in (logsource or {}).items() if k in ("product", "category", "service")}
    for src in SOURCES:
        ok = True
        for k, want in src["match"].items():
            want = want if isinstance(want, tuple) else (want,)
            if ls.get(k) not in want:
                ok = False
        # Endpoint categories are product-agnostic (windows / linux / macos)
        if ok and not src.get("raw") and ls.get("product") not in (None, "windows", "linux", "macos"):
            ok = False
        if ok:
            return src
    raise Unsupported(f"logsource {ls} is not mapped to a CIM table")


def raw_path(field):
    parts = field.split(".")
    if all(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", p) for p in parts):
        return ".".join(parts)
    if re.match(r"^[A-Za-z0-9_\-]+$", field):
        return '"' + field + '"'
    raise Unsupported(f"field name {field!r}")


def field_expr(src, field):
    """SQL expression (VARCHAR) for a Sigma field on this source; also the fixture location."""
    key = field.lower()
    if key in (src.get("fields") or {}):
        col = src["fields"][key]
        return f"{col}::VARCHAR", ("col", col if col != REG_PATH else "registry_path")
    name = (src.get("aliases") or {}).get(key, field)
    p = raw_path(name)
    if src.get("props"):
        return (f"COALESCE(GET_PATH(_raw, '{p}'), GET_PATH(_raw, 'properties.{p}'))::VARCHAR",
                ("raw", "properties." + name))
    return f"GET_PATH(_raw, '{p}')::VARCHAR", ("raw", name)


# ---------------------------------------------------------------------------
# Values -> SQL
# ---------------------------------------------------------------------------
def sql_lit(s):
    return "'" + str(s).replace("\\", "\\\\").replace("'", "''") + "'"


def sigma_tokens(value):
    """Split a Sigma string into literal chars and wildcards ('*' / '?'), honouring \\ escapes."""
    out, i, s = [], 0, str(value)
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(("lit", s[i + 1]))
            i += 2
            continue
        out.append(("wild", c) if c in "*?" else ("lit", c))
        i += 1
    return out


def like_pattern(tokens):
    p = ""
    for kind, c in tokens:
        if kind == "wild":
            p += "%" if c == "*" else "_"
        else:
            p += ("!" + c) if c in "%_!" else c
    return p


def windash_variants(v):
    s = str(v)
    if not re.search(r"(^|\s)-", s):
        return [s]
    out = []
    for d in ["-", "/", "\u2013", "\u2014", "\u2015"]:
        out.append(re.sub(r"(^|\s)-", lambda m: m.group(1) + d, s))
    return out


class Atom:
    """One field test. SQL and Python evaluation share these semantics."""

    def __init__(self, field, op, value, src, cased=False):
        self.field, self.op, self.value, self.cased = field, op, value, cased
        self.expr, self.loc = field_expr(src, field) if field else (None, None)
        self.src = src

    def key(self):
        return (self.field or "", self.op, str(self.value))

    # -- SQL ---------------------------------------------------------------
    def sql(self):
        e, v = self.expr, self.value
        if self.field is None:  # keyword search
            hay = keyword_haystack(self.src)
            return f"COALESCE(CONTAINS(LOWER({hay}), {sql_lit(str(v).lower())}), FALSE)"
        if self.op == "null":
            return f"({e} IS NULL OR {e} = '')"
        if self.op == "exists":
            return f"({e} IS NOT NULL)" if v else f"({e} IS NULL)"
        if self.op in ("gt", "gte", "lt", "lte"):
            sym = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[self.op]
            return f"COALESCE(TRY_TO_DOUBLE({e}) {sym} {float(v)}, FALSE)"
        if self.op == "re":
            flags = "c" if self.cased else "i"
            return f"COALESCE(REGEXP_LIKE({e}, {sql_lit('.*(' + snowflake_regex(v) + ').*')}, '{flags}s'), FALSE)"
        if self.op == "cidr":
            net = ipaddress.ip_network(str(v), strict=False)
            if net.version != 4:
                raise Unsupported("IPv6 cidr")
            return (f"COALESCE(TRY_CAST(PARSE_IP({e} || '/32', 'INET', 1):ipv4::VARCHAR AS NUMBER) "
                    f"BETWEEN {int(net.network_address)} AND {int(net.broadcast_address)}, FALSE)")
        toks = sigma_tokens(v)
        pat = like_pattern(toks)
        pat = {"contains": "%" + pat + "%", "startswith": pat + "%", "endswith": "%" + pat}.get(self.op, pat)
        like = "LIKE" if self.cased else "ILIKE"
        return f"COALESCE({e} {like} {sql_lit(pat)} ESCAPE '!', FALSE)"

    # -- Python (fixture verification) --------------------------------------
    def eval(self, row):
        if self.field is None:
            hay = " ".join(str(x) for x in flatten_values(row)).lower()
            return str(self.value).lower() in hay
        x = lookup(row, self.loc)
        if self.op == "null":
            return x is None or x == ""
        if self.op == "exists":
            return (x is not None) == bool(self.value)
        if x is None:
            return False
        x = str(x)
        if self.loc[0] == "col" and self.loc[1] == "registry_path":
            for a, b in (("HKEY_LOCAL_MACHINE", "HKLM"), ("HKEY_CURRENT_USER", "HKCU"),
                         ("HKEY_USERS", "HKU"), ("HKEY_CLASSES_ROOT", "HKCR")):
                x = x.replace(a, b)
        if self.op in ("gt", "gte", "lt", "lte"):
            try:
                f = float(x)
            except ValueError:
                return False
            return {"gt": f > self.value, "gte": f >= self.value, "lt": f < self.value, "lte": f <= self.value}[self.op]
        if self.op == "re":
            return re.search(str(self.value), x, 0 if self.cased else re.I | re.S) is not None
        if self.op == "cidr":
            try:
                return ipaddress.ip_address(x) in ipaddress.ip_network(str(self.value), strict=False)
            except ValueError:
                return False
        rx = "".join(".*" if (k == "wild" and c == "*") else "." if k == "wild" else re.escape(c)
                     for k, c in sigma_tokens(self.value))
        rx = {"contains": ".*" + rx + ".*", "startswith": rx + ".*", "endswith": ".*" + rx}.get(self.op, rx)
        return re.fullmatch(rx, x, re.S if self.cased else re.I | re.S) is not None

    # -- fixture value -------------------------------------------------------
    def example(self):
        """A concrete string satisfying this atom on its own (None when it must be absent)."""
        if self.op == "null":
            return None
        if self.op == "exists":
            return "present" if self.value else None
        if self.op in ("gt", "gte"):
            return str(int(self.value) + 1)
        if self.op in ("lt", "lte"):
            return str(int(self.value) - 1)
        if self.op == "cidr":
            net = ipaddress.ip_network(str(self.value), strict=False)
            return str(net.network_address + (1 if net.num_addresses > 2 else 0))
        if self.op == "re":
            raise Unsupported("regex-only branch: cannot synthesise a fixture")
        core = "".join(("x" if c == "*" else "a") if k == "wild" else c for k, c in sigma_tokens(self.value))
        return {"contains": "xx " + core + " xx", "startswith": core + " xx", "endswith": "xx " + core}.get(self.op, core)


def snowflake_regex(v):
    """Sigma regexes are PCRE; Snowflake's engine has no non-capturing groups, lookarounds, lazy
    quantifiers or backreferences. Translate what is equivalent, reject the rest."""
    r = str(v)
    r = re.sub(r"^\(\?[is]+\)", "", r)          # leading inline flags: we match case-insensitively already
    if re.search(r"\(\?[=!<]|\(\?[a-z]+[:)]|\\[1-9]|[*+?}]\?|\\[pPkK]\{?", r.replace("(?:", "(")):
        raise Unsupported("regex uses PCRE-only syntax (lookaround/lazy/backreference)")
    return r.replace("(?:", "(")


def keyword_haystack(src):
    t = src["table"]
    cols = {"ENDPOINT_PROCESSES": ["process", "process_path", "parent_process"],
            "ENDPOINT_REGISTRY": ["registry_path", "registry_value_data"],
            "ENDPOINT_FILESYSTEM": ["file_path"],
            "DNS_ACTIVITY": ["query"], "WEB_ACTIVITY": ["url", "http_user_agent"]}.get(t, [])
    parts = [f"COALESCE({c}::VARCHAR, '')" for c in cols] + ["COALESCE(_raw::VARCHAR, '')"]
    return " || ' ' || ".join(parts)


def flatten_values(v):
    if isinstance(v, dict):
        for x in v.values():
            yield from flatten_values(x)
    elif isinstance(v, list):
        for x in v:
            yield from flatten_values(x)
    elif v is not None:
        yield v


def lookup(row, loc):
    kind, name = loc
    if kind == "col":
        return row.get(name)
    cur = row.get("_raw") or {}
    for part in name.split("."):
        if not isinstance(cur, dict) or part not in cur:
            cur = None
            break
        cur = cur[part]
    if cur is None and name.startswith("properties."):
        return lookup(row, ("raw", name[len("properties."):]))
    return None if isinstance(cur, (dict, list)) else cur


def assign(row, loc, value):
    kind, name = loc
    if kind == "col":
        row[name] = value
        return
    cur = row.setdefault("_raw", {})
    parts = name.split(".")
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
        if not isinstance(cur, dict):
            raise Unsupported(f"conflicting fixture path {name}")
    cur[parts[-1]] = value


# ---------------------------------------------------------------------------
# Detection tree: ("and"|"or", [children]), ("not", child), Atom, True/False
# ---------------------------------------------------------------------------
def field_spec(key, value, src):
    parts = key.split("|")
    field, mods = parts[0], [m.lower() for m in parts[1:]]
    for m in mods:
        if m not in SUPPORTED_MODS:
            raise Unsupported(f"modifier |{m}")
    cased = "cased" in mods
    op = next((m for m in mods if m in ("contains", "startswith", "endswith", "re", "cidr", "exists",
                                         "gt", "gte", "lt", "lte")), "eq")
    values = value if isinstance(value, list) else [value]
    atoms = []
    for v in values:
        if v is None:
            atoms.append(Atom(field, "null", None, src))
            continue
        if op == "exists":
            atoms.append(Atom(field, "exists", bool(v), src))
            continue
        if isinstance(v, bool):
            v = str(v).lower()
        if op in ("gt", "gte", "lt", "lte"):
            atoms.append(Atom(field, op, float(v), src))
            continue
        if op == "eq" and str(v) == "":
            atoms.append(Atom(field, "null", None, src))
            continue
        variants = windash_variants(v) if "windash" in mods else [str(v)]
        alts = [Atom(field, op, x, src, cased) for x in variants]
        atoms.append(alts[0] if len(alts) == 1 else ("or", alts))
    return ("and" if "all" in mods else "or", atoms) if len(atoms) > 1 else atoms[0]


def selection(value, src):
    if isinstance(value, dict):
        if not value:
            raise Unsupported("empty selection")
        return ("and", [field_spec(k, v, src) for k, v in value.items()])
    if isinstance(value, list):
        if all(isinstance(x, dict) for x in value):
            return ("or", [selection(x, src) for x in value])
        if all(not isinstance(x, (dict, list)) for x in value):
            return ("or", [Atom(None, "contains", str(x), src) for x in value])
    if isinstance(value, (str, int)):
        return Atom(None, "contains", str(value), src)
    raise Unsupported("selection shape")


TOKEN_RE = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[A-Za-z0-9_*]+)", re.I)


def parse_condition(cond, sels):
    if "|" in cond:
        raise Unsupported("aggregation condition (count/near)")
    toks, pos = [], 0
    while pos < len(cond):
        m = TOKEN_RE.match(cond, pos)
        if not m:
            if cond[pos:].strip() == "":
                break
            raise Unsupported(f"condition syntax near {cond[pos:pos + 20]!r}")
        toks.append(m.group(1))
        pos = m.end()
    toks = [t.lower() if t.lower() in ("and", "or", "not", "(", ")", "1 of", "all of") else t for t in toks]
    it = {"i": 0}

    def peek():
        return toks[it["i"]] if it["i"] < len(toks) else None

    def take():
        t = peek()
        it["i"] += 1
        return t

    def names(pat):
        if pat == "them":
            return [n for n in sels if not n.startswith("_")]
        rx = re.compile("^" + re.escape(pat).replace("\\*", ".*") + "$")
        found = [n for n in sels if rx.match(n)]
        if not found:
            raise Unsupported(f"no selection matches {pat}")
        return found

    def primary():
        t = take()
        if t == "(":
            e = expr()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return e
        if t == "not":
            return ("not", primary())
        if t in ("1 of", "all of"):
            ns = names(take())
            return ("or" if t == "1 of" else "and", [sels[n] for n in ns])
        if t in sels:
            return sels[t]
        raise Unsupported(f"unknown identifier {t}")

    def term():
        e = [primary()]
        while peek() == "and":
            take()
            e.append(primary())
        return e[0] if len(e) == 1 else ("and", e)

    def expr():
        e = [term()]
        while peek() == "or":
            take()
            e.append(term())
        return e[0] if len(e) == 1 else ("or", e)

    out = expr()
    if peek() is not None:
        raise Unsupported(f"trailing condition tokens: {toks[it['i']:]}")
    return out


def to_sql(n):
    if isinstance(n, Atom):
        return n.sql()
    if n[0] == "not":
        return "NOT (" + to_sql(n[1]) + ")"
    joiner = " AND " if n[0] == "and" else " OR "
    return "(" + joiner.join(to_sql(c) for c in n[1]) + ")"


def evaluate(n, row):
    if isinstance(n, Atom):
        return n.eval(row)
    if n[0] == "not":
        return not evaluate(n[1], row)
    vals = (evaluate(c, row) for c in n[1])
    return all(vals) if n[0] == "and" else any(vals)


# ---------------------------------------------------------------------------
# Fixture synthesis: DNF branches -> one positive row each; negative breaks one atom
# ---------------------------------------------------------------------------
def nnf(n, neg=False):
    if isinstance(n, Atom):
        return ("lit", n, neg)
    if n[0] == "not":
        return nnf(n[1], not neg)
    op = n[0] if not neg else ("or" if n[0] == "and" else "and")
    return (op, [nnf(c, neg) for c in n[1]])


def dnf(n, limit=64):
    """List of clauses; each clause is a list of (atom, negated)."""
    if n[0] == "lit":
        return [[(n[1], n[2])]]
    parts = [dnf(c, limit) for c in n[1]]
    if n[0] == "or":
        out = [c for p in parts for c in p]
    else:
        out = [[]]
        for p in parts:
            out = [a + b for a, b in itertools.product(out, p)][:limit * 4]
    return out[:limit]


def build_row(src, clause, neutral=False):
    row = {}
    groups = {}
    for atom, negated in clause:
        if atom.field is None:
            if not negated:
                groups.setdefault(("kw",), []).append(atom)
            continue
        groups.setdefault(atom.loc, []).append((atom, negated))
    for loc, items in groups.items():
        if loc == ("kw",):
            # Keywords: put them in the main detail field / raw text
            text = " ".join(a.example() for a in items)
            target = ("col", src["detail"]) if not src.get("raw") else ("raw", "message")
            assign(row, target, text)
            continue
        pos = [a for a, ng in items if not ng]
        if not pos:
            if neutral:  # e.g. 'not CommandLine: null' needs the field present but not matching any filter
                assign(row, loc, "xdrneutral")
            continue  # only negated tests: leave the field absent
        eqs = [a for a in pos if a.op not in ("contains", "startswith", "endswith")]
        if eqs:
            val = eqs[0].example()
        else:
            starts = [a.example().replace(" xx", "") for a in pos if a.op == "startswith"]
            ends = [a.example().replace("xx ", "") for a in pos if a.op == "endswith"]
            mids = [str(a.value) for a in pos if a.op == "contains"]
            mids = ["".join(("x" if c == "*" else "a") if k == "wild" else c for k, c in sigma_tokens(m)) for m in mids]
            # Keep each value's own whitespace (' -r' must stay ' -r'); separators never break a substring
            val = (starts[0] if starts else "") + "".join(" " + m + " " for m in mids) + (ends[0] if ends else "")
        assign(row, loc, val)
    return row


def entity_row(src, row):
    """Canary marker: the column the XDR runner and canary check use (user_name/src/dest)."""
    carrier = src["marker"]
    if row.get(carrier) is not None:
        carrier = next(c for c in ("dest", "src", "user_name") if row.get(c) is None)
    row[carrier] = CANARY_ENTITY if carrier != "dest" else "host-" + CANARY_ENTITY
    if src.get("vendor"):
        row["vendor_product"] = src["vendor"]
    if src["table"] in ("CLOUD_API",):
        row.setdefault("result", "success")
    return row


def synthesise(src, tree):
    branches = dnf(nnf(tree))
    positives, seen = [], set()
    for clause in branches:
        row = None
        for neutral in (False, True):
            try:
                cand = entity_row(src, build_row(src, clause, neutral))
            except Unsupported:
                continue
            if evaluate(tree, cand):
                row = cand
                break
        if row is None:
            continue
        k = json.dumps(row, sort_keys=True)
        if k in seen:
            continue
        seen.add(k)
        positives.append(row)
        if len(positives) >= MAX_BRANCHES:
            break
    if not positives:
        raise Unsupported("could not synthesise a matching fixture (regex-only or contradictory)")
    # Negative: break one positive test of the first branch so the rule must not fire
    negative = None
    base = positives[0]
    for atom, negated in branches[0]:
        if negated or atom.field is None:
            continue
        cand = json.loads(json.dumps(base))
        assign(cand, atom.loc, "xdrbenign")
        if not evaluate(tree, cand):
            negative = cand
            break
    out = {"positive": [{"table": src["table"], "row": r, "count": 1, "offset_minutes": 1, "branch": i + 1}
                         for i, r in enumerate(positives)]}
    if negative:
        out["negative"] = [{"table": src["table"], "row": negative, "count": 1, "offset_minutes": 1}]
    return out, len(branches)


# ---------------------------------------------------------------------------
# Rule assembly
# ---------------------------------------------------------------------------
def attack_tags(tags):
    tech, tactic = None, None
    for t in tags or []:
        t = str(t).lower()
        m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", t)
        if m and not tech:
            tech = m.group(1).upper()
        if t.startswith("attack.") and t[7:].replace("-", "_") in TACTICS and not tactic:
            tactic = TACTICS[t[7:].replace("-", "_")]
    return tech, tactic


def projection(src, title):
    user = src.get("user", "user_name")
    t = sql_lit(title[:120] + ": ")
    return (f"SELECT _time, {user}::VARCHAR AS user_name, {src['src']}::VARCHAR AS src, dest::VARCHAR AS dest,\n"
            f"       {t} || LEFT(COALESCE({src['detail']}::VARCHAR, ''), 300) AS description\n"
            f"FROM {DB}.RAW_LOGS.{src['table']}\n")


def compile_rule(text, rule_id=None):
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return {"ok": False, "reason": "yaml: " + str(e)[:200]}
    if not isinstance(doc, dict) or "detection" not in doc:
        return {"ok": False, "reason": "not a Sigma rule"}
    meta = {"sigma_id": doc.get("id"), "title": doc.get("title"), "status": doc.get("status"),
            "level": doc.get("level"), "logsource": doc.get("logsource")}
    try:
        if doc.get("correlation") or doc.get("type") == "correlation":
            raise Unsupported("correlation rule")
        src = resolve_source(doc.get("logsource"))
        det = dict(doc["detection"])
        cond = det.pop("condition", None)
        det.pop("timeframe", None)
        if isinstance(cond, list):
            cond = " or ".join(f"({c})" for c in cond)
        if not cond:
            raise Unsupported("no condition")
        sels = {k: selection(v, src) for k, v in det.items()}
        tree = parse_condition(str(cond), sels)
        where = to_sql(tree)
        fixtures, n_branches = synthesise(src, tree)
    except Unsupported as e:
        return {"ok": False, "reason": str(e), **meta}
    except (ValueError, TypeError, KeyError) as e:
        return {"ok": False, "reason": f"compile error: {e}"[:300], **meta}
    title = str(doc.get("title") or "Sigma rule")
    vendor_filter = f"WHERE vendor_product ILIKE {sql_lit(src['vendor'])}\n  AND " if src.get("vendor") else "WHERE "
    sql = projection(src, title) + vendor_filter + where
    if len(sql) > MAX_SQL:
        return {"ok": False, "reason": f"too large: compiled SQL is {len(sql)} chars (max {MAX_SQL})", **meta}
    tech, tactic = attack_tags(doc.get("tags"))
    fps = doc.get("falsepositives")
    rule = {
        "id": rule_id, "name": title[:200],
        "description": (str(doc.get("description") or "").strip()
                        + f" (Sigma {doc.get('id')}, author: {doc.get('author', 'unknown')})")[:2000],
        "severity": LEVEL_SEVERITY.get(str(doc.get("level", "medium")).lower(), 3),
        "tactic": tactic, "technique": tech, "table": src["table"], "vendor_product": src.get("vendor"),
        "threshold": 1, "window_minutes": 60, "lookback_minutes": 240, "expected_latency_seconds": 600,
        "false_positives": ("; ".join(str(x) for x in fps) if isinstance(fps, list) else str(fps or ""))[:1900] or None,
        "references": [str(x) for x in (doc.get("references") or [])][:10],
        "fixtures": fixtures, "sql": sql,
    }
    return {"ok": True, "reason": "compiled", "rule": rule, "source_id": src["id"],
            "branches": n_branches, "fixture_branches": len(fixtures["positive"]), **meta}


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        r = compile_rule(open(path).read(), "SIG-00001")
        print(json.dumps(r, indent=2, default=str))
