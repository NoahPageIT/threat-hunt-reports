# Threat Hunt Report: LOG(N) Pacific Hunt 08 — Second Vector

> 🌐 **[View Interactive Report](https://noahpageit.github.io/threat-hunt-reports/ThreatHunt08_SecondVector.html)** — Full cyber aesthetic HTML version with MITRE ATT&CK mapping, KQL queries, and attack timeline

**Hunt Platform:** hunt.lognpacific.com
**Tenant:** lognpacific.org
**Hunt Window:** June 10–20, 2026 (UTC)
**Analyst:** Crypto
**Date Completed:** June 20, 2026

---

## Executive Summary

A Business Email Compromise (BEC) attack targeted finance user `m.smith@lognpacific.org` from external IP `103.69.224.136`. The attacker authenticated via legacy protocols that bypassed Conditional Access policies, established inbox forwarding rules, planted a malicious Power Automate flow, and abused the Microsoft Graph API to exfiltrate financial data. The attacker's IP footprint spanned **7 distinct log sources** across the Microsoft 365 and Entra ID stack.

---

## Attack Timeline

```
[June 11 ~03:30 UTC] Attacker authenticates to m.smith@lognpacific.org
                      from 103.69.224.136 via legacy auth (OWA/browser)
                      ConditionalAccessStatus = notApplied
                      AuthenticationProtocol = none

[June 11 ~03:32 UTC] Inbox forwarding rule created in OWA
                      Rule forwards mail to merovingian1337@proton.me
                      Logged in: OfficeActivity

[June 11 ~03:35 UTC] Power Automate flow created via Microsoft Flow Portal
                      Logged in: CloudAppEvents
                      AppId: 7ab7862c-4c57-491e-8a45-d52a7e023983

[June 11 ~12:41 UTC] Flow triggers Graph API call to read mail and
                      send exfiltration email
                      Destination IP: 20.150.129.194
                      Logged in: MicrosoftGraphActivityLogs

[June 11 ~12:41 UTC] Email exfiltrated to merovingian1337@proton.me
                      Subject: "FW: Updated Banking Details - ..."
                      Logged in: EmailEvents
```

---

## Key Indicators of Compromise

| Type | Value |
|------|-------|
| Attacker Source IP | `103.69.224.136` |
| Compromised Account | `m.smith@lognpacific.org` |
| Exfiltration Recipient | `merovingian1337@proton.me` |
| Exfiltration Destination IP | `20.150.129.194` |
| Malicious App AppId | `7ab7862c-4c57-491e-8a45-d52a7e023983` |
| Abused Cloud Service | Microsoft Power Automate |

---

## Log Source Coverage

| # | Table | Field | Records |
|---|-------|--------|---------|
| 1 | SigninLogs | IPAddress | 56 |
| 2 | AADNonInteractiveUserSignInLogs | IPAddress | token refresh events |
| 3 | AuditLogs | InitiatedBy | directory events |
| 4 | OfficeActivity | ClientIP | 29 |
| 5 | MicrosoftGraphActivityLogs | IPAddress | 146 |
| 6 | CloudAppEvents | IPAddress | 35 |
| 7 | EmailEvents | SenderIPv4 | 1 |

> **Hunt Lesson:** Initial triage focused on 5 tables and missed `AADNonInteractiveUserSignInLogs` and `AuditLogs`. Always run `search "IP"` across all workspace tables first.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
|--------|-----------|--------|
| Initial Access | T1078 — Valid Accounts | Compromised M365 credentials for m.smith |
| Defense Evasion | T1562 — Impair Defenses | Legacy auth bypassed Conditional Access (notApplied) |
| Persistence | T1137 — Office Application Startup | OWA inbox forwarding rule created |
| Collection | T1114.003 — Email Forwarding Rule | Mail forwarded to external address |
| Execution | T1651 — Cloud Administration Command | Power Automate flow created and triggered |
| Exfiltration | T1567 — Exfiltration Over Web Service | Graph API used to read and forward mail |

---

## Security Control Gaps

### 1. Conditional Access Not Enforced on Legacy Auth
All sign-ins returned `ConditionalAccessStatus = "notApplied"` with `AuthenticationProtocol = "none"`. Legacy auth falls outside CA policy scope unless explicitly blocked.

**Remediation:** Block legacy authentication via a CA policy using the "Block legacy authentication" template in Entra ID.

### 2. Power Automate Governance Gap
The attacker created a functional exfiltration flow using the compromised account's delegated permissions. No DLP policy blocked external mail sends.

**Remediation:** Implement Power Platform DLP policies restricting the Office 365 Mail connector from sending to external destinations.

### 3. Session Persistence After Password Reset
Active refresh tokens survive a password reset — an attacker retains access even after the password is changed.

**Remediation:** **Revoke sessions first** (`Revoke-AzureADUserAllRefreshToken`), then reset the password.

---

## KQL Queries

### Broad IP Pivot
```kql
search "103.69.224.136"
| where TimeGenerated between(datetime(2026-06-10T00:00:00Z) .. datetime(2026-06-20T23:59:59Z))
| summarize count() by $table
| order by count_ desc
```

### Sign-In Activity
```kql
SigninLogs
| where TimeGenerated between(datetime(2026-06-10T00:00:00Z) .. datetime(2026-06-20T23:59:59Z))
| where IPAddress == "103.69.224.136"
| project TimeGenerated, UserPrincipalName, AppDisplayName, ConditionalAccessStatus,
          AuthenticationProtocol, ResultType, ResultDescription
| order by TimeGenerated asc
```

### Power Automate Flow Creation
```kql
CloudAppEvents
| where TimeGenerated between(datetime(2026-06-10T00:00:00Z) .. datetime(2026-06-20T23:59:59Z))
| where IPAddress == "103.69.224.136"
| where Application == "Microsoft Power Automate"
| project TimeGenerated, AccountId, ActionType, Application, AppId, IPAddress
```

### Graph API Exfiltration Calls
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between(datetime(2026-06-10T00:00:00Z) .. datetime(2026-06-20T23:59:59Z))
| where IPAddress == "103.69.224.136"
| project TimeGenerated, UserId, RequestUri, ResponseStatusCode, IPAddress
| order by TimeGenerated asc
```

### Inbox Rule Creation
```kql
OfficeActivity
| where TimeGenerated between(datetime(2026-06-10T00:00:00Z) .. datetime(2026-06-20T23:59:59Z))
| where ClientIP startswith "103.69.224.136"
| where Operation contains "Rule"
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
```

### Exfiltrated Email
```kql
EmailEvents
| where TimeGenerated between(datetime(2026-06-10T00:00:00Z) .. datetime(2026-06-20T23:59:59Z))
| where SenderIPv4 == "103.69.224.136"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject,
          EmailDirection, DeliveryAction, SenderIPv4
```

---

## Containment Steps

1. **Revoke all active sessions** — `Revoke-AzureADUserAllRefreshToken` for m.smith
2. **Reset the account password** after sessions are revoked
3. **Delete the malicious inbox rule** in Exchange Online admin
4. **Disable the Power Automate flow** and audit all flows owned by m.smith
5. **Block the source IP** `103.69.224.136` in Entra ID Named Locations
6. **Enable MFA** on the account before re-enabling access
7. **Block legacy authentication** via Conditional Access

---

## Lessons Learned

- **Run the broad `search` pivot first.** Targeted union queries missed 2 of 7 sources. `search "IP"` across all tables should be the starting point.
- **Legacy auth is a persistent blind spot.** `ConditionalAccessStatus = "notApplied"` means the sign-in was completely outside CA policy scope.
- **Power Platform needs DLP governance.** Power Automate with delegated credentials bypasses most email DLP controls.
- **Session revocation is not automatic.** Password reset and session revocation are separate — containment requires both.

---

*Hunt: LOG(N) Pacific Hunt 08 — Second Vector | Platform: hunt.lognpacific.com*
