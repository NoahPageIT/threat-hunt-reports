# Threat Hunt Report — Rocky Clinic OpenEMR Breach
**Hunt ID:** HUNT 07
**Platform:** hunt.lognpacific.com (Microsoft Sentinel / KQL)
**Target Host:** `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`
**Investigation Window:** 2026-02-04 to 2026-02-14 UTC
**Report Status:** In Progress — Q03/Q04 pending resolution

---

## Executive Summary

A threat actor compromised Rocky Clinic's OpenEMR environment on host `rocky83` through an initial foothold via the web-facing OpenEMR application, followed by lateral privilege escalation, persistence via systemd services, patient data exfiltration, and active defense evasion. The actor operated primarily through Mullvad VPN exit nodes and pivoted to a C2 server at `20.62.27.80`. Evidence indicates targeted access to patient records via Docker-containerized MariaDB, data staging, and log tampering.

---

## 1. Environment

| Field | Value |
|---|---|
| Host | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| OS | RockyLinux |
| Container runtime | Docker |
| Primary compromised account | `it.admin` |
| Initial breach account | `r0ckyyy335` (OpenEMR app account) |

---

## 2. Confirmed Flags

| Flag | Answer | Description |
|---|---|---|
| Q00 | `ready to hunt` | Hunt initialized |
| Q01 | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` | Target hostname |
| Q02 | `docker` | Container runtime on target |
| Q05 | `it.admin` | Account used in suspicious remote logon |
| Q06 | `4` | Count of suspicious sessions / related metric |
| Q07 | `RockyLinux` | OS of target host |

---

## 3. Attack Timeline

### Phase 1 — Initial Access (2026-02-05)

- **2026-02-05 00:16 UTC** — First login by `r0ckyyy335` from `68.53.47.150`, an IP shared across multiple accounts (r0ckyyy335, it.admin, it.infra, helpdesk.tier1, helpdesk.tier2), indicating potential credential stuffing or shared attacker infrastructure.
- `r0ckyyy335` is an OpenEMR application-level account, providing the actor a foothold within the containerized EMR environment.

### Phase 2 — Reconnaissance & Privilege Escalation (2026-02-09 to 2026-02-10)

| Timestamp (UTC) | Source IP | POSIX Session | Notes |
|---|---|---|---|
| 2026-02-09 20:02 | 149.34.244.158 | 24468 | First Mullvad logon |
| 2026-02-10 19:52 | 146.70.202.116 | 7770 | |
| 2026-02-10 19:53 | 146.70.202.116 | 8194 | `sudo -i` at 19:54 — privilege escalation |

The actor ran `sudo -u system setup.sh` to install custom binaries: `check_disk`, `net_monitor`, `proc_count`, `mem_check`, `uptime_log`.

### Phase 3 — Persistence Installation (2026-02-11 04:13–04:16 UTC)

| Timestamp (UTC) | Source IP | POSIX Session | Activity |
|---|---|---|---|
| 2026-02-11 04:13 | 146.70.202.117 | 6866 | `vim svc_integration_jobs` |
| 2026-02-11 04:34 | 146.70.202.115 | 11971 | `systemctl restart` — activating persistence |

**Persistence mechanism:** `integration-monitor.service` systemd service installed 2026-02-11 04:13–04:16 UTC.

### Phase 4 — C2 Establishment (2026-02-11 04:46–05:02 UTC)

| Timestamp (UTC) | Source IP | POSIX Session | Activity |
|---|---|---|---|
| 2026-02-11 04:46 | 146.70.202.116 | 14757 | `nc 20.62.27.80` + Python reverse shell; SSH as `streetrack` |
| 2026-02-11 05:02 | 146.70.202.117 | 19517 | `nc 20.62.27.80` |

**C2:** `20.62.27.80:443` | **Operator:** `streetrack`

### Phase 5 — Defense Evasion (2026-02-11 15:15–16:12 UTC)

- `sudo truncate -s 0 /var/log/wtmp` — wipes login history
- `sed -i` targeting `/var/log/secure` and `/var/log/messages`
- `vim integration-monitor` + Python reverse shell (session 16144)

### Phase 6 — Data Exfiltration (2026-02-12 to 2026-02-13)

- Session 7642: `nc`, `scp`, `rsync`, `tar` — data staging/transfer
- `openemr_audit_export.sh` and `openemr_export_docs.sh` scheduled via cron
- Staged: `/var/log/openemr/audit/openemr_audit.ndjson`, `/var/log/openemr/doc_exports/`
- Patient data queried via `docker exec` into `openemr-mariadb`

---

## 4. Attacker Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `149.34.244.158` | Mullvad VPN | 1 logon |
| `146.70.202.116` | Mullvad VPN | 5 logons — primary operator IP |
| `146.70.202.117` | Mullvad VPN | 3 logons |
| `146.70.202.115` | Mullvad VPN | 1 logon |
| `149.22.80.122` | Mullvad VPN | 2 logons |
| `68.53.47.150` | Shared attacker IP | Across r0ckyyy335, it.admin, it.infra, helpdesk accounts |
| `20.62.27.80:443` | C2 server | Python reverse shells; SSH as `streetrack` |

---

## 5. TTPs (MITRE ATT&CK Mapping)

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | OpenEMR web app via `r0ckyyy335` |
| Persistence | T1543.002 — Systemd Service | `integration-monitor.service` |
| Privilege Escalation | T1548.003 — Sudo | `sudo -i`, `sudo -u system setup.sh` |
| Defense Evasion | T1070.002 — Clear Linux Logs | `truncate /var/log/wtmp`, `sed -i` on secure/messages |
| Discovery | T1033 — System Owner/User Discovery | `who`, `ps aux`, `w` |
| C2 | T1059.006 — Python | Python reverse shells to `20.62.27.80:443` |
| C2 | T1071.001 — Web Protocols | C2 over port 443 |
| Lateral Movement | T1021.004 — SSH | SSH to `streetrack@20.62.27.80` |
| Exfiltration | T1020 — Automated Exfiltration | Cron-scheduled export scripts |
| Exfiltration | T1048 — Exfil Over Alt Protocol | `nc`, `scp`, `rsync` to C2 |
| Collection | T1005 — Data from Local System | OpenEMR audit logs + doc exports |

---

## 6. Open Investigation Items

### Q03 — First Recon Command PID (UNSOLVED)

First command in a Mullvad-anchored `it.admin` session checking who else is logged in. Hint: "Operators check who else is on the box before doing anything loud."

**PIDs tried (all wrong):** 55807, 6155, 6910, 9006, 24429, 24659, 55787, 55850, 55043, 16050, 16051, 16053, 16054, 16048, 9067, 106774, 15600, 15955, 55076, 24469, 7307, 16047

### Q04 — SHA256 of Last Interactive Command Binary (UNSOLVED)

SHA256 of the binary behind the last interactive command before session cleanup in the Q03 session.

**SHA256s tried (all wrong):**
- `0c6b3ffbfb9eeb38d5858da069686886b8e84f39706f15b7efb751e4195b2754` (ls)
- `68c3982460cd8c08f2d3c50bf9ad7c116c43b4f4a577c2af5523c8ec10be44e7` (ping)

### Q08 — Gated behind Q03/Q04

---

## 7. IOCs

| Type | Value |
|---|---|
| C2 | `20.62.27.80:443` |
| Mullvad exits | `149.34.244.158`, `146.70.202.115/116/117`, `149.22.80.122` |
| Shared attacker IP | `68.53.47.150` |
| Persistence unit | `integration-monitor.service` |
| Implant binaries | `check_disk`, `net_monitor`, `proc_count`, `mem_check`, `uptime_log` |
| Exfil scripts | `openemr_audit_export.sh`, `openemr_export_docs.sh` |
| C2 operator | `streetrack` (SSH user on `20.62.27.80`) |
| Initial account | `r0ckyyy335` |
| Hijacked account | `it.admin` |

---

## 8. Remediation

1. Isolate `rocky83` pending forensic image
2. Rotate all credentials (it.admin, it.infra, helpdesk accounts, r0ckyyy335)
3. Remove `integration-monitor.service` and implant binaries
4. Block `20.62.27.80` and Mullvad ranges at perimeter
5. Assess PHI exposure for HIPAA breach notification
6. Recover tampered logs from SIEM ingestion prior to 2026-02-11 15:15 UTC
7. Audit and purge malicious cron jobs
8. Patch OpenEMR initial access vector

---

## 9. KQL Queries

```kql
// Suspicious it.admin Mullvad logons
DeviceLogonEvents
| where DeviceName == "rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where AccountName == "it.admin"
| where RemoteIP in ("149.34.244.158","146.70.202.116","146.70.202.117","146.70.202.115","149.22.80.122")
| project Timestamp, RemoteIP, LogonType, AdditionalFields
| order by Timestamp asc
```

```kql
// Process activity in a POSIX session
DeviceProcessEvents
| where DeviceName == "rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where AdditionalFields has "<SESSION_ID>"
| project Timestamp, ProcessId, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

```kql
// C2 connections
DeviceNetworkEvents
| where DeviceName == "rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where RemoteIP == "20.62.27.80"
| project Timestamp, InitiatingProcessId, InitiatingProcessFileName, RemotePort
| order by Timestamp asc
```

```kql
// Log tampering
DeviceProcessEvents
| where DeviceName == "rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where ProcessCommandLine has_any ("truncate","sed -i",">/var/log")
| project Timestamp, ProcessId, ProcessCommandLine, AccountName
```

---

*LOG(N) Pacific HUNT 07 | hunt.lognpacific.com | Analyst: Crypto | Status: In Progress*
