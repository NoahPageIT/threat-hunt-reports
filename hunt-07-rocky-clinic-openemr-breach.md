# Threat Hunt Report — Rocky Clinic OpenEMR Breach

![Hunt 07 Attack Chain — Rocky Clinic OpenEMR Breach](https://raw.githubusercontent.com/NoahPageIT/threat-hunt-reports/main/hunt07_banner.png)

**Hunt ID:** HUNT 07
**Platform:** hunt.lognpacific.com (Microsoft Sentinel / KQL)
**Target Host:** `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`
**Investigation Window:** 2026-02-04 to 2026-02-14 UTC
**Report Status:** In Progress — Q03/Q04 pending resolution


---


## Executive Summary


A threat actor compromised Rocky Clinic's OpenEMR environment on host `rocky83` through an initial foothold via the web-facing OpenEMR application, followed by lateral privilege escalation, persistence via systemd services, patient data exfiltration, and active defense evasion. The actor operated primarily through Mullvad VPN exit nodes and pivoted to a C2 server at `20.62.27.80`. Evidence indicates targeted access to patient records via Docker-containerized MariaDB, data staging, and log tampering.
