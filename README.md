# Enterprise SOC L2 Threat Detection & Incident Investigation Lab

![Splunk](https://img.shields.io/badge/Splunk-Enterprise%20Security-black?style=flat-square&logo=splunk&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Aligned-red?style=flat-square)
![Log Sources](https://img.shields.io/badge/Log%20Sources-11%20Types-blue?style=flat-square)
![SPL Detections](https://img.shields.io/badge/SPL%20Detections-10%20Use%20Cases-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Lab%20Complete-brightgreen?style=flat-square)
![Purpose](https://img.shields.io/badge/Purpose-Portfolio%20%26%20Learning-purple?style=flat-square)

> **Authenticity Statement:** This is a hands-on SOC learning and portfolio project built using entirely synthetic data and simulated security scenarios.
> It does not represent a real production environment, a professional SOC engagement, or any real-world breach.
> All users, hosts, IP addresses, events, and alerts are synthetic or simulated.

---

## Overview

A Splunk-based SOC L1-to-L2 investigation lab that simulates a realistic enterprise threat detection and incident response workflow.

The lab begins with a single visible alert — **Multiple Failed Authentication Attempts** — and requires the analyst to pivot across 11 synthetic telemetry sources to uncover a multi-stage attack chain covering credential brute-force, endpoint compromise, C2-style beaconing, privilege escalation, lateral movement, and simulated data exfiltration.

The complete lab corpus contains **thousands of synthetic security events** across authentication, endpoint, network, email, EDR-style, threat intelligence, asset, and identity telemetry. The public repository contains representative samples only.

---

## What This Lab Covers

| Area | Skills Practiced |
|---|---|
| **Alert Triage** | L1 alert review, severity assessment, initial scoping |
| **Authentication Analysis** | Brute-force detection, success-after-failure correlation |
| **Endpoint Investigation** | Sysmon process chains, PowerShell indicators, LOLBin patterns |
| **Network Analysis** | Firewall traffic review, beaconing heuristics, outbound transfer |
| **Identity & Asset Context** | Privilege analysis, asset criticality, user enrichment |
| **Threat Intelligence** | IOC matching via lookup, indicator-aware pivoting |
| **Email Security** | Phishing-related email correlation |
| **Detection Engineering** | SPL use case authoring, tuning, and documentation |
| **Threat Hunting** | Hypothesis-driven investigation beyond the initial alert |
| **Incident Documentation** | Timeline reconstruction, escalation tickets, IR reports |

---

## The Investigation Scenario

The analyst starts with only one visible detection:

```
Alert:     Multiple Failed Authentication Attempts
User:      sjenkins
Source:    10.20.10.142  (SOC-WKS-084)
Target:    10.20.20.10   (SOC-DC-01 — Domain Controller)
Failures:  25 in a 5-minute window
Severity:  Medium
```

The goal is to determine — using only evidence-backed pivots — whether this alert is:
- A false positive (locked-out user, misconfigured app)
- An isolated credential attack
- The entry point of a wider multi-stage compromise

> The investigation workflow, SPL searches, and escalation logic are documented step by step inside the `investigations/` folder. Do **not** read `answer-key/` first.

---

## Telemetry Sources Included

| Source | File | Description |
|---|---|---|
| Windows Authentication | `windows_auth.csv` | Logon events (4624, 4625, 4728) |
| Sysmon Process Events | `sysmon_process.csv` | Process execution, parent-child chains, command lines |
| Firewall Traffic | `firewall_traffic.csv` | Network connections, direction, bytes, ports |
| VPN Auth | `vpn_auth.csv` | Remote-access sessions, source IPs |
| Proxy / Web | `proxy_web.csv` | Outbound web requests, domains, user agent |
| DNS Queries | `dns_queries.csv` | Domain resolution activity per host |
| EDR-Style Alerts | `edr_alerts.csv` | Endpoint security alerts with severity and context |
| Email Security | `email_security.csv` | Delivery events, suspicious message flags |
| Threat Intelligence | `threat_intel_iocs.csv` | IOC lookup table (IPs, domains, classification) |
| Asset Inventory | `asset_inventory.csv` | Host role, criticality, owner |
| Identity Context | `identity_context.csv` | User role, department, privilege level |

All sample files are in `datasets/sample/`.

---

## SPL Detection Use Cases

10 SPL detection and investigation searches are included, covering:

| # | Detection | Technique |
|---|---|---|
| 1 | Multiple Failed Authentication Attempts | Credential Brute-Force |
| 2 | Successful Login After Repeated Failures | Account Compromise |
| 3 | Suspicious PowerShell / Encoded Command | Defense Evasion / Execution |
| 4 | Rare Parent-Child Process Chain | Anomalous Execution |
| 5 | Proxy IOC Match | Command & Control |
| 6 | DNS IOC Match | C2 / Exfiltration Domain |
| 7 | Periodic Outbound Beaconing Heuristic | C2 Beaconing |
| 8 | Privileged Group Membership Change | Privilege Escalation |
| 9 | Lateral Movement Candidate to Critical Server | Lateral Movement |
| 10 | Abnormal Outbound Transfer | Data Exfiltration |

> All SPL is in `detections/`. Only searches executed against retained evidence are described as validated.

---

## Investigation Workflow (L1 → L2)

The guided 16-step workflow in `investigations/` walks through:

1. Initial alert review and scoping
2. Identity enrichment
3. Asset criticality check
4. Authentication history analysis
5. Endpoint process investigation
6. PowerShell and command-line analysis
7. Proxy and DNS pivots
8. Email security correlation
9. EDR-style alert triage
10. Firewall and VPN investigation
11. Privilege-change analysis
12. Critical-server access review
13. Outbound transfer analysis
14. Incident timeline reconstruction
15. False-positive assessment
16. L1-to-L2 escalation decision

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Simulated |
|---|---|
| Initial Access | Phishing (T1566) |
| Credential Access | Brute Force (T1110), OS Credential Dumping (T1003) |
| Defense Evasion | Obfuscated Files (T1027), Encoded Command (T1027.010) |
| Execution | PowerShell (T1059.001) |
| Persistence | Account Manipulation (T1098) |
| Privilege Escalation | Valid Accounts (T1078) |
| Lateral Movement | Remote Services (T1021) |
| Command & Control | Application Layer Protocol (T1071) |
| Exfiltration | Exfiltration Over C2 Channel (T1041) |

---

## Repository Structure

```
enterprise-soc-l2-splunk-investigation-lab/
├── architecture/          # Synthetic SOC design, log flow, subnet map
├── datasets/
│   ├── sample/            # Representative synthetic CSV samples (all 11 sources)
│   └── README.md          # Dataset field reference
├── detections/            # SPL detection and investigation use cases
├── investigations/        # Guided L1-to-L2 investigation workflow
├── dashboards/            # Splunk dashboard XML configuration
├── reports/               # Incident and investigation report templates
├── tickets/               # L1-to-L2 escalation ticket templates
├── splunk/                # Ingestion guide for Splunk Free / Trial
└── screenshots/           # Personally executed Splunk search evidence only
```

---

## Synthetic Lab Environment

| Asset | Hostname | IP Address | Role |
|---|---|---|---|
| Domain Controller | SOC-DC-01 | 10.20.20.10 | Authentication authority |
| DNS Server | SOC-DNS-01 | 10.20.20.11 | Internal DNS |
| Application Server | SOC-SRV-APP01 | 10.20.20.20 | Internal application |
| SQL Database | SOC-SRV-SQL01 | 10.20.20.30 | Critical data store |
| Analyst Workstation | SOC-WKS-084 | 10.20.10.142 | Compromised user endpoint |
| Admin Workstation | SOC-WKS-012 | 10.20.10.112 | Admin user endpoint |
| VPN Gateway | SOC-VPN-01 | 192.168.20.20 | Remote access |
| Public Web Server | SOC-WEB-01 | 192.168.20.30 | DMZ web server |
| Splunk SIEM | SOC-SPL-01 | 10.20.30.10 | Security monitoring |

Domain: `soc-lab.local` — All phishing and C2 indicators use the reserved `.example` TLD.

---

## Skills Demonstrated

```
SOC Alert Triage            Splunk SPL Authoring        Security Log Analysis
Multi-Source Correlation    Windows Auth Investigation   Endpoint Process Analysis
Network Traffic Analysis    VPN & Remote Access Review   Proxy & DNS Investigation
EDR Alert Triage            Email Security Correlation   IOC Enrichment & Lookup
Detection Engineering       Threat Hunting               False-Positive Analysis
Incident Timeline Build     L1-to-L2 Escalation Logic   MITRE ATT&CK Mapping
IR Documentation            Containment Recommendations  Evidence-Based Pivoting
```

---

## Getting Started

1. Clone this repository
2. Follow `splunk/ingestion-guide.md` to load sample CSVs into Splunk Free or Trial
3. Open `investigations/analyst-mission.md` — this is your starting brief
4. Work through `investigations/phase3-guided-investigation.md`
5. Use SPL from `detections/phase3-detection-pack.md` to run your searches
6. Do **not** open `answer-key/` until you have made your escalation decision

---

## Disclaimer

This repository was created strictly for defensive cybersecurity learning, hands-on SOC practice, and portfolio demonstration.

All users, IP addresses, hostnames, events, alerts, and scenarios are entirely synthetic and simulated. No real customer data, production systems, client environments, or real-world breach data are included or referenced.

This project does not represent professional SOC work experience, a real incident investigation, or a real client engagement.
