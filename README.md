# 🛡️ SOC Investigation Playbook & Blue Team Field Guide

[![Security](https://img.shields.io/badge/Domain-SOC%20%7C%20DFIR%20%7C%20Blue%20Team-blue.svg)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/Aligned-MITRE%20ATT%26CK-orange.svg)](#)
[![Telemetry](https://img.shields.io/badge/Telemetry-Windows%20%7C%20AD%20%7C%20Sysmon%20%7C%20Network-green.svg)](#)
[![Documentation](https://img.shields.io/badge/Docs-Markdown%20%7C%20Playbooks-informational.svg)](#)

A structured, battle-tested reference guide and investigation methodology tailored for **SOC Analysts**, **DFIR Specialists**, **Threat Hunters**, and **Detection Engineers**. 

This repository consolidates event telemetry, protocol behaviors, forensic artifacts, and step-by-step investigation playbooks into an intuitive, quick-reference operational repository.

---

## 📌 Repository Architecture

```text
SOC-Investigation-Playbook/
├── 01 References/          # Low-level telemetry, audit policies, log schemas & ports
├── 02 Methodology/         # Threat-specific triage playbooks, investigative flowcharts & worksheets
└── 03 Frameworks/           # Defensive models (Kill Chain, Diamond Model, Pyramid of Pain)
```

---

## 📖 Module Breakdown

### 📂 [01 References/](01%20References/)
*Low-level telemetry dictionaries, audit requirements, and forensic quick-references.*

| Document | Focus & Highlights | Key Telemetry / Use Case |
|---|---|---|
| [`01_Windows_Events_IDs.md`](01%20References/01_Windows_Events_IDs.md) | Windows Security & System Event IDs | Logon types (4624/4625), Process creation (4688), Service installs (7045/4697), Scheduled tasks (4698), Object access |
| [`02_AD_Events_IDs.md`](01%20References/02_AD_Events_IDs.md) | Domain Controller & Active Directory Telemetry | Kerberos (4768/4769/4771), NTLM (4776), Directory Service changes (5136/4662), Trusts, NPS (6272/6273), GPO changes |
| [`03_Protocols.md`](01%20References/03_Protocols.md) | Enterprise Network & Directory Protocols | Port-to-protocol mapping, transport protocols, suspicious behavior indicators, and lateral movement channels |
| [`03_Sysmon_Events_IDs.md`](01%20References/03_Sysmon_Events_IDs.md) | Sysmon Threat Hunting & Triage Reference | Event IDs 1–29 categorized into 🔴 Critical, 🟡 Important, 🟢 Supporting with field analysis and correlation |
| [`04_Log_Fields.md`](01%20References/04_Log_Fields.md) | Network Firewall & Web Proxy Schemas | 14 Firewall fields and 22 Web Proxy attributes with concise SOC analyst investigation value |
| [`05_Headers.md`](01%20References/05_Headers.md) | Email Forensic Header Analysis | Bottom-up `Received` chain parsing, SPF/DKIM/DMARC/ARC validation matrix, BEC and spoofing indicators |

---

### 📂 [02 Methodology/](02%20Methodology/)
*End-to-end tactical investigation workflows, hypothesis generation, and evidence correlation.*

| Document | Focus & Highlights | Investigation Angles |
|---|---|---|
| [`zzz SOC Analyst Methodology.md`](02%20Methodology/zzz%20SOC%20Analyst%20Methodology.md) | Master Investigation Worksheet | Alert triage, entity extraction, behavioral description, timeline reconstruction, hypothesis, and containment |
| [`01_Reconnaissance.md`](02%20Methodology/01_Reconnaissance.md) | Pre-Attack & Internal Discovery | Scanning activity, port enumeration, DNS reconnaissance, and directory mapping |
| [`02_Initial_Access.md`](02%20Methodology/02_Initial_Access.md) | Breach Point Investigation | Phishing triage, brute-force patterns, anomalous VPN/RDP sessions, and compromised mailboxes |
| [`03_Lateral_Movement.md`](02%20Methodology/03_Lateral_Movement.md) | Internal Pivoting & Spreading | SMB share abuse, PsExec/WMI/WinRM remote execution, and workstation-to-workstation RDP tracking |
| [`03_Persistence_Techniques.md`](02%20Methodology/03_Persistence_Techniques.md) | Foothold Identification | Run/RunOnce registry keys, rogue scheduled tasks, malicious services, and startup folder abuse |
| [`04_C&C_Communications.md`](02%20Methodology/04_C&C_Communications.md) | Command & Control Detection | Beaconing timing analysis, DNS tunneling, User-Agent anomalies, DGA recognition, and data exfiltration patterns |
| [`05_DoS_DDoS.md`](02%20Methodology/05_DoS_DDoS.md) | Denial-of-Service Triage | Volumetric spikes, resource exhaustion, and network flow anomaly validation |
| [`AD_Attacks.md`](02%20Methodology/AD_Attacks.md) | Identity & Domain Compromise | Kerberoasting, AS-REP Roasting, DCSync, Golden/Silver tickets, and privilege escalation |
| [`Network_Flows_and_Security_Solutions_Alerts.md`](02%20Methodology/Network_Flows_and_Security_Solutions_Alerts.md) | Network Telemetry Correlation | Correlating NetFlow/IPFIX, Next-Gen Firewalls, NIDS/NIPS, and EDR detections |
| [`Ransomware.md`](02%20Methodology/Ransomware.md) | High-Urgency Outbreak Playbook | Rapid containment, blast radius scoping, shadow copy validation, and root-cause tracing |

---

### 📂 [03 Frameworks/](03%20Frameworks/)
*High-level defensive architecture, threat actor modeling, and strategic response frameworks.*

* **[`Frameworks.md`](03%20Frameworks/Frameworks.md)**: Conceptual mapping of the Cyber Kill Chain, Unified Kill Chain, Diamond Model of Intrusion Analysis, and Pyramid of Pain.
* **[`zzzz cheatsheets.md`](03%20Frameworks/zzzz%20cheatsheets.md)**: Operational cheatsheet pointers and Blue Team Field Manual (BTFM) operational notes.

---

## 🎯 How to Use This Playbook

### 1. Alert Triage & Intake (Tier 1)
* Open [`zzz SOC Analyst Methodology.md`](02%20Methodology/zzz%20SOC%20Analyst%20Methodology.md) to log entities (Account, Host, Source IP, Destination, Process, Hash).
* Perform fast-lookup of unfamiliar events or fields in [`01_Windows_Events_IDs.md`](01%20References/01_Windows_Events_IDs.md), [`03_Sysmon_Events_IDs.md`](01%20References/03_Sysmon_Events_IDs.md), or [`04_Log_Fields.md`](01%20References/04_Log_Fields.md).

### 2. Hypothesis & Deep-Dive Investigation (Tier 2 / DFIR)
* Select the relevant playbook under [`02 Methodology/`](02%20Methodology/) based on observed behavior (e.g., C2 beaconing, lateral movement via SMB/RDP, or phishing triage).
* Reconstruct the timeline chronologically: **Before the Alert $\rightarrow$ Initial Trigger $\rightarrow$ Post-Execution Activity**.

### 3. Threat Hunting & Detection Engineering
* Use the event tables and key fields across [`01 References/`](01%20References/) to configure SIEM correlation rules, Sigma signatures, and Sysmon XML filter rules.
* Validate detection coverage against MITRE ATT&CK techniques.

---

## 🗺️ MITRE ATT&CK Matrix Alignment

| MITRE ATT&CK Tactic | Playbook / Reference File |
|---|---|
| **Reconnaissance (TA0043)** | [`01_Reconnaissance.md`](02%20Methodology/01_Reconnaissance.md) |
| **Initial Access (TA0001)** | [`02_Initial_Access.md`](02%20Methodology/02_Initial_Access.md), [`05_Headers.md`](01%20References/05_Headers.md) |
| **Execution (TA0002)** | [`01_Windows_Events_IDs.md`](01%20References/01_Windows_Events_IDs.md), [`03_Sysmon_Events_IDs.md`](01%20References/03_Sysmon_Events_IDs.md) |
| **Persistence (TA0003)** | [`03_Persistence_Techniques.md`](02%20Methodology/03_Persistence_Techniques.md) |
| **Privilege Escalation (TA0004)** | [`AD_Attacks.md`](02%20Methodology/AD_Attacks.md), [`02_AD_Events_IDs.md`](01%20References/02_AD_Events_IDs.md) |
| **Lateral Movement (TA0008)** | [`03_Lateral_Movement.md`](02%20Methodology/03_Lateral_Movement.md), [`03_Protocols.md`](01%20References/03_Protocols.md) |
| **Command and Control (TA0011)** | [`04_C&C_Communications.md`](02%20Methodology/04_C&C_Communications.md), [`04_Log_Fields.md`](01%20References/04_Log_Fields.md) |
| **Impact (TA0040)** | [`Ransomware.md`](02%20Methodology/Ransomware.md), [`05_DoS_DDoS.md`](02%20Methodology/05_DoS_DDoS.md) |

---

## ⚡ Key Principles for Investigators

1. **Telemetry Over Assumptions**: An event ID or firewall drop is an observation, not a verdict. Always correlate across host and network telemetry.
2. **Reconstruct the Story**: Identify the user account, originating IP, parent-child process tree, and timeline before drawing conclusions.
3. **Preserve Volatile Evidence**: Prioritize rapid scoping and containment while preventing evidence destruction on compromised endpoints.

---

## 🤝 Contributing & Usage

Contributions, detection rule improvements, and playbook additions are welcome:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-playbook`).
3. Commit your documentation following the standard table and telemetry schema.
4. Submit a Pull Request.

---
*Maintained for Blue Teams, DFIR practitioners, and Cybersecurity Operations Centers.*
