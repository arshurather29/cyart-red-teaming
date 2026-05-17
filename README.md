# 🛡️ Week 2 — Practical Cybersecurity: Threat Hunting, Malware Analysis & Incident Response

> **Repository:** `cyart-red-teaming`
> **Folder:** `Week 2`
> **Deadline:** Friday, 4:30 PM
> **Submission Format:** GitHub Repository with Documentation (PDF, Notes, Screenshots) + Workflow with Steps

---

## 📁 Folder Structure

```
Week 2/
├── README.md                          ← You are here
├── 01_Threat_Hunting/
│   ├── sigma_rule_powershell.yml      ← Sigma rule for PowerShell detection
│   ├── elastic_query_results.csv      ← Event ID 4688 query results
│   ├── notes.md                       ← Observations and findings
│   └── screenshots/
├── 02_Malware_Analysis/
│   ├── static_analysis_report.md     ← strings output summary
│   ├── hybrid_analysis_comparison.md ← Dynamic vs static findings
│   └── screenshots/
├── 03_Vulnerability_Management/
│   ├── openvas_scan_results.xml       ← Raw scan export
│   ├── defectdojo_import_notes.md    ← Import steps
│   ├── remediation_plan.md           ← Prioritized vuln table + fixes
│   └── screenshots/
├── 04_Incident_Response_Simulation/
│   ├── phishing_attack_summary.md    ← 100-word attack path summary
│   ├── velociraptor_artifacts.csv    ← Collected process/network artifacts
│   ├── ioc_analysis.md               ← IOC findings
│   └── screenshots/
├── 05_Network_Defense/
│   ├── suricata_rule.rules            ← Custom Suricata block rule
│   ├── attck_mapping.md              ← Alert → MITRE ATT&CK mapping table
│   └── screenshots/
├── 06_Risk_Assessment/
│   ├── ale_calculation.xlsx           ← ALE spreadsheet (Google Sheets export)
│   ├── risk_matrix.md                ← 5x5 risk matrix
│   └── screenshots/
├── 07_Incident_Response_Report/
│   ├── ir_report_phishing.pdf        ← Full SANS-style IR report
│   ├── ir_flowchart.png              ← Detection → Containment → Recovery diagram
│   └── screenshots/
└── 08_Capstone/
    ├── attack_simulation_notes.md    ← Metasploit exploit steps
    ├── wazuh_alert_log.csv           ← Detection table with MITRE mapping
    ├── crowdsec_block_confirmation.md← Containment verification
    ├── capstone_report.md            ← 200-word final incident report
    └── screenshots/
```

---

## 🔍 Task 1 — Threat Hunting with Open-Source Tools

**Tools:** Elastic Security · Security Onion · Sigma Rules

### Sigma Rule — Suspicious PowerShell Detection

```yaml
title: Suspicious PowerShell Activity
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-Command'
  condition: selection
```

**Test Command (harmless):**
```powershell
powershell -Command "Write-Host Test"
```

### Elastic Security Query — Event ID 4688

| Timestamp | Process | Command Line | Notes |
|---|---|---|---|
| 2025-08-18 10:00:00 | powershell.exe | -Command Write-Host | Suspicious execution |

📂 See `01_Threat_Hunting/` for full query results and screenshots.

---

## 🦠 Task 2 — Malware Analysis Basics

**Tools:** REMnux · Hybrid Analysis

### Static Analysis

```bash
strings calc.exe > output.txt
```

Summarize 3 interesting strings found in the output in a 50-word report. See `02_Malware_Analysis/static_analysis_report.md`.

### Dynamic Analysis

Submit `calc.exe` to [Hybrid Analysis](https://www.hybrid-analysis.com/) and compare behavior report with REMnux findings.

📂 See `02_Malware_Analysis/` for comparison notes and screenshots.

---

## 🔓 Task 3 — Vulnerability Management Pipeline

**Tools:** OpenVAS · DefectDojo

### Prioritized Vulnerabilities (Metasploitable2 Scan)

| Vulnerability | CVSS Score | Description |
|---|---|---|
| VSFTPD Backdoor | 7.5 | Allows unauthenticated remote access |
| Samba MS-RPC | 6.8 | Remote code execution via SMB |
| UnrealIRCd Backdoor | 7.8 | Arbitrary command execution |

### Remediation Plan

- **VSFTPD:** Upgrade to patched version or disable the FTP service entirely.
- **Samba:** Apply available patches; restrict SMB access via firewall rules.
- **UnrealIRCd:** Remove or replace with a patched build; block relevant ports.

📂 See `03_Vulnerability_Management/` for scan exports, DefectDojo import steps, and screenshots.

---

## 🎣 Task 4 — Incident Response Simulation

**Tools:** Velociraptor · MITRE Caldera

### Phishing Attack Path Summary

A mock phishing payload was deployed via MITRE Caldera on a Windows VM. The payload was delivered through a simulated email attachment, triggering execution of a malicious script. Caldera's agent established persistence by modifying the registry run key and initiated a reverse connection. The attack was mapped to MITRE ATT&CK techniques T1566 (Phishing) and T1547 (Boot/Logon Autostart Execution).

### Velociraptor Artifact Collection Queries

```sql
SELECT * FROM processes;
SELECT * FROM netstat;
```

Results exported to `04_Incident_Response_Simulation/velociraptor_artifacts.csv`.

📂 See `04_Incident_Response_Simulation/` for full IOC analysis and screenshots.

---

## 🌐 Task 5 — Network Defense with Open-Source Tools

**Tools:** Suricata · Elastic SIEM · CrowdSec

### Suricata Block Rule

```
drop ip 192.168.1.100 any -> any any (msg:"Block Malicious IP"; sid:1000001;)
```

**Test:** Ping from another VM on the network to verify the rule blocks traffic.

### MITRE ATT&CK Mapping

| Alert | Tactic | Technique | Notes |
|---|---|---|---|
| Suspicious HTTP | Command and Control | T1071 | Outbound traffic to C2 server |
| PowerShell Execution | Execution | T1059.001 | Encoded command execution |

📂 See `05_Network_Defense/` for rule files, Elastic SIEM screenshots, and ATT&CK mapping.

---

## 📊 Task 6 — Risk Assessment Practice

**Tool:** Google Sheets

### ALE Calculation — Ransomware Scenario

```
SLE (Single Loss Expectancy) = $10,000
ARO (Annual Rate of Occurrence) = 0.2

ALE = SLE × ARO
ALE = $10,000 × 0.2 = $2,000
```

### 5×5 Risk Matrix

| | **Negligible** | **Minor** | **Moderate** | **Significant** | **Catastrophic** |
|---|---|---|---|---|---|
| **Almost Certain** | Low | Medium | High | Critical | Critical |
| **Likely** | Low | Medium | High | High | Critical |
| **Possible** | Low | Low | Medium | High | Critical |
| **Unlikely** | Negligible | Low | Medium | Medium | High |
| **Rare** | Negligible | Negligible | Low | Low | Medium |

> **Ransomware Scenario Score:** Likelihood = Possible · Impact = Catastrophic → **Critical**

📂 See `06_Risk_Assessment/` for full spreadsheet and matrix.

---

## 📝 Task 7 — Incident Response Report

**Template:** SANS IR Report Format

### Report Structure

1. **Executive Summary** — High-level overview of the incident and business impact
2. **Timeline** — Chronological sequence of events from detection to recovery
3. **Technical Findings** — Artifacts, IOCs, and affected systems
4. **Mitigation Steps** — Actions taken and recommended follow-up measures

### IR Process Flowchart

```
[Detection] → [Analysis] → [Containment] → [Eradication] → [Recovery] → [Lessons Learned]
```

📂 See `07_Incident_Response_Report/` for the full PDF report and flowchart diagram.

---

## 🏆 Task 8 — Capstone: Full Incident Response Cycle

**Tools:** Metasploit · Wazuh · CrowdSec · Google Docs

### Attack Simulation — VSFTPD Backdoor

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <target-ip>
run
```

### Wazuh Detection Log

| Timestamp | Source IP | Alert Description | MITRE Technique |
|---|---|---|---|
| 2025-08-18 11:00:00 | 192.168.1.100 | VSFTPD exploit attempt | T1190 |
| 2025-08-18 11:02:00 | 192.168.1.100 | Shell spawned on host | T1059 |

### Containment — CrowdSec IP Block

```bash
cscli decisions add --ip 192.168.1.100 --reason "VSFTPD exploit"
```

Verify with: `ping 192.168.1.100` → should time out.

### Capstone Summary Report

The simulated attack exploited the VSFTPD 2.3.4 backdoor vulnerability (CVE-2011-2523) on a Metasploitable2 target. The attacker gained a root shell via port 6200. Wazuh detected the exploit attempt within 30 seconds, generating alerts mapped to MITRE ATT&CK T1190 (Exploit Public-Facing Application). CrowdSec was used to block the attacker's IP immediately, halting further lateral movement. Key recommendations include patching or removing VSFTPD, enabling network segmentation, and deploying real-time SIEM alerting with automated IP blocking for all production environments.

📂 See `08_Capstone/` for all documentation, logs, and the full report.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| Elastic Security / Security Onion | Log ingestion and threat hunting |
| Sigma Rules | Detection rule creation |
| REMnux | Static malware analysis |
| Hybrid Analysis | Dynamic malware sandbox |
| OpenVAS | Vulnerability scanning |
| DefectDojo | Vulnerability management platform |
| Velociraptor | Digital forensic artifact collection |
| MITRE Caldera | Adversary simulation |
| Suricata | Network intrusion detection/prevention |
| CrowdSec | Collaborative IP blocking |
| Metasploit | Attack simulation framework |
| Wazuh | Open-source SIEM and XDR |
| Google Sheets | Risk assessment calculations |

---

## 📌 Submission Checklist

- [ ] All 8 task folders created with documentation
- [ ] Screenshots included in each subfolder
- [ ] Sigma rule `.yml` file uploaded
- [ ] Suricata `.rules` file uploaded
- [ ] IR Report PDF in `07_Incident_Response_Report/`
- [ ] Capstone report in `08_Capstone/`
- [ ] This `README.md` is at the root of the `Week 2/` folder

---

*Week 2 — CYART Red Teaming Program*
