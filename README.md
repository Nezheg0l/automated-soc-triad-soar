# 🛡️ Enterprise SOAR & Threat Intelligence Automated Containment Pipeline

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)
![EDR](https://img.shields.io/badge/EDR-LimaCharlie_v5-orange.svg)
![ThreatIntel](https://img.shields.io/badge/ThreatIntel-VirusTotal_v3-blueviolet.svg)

An automated **Security Orchestration, Automation, and Response (SOAR)** engine built in Python to reduce **MTTR (Mean Time to Respond)** from minutes to seconds. 

The system ingests webhooks from IDS/SIEM sources (e.g., Suricata, Wazuh), enriches events with Threat Intelligence via VirusTotal API, calculates threat severity, and automatically executes **network isolation (Containment)** on the victim host via LimaCharlie EDR SDK while notifying SOC analysts in Telegram.

---

## 🚀 Key Features & Capabilities

* **Automated Threat Intelligence Enrichment:** Real-time lookup of destination/C2 IPs against VirusTotal v3 API.
* **Automated Containment:** Instant host isolation via official LimaCharlie EDR SDK v5 upon detecting confirmed malicious IOCs.
* **Defensible Verdict Generation:** Automated classification of alerts into `True Positive (Critical)` vs `Suspicious` backed by TI scores.
* **Real-Time SOC Analyst Alerting:** Formatted Markdown alerts with full incident context, MITRE ATT&CK mapping, and action status sent via Telegram API.
* **Async & High-Performance:** Built with FastAPI `BackgroundTasks` to handle incoming webhooks asynchronously without blocking the queue.

---

## 📌 MITRE ATT&CK Mapping

| Tactic | Technique ID | Description | Automated SOAR Action |
| :--- | :--- | :--- | :--- |
| **Command and Control** | `T1071` | Application Layer Protocol | Threat Intel enrichment & network isolation |
| **Execution** | `T1059` | Command and Scripting Interpreter | Process & Network socket context extraction |

---

## 🛠️ Tech Stack

* **Language:** Python 3.10+
* **Framework:** FastAPI, Uvicorn
* **EDR/XDR Integration:** LimaCharlie SECaaS (Python SDK v5)
* **Threat Intelligence:** VirusTotal API v3
* **Notifications:** Telegram Bot API
