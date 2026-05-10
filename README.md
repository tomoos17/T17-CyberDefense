# T17 — Offline AI-Powered Cybersecurity Threat Detection Framework

> A fully offline, locally-deployed AI cybersecurity agent using tiered
> large language model inference for intelligent, multi-layer threat detection.

---

## What is T17?

T17 is a modular AI cybersecurity framework that detects threats in system
logs and network traffic using local large language models — no cloud, no API
keys, no data leaving your machine.

Unlike traditional antivirus tools that match known signatures, T17 reasons
about threats contextually through a three-layer AI pipeline:

```
Log / Packet / Web input
        ↓
curiosity.py     — scores suspiciousness (0-10)
        ↓
ai_brain.py      — tiered LLM analysis (Phi-3 Mini or Mistral 7B)
        ↓
reflection.py    — verifies output, confidence score, MITRE mapping
        ↓
Structured JSON threat report
```

---

## Key Features

- **Tiered inference** — Phi-3 Mini for medium-risk (fast), Mistral 7B for
  high-risk (deep). Right model for the right threat.
- **MITRE ATT&CK mapping** — every detection tagged with an industry-standard
  technique ID (e.g. T1059.001 PowerShell, T1068 Privilege Escalation)
- **Confidence scoring** — every output rated 0-100 so results are measurable
- **Hallucination detection** — reflection layer flags uncertain AI responses
- **Persistent memory** — T17 remembers past threats and recognises patterns
- **Network analysis** — Scapy-based pcap analysis detecting C2 beaconing,
  port scans, SYN floods, DNS tunnelling, and data exfiltration
- **Web dashboard** — Flask-based UI at localhost:5000 with real-time results
- **Auto-generated reports** — timestamped threat intelligence reports saved
  to the reports/ folder
- **Feedback loop** — user corrections improve future detection accuracy
- **100% offline** — runs entirely on your local machine via Ollama

---

## Project Structure

```
T17/
├── main.py                     ← pipeline test runner (frozen)
├── t17.py                      ← CLI interface (5 commands)
├── botsv3_eval.py              ← BOTSv3 evaluation script
│
├── core/
│   ├── ai_brain.py             ← tiered LLM inference + 80+ MITRE mappings
│   ├── curiosity.py            ← entropy scoring + 150+ keyword heuristics
│   ├── reflection.py           ← verification + confidence + verdict
│   ├── log_parser.py           ← simple + Windows Event Log parser
│   ├── network_parser.py       ← Scapy pcap analysis
│   ├── web_scanner.py          ← scans web pages for threats
│   ├── threat_engine.py        ← combines modules into unified pipeline
│   ├── memory.py               ← saves and retrieves past threats
│   ├── feedback_loop.py        ← stores user corrections
│   └── report_generator.py     ← generates threat intelligence reports
│
├── ui/
│   └── app.py                  ← Flask web dashboard (localhost:5000)
│
├── configs/
│   └── prompt_templates.json   ← structured prompts for LLM reasoning
│
├── data/
│   ├── memory.json             ← persistent threat memory store
│   ├── memory_store.json       ← backup memory
│   └── feedback_log.json       ← user feedback history
│
├── botsv3/                     ← BOTSv3 evaluation data
│   ├── PowerShell.csv          ← T1059.001 real attack logs
│   ├── Failed_logins.csv       ← T1110 brute force logs
│   ├── Privilege_escalation.csv← T1068 privilege escalation logs
│   ├── Privilege_escalation2.csv← T1068 privileged service calls
│   ├── Network_scanning.csv    ← T1046 network scanning logs
│   ├── Process_creation.csv    ← T1059 process creation logs
│   ├── evaluation_results.json ← full evaluation results JSON
│   └── T17_BOTSv3_Evaluation_Report.txt ← evaluation report
│
├── logs/                       ← place real log files here
│   ├── test.log                ← simulated attack test logs
│   └── security.log            ← real Windows Security Event Logs
│
├── captures/                   ← network capture files
│   ├── attack.pcap             ← Scapy-generated test pcap
│   ├── portscan.pcap           ← port scan test capture
│   └── portscan2.pcap          ← second port scan capture
│
├── reports/                    ← auto-generated threat reports
│
└── README.md
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Interface Layer                     │
│    CLI (t17.py)  •  Web Dashboard (ui/app.py)        │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│                  Data Layer                          │
│   log_parser  +  web_scanner  +  network_parser      │
│   System logs  •  .pcap files  •  Web content        │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│               Reasoning Layer                        │
│                                                      │
│  L1  curiosity.py    — entropy + keyword scoring     │
│  L2  ai_brain.py     — tiered Phi-3 / Mistral 7B     │
│  L3  reflection.py   — verify + MITRE + confidence   │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│                  Output Layer                        │
│   JSON threat report  •  MITRE ID  •  confidence     │
│   memory.py  •  report_generator.py  •  dashboard    │
└─────────────────────────────────────────────────────┘
```

---

## Tiered Inference — How It Works

T17 does not send every log to the AI. It first scores each input:

| Curiosity Score | Action | Model Used |
|---|---|---|
| 0 – 3 | Discard — not suspicious | None |
| 4 – 6 | Analyse — medium risk | Phi-3 Mini (fast, ~5-10s) |
| 7 – 10 | Deep analyse — high risk | Mistral 7B (deep, ~15-25s) |

This saves compute and makes T17 practical on standard hardware without a GPU.

---

## MITRE ATT&CK Mapping

T17 maps every detection to a MITRE ATT&CK technique ID across 10 tactic
categories covering 80+ technique mappings:

| Technique | ID | Tactic |
|---|---|---|
| PowerShell execution | T1059.001 | Execution |
| Unix Shell | T1059.004 | Execution |
| Obfuscated files (Base64) | T1027 | Defence Evasion |
| Disable Security Tools | T1562.001 | Defence Evasion |
| Clear Event Logs | T1070.001 | Defence Evasion |
| Process Injection | T1055 | Defence Evasion |
| LSASS Memory Dump | T1003.001 | Credential Access |
| Brute Force | T1110 | Credential Access |
| Password Spraying | T1110.003 | Credential Access |
| Privilege Escalation | T1068 | Privilege Escalation |
| Bypass UAC | T1548.002 | Privilege Escalation |
| Token Impersonation | T1134.001 | Privilege Escalation |
| Network Port Scanning | T1046 | Discovery |
| Remote System Discovery | T1018 | Discovery |
| Account Discovery | T1087 | Discovery |
| Remote Desktop Protocol | T1021.001 | Lateral Movement |
| Pass the Hash | T1550.002 | Lateral Movement |
| SMB Admin Shares | T1021.002 | Lateral Movement |
| Scheduled Task | T1053.005 | Persistence |
| Registry Run Keys | T1547.001 | Persistence |
| Web Shell | T1505.003 | Persistence |
| C2 Communication | T1071 | Command & Control |
| DNS C2 | T1071.004 | Command & Control |
| Ingress Tool Transfer | T1105 | Command & Control |
| Exfiltration Over C2 | T1041 | Exfiltration |
| Data Encrypted for Impact | T1486 | Impact |
| Network Denial of Service | T1499 | Impact |

---

## Example Output

```
=======================================================
  T17 THREAT REPORT
=======================================================
  Status:       threat_report
  Timestamp:    2026-04-25T05:07:56
  Model used:   phi3
  Severity:     HIGH
  Confidence:   55/100
  MITRE ID:     T1059.001 — PowerShell Encoded
  Tactic:       Execution
  Verdict:      🟠 Possible threat detected. Low-medium confidence.
-------------------------------------------------------
  Reasoning:
  threat_type: PowerShell injection attack
  severity: high
  reasoning: The input string appears to be a base64 encoded
  command which, when decoded and executed via PowerShell's
  Invoke-Expression cmdlet, indicates an attempt to execute
  arbitrary code on the target system...
=======================================================
✅ Threat saved to memory.
```

---

## CLI Commands

```bash
# Analyse a single log entry
python t17.py analyse "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS"

# Scan a log file
python t17.py scan logs\test.log

# Scan and generate a threat intelligence report
python t17.py report logs\test.log

# Export and scan real Windows Security logs (requires admin)
wevtutil qe Security /c:100 /f:text > logs\security.log
python t17.py live

# Analyse a network capture file
python t17.py network captures\attack.pcap
```

---

## Web Dashboard

```bash
# Start the dashboard
python ui\app.py

# Open browser at
http://localhost:5000
```

Dashboard features:
- **Analyse tab** — single log entry analysis with 5 quick-test buttons
- **Scan File tab** — full pipeline scan with threat cards and stat counters
- **Memory tab** — view and clear stored threats

---

## Data Sources — Log Types

**System logs**
- Windows Event Logs (Security, System, Application) via wevtutil
- Linux syslog / auth.log / kern.log
- PowerShell command history
- Sysmon process creation (Event ID 4688)
- BOTSv3 real attack logs from Splunk Enterprise

**Network logs**
- Offline .pcap files (Wireshark / tcpdump / Scapy)
- DNS query logs
- HTTP/S request logs

**Security logs**
- Failed authentication / brute-force attempts (EventCode 4625)
- Privilege assignment (EventCode 4672)
- Process creation (EventCode 4688)
- Scheduled task creation (EventCode 4698)
- Audit log cleared (EventCode 1102)

---

## Requirements

```
Python 3.11+
Ollama (https://ollama.ai)
```

Install Ollama models:
```bash
ollama pull phi3
ollama pull mistral
ollama pull llama3
```

Install Python dependencies:
```bash
pip install flask scapy requests
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/tomoos17/T17-CyberDefense
cd T17-CyberDefense

# Install dependencies
pip install flask scapy requests

# Install Ollama models
ollama pull phi3
ollama pull mistral

# Create required folders
mkdir logs
mkdir captures
mkdir reports

# Initialise memory (Windows PowerShell)
'[]' | Out-File -FilePath data\memory.json -Encoding UTF8

# Run pipeline test
python main.py
```

---

## Running BOTSv3 Evaluation

```bash
# Place BOTSv3 CSV files in botsv3/ folder
# Clear memory first
'[]' | Out-File -FilePath data\memory.json -Encoding UTF8

# Run evaluation
python botsv3_eval.py
```

---

## Current Status

| Feature | Status |
|---|---|
| log_parser.py — simple + Windows Event Logs | ✅ Complete |
| curiosity.py — 150+ keywords, entropy scoring | ✅ Complete |
| ai_brain.py — tiered inference, 80+ MITRE mappings | ✅ Complete |
| reflection.py — confidence, hallucination, MITRE | ✅ Complete |
| memory.py — persistent JSON threat storage | ✅ Complete |
| feedback_loop.py | ✅ Complete |
| report_generator.py — timestamped threat reports | ✅ Complete |
| network_parser.py — Scapy pcap analysis | ✅ Complete |
| CLI interface (t17.py) — 5 commands | ✅ Complete |
| Web dashboard (ui/app.py) — Flask localhost:5000 | ✅ Complete |
| Real Windows log reader (wevtutil) | ✅ Complete |
| BOTSv3 evaluation | ✅ Complete |
| Live network packet capture | 🔄 Future work |
| Fine-tuned security models | 🔄 Future work |

---

## Evaluation Results

### Controlled Test Dataset
- **6 attack scenarios tested** — 6 detected (100% detection rate)
- Attack types: PowerShell (T1059.001), Privilege Escalation (T1068),
  Brute Force (T1110), Certutil (T1105), C2 Beaconing (T1041),
  Port Scan (T1046)

### BOTSv3 Real-World Evaluation
- **Dataset:** Splunk Boss of the SOC v3 — real 2018 attack logs
- **Logs tested:** 153 across 6 attack categories
- **Threats detected:** 142

| Metric | Score |
|---|---|
| Detection Rate | 92.8% |
| Precision | 56.3% |
| Recall | 87.9% |
| F1 Score | 68.7% |

| Category | Tested | Detected | Rate |
|---|---|---|---|
| PowerShell Execution (T1059.001) | 30 | 29 | 96.7% |
| Brute Force (T1110) | 3 | 3 | 100.0% |
| Privilege Escalation (T1068) | 30 | 30 | 100.0% |
| Privileged Service Call (T1068) | 30 | 30 | 100.0% |
| Network Service Scanning (T1046) | 30 | 20 | 66.7% |
| Process Creation (T1059) | 30 | 30 | 100.0% |

### Real Windows Security Logs
- **7,001 real log entries scanned** from development machine
- **0 threats detected** — correct behaviour on clean system
- Confirms T17 does not generate false positives on normal activity

---

## Why T17 is Different

| Feature | Traditional AV | Wazuh + LLM | T17 |
|---|---|---|---|
| Detection method | Signatures only | Rules + LLM | 3-layer AI reasoning |
| Fully offline | Partial | Yes | 100% offline |
| Network packets | No | Log only | Scapy PCAP |
| MITRE ATT&CK | No | Partial | Every output |
| Tiered inference | No | Single model | Phi-3 + Mistral 7B |
| Confidence score | No | No | Per detection (0-100) |
| Explainability | None | Partial | Full reasoning |
| Auto reports | No | Partial | Timestamped .txt |
| Web dashboard | No | Yes | localhost:5000 |

---

## Is T17 an AI Agent?

Yes. T17 meets all four properties of an AI agent:

| Property | How T17 implements it |
|---|---|
| Perception | Reads logs, packets, and web content from environment |
| Reasoning | Three-layer pipeline — curiosity → ai_brain → reflection |
| Memory | memory.py stores every past threat persistently |
| Learning | feedback_loop.py improves future decisions from corrections |

---

## Dissertation

**Title:** T17: A Tiered Local LLM Framework for Offline
AI-Powered Cybersecurity Threat Detection

**Author:** Thomas Gabriel Naduvilaveedu Martin
**Registration:** 10762669
**Course:** BSc (Hons) Cybersecurity — COMP3000
**Institution:** University of Plymouth 2025-2026
**Word Count:** 8,959

---

## Future Work — T17 → Tau

- RAG memory layer — ChromaDB vector store for semantic threat retrieval
- Fine-tuning on security datasets (EMBER, CIC-IDS2017)
- Autonomous agent loop — real-time background monitoring
- Live network packet capture — Npcap integration for Windows
- Full BOTSv3 evaluation — complete 1.9 million event dataset
- SIEM integration — Splunk / Wazuh connector
- Voice companion mode — Jarvis-style interaction

---

## Acknowledgements

- Meta AI — LLaMA 3
- Microsoft Research — Phi-3 Mini
- Mistral AI — Mistral 7B
- Ollama — local LLM serving infrastructure
- MITRE Corporation — ATT&CK Framework v15
- Splunk — BOTSv3 Dataset
- Scapy — network packet analysis library
- Flask — web dashboard framework
