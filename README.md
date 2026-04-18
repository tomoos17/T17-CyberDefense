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
- **Feedback loop** — user corrections improve future detection accuracy
- **100% offline** — runs entirely on your local machine via Ollama

---

## Project Structure

```
T17/
├── main.py                     ← entry point — runs the full pipeline
├── t17.py                      ← CLI interface (in progress)
│
├── core/
│   ├── ai_brain.py             ← tiered LLM inference + MITRE mapping
│   ├── curiosity.py            ← entropy scoring + keyword heuristics
│   ├── reflection.py           ← verification + confidence + verdict
│   ├── log_parser.py           ← parses raw logs into structured dicts
│   ├── web_scanner.py          ← scans web pages for threats
│   ├── threat_engine.py        ← combines modules into unified pipeline
│   ├── nmap_analyzer.py        ← reads nmap scan results
│   ├── memory.py               ← saves and retrieves past threats
│   ├── feedback_loop.py        ← stores user corrections
│   └── network_parser.py       ← Scapy packet analysis (in progress)
│
├── configs/
│   └── prompt_templates.json   ← structured prompts for LLM reasoning
│
├── data/
│   ├── memory.json             ← persistent threat memory store
│   ├── memory_store.json       ← backup memory
│   └── feedback_log.json       ← user feedback history
│
├── tools/
│   ├── nmap_tool.py            ← nmap integration
│   ├── virus_total.py          ← VirusTotal API (stub)
│   └── whois_lookup.py         ← WHOIS lookup (stub)
│
├── logs/                       ← place real log files here
├── t17pkg/
│   ├── __init__.py
│   └── config.py               ← centralised settings
│
└── README.md
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Interface Layer                     │
│         CLI (t17 scan / analyse / detect)            │
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
│   memory.py  •  feedback_loop.py                     │
└─────────────────────────────────────────────────────┘
```

---

## Tiered Inference — How It Works

T17 does not send every log to the AI. It first scores each input:

| Curiosity Score | Action | Model Used |
|---|---|---|
| 0 – 3 | Discard — not suspicious | None |
| 4 – 5 | Analyse — medium risk | Phi-3 Mini (fast, ~5-10s) |
| 6 – 10 | Deep analyse — high risk | Mistral 7B (deep, ~15-25s) |

This saves compute and makes T17 practical on standard hardware without a GPU.

---

## MITRE ATT&CK Mapping

Every T17 threat report includes a MITRE technique ID:

| Technique | ID | Tactic |
|---|---|---|
| PowerShell execution | T1059.001 | Execution |
| Obfuscated files (Base64) | T1027 | Defence Evasion |
| Network port scanning | T1046 | Discovery |
| Brute force login | T1110 | Credential Access |
| Privilege escalation | T1068 | Privilege Escalation |
| DNS command & control | T1071.004 | Command & Control |
| Data exfiltration | T1041 | Exfiltration |
| Lateral movement | T1021 | Lateral Movement |
| Ingress tool transfer | T1105 | Command & Control |
| Denial of service | T1499 | Impact |
| Scheduled task | T1053 | Persistence |
| Modify registry | T1112 | Defence Evasion |

---

## Example Output

```
=======================================================
  T17 THREAT REPORT
=======================================================
  Status:       threat_report
  Timestamp:    2026-03-26T15:36:05
  Model used:   phi3
  Severity:     MEDIUM
  Confidence:   65/100
  MITRE ID:     T1059.001 — PowerShell
  Tactic:       Execution
  Verdict:      🟡 Medium confidence threat. Investigate further.
-------------------------------------------------------
  Reasoning:
  This appears to be a Base64 encoded PowerShell command.
  Encoded commands are commonly used to obfuscate malicious
  payloads and bypass security controls...
=======================================================
```

---

## Data Sources — Log Types

**System logs**
- Windows Event Logs (Security, System, Application)
- Linux syslog / auth.log / kern.log
- PowerShell / Bash command history
- Sysmon process creation (Event ID 4688)

**Network logs**
- Live packet capture via Scapy
- Offline .pcap files (Wireshark / tcpdump)
- DNS query logs
- HTTP/S request logs

**Security logs**
- Failed authentication / brute-force attempts
- Firewall deny/allow logs
- YARA scan results
- BOTSv3 dataset (evaluation)

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
pip install requests scapy
```

---

## Running T17

```bash
# Run the full pipeline on test logs
python main.py

# Export real Windows logs and analyse them
wevtutil qe Security /c:50 /f:text > logs\security.log
python main.py

# CLI interface (in progress)
python t17.py scan logs\security.log
python t17.py analyse "suspicious command here"
python t17.py live
```

---

## Current Status

| Feature | Status |
|---|---|
| log_parser.py | ✅ Working |
| curiosity.py — scoring | ✅ Working |
| ai_brain.py — tiered inference | ✅ Working |
| reflection.py — MITRE + confidence | ✅ Working |
| memory.py — persistent storage | ✅ Working |
| feedback_loop.py | ✅ Working |
| threat_engine.py | ✅ Working |
| CLI interface (t17.py) | 🔄 In progress |
| network_parser.py (Scapy) | 🔄 In progress |
| Real Windows log reader | 🔄 In progress |
| BOTSv3 evaluation | 📋 Planned |

---

## Evaluation

T17 is evaluated against the **Splunk Boss of the SOC v3 (BOTSv3)** dataset —
a real-world attack scenario dataset used in security competitions.

Metrics measured:
- **Precision** — of threats T17 flagged, how many were real
- **Recall** — of all real threats, how many T17 caught
- **F1 Score** — balance between precision and recall

---

## Why T17 is Different

| Feature | Traditional AV | Wazuh + LLM | T17 |
|---|---|---|---|
| Detection method | Signatures only | Rules + LLM | 3-layer AI reasoning |
| Fully offline | Partial | Yes | 100% offline |
| Network packets | No | Log only | Scapy PCAP + live |
| MITRE ATT&CK | No | Partial | Every output |
| Tiered inference | No | Single model | Phi-3 + Mistral 7B |
| Confidence score | No | No | Per detection |
| Explainability | None | Partial | Full reasoning JSON |

---

## Is T17 an AI Agent?

Yes. T17 meets all four properties of an AI agent:

| Property | How T17 implements it |
|---|---|
| Perception | Reads logs, packets, and web content from the environment |
| Reasoning | Three-layer pipeline — curiosity → ai_brain → reflection |
| Memory | memory.py stores every past threat persistently |
| Learning | feedback_loop.py improves future decisions from corrections |

---

## Dissertation

**Title:** T17: A Tiered Local LLM Framework for Offline
AI-Powered Cybersecurity Threat Detection

**Author:** Thomas Gabriel
**Course:** BSc Cybersecurity

---

## Future Work — T17 → Tau

- RAG memory layer — vector store of past threats for semantic retrieval
- Fine-tuning on malware datasets (EMBER, CIC-IDS)
- Autonomous agent loop — real-time background monitoring
- Network traffic deep inspection — live PCAP analysis
- Voice companion mode — Jarvis-style interaction
- Web dashboard — FastAPI + React threat visualisation
- Splunk / SIEM integration layer

---

## Acknowledgements

- Meta — LLaMA 3
- Microsoft Research — Phi-3 Mini
- Mistral AI — Mistral 7B
- Ollama — local LLM serving
- MITRE Corporation — ATT&CK Framework v15
- Splunk — BOTSv3 Dataset
