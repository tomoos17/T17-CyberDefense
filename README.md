 T17 Sprint Plan: Core Features, Upgrades & Timeline

Project Code Name: T17 (Tau-Ready Autonomous AI for Cybersecurity)Document Type: Feature-Based 
Sprint Guide + Upgrade RoadmapTimeline: 12 Weeks (Extendable)

🧠 Core Vision of T17

T17 is an intelligent, modular cybersecurity assistant inspired by AGI traits.
Its goals are to observe, analyze, reason, and improve over time. It learns from interactions,
recognizes threats, and suggests intelligent actions — mimicking a junior SOC analyst with 
self-learning potential. The architecture is fully modular, containerizable, and designed
to be deployed in a secure, local environment without dependency on the cloud.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

🔑 Core Functional Modules & Features

Module

Function Description

Technologies Used

ai_brain.py

Central reasoning unit – interacts with log parser, memory, reflection engine

GPT-4 (OpenAI API) or LLaMA 3 (via Ollama / LM Studio)

log_parser.py

Normalizes and structures raw logs into clean input data for AI

Python, Regex, JSON, YAML

threat_engine.py

Uses LLM + rules to identify threat patterns (e.g., brute force, port scans)

Scikit-learn, LangChain, Rule-based filters

reflection.py

Compares past vs. present decisions, identifies false positives/negatives

Pandas, Vector Search (FAISS or Chroma)

memory.py

Long-term memory store for logs, decisions, and threat fingerprints

ChromaDB / SQLite / Pinecone (optional local)

curiosity.py

Identifies knowledge gaps and triggers deeper analysis or new questions

Entropy detection, frequency scoring

nmap_tool.py

Interfaces with Nmap to run scans on demand or when suspicious IPs are found

Nmap CLI, subprocess, XML parsing

whois_lookup.py

Pulls WHOIS data for domains/IPs seen in logs or flagged events

Python whois, Shodan API integration

virus_total.py

Integrates with VT API to check file hashes or URLs seen in logs

VirusTotal API, Hashlib

feedback_loop.py

Accepts human input for corrections, which tunes future predictions

CLI prompts, Tkinter/Streamlit UI

report_generator.py

Generates SOC-style daily or incident reports in plain English

Jinja2 templating, Markdown export

reward_engine.py

Internal reward system to simulate curiosity and reflectivity (AGI trait booster)

Custom Python logic, local JSON ledger

📊 Architecture Diagram

         ┌──────────────────────────────┐
         │        User Interface        │◄──────────────┐
         └────────────┬─────────────────┘               │
                      ▼                                 │
              ┌───────────────┐                         │
              │   Log Parser  │◄─────System Logs        │
              └──────┬────────┘                         │
                     ▼                                  │
            ┌────────────────────┐                      │
            │   AI Reasoning Core│                      │
            └──────┬──────┬──────┘                      │
                   ▼      ▼                             │
      ┌──────────────┐ ┌──────────────┐                 │
      │  Memory Store│ │  Tool Layer  │◄──External APIs │
      └─────┬────────┘ └────┬─────────┘                 │
            ▼               ▼                           │
      ┌──────────────┐ ┌───────────────┐                │
      │  Reflection  │ │ Curiosity AI  │                │
      └─────┬────────┘ └────┬──────────┘                │
            ▼               ▼                           │
     ┌─────────────┐ ┌─────────────────┐                │
     │Feedback Loop│ │ Report Generator│                │
     └─────────────┘ └─────────────────┘                │

----------------------------------------------------------------------------------------
🗂️ 12-Week Detailed Sprint Plan

🔧 Phase 1: Core System Setup (Weeks 1–3)

Goal: Lay down the skeleton of T17

Week 1

Finalize architecture

Set up GitHub, version control, project boards

Design modular folder structure

Define AGI traits to simulate (reasoning, reflection, curiosity)

Write README with project overview, goals, and usage

Week 2

Build main.py, CLI interface

Implement log_parser.py

Create configs/prompt_templates.json

Develop base prompts for log summarization and threat detection

Week 3

Implement ai_brain.py

Implement threat_engine.py with basic brute-force logic

Test against sample log files

Begin using local LLM via LM Studio or Ollama

⚙️ Phase 2: Intelligence Layer (Weeks 4–6)

Goal: Add reasoning, memory, and adaptability

Week 4

Implement memory.py using ChromaDB or SQLite

Store threat detections, log summaries

Enable embedding-based log retrieval

Week 5

Implement reflection.py

Compare present detections vs. memory

Create similarity scoring + output visualization

Week 6

Implement feedback_loop.py

Allow user to confirm/reject AI suggestions

Create logs of improvements to prompts/logic

🧠 Phase 3: Cognitive Boost (Weeks 7–9)

Goal: Simulate AGI-like reasoning and curiosity

Week 7

Implement curiosity.py

Score entropy and input gaps in logs

Let AI generate follow-up analysis tasks

Week 8

Implement reward_engine.py

Simulate reinforcement for good questions or accurate reflections

Add point tracking via local JSON ledger

Week 9

Add tools: Nmap, VirusTotal, WHOIS

Allow dynamic scan triggers on flagged logs or IPs

Enable fallback to local-only tools if offline

📊 Phase 4: Output & Simulation (Weeks 10–12)

Goal: Complete usable outputs and simulate defensive behavior

Week 10

Implement report_generator.py

Create Markdown or PDF reports summarizing daily events

Week 11

Add autonomous_defense.py

Simulate IP bans, alert generation

Provide summary of suggested actions, not direct execution (for safety)

Week 12

Final test run and demo

Code cleanup + documentation

Tag v1.0 release and write RELEASE.md

-----------------------------------------------------------------------------------

🧬 Future Upgrades: T17 ➞ Tau

Feature Type

Description

✨ Self-Rewriting Logic

Tau rewrites and evolves its own prompt structure based on reflection

🧠 Emotion Mapping

Add pseudo-emotions based on severity, urgency, or confidence

🔁 Real-Time Streaming

Integrate live log feeds via Syslog/Splunk/ELK stack

🔍 Multimodal Input

Support webcam, mic, and visual input for AGI evolution (TOME fork)

🔒 Closed Environment

Isolate Tau in an offline VM to simulate safe cognitive loops

________________________________________________________________________________________________________________

✅ Summary

T17 is not just a tool — it’s a self-improving cybersecurity assistant. 
Its structure allows for AGI-simulated traits: reflection, curiosity, 
and adaptive reasoning. This roadmap ensures a functional prototype is 
ready in 12 weeks while preparing for the leap to Tau — a semi-autonomous, 
self-aware digital security companion.

Next Steps:

Continue with ai_brain.py

Build each module with isolation and safety in mind

Keep ethical boundaries and privacy as core constraints

