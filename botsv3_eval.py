#!/usr/bin/env python3
# botsv3_eval.py — T17 BOTSv3 Evaluation Script
# Run from T17 root: python botsv3_eval.py

import sys
import os
import csv
import json
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.log_parser import parse_log
from core.curiosity import score_input
from core.ai_brain import AIBrain
from core.reflection import reflect
from core.memory import save_to_memory, load_memory

# ── CONFIGURATION ─────────────────────────────────────────────
BOTSV3_DIR   = "botsv3"
RESULTS_FILE = "botsv3/evaluation_results.json"
REPORT_FILE  = "botsv3/T17_BOTSv3_Evaluation_Report.txt"
MAX_PER_FILE = 30

# ── EVAL FILES ────────────────────────────────────────────────
EVAL_FILES = {
    "PowerShell.csv":           {"mitre": "T1059.001", "name": "PowerShell Execution",    "field": "Message",    "tactic": "Execution"},
    "Failed_logins.csv":        {"mitre": "T1110",     "name": "Brute Force",             "field": "Message",    "tactic": "Credential Access"},
    "Privilege_escalation.csv": {"mitre": "T1068",     "name": "Privilege Escalation",    "field": "Privileges", "tactic": "Privilege Escalation"},
    "Privilege_escalation2.csv":{"mitre": "T1068",     "name": "Privileged Service Call", "field": "Privileges", "tactic": "Privilege Escalation"},
    "Network_scanning.csv":     {"mitre": "T1046",     "name": "Network Service Scanning","field": "src_ip",     "tactic": "Discovery"},
    "Process_creation.csv":     {"mitre": "T1059",     "name": "Process Creation",        "field": "Message",    "tactic": "Execution"},
}

def extract_log_text(row, field_hint):
    """Extract meaningful text from a CSV row."""
    # Network scanning — build descriptive string
    if "src_ip" in row and "dest_port" in row:
        return f"port scan detected {row.get('src_ip','')} scanning port {row.get('dest_port','')} count {row.get('count','')}"

    # Privilege escalation
    if "Privileges" in row and row.get("Privileges", "").strip():
        account = row.get("Account_Name", "unknown")
        priv    = row.get("Privileges", "")
        host    = row.get("host", "")
        return f"EventCode=4673 privileged service called {priv} Account: {account} Host: {host} privilege escalation"

    # Message field — most Windows event logs
    if "Message" in row and row.get("Message", "").strip():
        return row["Message"].strip()[:300]

    # Failed logins
    if "Account_Name" in row:
        account = row.get("Account_Name", "unknown")
        source  = row.get("Source_Network_Address", "unknown")
        reason  = row.get("Failure_Reason", "")
        return f"EventCode=4625 failed login Account: {account} Source: {source} {reason}"

    return " ".join(str(v) for v in row.values() if v)[:300]

def run_evaluation():
    print("\n" + "="*60)
    print("  T17 BOTSv3 EVALUATION")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    # Clear memory
    with open("data/memory.json", "w") as f:
        json.dump([], f)

    brain  = AIBrain()
    results = {}

    total_tested   = 0
    total_detected = 0
    total_tp       = 0
    total_fp       = 0
    total_fn       = 0

    for filename, meta in EVAL_FILES.items():
        filepath = os.path.join(BOTSV3_DIR, filename)
        if not os.path.exists(filepath):
            print(f"⚠️  Skipping {filename} — not found")
            continue

        print(f"\n── {meta['name']} ({meta['mitre']})")

        cat = {
            "mitre":    meta["mitre"],
            "name":     meta["name"],
            "tactic":   meta["tactic"],
            "tested":   0,
            "detected": 0,
            "missed":   0,
            "details":  []
        }

        with open(filepath, "r", encoding="utf-8-sig", errors="ignore") as f:
            reader = csv.DictReader(f)
            rows   = list(reader)

        sample = rows[:MAX_PER_FILE]
        print(f"   Testing {len(sample)} entries...")

        for i, row in enumerate(sample):
            log_text = extract_log_text(row, meta["field"])
            if not log_text or len(log_text) < 5:
                continue

            cat["tested"] += 1
            total_tested  += 1

            log_entry = parse_log(log_text)
            score     = score_input(log_text, log_entry)

            if score < 4:
                cat["missed"] += 1
                total_fn      += 1
                cat["details"].append({
                    "log": log_text[:80], "score": score,
                    "detected": False, "reason": "Below threshold"
                })
                continue

            brain_result = brain.analyse(log_text, score=score)
            report       = reflect(brain_result)

            detected = report.get("status") == "threat_report"
            mitre_id = report.get("mitre", {}).get("id", "T0000")
            conf     = report.get("confidence", 0)
            sev      = report.get("severity", "unknown")

            if detected:
                cat["detected"] += 1
                total_detected  += 1
                total_tp        += 1
                status = f"✅ {mitre_id} | {sev.upper()} | {conf}/100"
            else:
                cat["missed"] += 1
                total_fn      += 1
                status = f"❌ MISSED"

            cat["details"].append({
                "log": log_text[:80], "score": score,
                "detected": detected, "mitre": mitre_id,
                "confidence": conf, "severity": sev
            })

            if i < 3 or detected:
                print(f"   [{i+1:02d}] Score:{score} | {status}")

            time.sleep(0.3)

        dr = cat["detected"] / cat["tested"] * 100 if cat["tested"] > 0 else 0
        print(f"   → {cat['detected']}/{cat['tested']} detected ({dr:.1f}%)")
        results[filename] = cat

    # ── METRICS ───────────────────────────────────────────────
    for fname, cat in results.items():
        expected = cat["mitre"]
        for d in cat["details"]:
            detected_mitre = d.get("mitre", "")
            if d.get("detected") and not detected_mitre.startswith(expected[:5]):
                total_fp += 1
                total_tp  = max(0, total_tp - 1)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1        = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    # ── SUMMARY ───────────────────────────────────────────────
    print("\n" + "="*60)
    print("  EVALUATION RESULTS")
    print("="*60)
    print(f"  Total logs tested:    {total_tested}")
    print(f"  Threats detected:     {total_detected}")
    print(f"  Missed (FN):          {total_fn}")
    print(f"  False positives (FP): {total_fp}")
    if total_tested > 0:
        print(f"  Detection rate:       {total_detected/total_tested*100:.1f}%")
    print(f"  Precision:            {precision:.3f} ({precision*100:.1f}%)")
    print(f"  Recall:               {recall:.3f} ({recall*100:.1f}%)")
    print(f"  F1 Score:             {f1:.3f} ({f1*100:.1f}%)")
    print("="*60)

    # ── SAVE ──────────────────────────────────────────────────
    final = {
        "timestamp":      datetime.now().isoformat(),
        "total_tested":   total_tested,
        "total_detected": total_detected,
        "total_fn":       total_fn,
        "total_fp":       total_fp,
        "precision":      round(precision, 3),
        "recall":         round(recall, 3),
        "f1_score":       round(f1, 3),
        "categories":     results
    }

    os.makedirs(BOTSV3_DIR, exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(final, f, indent=2)

    generate_report(final)
    print(f"\n📄 Report saved to {REPORT_FILE}")
    print(f"💾 Results saved to {RESULTS_FILE}")
    return final

def generate_report(data):
    div  = "=" * 60
    thin = "-" * 60
    lines = []

    lines.append(div)
    lines.append("  T17 BOTSv3 EVALUATION REPORT")
    lines.append("  Offline AI-Powered Cybersecurity Framework")
    lines.append(div)
    lines.append(f"  Generated:      {data['timestamp'][:19]}")
    lines.append(f"  Dataset:        Splunk Boss of the SOC v3 (BOTSv3)")
    lines.append(f"  Logs tested:    {data['total_tested']}")
    lines.append(f"  Threats found:  {data['total_detected']}")
    lines.append(div)
    lines.append("")

    seen = set()
    for fname, cat in data["categories"].items():
        key = cat["name"]
        if key in seen:
            continue
        seen.add(key)
        dr = cat["detected"]/cat["tested"]*100 if cat["tested"] > 0 else 0
        lines.append(f"  {cat['name']} ({cat['mitre']})")
        lines.append(thin)
        lines.append(f"  Tested:    {cat['tested']}")
        lines.append(f"  Detected:  {cat['detected']}")
        lines.append(f"  Missed:    {cat['missed']}")
        lines.append(f"  Rate:      {dr:.1f}%")
        lines.append("")

    lines.append(div)
    lines.append("  OVERALL METRICS")
    lines.append(thin)
    if data["total_tested"] > 0:
        dr = data["total_detected"] / data["total_tested"] * 100
        lines.append(f"  Detection rate:  {data['total_detected']}/{data['total_tested']} ({dr:.1f}%)")
    lines.append(f"  Precision:       {data['precision']} ({data['precision']*100:.1f}%)")
    lines.append(f"  Recall:          {data['recall']} ({data['recall']*100:.1f}%)")
    lines.append(f"  F1 Score:        {data['f1_score']} ({data['f1_score']*100:.1f}%)")
    lines.append(div)
    lines.append("")
    lines.append("  Generated by T17 — Offline AI Cybersecurity Framework")
    lines.append("  100% Local  •  No Cloud  •  MITRE ATT&CK Mapped")
    lines.append(div)

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

if __name__ == "__main__":
    run_evaluation()
