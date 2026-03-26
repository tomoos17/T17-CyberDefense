# main.py — T17 MVP
# Full pipeline: parse → curiosity → ai_brain → reflection → report

from core.log_parser import parse_logs
from core.curiosity import analyze_novelty, keyword_score, score_input
from core.ai_brain import AIBrain
from core.reflection import reflect, print_report
from core.memory import save_to_memory, search_memory

# ── TEST LOGS ─────────────────────────────────────────────────
# In the real version these come from actual log files
raw_logs = [
    "Failed login from 192.168.0.10 via SSH",
    "Accepted login from 10.0.0.22 over HTTP",
    "Failed login from 192.168.0.10 via SSH",
    "Failed login from 192.168.0.10 via SSH",
    "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
    "User root attempted sudo access from 172.16.0.5 via SSH"
]

# ── SETUP ─────────────────────────────────────────────────────
brain = AIBrain()

print("\n" + "="*55)
print("  T17 — STARTING ANALYSIS")
print("="*55)

# ── STEP 1: PARSE LOGS ────────────────────────────────────────
structured_logs = parse_logs(raw_logs)
print(f"\n✅ Parsed {len(structured_logs)} log entries")

# ── STEP 2: LOOP THROUGH EACH LOG ────────────────────────────
for log in structured_logs:

    raw_text = log.get("raw", "")

    # STEP 3: CURIOSITY SCORING
    curiosity_score = score_input(raw_text, log)
    novelty = analyze_novelty(log)

    print(f"\n--- Log: {raw_text[:60]}")
    print(f"    Curiosity score: {curiosity_score}/10")

    # STEP 4: SKIP IF NOT SUSPICIOUS
    if curiosity_score < 4:
        print("    ⬇️  Score too low — skipping")
        continue

    # STEP 5: CHECK MEMORY — seen this before?
    existing = search_memory(log)
    if existing:
        print(f"    📂 Known threat — seen before: {existing}")
        continue

    # STEP 6: AI BRAIN ANALYSIS
    print(f"    🧠 Sending to AI brain...")
    brain_result = brain.analyse(raw_text, score=curiosity_score)

    # STEP 7: REFLECTION — verify + confidence + MITRE
    report = reflect(brain_result)

    # STEP 8: PRINT THE REPORT
    print_report(report)

    # STEP 9: SAVE TO MEMORY
    save_to_memory({
        "raw":        raw_text,
        "ip":         log.get("ip", "unknown"),
        "event":      log.get("event", "unknown"),
        "protocol":   log.get("protocol", "unknown"),
        "severity":   report.get("severity"),
        "confidence": report.get("confidence"),
        "mitre_id":   report.get("mitre", {}).get("id")
    })
    print("    💾 Saved to memory")

print("\n" + "="*55)
print("  T17 — ANALYSIS COMPLETE")
print("="*55 + "\n")