# t17.py — T17 Command Line Interface
# Usage:
#   python t17.py scan logs\security.log
#   python t17.py analyse "powershell -enc abc123"
#   python t17.py live

import sys
import os
import argparse

# Add core to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.log_parser import parse_logs, parse_log
from core.curiosity import score_input, analyze_novelty
from core.ai_brain import AIBrain
from core.reflection import reflect, print_report
from core.memory import save_to_memory, search_memory

# ── BANNER ────────────────────────────────────────────────────
def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║          T17 — Cybersecurity AI Agent            ║
║     Offline  •  Local LLM  •  MITRE Mapped       ║
╚══════════════════════════════════════════════════╝
    """)

# ── CORE PIPELINE ─────────────────────────────────────────────
def run_pipeline(raw_logs: list, brain: AIBrain):
    """
    Runs the full T17 pipeline on a list of raw log strings.
    curiosity → ai_brain → reflection → report
    """
    structured_logs = parse_logs(raw_logs)
    print(f"📂 Loaded {len(structured_logs)} log entries\n")

    flagged = 0

    for log in structured_logs:
        raw_text = log.get("raw", "").strip()
        if not raw_text:
            continue

        # Score it
        curiosity_score = score_input(raw_text, log)

        print(f"── {raw_text[:65]}")
        print(f"   Score: {curiosity_score}/10", end="  ")

        # Too low — skip
        if curiosity_score < 4:
            print("⬇️  Not suspicious — skipping")
            continue

        # Check memory
        existing = search_memory(log)
        if existing:
            print(f"📂 Known threat from memory")
            continue

        # Send to AI
        print(f"🧠 Analysing with AI...")
        brain_result = brain.analyse(raw_text, score=curiosity_score)
        report = reflect(brain_result)

        # Print report
        print_report(report)
        flagged += 1

        # Save to memory
        save_to_memory({
            "raw":        raw_text,
            "ip":         log.get("ip", "unknown"),
            "event":      log.get("event", "unknown"),
            "protocol":   log.get("protocol", "unknown"),
            "severity":   report.get("severity"),
            "confidence": report.get("confidence"),
            "mitre_id":   report.get("mitre", {}).get("id")
        })

    print(f"\n{'='*50}")
    print(f"  Scan complete — {flagged} threat(s) detected")
    print(f"{'='*50}\n")

# ── COMMAND: SCAN ─────────────────────────────────────────────
def cmd_scan(filepath: str, brain: AIBrain):
    """
    Scan a log file.
    Usage: python t17.py scan logs/ecurity.log
    """
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        print(f"   Make sure the file exists and the path is correct.")
        sys.exit(1)

    print(f"🔍 Scanning: {filepath}\n")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw_logs = f.readlines()

    if not raw_logs:
        print("⚠️  File is empty.")
        sys.exit(1)

    run_pipeline(raw_logs, brain)

# ── COMMAND: ANALYSE ──────────────────────────────────────────
def cmd_analyse(text: str, brain: AIBrain):
    """
    Analyse a single line of text directly.
    Usage: python t17.py analyse "powershell -enc abc123"
    """
    print(f"🔍 Analysing: {text}\n")
    run_pipeline([text], brain)

# ── COMMAND: LIVE ─────────────────────────────────────────────
def cmd_live(brain: AIBrain):
    """
    Read real Windows Event Logs from this machine and analyse them.
    Usage: python t17.py live
    """
    print("🔴 Reading live Windows Security logs...\n")

    # Export Windows logs to a temp file
    temp_file = "logs\\live_export.log"
    os.makedirs("logs", exist_ok=True)

    exit_code = os.system(
        f'wevtutil qe Security /c:100 /f:text > {temp_file} 2>nul'
    )

    if not os.path.exists(temp_file) or os.path.getsize(temp_file) == 0:
        print("⚠️  Could not read Windows Event Logs.")
        print("   Try running PowerShell as Administrator.")
        sys.exit(1)

    print(f"✅ Exported Windows logs to {temp_file}")
    cmd_scan(temp_file, brain)

# ── MAIN ──────────────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="t17",
        description="T17 — Offline AI Cybersecurity Threat Detection"
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a log file"
    )
    scan_parser.add_argument(
        "filepath",
        help="Path to log file e.g. logs\\security.log"
    )

    # analyse command
    analyse_parser = subparsers.add_parser(
        "analyse",
        help="Analyse a single line of text"
    )
    analyse_parser.add_argument(
        "text",
        help='Text to analyse e.g. "powershell -enc abc"'
    )

    # live command
    subparsers.add_parser(
        "live",
        help="Read and analyse real Windows Event Logs"
    )

    args = parser.parse_args()

    # Show help if no command given
    if not args.command:
        parser.print_help()
        print("\n  Examples:")
        print("  python t17.py scan logs\\security.log")
        print('  python t17.py analyse "powershell -enc abc123"')
        print("  python t17.py live\n")
        sys.exit(0)

    # Initialise AI brain once — shared across all commands
    print("⚙️  Loading AI brain...")
    brain = AIBrain()
    print("✅ Ready\n")

    # Route to correct command
    if args.command == "scan":
        cmd_scan(args.filepath, brain)
    elif args.command == "analyse":
        cmd_analyse(args.text, brain)
    elif args.command == "live":
        cmd_live(brain)

if __name__ == "__main__":
    main()