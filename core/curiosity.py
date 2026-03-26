# core/curiosity.py — T17 Layer 1
# Scores input 0-10: how suspicious is this?

import math
from collections import defaultdict

# Global frequency tracker
event_frequency = defaultdict(int)

# Expanded threat keywords
THREAT_KEYWORDS = [
    # System abuse
    "sudo", "root", "reverse shell", "netcat", "nmap",
    "brute force", "failed login", "unauthorized",
    # PowerShell / encoding
    "powershell", "-enc", "base64", "invoke-webrequest",
    "certutil", "wget", "curl", "bypass",
    # Network threats
    "port scan", "syn flood", "dns tunnel", "exfiltrat",
    "lateral", "beacon", "c2", "command and control",
    # Malware indicators
    "malware", "ransomware", "trojan", "exploit",
    "privilege escalat", "scheduled task", "registry"
]

def calculate_entropy_score(event: str) -> float:
    """
    Tracks how often we've seen this event.
    First time = high novelty (suspicious).
    Seen many times = low novelty (probably normal).
    """
    event_frequency[event] += 1
    frequency = event_frequency[event]
    entropy_score = -math.log2(1 / (frequency + 1))
    return round(entropy_score, 2)

def analyze_novelty(log_entry: dict) -> dict:
    """
    Calculates novelty score from the log entry.
    Uses .get() with safe fallbacks so it never crashes
    on missing keys.
    """
    event    = log_entry.get("event",    "unknown")
    ip       = log_entry.get("ip",       "unknown")
    protocol = log_entry.get("protocol", "unknown")

    key   = f"{event}|{ip}|{protocol}"
    score = calculate_entropy_score(key)
    level = "high" if score <= 1 else "medium" if score <= 3 else "low"

    return {
        "score":         score,
        "novelty_level": level
    }

def keyword_score(raw_log: str) -> int:
    """
    Counts how many threat keywords appear in the log.
    Each match adds 1 point — capped at 5 so it
    doesn't overwhelm the novelty score.
    """
    raw_lower = raw_log.lower()
    matches   = sum(1 for word in THREAT_KEYWORDS if word in raw_lower)
    return min(matches, 5)

def frequency_score(event: str, memory_logs: list) -> int:
    """
    Counts how many times this event appeared in memory.
    More occurrences = more suspicious pattern.
    """
    return sum(1 for entry in memory_logs if event in entry.get("event", ""))

def score_input(raw_log: str, log_entry: dict = None) -> int:
    """
    MAIN SCORING FUNCTION — used by main.py
    Combines keyword score + novelty into a single 0-10 score.
    Keywords carry more weight than novelty.
    """
    # Keyword score (0-5) — each match = 2 points, capped at 5
    kw = min(5, keyword_score(raw_log) * 2)

    # Novelty score (0-5)
    if log_entry:
        novelty_raw = analyze_novelty(log_entry).get("score", 0)
        novelty = min(5, round(novelty_raw))
    else:
        novelty = 1

    total = min(10, kw + novelty)
    return total