# core/curiosity.py

import math
from collections import defaultdict

# Global tracker for frequency
event_frequency = defaultdict(int)

# Keywords we treat as suspicious
THREAT_KEYWORDS = [
    "sudo", "root", "reverse shell", "netcat", "nmap", "brute force"
]

def calculate_entropy_score(event: str) -> float:
    """
    Simulates entropy: higher score means rarer event.
    """
    event_frequency[event] += 1
    frequency = event_frequency[event]
    entropy_score = -math.log2(1 / (frequency + 1))
    return round(entropy_score, 2)

def analyze_novelty(log_entry: dict) -> dict:
    """
    Calculates entropy and classifies novelty level.
    """
    key = f"{log_entry['event']}|{log_entry['ip']}|{log_entry['protocol']}"
    score = calculate_entropy_score(key)
    level = "high" if score <= 1 else "medium" if score <= 3 else "low"

    return {
        "score": score,
        "novelty_level": level
    }

def keyword_score(raw_log: str) -> int:
    """
    Checks how many threat keywords appear in the log.
    """
    return sum(1 for word in THREAT_KEYWORDS if word.lower() in raw_log.lower())

def frequency_score(event: str, memory_logs: list) -> int:
    """
    Counts how many times similar events occurred in memory.
    """
    return sum(1 for entry in memory_logs if event in entry.get("event", ""))
