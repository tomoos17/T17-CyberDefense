# core/curiosity.py — T17 Layer 1
# Scores input 0-10: how suspicious is this?

import math
from collections import defaultdict

# Global frequency tracker
event_frequency = defaultdict(int)

# Expanded threat keywords
THREAT_KEYWORDS = [

    # ── POWERSHELL / EXECUTION ────────────────────────────────
    "powershell", "-enc", "-encodedcommand", "-nop", "-noprofile",
    "-windowstyle hidden", "-executionpolicy bypass", "invoke-expression",
    "iex", "invoke-webrequest", "invoke-restmethod", "downloadstring",
    "downloadfile", "start-process", "shellcode", "runspace",

    # ── LOLBins — living off the land ────────────────────────
    "certutil", "certutil.exe", "bitsadmin", "mshta", "mshta.exe",
    "wscript", "cscript", "regsvr32", "rundll32", "msiexec",
    "wmic", "wmic.exe", "forfiles", "pcalua", "syncappvpublishingserver",
    "appsyncpublishingserver", "cmstp", "xwizard", "odbcconf",
    "ieexec", "msconfig", "replace.exe", "ftp.exe", "desktopimgdownldr",

    # ── DOWNLOAD / C2 ─────────────────────────────────────────
    "wget", "curl", "http://", "https://", "ftp://",
    "downloadcradle", "payload", "dropper", "stager",
    "beacon", "c2", "command and control", "reverse shell",
    "bind shell", "netcat", "nc.exe", "ncat", "socat",

    # ── ENCODING / OBFUSCATION ────────────────────────────────
    "base64", "-enc", "frombase64string", "tobase64string",
    "char(", "chr(", "0x", "\\x", "urlencode", "gzip",
    "compress", "decompress", "xor", "rot13", "obfuscat",

    # ── PRIVILEGE ESCALATION ──────────────────────────────────
    "sudo", "su -", "root", "whoami", "net user",
    "net localgroup administrators", "net group", "runas",
    "impersonat", "token", "privilege", "elevat", "bypassuac",
    "uac bypass", "eventvwr", "fodhelper", "sdclt",

    # ── CREDENTIAL ACCESS ─────────────────────────────────────
    "mimikatz", "sekurlsa", "lsass", "hashdump", "ntds.dit",
    "sam database", "credential", "password", "passwd",
    "shadow", "/etc/passwd", "/etc/shadow", "procdump",
    "comsvcs.dll", "minidump", "wdigest", "logonpasswords",

    # ── NETWORK SCANNING / DISCOVERY ─────────────────────────
    "nmap", "port scan", "masscan", "zmap", "arp scan",
    "netdiscover", "ping sweep", "traceroute", "whois",
    "dns lookup", "host discovery", "os detection", "-sS", "-sV",

    # ── LATERAL MOVEMENT ─────────────────────────────────────
    "psexec", "wmiexec", "smbexec", "dcomexec", "atexec",
    "pass the hash", "pass the ticket", "overpass the hash",
    "rdp", "remote desktop", "winrm", "evil-winrm",
    "ssh tunnel", "port forward", "pivot",

    # ── PERSISTENCE ───────────────────────────────────────────
    "scheduled task", "schtasks", "registry run",
    "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
    "startup folder", "autorun", "service install",
    "sc create", "sc config", "new-service", "set-service",
    "cron", "crontab", "rc.local", "init.d", "systemd",
    "backdoor", "webshell", "web shell",

    # ── DEFENCE EVASION ───────────────────────────────────────
    "amsi", "amsibypass", "etw", "etwbypass", "disable defender",
    "set-mppreference", "add-mppreference", "exclusion",
    "clear-eventlog", "wevtutil cl", "remove-item",
    "timestomp", "alternate data stream", ":$data",
    "srm", "shred", "wipe", "antiforensic", "anti-forensic",

    # ── EXFILTRATION ──────────────────────────────────────────
    "exfiltrat", "data theft", "dns tunnel", "dnscat",
    "icmp tunnel", "steganograph", "covert channel",
    "compress-archive", "7zip", "rar", "zip password",

    # ── BRUTE FORCE ───────────────────────────────────────────
    "brute force", "bruteforce", "hydra", "medusa", "hashcat",
    "john the ripper", "password spray", "credential stuffing",
    "failed login", "authentication failure", "invalid password",
    "account locked", "too many attempts",

    # ── MALWARE INDICATORS ────────────────────────────────────
    "malware", "ransomware", "trojan", "rootkit", "keylogger",
    "spyware", "adware", "botnet", "rat ", "remote access trojan",
    "exploit", "shellcode", "rop chain", "heap spray",
    "buffer overflow", "use after free", "format string",

    # ── INJECTION ─────────────────────────────────────────────
    "inject", "dll injection", "process injection",
    "process hollowing", "reflective", "virtualalloc",
    "writeprocessmemory", "createremotethread",
    "setwindowshookex", "queueuserapc",

    # ── LINUX / UNIX SPECIFIC ─────────────────────────────────
    "chmod 777", "chmod +x", "/tmp/", "/dev/shm",
    "bash -i", "bash -c", "sh -i", "python -c",
    "perl -e", "ruby -e", "nc -e", "mkfifo",
    "iptables -F", "ufw disable", "setenforce 0",

    # ── WINDOWS EVENT LOG INDICATORS ──────────────────────────
    "4625", "4648", "4698", "4720", "4726", "1102",
    "4672", "4673", "4688", "4657", "5140",
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
    # Keyword score capped at 5 — more keywords = better coverage
    # but score stays balanced
    kw = min(5, keyword_score(raw_log) * 2)

    if log_entry:
        novelty_raw = analyze_novelty(log_entry).get("score", 0)
        novelty = min(5, round(novelty_raw))
    else:
        novelty = 1

    total = min(10, kw + novelty)
    return total