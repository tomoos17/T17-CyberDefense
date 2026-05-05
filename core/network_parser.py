# core/network_parser.py — T17 Network Traffic Analysis
# Analyses .pcap files using Scapy for network-level threat detection

import math
import os
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── SUSPICIOUS PORTS ─────────────────────────────────────────
SUSPICIOUS_PORTS = {
    22:    "SSH",
    23:    "Telnet",
    445:   "SMB",
    3389:  "RDP",
    4444:  "Metasploit default",
    5555:  "Android Debug / C2",
    6666:  "Common C2 port",
    8080:  "HTTP alternate",
    1337:  "Common hacker port",
    31337: "Elite/Back Orifice",
}

# ── ENTROPY CALCULATION ───────────────────────────────────────
def calculate_entropy(data: bytes) -> float:
    """High entropy = possibly encrypted or encoded payload."""
    if not data or len(data) < 4:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return round(entropy, 2)

# ── PACKET ANALYSER ───────────────────────────────────────────
def analyse_pcap(filepath: str) -> list:
    """
    Read a .pcap file and return a list of suspicious flow summaries
    ready to feed into the T17 pipeline.
    """
    if not SCAPY_AVAILABLE:
        return [{
            "raw":      "Scapy not installed — run: pip install scapy",
            "event":    "Module Error",
            "ip":       None,
            "protocol": "Unknown"
        }]
    filepath = os.path.normpath(filepath)
    if not os.path.exists(filepath):
        return [{
            "raw":      f"File not found: {filepath}",
            "event":    "File Error",
            "ip":       None,
            "protocol": "Unknown"
        }]
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return [{
            "raw":      f"Could not read pcap: {str(e)}",
            "event":    "Parse Error",
            "ip":       None,
            "protocol": "Unknown"
        }]

    # Track flows and DNS queries
    flows        = defaultdict(list)
    dns_queries  = []
    port_targets = defaultdict(set)

    for pkt in packets:
        if IP not in pkt:
            continue

        src   = pkt[IP].src
        dst   = pkt[IP].dst
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"

        # Get port
        dport = 0
        if TCP in pkt:
            dport = pkt[TCP].dport
        elif UDP in pkt:
            dport = pkt[UDP].dport

        # Get payload entropy
        payload = bytes(pkt[IP].payload) if pkt[IP].payload else b""
        entropy = calculate_entropy(payload)

        # Get TCP flags
        flags = str(pkt[TCP].flags) if TCP in pkt else ""

        # Track flow
        flow_key = f"{src}->{dst}"
        flows[flow_key].append({
            "dport":   dport,
            "entropy": entropy,
            "flags":   flags,
            "size":    len(payload)
        })

        # Track port scanning — same src hitting many ports on same dst
        port_targets[f"{src}->{dst}"].add(dport)

        # DNS queries
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            try:
                query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                dns_queries.append({"src": src, "query": query})
            except Exception:
                pass

    # ── BUILD SUMMARIES ───────────────────────────────────────
    summaries = []

    for flow_key, pkts in flows.items():
        if not pkts:
            continue

        src, dst     = flow_key.split("->")
        count        = len(pkts)
        avg_entropy  = sum(p["entropy"] for p in pkts) / count
        total_bytes  = sum(p["size"] for p in pkts)
        ports_hit    = port_targets[flow_key]
        all_flags    = set(p["flags"] for p in pkts)

        # ── DETECT THREATS ────────────────────────────────────

        # Port scan — many different ports from same source
        if len(ports_hit) > 10:
            summaries.append({
                "raw":      f"Port scan detected: {src} scanned {len(ports_hit)} ports on {dst}",
                "event":    "Port Scan",
                "ip":       src,
                "protocol": "TCP",
                "detail":   f"Ports targeted: {sorted(list(ports_hit))[:10]}..."
            })

        # SYN flood — many SYN flags, no established connections
        syn_count = sum(1 for p in pkts if "S" in p["flags"] and "A" not in p["flags"])
        if syn_count > 20:
            summaries.append({
                "raw":      f"SYN flood detected: {src} sent {syn_count} SYN packets to {dst}",
                "event":    "SYN Flood",
                "ip":       src,
                "protocol": "TCP",
                "detail":   f"Total packets: {count}"
            })

        # High entropy large outbound — possible data exfiltration
        if avg_entropy > 7.0 and total_bytes > 10000:
            summaries.append({
                "raw":      f"Possible exfiltration: {src} sent {total_bytes} bytes to {dst} with high entropy ({avg_entropy})",
                "event":    "Data Exfiltration",
                "ip":       src,
                "protocol": "TCP/UDP",
                "detail":   f"Entropy: {avg_entropy} — possibly encrypted data leaving network"
            })

        # Connection to suspicious port
        for port in ports_hit:
            if port in SUSPICIOUS_PORTS:
                summaries.append({
                    "raw":      f"Connection to suspicious port: {src} connected to {dst}:{port} ({SUSPICIOUS_PORTS[port]})",
                    "event":    "Suspicious Port Connection",
                    "ip":       src,
                    "protocol": "TCP",
                    "detail":   f"Port {port} is known for: {SUSPICIOUS_PORTS[port]}"
                })
                break

        # C2 beaconing — regular small packets to same destination
        if count > 10 and total_bytes < 5000 and count / max(total_bytes, 1) > 0.01:
            summaries.append({
                "raw":      f"Possible C2 beaconing: {src} sent {count} small packets to {dst}",
                "event":    "C2 Beaconing",
                "ip":       src,
                "protocol": "TCP/UDP",
                "detail":   f"Regular small packets suggest command and control traffic"
            })

    # DNS tunnelling — unusually long domain names
    for q in dns_queries:
        query = q["query"]
        if len(query) > 50:
            summaries.append({
                "raw":      f"Possible DNS tunnelling: {q['src']} queried unusually long domain: {query}",
                "event":    "DNS Tunnelling",
                "ip":       q["src"],
                "protocol": "DNS",
                "detail":   f"Domain length {len(query)} chars — normal domains are under 30"
            })

    if not summaries:
        summaries.append({
            "raw":      f"No suspicious network activity detected in {filepath}",
            "event":    "Clean",
            "ip":       None,
            "protocol": "N/A"
        })

    return summaries