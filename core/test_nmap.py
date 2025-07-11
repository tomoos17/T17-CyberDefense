# core/test_nmap.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from tools.nmap_tool import run_nmap_scan

# Sample target — you can replace with a valid IP or domain
target = "scanme.nmap.org"  # Public test domain by Nmap

print(f"🔍 Running Nmap scan on {target}...\n")
result = run_nmap_scan(target)
print("📄 Nmap Scan Output:\n")
print(result)
