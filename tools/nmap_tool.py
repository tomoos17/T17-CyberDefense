
import subprocess

def run_nmap_scan(target):
    try:
        result = subprocess.check_output(['nmap', '-sV', target], text=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"[ERROR] Nmap scan failed: {e}"
