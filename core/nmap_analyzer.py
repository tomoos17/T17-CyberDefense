# core/nmap_analyzer.py

import json
import requests
from tools.nmap_tool import run_nmap_scan  # This pulls the function from tools/

def ask_llama_to_analyze(nmap_output):
    try:
        prompt = (
            "You are a cybersecurity analyst.\n"
            "Analyze the following Nmap output and identify any potential security risks:\n\n"
            f"{nmap_output}\n\n"
            "Give a professional summary including port risks, outdated services, and exposure level."
        )
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3", "prompt": prompt, "stream": False}
        )
        result = response.json()
        return result.get("response", "[No response from LLaMA 3]")
    except Exception as e:
        return f"[Error contacting LLaMA 3] {str(e)}"

# ✅ Run it directly
if __name__ == "__main__":
    domain = "scanme.nmap.org"
    nmap_output = run_nmap_scan(domain)
    print("📄 Nmap Output:")
    print(nmap_output)

    analysis = ask_llama_to_analyze(nmap_output)
    print("\n🧠 LLaMA 3 Analysis:")
    print(analysis)
