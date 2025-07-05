import requests
from core.ai_brain import analyze_log


log_input = "Failed login from 192.168.0.12 via SSH"
result = analyze_log(log_input)
print("🤖 LLaMA 3 replied:\n", result)

def query_llama3(prompt):
    url = "http://localhost:11434/api/generate"
    headers = {"Content-Type": "application/json"}
    data = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(url, json=data, headers=headers)
    result = response.json()
    return result["response"]

# 🧪 Try this sample prompt
prompt = "Summarize this log: Failed login from 10.0.0.55 via SSH"
reply = query_llama3(prompt)
print("🤖 LLaMA 3 replied:\n", reply)
