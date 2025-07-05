# test_brain.py

from ai_brain import AIBrain
import requests
import json  # ✅ Needed for processing the stream

# 🔁 Real LLaMA 3 handler using Ollama API with streaming
def llama_llm(prompt):
    payload = {
        "model": "llama3",
        "prompt": prompt,
        "stream": True  # 👈 Tell Ollama to send streamed chunks
    }

    try:
        response = requests.post("http://localhost:11434/api/generate", json=payload, stream=True)
        response.raise_for_status()

        result = ""
        for line in response.iter_lines():
            if line:
                data = json.loads(line.decode("utf-8"))
                result += data.get("response", "")

        return result.strip() or "[Empty response]"

    except Exception as e:
        return f"[Error contacting LLaMA 3] {str(e)}"

# 🧠 Initialize the brain
brain = AIBrain()

# 🧪 Use test input
result = brain.process(
    intent="summarize_logs",
    llm_handler=llama_llm,
    log_data="Failed login from 192.168.0.10\nAccepted login from 192.168.0.11"
)

print("=== AI Output ===")
print(result)
