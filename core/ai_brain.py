# ai_brain.py

import json
import requests
import os

def analyze_log(log_entry):
    """
    Sends a log entry to the local LLaMA 3 model via Ollama
    and returns the model's response.
    """
    payload = {
        "model": "llama3",
        "prompt": f"Summarize this log: {log_entry}"
    }

    try:
        response = requests.post("http://localhost:11434/api/generate", json=payload, stream=False)
        result = response.json()
        return result.get("response", "[No response from model]")
    except Exception as e:
        return f"[Error contacting LLaMA 3] {str(e)}"

class AIBrain:
    def __init__(self, prompt_file="configs/prompt_templates.json"):
        self.prompts = self.load_prompts(prompt_file)

    def load_prompts(self, path):
        # Get the current directory of this file (ai_brain.py)
        base_dir = os.path.dirname(os.path.abspath(__file__))

        # Move one level up to project root (T17)
        root_dir = os.path.join(base_dir, "..")

        # Build absolute path to the prompt file
        full_path = os.path.normpath(os.path.join(root_dir, path))

        with open(full_path, 'r') as f:
            return json.load(f)

    def generate_prompt(self, intent, **kwargs):
        template = self.prompts.get(intent, "")
        if not template:
            return "[Error] Unknown prompt type"
        return template.format(**kwargs)

    def process(self, intent, llm_handler, **kwargs):
        prompt = self.generate_prompt(intent, **kwargs)
        response = llm_handler(prompt)
        return response
