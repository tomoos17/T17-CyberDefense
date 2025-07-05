# ai_brain.py

import json

class AIBrain:
    def __init__(self, prompt_file="configs/prompt_templates.json"):
        self.prompts = self.load_prompts(prompt_file)

    def load_prompts(self, path):
        with open(path, 'r') as f:
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
