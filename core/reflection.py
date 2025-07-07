import json
import os

MEMORY_FILE = "data/memory.json"

def load_memory():
    if not os.path.exists(MEMORY_FILE):
        return []
    with open(MEMORY_FILE, 'r') as f:
        return json.load(f)

def save_to_memory(entry):
    memory = load_memory()
    memory.append(entry)
    with open(MEMORY_FILE, 'w') as f:
        json.dump(memory, f, indent=2)

def is_similar(entry1, entry2):
    return entry1['ip'] == entry2['ip'] and entry1['event'] == entry2['event']

def reflect_on_threat(new_threat):
    memory = load_memory()
    for old in memory:
        if is_similar(new_threat, old):
            return {
                "status": "known_threat",
                "matched_entry": old
            }
    return {
        "status": "new_threat"
    }
