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

def search_memory(threat):
    memory = load_memory()
    for entry in memory:
        if entry["ip"] == threat["ip"] and entry["event"] == threat["event"] and entry["protocol"] == threat["protocol"]:
            return entry
    return None

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
