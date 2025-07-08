import json
import os

MEMORY_FILE = "data/memory.json"

def save_to_memory(threat_entry):
    if not os.path.exists(MEMORY_FILE):
        data = []
    else:
        with open(MEMORY_FILE, 'r') as f:
            data = json.load(f)

    data.append(threat_entry)

    with open(MEMORY_FILE, 'w') as f:
        json.dump(data, f, indent=2)

    print("✅ Threat saved to memory.")

def search_memory(threat_entry):
    if not os.path.exists(MEMORY_FILE):
        return None

    with open(MEMORY_FILE, 'r') as f:
        data = json.load(f)

    for item in data:
        if (
            item["ip"] == threat_entry["ip"] and
            item["event"] == threat_entry["event"]
        ):
            return item  # Found a match

    return None
