# core/memory.py — T17 persistent threat memory

import json
import os

MEMORY_FILE = "data/memory.json"

def load_memory():
    """Load memory safely — handles empty or corrupt files."""
    if not os.path.exists(MEMORY_FILE):
        return []
    try:
        with open(MEMORY_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return []
            return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        # File is corrupt or empty — start fresh
        return []

def save_to_memory(threat_entry):
    """Save a threat entry to memory."""
    memory = load_memory()
    memory.append(threat_entry)
    os.makedirs("data", exist_ok=True)
    with open(MEMORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(memory, f, indent=2)
    print("✅ Threat saved to memory.")

def search_memory(threat_entry):
    """Search memory for a matching threat."""
    memory = load_memory()
    for item in memory:
        if (
            item.get("ip")       == threat_entry.get("ip") and
            item.get("event")    == threat_entry.get("event") and
            item.get("protocol") == threat_entry.get("protocol")
        ):
            return item
    return None

def clear_memory():
    """Wipe memory — useful for testing."""
    os.makedirs("data", exist_ok=True)
    with open(MEMORY_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f)
    print("🗑️  Memory cleared.")