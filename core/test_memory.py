# core/test_memory.py

from memory import save_to_memory, search_memory

# Sample threat log
new_threat = {
    "ip": "10.0.0.99",
    "event": "Port Scan Detected",
    "protocol": "TCP",
    "raw": "Multiple scan attempts from 10.0.0.99"
}

# Save it
save_to_memory(new_threat)

# Search it again
result = search_memory(new_threat)

print("🔍 Memory Search Result:")
print(result if result else "No match found")
