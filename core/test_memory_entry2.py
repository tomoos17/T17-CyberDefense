from memory import save_to_memory, search_memory

# Another threat entry (not yet in memory)
another_threat = {
    "ip": "172.16.5.5",
    "event": "Multiple Login Failures",
    "protocol": "SSH",
    "raw": "Detected multiple failed login attempts from 172.16.5.5 via SSH"
}

# Check if it already exists in memory
result = search_memory(another_threat)

if result:
    print("🧠 Already known threat:")
    print(result)
else:
    print("🆕 New threat found! Saving to memory...")
    save_to_memory(another_threat)
