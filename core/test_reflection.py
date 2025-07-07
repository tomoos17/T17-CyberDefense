from reflection import reflect_on_threat, save_to_memory

# Define a sample threat
sample_threat = {
    "ip": "192.168.0.10",
    "event": "Login Failure",
    "protocol": "SSH",
    "raw": "Failed login from 192.168.0.10 via SSH"
}

# First, reflect on it (should be new if memory is empty)
result = reflect_on_threat(sample_threat)
print("Reflection Result:", result)

# Now save it to memory
if result["status"] == "new_threat":
    save_to_memory(sample_threat)
    print("Threat saved to memory.")

# Try again (should now be known)
result2 = reflect_on_threat(sample_threat)
print("Reflection Result After Saving:", result2)
