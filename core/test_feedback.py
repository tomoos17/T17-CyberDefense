# core/test_feedback.py

from feedback_loop import ask_for_feedback

# Simulated threat from AI
sample_threat = {
    "ip": "192.168.0.77",
    "event": "Login Failure",
    "protocol": "SSH",
    "raw": "Failed login from 192.168.0.77 via SSH"
}

ask_for_feedback(sample_threat)
