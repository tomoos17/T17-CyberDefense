# test_brain.py

from ai_brain import AIBrain

# Simulate the AI response
def fake_llm(prompt):
    return "[Fake AI Response] " + prompt[:100] + "..."

# Initialize the brain
brain = AIBrain()

# Use test input
result = brain.process(
    intent="summarize_logs",
    llm_handler=fake_llm,
    log_data="Failed login from 192.168.0.10\nAccepted login from 192.168.0.11"
)

print("=== AI Output ===")
print(result)
