# core/feedback_loop.py

import json
import os

FEEDBACK_FILE = "data/feedback_log.json"

def load_feedback():
    if not os.path.exists(FEEDBACK_FILE):
        return []
    with open(FEEDBACK_FILE, 'r') as f:
        return json.load(f)

def save_feedback(entry, user_response):
    feedback_entry = {
        "threat": entry,
        "feedback": user_response
    }
    all_feedback = load_feedback()
    all_feedback.append(feedback_entry)

    with open(FEEDBACK_FILE, 'w') as f:
        json.dump(all_feedback, f, indent=2)

    print("✅ Feedback saved.")

def ask_for_feedback(threat):
    print("\n🔍 Detected Threat:")
    print(json.dumps(threat, indent=2))
    user_input = input("🧠 Was this detection correct? (yes/no): ").strip().lower()
    
    if user_input not in ["yes", "no"]:
        print("⚠️ Invalid input. Please enter 'yes' or 'no'.")
        return

    save_feedback(threat, user_input)
