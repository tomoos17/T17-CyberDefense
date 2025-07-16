# core/web_scanner.py

import requests
from bs4 import BeautifulSoup

def extract_forms(url):
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"❌ Error: {e}")
        return []

    soup = BeautifulSoup(res.text, "html.parser")
    forms = soup.find_all("form")

    form_data = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").upper()
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.get("type", "text")
            input_name = input_tag.get("name")
            inputs.append({"type": input_type, "name": input_name})

        form_data.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })

    return form_data


if __name__ == "__main__":
    target_url = "https://juice-shop.herokuapp.com/"
    print(f"🔍 Scanning: {target_url}")
    
    forms = extract_forms(target_url)

    if not forms:
        print("   ❌ No forms found.")
    else:
        print(f"   📝 Found {len(forms)} form(s):\n")
        for idx, form in enumerate(forms, 1):
            print(f"   🔹 Form {idx}:")
            print(f"      ┣ Action : {form['action']}")
            print(f"      ┣ Method : {form['method']}")
            for input_field in form['inputs']:
                print(f"      ┗ Input  : {input_field}")
