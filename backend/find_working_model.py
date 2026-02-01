import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("❌ Error: GEMINI_API_KEY not found in .env")
    exit(1)

genai.configure(api_key=api_key)

print(f"Key loaded: {api_key[:5]}...{api_key[-5:]}")
print("-" * 50)
print("TESTING MODEL AVAILABILITY")
print("-" * 50)

candidates = [
    'gemini-1.5-flash',
    'gemini-1.5-flash-latest',
    'gemini-flash-latest',
    'gemini-1.5-pro',
    'gemini-pro',
    'gemini-1.0-pro'
]

working_model = None

for model_name in candidates:
    print(f"\nTesting model: '{model_name}'...")
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content("Reply with 'OK'")
        print(f"SUCCESS! {model_name} responded: {response.text.strip()}")
        working_model = model_name
        break
    except Exception as e:
        print(f"FAILED {model_name}: {e}")

print("-" * 50)
if working_model:
    print(f"FINAL VERDICT: Use model '{working_model}' in main.py")
else:
    print("ALL MODELS FAILED. Check API Key or Library Version.")
    print("Listing ALL available models reported by API:")
    try:
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                print(f"- {m.name}")
    except Exception as e:
        print(f"Could not list models: {e}")
