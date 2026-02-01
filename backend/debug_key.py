import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load .env
load_dotenv()

api_key = os.getenv('GEMINI_API_KEY')

print("-" * 50)
print("GEMINI API KEY DEBUGGER")
print("-" * 50)

if not api_key:
    print("❌ ERROR: GEMINI_API_KEY not found in .env file!")
    exit(1)

print(f"Key loaded: {api_key[:4]}...{api_key[-4:]} (Length: {len(api_key)})")

try:
    print("\nAttempting to connect to Gemini...")
    genai.configure(api_key=api_key)
    
    print("Listing available models...")
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"- {m.name}")

    model = genai.GenerativeModel('gemini-1.5-pro') # Trying Pro as fallback
    print("Sending test prompt to gemini-1.5-pro...")
    response = model.generate_content("Hello")
    
    print("\nSUCCESS! Gemini is responding.")
    print(f"Response: {response.text}")
    print("-" * 50)
    print("Your API Key is working correctly.")
    print("-" * 50)

except Exception as e:
    print("\nFAILURE! The API Key or Connection failed.")
    print("RAW ERROR DETAILS:")
    print(e)
    print("-" * 50)
    print("RECOMMENDATION:")
    err_str = str(e)
    if "429" in err_str:
        print("-> Your API Key has exceeded its Free Tier quota.")
    elif "400" in err_str or "403" in err_str:
        print("-> Your API Key is INVALID. Please generate a new one.")
    else:
        print("-> Unknown network or library error.")
print("-" * 50)
