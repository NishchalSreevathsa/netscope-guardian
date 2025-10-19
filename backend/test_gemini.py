import os
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

api_key = os.getenv('GEMINI_API_KEY')

print(f"API Key loaded: {api_key[:20]}..." if api_key else "No API key found!")

if not api_key:
    print("ERROR: No API key in .env file")
    exit(1)

# Test the API key
try:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.0-flash-exp')
    response = model.generate_content("Say hello")
    print("✅ API Key is VALID!")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"❌ API Key is INVALID: {e}")