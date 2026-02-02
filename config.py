import os
from dotenv import load_dotenv

# Force load the .env file from the current directory
load_dotenv()

# Get the keys and provide a clear error if they are missing
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
API_KEY = os.getenv("HONEYPOT_API_KEY", "secret123")

# Debug print (you can remove this once it works)
if not GEMINI_API_KEY:
    print("❌ ERROR: GEMINI_API_KEY is missing from environment variables!")
else:
    print("✅ GEMINI_API_KEY found.")