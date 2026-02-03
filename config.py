import os
from dotenv import load_dotenv

# Force load the .env file from the current directory
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
API_KEY = os.getenv("HONEYPOT_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "models/gemini-flash-lite-latest")

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY missing. Set it in .env or environment.")
if not API_KEY:
    raise ValueError("HONEYPOT_API_KEY missing. Set it in .env or environment.")

MAX_HISTORY = int(os.getenv("MAX_HISTORY", "50"))
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "8000"))
