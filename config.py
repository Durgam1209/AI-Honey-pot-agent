import os
from dotenv import load_dotenv

# Force load the .env file from the current directory
load_dotenv()

API_KEY = os.getenv("HONEYPOT_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

if not API_KEY:
    raise ValueError("HONEYPOT_API_KEY missing. Set it in .env or environment.")
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY missing. Set it in .env or environment.")

MAX_HISTORY = int(os.getenv("MAX_HISTORY", "50"))
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "8000"))
