from google import genai
from config import GEMINI_API_KEY

client = genai.Client(api_key=GEMINI_API_KEY)

def generate_text(model: str, prompt: str):
    return client.models.generate_content(model=model, contents=prompt)
