import google.generativeai as genai  
from config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

flash_model = genai.GenerativeModel("gemini-1.5-flash")
pro_model = genai.GenerativeModel("gemini-1.5-pro")
