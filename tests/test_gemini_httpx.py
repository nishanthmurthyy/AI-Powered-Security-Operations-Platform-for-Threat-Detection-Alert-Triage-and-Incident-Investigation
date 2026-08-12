import os
from dotenv import load_dotenv
import httpx

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

url = (
    f"https://generativelanguage.googleapis.com/v1beta/models"
    f"?key={API_KEY}"
)

try:
    response = httpx.get(url, timeout=20)

    print("Status:", response.status_code)
    print(response.text[:500])

except Exception as e:
    print(type(e))
    print(e)