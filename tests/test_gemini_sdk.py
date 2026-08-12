import os
import certifi
import traceback

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

print("=" * 60)
print("GEMINI SDK DIRECT TEST")
print("=" * 60)

print("API key loaded :", bool(api_key))
print("Model          :", model)
print("Certifi        :", certifi.where())
print("SSL_CERT_FILE  :", os.getenv("SSL_CERT_FILE"))

try:
    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            api_version="v1"
        )
    )

    print("\nClient created successfully.")
    print("Sending request to Gemini...")

    response = client.models.generate_content(
        model=model,
        contents="Reply with exactly: Gemini connection successful."
    )

    print("\nSUCCESS")
    print(response.text)

except Exception as e:
    print("\nFAILED")
    print(type(e).__name__)
    print(str(e))
    traceback.print_exc()

print("=" * 60)