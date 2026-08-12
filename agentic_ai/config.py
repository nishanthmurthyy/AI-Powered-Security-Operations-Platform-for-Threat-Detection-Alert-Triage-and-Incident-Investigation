from pathlib import Path
from dotenv import load_dotenv
import os

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-2.5-flash"
)

TEMPERATURE = 0.2

MAX_TOKENS = 1200

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not found.")