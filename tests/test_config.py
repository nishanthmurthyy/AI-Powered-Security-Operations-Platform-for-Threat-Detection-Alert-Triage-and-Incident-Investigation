"""
Test configuration loading.
"""

from agentic_ai.config import (
    OPENAI_API_KEY,
    OPENAI_MODEL,
    TEMPERATURE,
    MAX_TOKENS
)

print("=" * 60)
print("CONFIGURATION TEST")
print("=" * 60)

print(f"Model           : {OPENAI_MODEL}")
print(f"Temperature     : {TEMPERATURE}")
print(f"Max Tokens      : {MAX_TOKENS}")

if OPENAI_API_KEY:
    print(f"API Key Loaded  : YES")
    print(f"Key Prefix      : {OPENAI_API_KEY[:10]}...")
else:
    print("API Key Loaded  : NO")

print("=" * 60)