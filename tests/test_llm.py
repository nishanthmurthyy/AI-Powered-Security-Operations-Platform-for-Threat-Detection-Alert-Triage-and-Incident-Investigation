"""
Test Gemini Connection
"""

from agentic_ai.llm import llm

print(">>> test_llm.py started")

print("=" * 60)
print("GEMINI CONNECTION TEST")
print("=" * 60)

system_prompt = """
You are a SOC analyst.

Return ONLY JSON.

Example:

{
    "summary":"Connection successful",
    "risk":"Low"
}
"""

user_data = {
    "message": "Test connection"
}

result = llm.investigate(
    system_prompt,
    user_data
)

print(result)

print("=" * 60)
print("Test Completed")