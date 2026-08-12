"""
Gemini LLM interface for the Agentic AI SOC platform.
"""

import json

from google import genai
from google.genai import types

from agentic_ai.config import (
    GEMINI_API_KEY,
    GEMINI_MODEL,
    TEMPERATURE,
    MAX_TOKENS,
)


class GeminiLLM:
    """Wrapper around the Google Gemini API."""

    def __init__(self):
        if not GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY is not configured."
            )

        self.client = genai.Client(
            api_key=GEMINI_API_KEY
        )

    def investigate(self, system_prompt, user_data):
        """
        Send security investigation data to Gemini
        and return the generated analysis.
        """

        try:
            # Convert investigation data to readable JSON
            user_prompt = json.dumps(
                user_data,
                indent=2,
                default=str
            )

            full_prompt = f"""
{system_prompt}

Security Investigation Data:
{user_prompt}

Important instructions:
- Analyze the security information carefully.
- Base your response only on the provided evidence.
- Do not invent evidence.
- Return ONLY valid JSON.
"""

            response = self.client.models.generate_content(
                model=GEMINI_MODEL,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=TEMPERATURE,
                    max_output_tokens=MAX_TOKENS,
                ),
            )

            text = response.text.strip()

            # Remove Markdown code fences if Gemini adds them
            if text.startswith("```json"):
                text = text[7:]

            elif text.startswith("```"):
                text = text[3:]

            if text.endswith("```"):
                text = text[:-3]

            text = text.strip()

            # Try to parse Gemini response as JSON
            try:
                return json.loads(text)

            except json.JSONDecodeError:
                return {
                    "status": "success",
                    "raw_response": text
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


# Global LLM instance
llm = GeminiLLM()


if __name__ == "__main__":
    print("=" * 60)
    print("GEMINI LLM MODULE")
    print("=" * 60)
    print("Model          :", GEMINI_MODEL)
    print("API Key Loaded :", bool(GEMINI_API_KEY))
    print("Client         : Initialized")
    print("=" * 60)