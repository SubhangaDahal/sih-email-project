"""
engines/ai_predictor.py

Semantic AI Threat Prediction Engine.
Extracts social engineering tactics, urgency heuristics, credential harvesting attempts,
and pretexting signals using LLM inference via the AICredits gateway.
"""

import asyncio
import json
import aiohttp

from api_key_fetcher import get_ai_credits_key

# AICredits OpenAI-compatible endpoint
AICREDITS_BASE_URL = "https://api.aicredits.in/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"  # Or "gemini-1.5-flash" depending on your configuration

SYSTEM_PROMPT = """You are an expert cybersecurity email threat intelligence engine.
Your task is to analyze incoming email metadata and body text for social engineering,
credential harvesting, financial pretexting, urgency traps, or executive impersonation.

You must respond ONLY with a single valid JSON object adhering strictly to this schema:
{
  "score": <float between 0.0 and 1.0>,
  "confidence": <float between 0.0 and 1.0>,
  "tactics": [<list of strings like "urgency", "credential_harvesting", "impersonation", "coercion">],
  "reasoning": "<concise analytical summary of why this is or is not phishing>",
  "flagged_phrases": [<list of specific extracted phrases from the email that triggered suspicion>]
}
"""

def extract_email_context(headers: list, body: str) -> tuple[str, str, str]:
    """
    Extracts Subject, From, and truncated body text from raw input.
    """
    subject = "(No Subject)"
    sender = "(Unknown Sender)"

    for header in headers:
        name = header.get("name", "").lower()
        if name == "subject":
            subject = header.get("value", "")
        elif name == "from":
            sender = header.get("value", "")

    # Truncate to bound latency and token consumption
    truncated_body = body[:4000] if body else ""
    return subject, sender, truncated_body


async def run_text_ai(body: str, headers: list = None) -> dict:
    """
    Asynchronous semantic threat analyzer.
    Integrates with the dispatch pipeline via asyncio.gather.
    """
    headers = headers or []
    subject, sender, truncated_body = extract_email_context(headers, body)

    # Short-circuit on completely empty emails
    if not truncated_body.strip() and subject == "(No Subject)":
        return {
            "score": 0.0,
            "confidence": 1.0,
            "tactics": [],
            "reasoning": "Empty email body and subject.",
            "flagged_phrases": []
        }

    api_key = get_ai_credits_key()
    if not api_key:
        print("[AI Predictor] Error: AI_CREDITS_KEY is missing or empty.")
        return {
            "score": 0.0,
            "confidence": 0.0,
            "tactics": [],
            "reasoning": "AI credits API key not configured.",
            "flagged_phrases": [],
            "error": "missing_api_key"
        }

    user_prompt = f"""Analyze this incoming email:
From: {sender}
Subject: {subject}

Body:
{truncated_body}
"""

    payload = {
        "model": DEFAULT_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,  # Low temperature for stable risk scoring
        "response_format": {"type": "json_object"}
    }

    req_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                AICREDITS_BASE_URL,
                headers=req_headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=12)
            ) as resp:
                if resp.status != 200:
                    raw_err = await resp.text()
                    print(f"[AI Predictor] API HTTP {resp.status}: {raw_err}")
                    return {
                        "score": 0.0,
                        "confidence": 0.0,
                        "tactics": [],
                        "reasoning": f"HTTP {resp.status} from inference gateway.",
                        "flagged_phrases": [],
                        "error": f"http_{resp.status}"
                    }

                data = await resp.json()
                raw_content = data["choices"][0]["message"]["content"]
                parsed_res = json.loads(raw_content)

                # Ensure required fields exist
                return {
                    "score": float(parsed_res.get("score", 0.0)),
                    "confidence": float(parsed_res.get("confidence", 0.0)),
                    "tactics": parsed_res.get("tactics", []),
                    "reasoning": parsed_res.get("reasoning", ""),
                    "flagged_phrases": parsed_res.get("flagged_phrases", [])
                }

    except asyncio.TimeoutError:
        print("[AI Predictor] Inference call timed out.")
        return {
            "score": 0.0,
            "confidence": 0.0,
            "tactics": [],
            "reasoning": "AI inference timed out.",
            "flagged_phrases": [],
            "error": "timeout"
        }
    except Exception as exc:
        print(f"[AI Predictor] Unexpected failure: {type(exc).__name__}: {exc}")
        return {
            "score": 0.0,
            "confidence": 0.0,
            "tactics": [],
            "reasoning": f"Inference pipeline exception: {exc}",
            "flagged_phrases": [],
            "error": str(exc)
        }


# ======================================================================
# STANDALONE VERIFICATION RUNNER
# ======================================================================

if __name__ == "__main__":
    async def _test():
        print("[*] Testing AI Predictor with simulated phishing email...")
        dummy_headers = [
            {"name": "From", "value": "security-alert@micros0ft-support.com"},
            {"name": "Subject", "value": "CRITICAL: Your Microsoft 365 Account Will Be Suspended in 24 Hours"}
        ]
        dummy_body = """Dear User,
We detected unauthorized login attempts to your account. Your mailbox will be deactivated immediately unless you verify your password.
Click here to confirm your identity: http://secure-microsoft-verify.ru/login
Failure to respond within 24 hours will lead to permanent deletion.
IT Support Team"""

        res = await run_text_ai(body=dummy_body, headers=dummy_headers)
        print("\n[*] AI Output:")
        print(json.dumps(res, indent=2))

    asyncio.run(_test())