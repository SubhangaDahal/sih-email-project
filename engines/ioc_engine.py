"""
engines/ioc_engine.py

IOC / Threat Intelligence Engine.

- URLs found in the email body are extracted, sanitized, and checked
  against Google Safe Browsing's threatMatches:find API.
- File attachments (hashed upstream via extract_attachment_hashes)
  are checked against VirusTotal's v3 file report API.

VirusTotal's public tier is rate-limited to 4 requests/minute.
A Redis-backed sliding-window rate limiter is implemented with an atomic
Lua script to enforce this constraint across any number of concurrent tasks.

Environment variables required:
    SAFE_BROWSING_API_KEY
    VIRUSTOTAL_API_KEY
    REDIS_URL   (defaults to redis://localhost:6379/0)
"""

import asyncio
import base64
import hashlib
import os
import re
import time

import aiohttp
import redis.asyncio as aioredis
from pydantic_settings import BaseSettings, SettingsConfigDict
# ======================================================================
# CONFIGURATION
# ======================================================================
class Settings(BaseSettings):
    SAFE_BROWSING_API_KEY: str
    VIRUS_TOTAL_API_KEY: str
    model_config = SettingsConfigDict(
        env_file='.env',
        extra='ignore',
        env_file_encoding='utf-8'
    )

settings = Settings()

SAFE_BROWSING_API_KEY = settings.SAFE_BROWSING_API_KEY
VIRUSTOTAL_API_KEY = settings.VIRUS_TOTAL_API_KEY

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# VirusTotal public API allows 4 requests / minute globally.
VT_RATE_LIMIT = 4
VT_RATE_WINDOW_SECONDS = 60
VT_RATE_LIMIT_KEY = "vt:rate_limiter"

# Case-insensitive URL extractor
URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


# ======================================================================
# REDIS CLIENT (lazy singleton)
# ======================================================================

_redis_client: "aioredis.Redis | None" = None


def get_redis_client() -> "aioredis.Redis":
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            REDIS_URL,
            decode_responses=True,
        )
    return _redis_client


# ======================================================================
# VIRUSTOTAL RATE LIMITER
# ======================================================================

_VT_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

local count = redis.call('ZCARD', key)

if count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, window + 5)
    return 1
end

local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
if oldest[2] then
    return oldest[2]
end
return "0"
"""


async def acquire_virustotal_slot():
    """
    Block (via non-blocking async sleep) until a VirusTotal slot is
    available under the shared 4-req/60s Redis budget.
    """
    r = get_redis_client()
    script = r.register_script(_VT_RATE_LIMIT_SCRIPT)

    while True:
        now = time.time()
        member = f"{now}:{id(asyncio.current_task())}"

        result = await script(
            keys=[VT_RATE_LIMIT_KEY],
            args=[now, VT_RATE_WINDOW_SECONDS, VT_RATE_LIMIT, member],
        )

        if result == 1 or result == "1":
            return

        oldest_ts = float(result)
        wait_for = max((oldest_ts + VT_RATE_WINDOW_SECONDS) - now, 0.5)
        print(f"[IOC][VT] Rate limit reached, waiting {wait_for:.1f}s")
        await asyncio.sleep(wait_for)


# ======================================================================
# URL EXTRACTION + SAFE BROWSING
# ======================================================================


def extract_urls(body: str) -> list:
    """
    Extract, sanitize, and deduplicate HTTP/HTTPS URLs from text.
    """
    if not body:
        return []

    urls = URL_REGEX.findall(body)
    cleaned = [u.rstrip(".,;:!?)]\"'") for u in urls]

    seen = set()
    deduped = []
    for u in cleaned:
        if u and u not in seen:
            seen.add(u)
            deduped.append(u)

    return deduped


async def check_urls_safe_browsing(urls: list) -> list:
    """
    Query Google Safe Browsing threatMatches:find.
    Returns matched threat entries or an empty list if clean/errored.
    """
    if not urls or not SAFE_BROWSING_API_KEY:
        if not SAFE_BROWSING_API_KEY and urls:
            print("[IOC][SafeBrowsing] Warning: SAFE_BROWSING_API_KEY is not set.")
        return []

    request_body = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:500]],
        },
    }

    params = {"key": SAFE_BROWSING_API_KEY}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                SAFE_BROWSING_URL,
                params=params,
                json=request_body,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    print(f"[IOC][SafeBrowsing] HTTP {resp.status}: {text}")
                    return []

                data = await resp.json()
                return data.get("matches", [])

    except Exception as exc:
        print(f"[IOC][SafeBrowsing] Request error: {type(exc).__name__}: {exc}")
        return []


# ======================================================================
# ATTACHMENT HASHING + VIRUSTOTAL
# ======================================================================


def extract_attachment_hashes(gmail_service, message_id: str, payload: dict) -> list:
    """
    Synchronously traverses MIME structure, decodes data, and hashes attachments.
    Must be called from a worker thread before launching async detection.
    """
    results = []

    def walk(node: dict):
        if not node:
            return

        filename = node.get("filename")
        body = node.get("body", {})

        if filename:
            data = body.get("data")

            # Fetch via Gmail API if attachment is not inlined
            if not data and body.get("attachmentId"):
                try:
                    attachment = (
                        gmail_service.users()
                        .messages()
                        .attachments()
                        .get(
                            userId="me",
                            messageId=message_id,
                            id=body["attachmentId"],
                        )
                        .execute()
                    )
                    data = attachment.get("data")
                except Exception as exc:
                    print(
                        f"[IOC] Attachment fetch error for {filename}: "
                        f"{type(exc).__name__}: {exc}"
                    )

            if data:
                try:
                    raw = base64.urlsafe_b64decode(data)
                    sha256 = hashlib.sha256(raw).hexdigest()
                    results.append({"filename": filename, "sha256": sha256})
                except Exception as exc:
                    print(
                        f"[IOC] Attachment hash failed for {filename}: "
                        f"{type(exc).__name__}: {exc}"
                    )

        for part in node.get("parts", []):
            walk(part)

    walk(payload)
    return results


async def check_file_virustotal(sha256: str) -> dict:
    """
    Queries VirusTotal v3 for a given SHA-256 hash.
    Enforces Redis-based rate limiting before dispatching.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"found": False, "sha256": sha256, "error": "no_api_key"}

    await acquire_virustotal_slot()

    request_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_FILE_URL.format(sha256=sha256)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=request_headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 404:
                    return {"found": False, "sha256": sha256}

                if resp.status == 429:
                    print("[IOC][VT] 429 received, backing off 15s...")
                    await asyncio.sleep(15)
                    return await check_file_virustotal(sha256)

                if resp.status != 200:
                    text = await resp.text()
                    print(f"[IOC][VT] HTTP {resp.status}: {text}")
                    return {
                        "found": False,
                        "sha256": sha256,
                        "error": f"http_{resp.status}",
                    }

                data = await resp.json()

    except Exception as exc:
        print(f"[IOC][VT] Request failed: {type(exc).__name__}: {exc}")
        return {"found": False, "sha256": sha256, "error": str(exc)}

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "found": True,
        "sha256": sha256,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "meaningful_name": attributes.get("meaningful_name"),
    }


# ======================================================================
# ENGINE ENTRY POINT
# ======================================================================


async def run_ioc_intel(body: str, headers: list, attachments: list = None) -> dict:
    """
    Main asynchronous dispatcher for the IOC engine.
    Scans body URLs against Safe Browsing and attachments against VirusTotal.
    """
    urls = extract_urls(body)
    attachments = attachments or []

    vt_tasks = [check_file_virustotal(att["sha256"]) for att in attachments]

    sb_matches, *vt_results = await asyncio.gather(
        check_urls_safe_browsing(urls),
        *vt_tasks,
    )

    malicious_urls = [
        m.get("threat", {}).get("url")
        for m in sb_matches
        if m.get("threat", {}).get("url")
    ]

    malicious_files = [
        {**att, **res}
        for att, res in zip(attachments, vt_results)
        if res.get("found")
        and (res.get("malicious", 0) > 0 or res.get("suspicious", 0) > 0)
    ]

    hits = malicious_urls + [f["filename"] for f in malicious_files]

    score = 0.0
    if malicious_urls:
        score = max(score, 0.9)
    if malicious_files:
        score = max(score, 1.0)

    return {
        "score": score,
        "hits": hits,
        "urls_checked": len(urls),
        "malicious_urls": malicious_urls,
        "safe_browsing_matches": sb_matches,
        "attachments_checked": len(attachments),
        "malicious_files": malicious_files,
        "virustotal_results": vt_results,
    }


# ======================================================================
# STANDALONE TEST RUNNER
# ======================================================================

if __name__ == "__main__":
    async def _test():
        print("[*] Running standalone IOC engine test...")
        test_body = (
            "URGENT: Click here to claim refund: "
            "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/ "
            "and also check https://google.com"
        )
        result = await run_ioc_intel(test_body, headers=[], attachments=[])
        print("[*] Results:")
        print(f"    Score: {result['score']}")
        print(f"    URLs Checked: {result['urls_checked']}")
        print(f"    Malicious URLs: {result['malicious_urls']}")
        print(f"    Hits: {result['hits']}")

    asyncio.run(_test())