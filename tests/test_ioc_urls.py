"""
tests/test_ioc_urls.py
Unit tests for URL extraction and Safe Browsing lookups in engines/ioc_engine.py.
"""

from unittest.mock import AsyncMock, patch
import pytest

from engines.ioc_engine import check_urls_safe_browsing, extract_urls, run_ioc_intel


# ======================================================================
# URL EXTRACTION TESTS
# ======================================================================

def test_extract_urls_basic_and_deduplication():
    body = (
        "Check this link: https://example.com/login and again https://example.com/login.\n"
        "Also visit http://test-site.org/path?q=1&b=2."
    )
    urls = extract_urls(body)
    assert len(urls) == 2
    assert "https://example.com/login" in urls
    assert "http://test-site.org/path?q=1&b=2" in urls


def test_extract_urls_strips_trailing_punctuation():
    body = (
        "Click here (https://secure-bank.com/reset). "
        "Or check: https://portal.net/auth! "
        "Visit https://docs.org/info?version=1.0, and http://site.com/test;"
    )
    urls = extract_urls(body)
    assert "https://secure-bank.com/reset" in urls
    assert "https://portal.net/auth" in urls
    assert "https://docs.org/info?version=1.0" in urls
    assert "http://site.com/test" in urls


def test_extract_urls_empty_body():
    assert extract_urls("") == []
    assert extract_urls(None) == []


# ======================================================================
# SAFE BROWSING & ENGINE INTEGRATION TESTS
# ======================================================================

@pytest.mark.asyncio
async def test_safe_browsing_flagged_threat():
    """Simulate Safe Browsing returning a positive malware/phishing match."""
    mock_matches = [
        {
            "threatType": "SOCIAL_ENGINEERING",
            "platformType": "ANY_PLATFORM",
            "threat": {"url": "http://malicious-credential-harvest.com/login"},
            "cacheDuration": "300s",
        }
    ]

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"matches": mock_matches})

    with patch("engines.ioc_engine.SAFE_BROWSING_API_KEY", "fake_test_key"), \
            patch("aiohttp.ClientSession.post") as mock_post:
        mock_post.return_value.__aenter__.return_value = mock_resp

        result = await check_urls_safe_browsing(["http://malicious-credential-harvest.com/login"])
        assert len(result) == 1
        assert result[0]["threat"]["url"] == "http://malicious-credential-harvest.com/login"


@pytest.mark.asyncio
async def test_safe_browsing_clean_urls():
    """Simulate Safe Browsing returning no threat matches."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={})

    with patch("engines.ioc_engine.SAFE_BROWSING_API_KEY", "fake_test_key"), \
            patch("aiohttp.ClientSession.post") as mock_post:
        mock_post.return_value.__aenter__.return_value = mock_resp

        result = await check_urls_safe_browsing(["https://google.com", "https://github.com"])
        assert result == []


@pytest.mark.asyncio
async def test_run_ioc_intel_end_to_end_url_only():
    """Test run_ioc_intel scoring when malicious URLs are detected in body text."""
    body = "Action required: update billing details at https://fake-paypal-verify.com/login immediately."

    mock_matches = [
        {
            "threatType": "MALWARE",
            "threat": {"url": "https://fake-paypal-verify.com/login"},
        }
    ]

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"matches": mock_matches})

    with patch("engines.ioc_engine.SAFE_BROWSING_API_KEY", "fake_test_key"), \
            patch("aiohttp.ClientSession.post") as mock_post:
        mock_post.return_value.__aenter__.return_value = mock_resp

        report = await run_ioc_intel(body=body, headers=[], attachments=[])

        assert report["score"] == 0.9
        assert report["urls_checked"] == 1
        assert "https://fake-paypal-verify.com/login" in report["malicious_urls"]
        assert "https://fake-paypal-verify.com/login" in report["hits"]
        assert report["attachments_checked"] == 0