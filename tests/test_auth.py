import pytest
from engines import run_auth_checks

@pytest.mark.asyncio
async def test_auth_all_pass():
    """Test a perfectly clean authentication header with aligned DMARC."""
    headers = [
        {
            "name": "Authentication-Results",
            "value": "mx.google.com; dkim=pass header.i=@domain.com; spf=pass smtp.mailfrom=domain.com; dmarc=pass header.from=domain.com"
        },
        {
            "name": "From",
            "value": "John Doe <user@domain.com>"
        }
    ]

    result = await run_auth_checks(headers)

    assert result["score"] == 0.0
    assert result["status"] == "PASS"
    assert result["spf"] == "pass"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "pass"
    assert result["alignment"] == "aligned"
    assert len(result["failures"]) == 0

@pytest.mark.asyncio
async def test_dmarc_misalignment_spoof():
    """Test when DMARC passes but the visible From domain doesn't match the authenticated domain."""
    headers = [
        {
            "name": "Authentication-Results",
            "value": "mx.google.com; dkim=pass header.i=@attacker.com; spf=pass smtp.mailfrom=attacker.com; dmarc=pass header.from=attacker.com"
        },
        {
            "name": "From",
            "value": "CEO <ceo@legit-company.com>"
        }
    ]

    result = await run_auth_checks(headers)

    # Misalignment triggers an immediate 1.0 FAIL in your new engine
    assert result["score"] == 1.0
    assert result["status"] == "FAIL"
    assert result["alignment"] == "misaligned"
    assert result["visible_domain"] == "legit-company.com"
    assert result["authenticated_domain"] == "attacker.com"

@pytest.mark.asyncio
async def test_single_mechanism_failure():
    """Test a partial failure (e.g., just SPF softfails) to trigger the 0.5 SUSPECT tier."""
    headers = [
        {
            "name": "Authentication-Results",
            "value": "mx.google.com; dkim=pass header.i=@domain.com; spf=softfail smtp.mailfrom=domain.com; dmarc=pass header.from=domain.com"
        },
        {
            "name": "From",
            "value": "user@domain.com"
        }
    ]

    result = await run_auth_checks(headers)

    # 1 failure = 0.5 SUSPECT
    assert result["score"] == 0.5
    assert result["status"] == "SUSPECT"
    assert result["spf"] == "softfail"
    assert len(result["failures"]) == 1

@pytest.mark.asyncio
async def test_multiple_failures():
    """Test when two mechanisms fail, triggering the 0.8 FAIL tier (excluding DMARC failure)."""
    headers = [
        {
            "name": "Authentication-Results",
            "value": "mx.google.com; dkim=fail; spf=fail smtp.mailfrom=spoof.com; dmarc=none header.from=domain.com"
        },
        {
            "name": "From",
            "value": "user@domain.com"
        }
    ]

    result = await run_auth_checks(headers)

    # >= 2 failures = 0.8 FAIL (as long as explicit DMARC isn't 'fail')
    assert result["score"] == 0.8
    assert result["status"] == "FAIL"
    assert len(result["failures"]) == 2

@pytest.mark.asyncio
async def test_dmarc_explicit_failure():
    """Test when DMARC explicitly fails, maxing out the score to 1.0."""
    headers = [
        {
            "name": "Authentication-Results",
            "value": "mx.google.com; dkim=fail; spf=fail; dmarc=fail header.from=domain.com"
        },
        {
            "name": "From",
            "value": "user@domain.com"
        }
    ]

    result = await run_auth_checks(headers)

    assert result["score"] == 1.0
    assert result["status"] == "FAIL"
    assert result["dmarc"] == "fail"

@pytest.mark.asyncio
async def test_received_spf_fallback():
    """Test if the engine correctly falls back to Received-SPF when the main header lacks SPF info."""
    headers = [
        {
            "name": "Authentication-Results",
            "value": "mx.google.com; dkim=pass header.i=@domain.com; dmarc=pass header.from=domain.com"
        },
        {
            "name": "Received-SPF",
            "value": "pass (google.com: domain of user@domain.com designates 1.2.3.4 as permitted sender)"
        },
        {
            "name": "From",
            "value": "user@domain.com"
        }
    ]

    result = await run_auth_checks(headers)

    # SPF should be extracted from Received-SPF, resulting in a perfect pass
    assert result["score"] == 0.0
    assert result["status"] == "PASS"
    assert result["spf"] == "pass"