"""
engines/auth_checks.py

Authentication / sender validation engine.

Gmail's receiving MTA already performs SPF, DKIM, and DMARC
verification before a message lands in the mailbox, and stamps the
verdict into the `Authentication-Results` header. This engine parses
that header (with a `Received-SPF` fallback for older-style SPF
results) rather than re-implementing DNS/crypto verification.

It also checks DMARC alignment -- whether the visible From: domain
matches the domain that was actually authenticated -- since that is
a strong signal against spoofed sender addresses.
"""

import re
from email.utils import parseaddr


# ======================================================================
# HEADER HELPERS
# ======================================================================


def get_header(headers: list, name: str) -> str:
    """
    Case-insensitive header lookup from a Gmail payload headers list.
    """
    name = name.lower()

    for header in headers:
        if header.get("name", "").lower() == name:
            return header.get("value", "")

    return ""


def parse_authentication_results(auth_header: str) -> dict:
    """
    Parse Gmail's Authentication-Results header into a dict like:

        {
            "spf": "pass",
            "dkim": "fail",
            "dmarc": "pass"
        }

    Gmail's header looks something like:

        mx.google.com;
        dkim=pass header.i=@example.com header.s=selector header.b=abc123;
        spf=pass (google.com: domain of foo@example.com designates
            1.2.3.4 as permitted sender) smtp.mailfrom=foo@example.com;
        dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
    """

    results = {}

    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(
            rf"\b{mechanism}=(\w+)",
            auth_header,
            re.IGNORECASE,
        )

        results[mechanism] = (
            match.group(1).lower()
            if match
            else "none"
        )

    return results


def parse_received_spf(received_spf_header: str) -> str:
    """
    Fallback for older-style SPF results.

    Example:

        Received-SPF: pass (google.com: domain of ...)
    """

    match = re.match(
        r"^\s*(\w+)",
        received_spf_header,
    )

    return match.group(1).lower() if match else "none"


def domain_from_header_from(auth_header: str) -> str:
    """
    Extract the domain used by DMARC from:

        header.from=example.com
    """

    match = re.search(
        r"\bheader\.from=([a-zA-Z0-9.-]+)",
        auth_header,
        re.IGNORECASE,
    )

    return match.group(1).lower() if match else ""


def domain_from_smtp_mailfrom(auth_header: str) -> str:
    """
    Extract the SMTP envelope sender domain (the actual MAIL FROM the
    receiving MTA talked to) from:

        smtp.mailfrom=foo@example.com
        smtp.mailfrom=example.com

    This is a distinct signal from `header.from=` above: header.from is
    the domain DMARC aligns against, but the envelope sender is never
    shown to the recipient and can legitimately (mailing lists, ESPs)
    or maliciously differ from both the visible From and the DMARC
    domain.
    """

    match = re.search(
        r"\bsmtp\.mailfrom=([^\s;]+)",
        auth_header,
        re.IGNORECASE,
    )

    if not match:
        return ""

    value = match.group(1)

    if "@" in value:
        value = value.rsplit("@", 1)[1]

    return value.strip().lower()


def domain_from_address(address: str) -> str:
    """
    Extract the domain from a normal RFC-style From header.

    Examples:

        user@example.com
        John Smith <user@example.com>

    Returns an empty string when no valid address/domain is found.
    """

    _, parsed_address = parseaddr(address)

    if "@" not in parsed_address:
        return ""

    domain = parsed_address.rsplit("@", 1)[1].strip().lower()

    return domain


# ======================================================================
# DMARC ALIGNMENT
# ======================================================================


def get_organizational_domain(domain: str) -> str:
    """
    Return a simple organizational-domain approximation.

    Examples:

        mail.example.com -> example.com
        example.com      -> example.com

    This intentionally does not attempt to implement the Public Suffix
    List. Full PSL-aware parsing can be added later if needed.

    For the current engine this gives us relaxed alignment behavior for
    ordinary domains while keeping the implementation dependency-free.
    """

    domain = domain.strip(".").lower()

    if not domain:
        return ""

    parts = domain.split(".")

    if len(parts) <= 2:
        return domain

    return ".".join(parts[-2:])


def check_dmarc_alignment(
    visible_domain: str,
    authenticated_domain: str,
) -> str:
    """
    Determine DMARC alignment between the visible From domain and the
    domain reported by Authentication-Results.

    Returns one of:

        "aligned"
        "misaligned"
        "unknown"

    Relaxed alignment is used here, meaning subdomains of the same
    organizational domain are considered aligned.

    Examples:

        example.com vs example.com
            -> aligned

        mail.example.com vs example.com
            -> aligned

        example.com vs attacker.com
            -> misaligned

        "" vs example.com
            -> unknown
    """

    if not visible_domain or not authenticated_domain:
        return "unknown"

    visible_org = get_organizational_domain(visible_domain)
    authenticated_org = get_organizational_domain(authenticated_domain)

    if visible_org == authenticated_org:
        return "aligned"

    return "misaligned"


# ======================================================================
# ENGINE ENTRY POINT
# ======================================================================


async def run_auth_checks(headers: list) -> dict:
    """
    Authentication / sender validation engine.

    Reads Gmail's Authentication-Results header (SPF/DKIM/DMARC) and
    checks:

      - SPF result
      - DKIM result
      - DMARC result
      - DMARC alignment
      - explicit authentication failures

    The engine produces evidence and a preliminary risk score.

    Score:

        0.0 = no authentication concerns detected
        0.5 = suspicious authentication evidence
        0.8 = multiple authentication failures
        1.0 = strong spoofing/authentication failure
    """

    # --------------------------------------------------------------
    # Read relevant headers
    # --------------------------------------------------------------

    auth_results_raw = get_header(
        headers,
        "Authentication-Results",
    )

    received_spf_raw = get_header(
        headers,
        "Received-SPF",
    )

    from_header = get_header(
        headers,
        "From",
    )

    # --------------------------------------------------------------
    # Parse SPF / DKIM / DMARC
    # --------------------------------------------------------------

    results = parse_authentication_results(
        auth_results_raw
    )

    # Authentication-Results is the preferred SPF source.
    # Received-SPF is only used as a fallback.
    if (
        results.get("spf", "none") == "none"
        and received_spf_raw
    ):
        results["spf"] = parse_received_spf(
            received_spf_raw
        )

    spf = results.get("spf", "none")
    dkim = results.get("dkim", "none")
    dmarc = results.get("dmarc", "none")

    # --------------------------------------------------------------
    # Extract sender domains
    # --------------------------------------------------------------

    visible_domain = domain_from_address(
        from_header
    )

    authenticated_domain = domain_from_header_from(
        auth_results_raw
    )

    alignment = check_dmarc_alignment(
        visible_domain,
        authenticated_domain,
    )

    # --------------------------------------------------------------
    # SMTP envelope sender vs visible From
    #
    # This is separate from DMARC alignment above. A message can be
    # fully DMARC-aligned (header.from matches the authenticated
    # domain) while the SMTP envelope sender -- which the recipient
    # never sees -- points somewhere else entirely. Relaxed
    # (organizational-domain) comparison is reused here so that normal
    # subdomain sending infrastructure doesn't get flagged.
    # --------------------------------------------------------------

    envelope_domain = domain_from_smtp_mailfrom(
        auth_results_raw
    )

    envelope_alignment = check_dmarc_alignment(
        visible_domain,
        envelope_domain,
    )

    # --------------------------------------------------------------
    # Authentication failures
    #
    # IMPORTANT:
    #
    # "none" means that no result was available.
    # It is NOT equivalent to an explicit authentication failure.
    # --------------------------------------------------------------

    failures = [
        mechanism
        for mechanism, value in (
            ("spf", spf),
            ("dkim", dkim),
            ("dmarc", dmarc),
        )
        if value in ("fail", "softfail")
    ]

    # --------------------------------------------------------------
    # Findings
    # --------------------------------------------------------------

    findings = []

    if spf in ("fail", "softfail"):
        findings.append(
            f"SPF {spf}"
        )

    if dkim in ("fail", "softfail"):
        findings.append(
            f"DKIM {dkim}"
        )

    if dmarc in ("fail", "softfail"):
        findings.append(
            f"DMARC {dmarc}"
        )

    if alignment == "misaligned":
        findings.append(
            "Visible From domain is misaligned with the "
            "DMARC-authenticated domain"
        )

    if envelope_alignment == "misaligned":
        findings.append(
            "SMTP envelope sender (smtp.mailfrom) domain does not "
            "match the visible From domain"
        )

    # --------------------------------------------------------------
    # Score
    #
    # Explicit DMARC failure is the strongest authentication signal.
    #
    # A known misalignment is also serious, but we do NOT treat
    # unknown alignment as a failure.
    # --------------------------------------------------------------

    if dmarc == "fail":
        score = 1.0
        status = "FAIL"

    elif alignment == "misaligned":
        score = 1.0
        status = "FAIL"

    elif len(failures) >= 2:
        score = 0.8
        status = "FAIL"

    elif failures:
        score = 0.5
        status = "SUSPECT"

    else:
        score = 0.0
        status = "PASS"

    # --------------------------------------------------------------
    # Return normalized engine result
    # --------------------------------------------------------------

    return {
        "score": score,
        "status": status,

        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,

        "visible_domain": visible_domain,
        "authenticated_domain": authenticated_domain,

        "alignment": alignment,

        "envelope_domain": envelope_domain,
        "envelope_alignment": envelope_alignment,

        "failures": failures,
        "findings": findings,
    }