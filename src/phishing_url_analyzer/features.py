"""Static URL feature / indicator extraction for the Phishing URL Risk Analyzer.

This module takes the structured output of :func:`parse_url` and derives
security-relevant indicators from it — purely by inspecting the URL string.
It performs **static string analysis only**: no network requests, no DNS
lookups, no fetching, visiting, or resolving of URLs.

Character-level counts are computed from the **trimmed original input**, not
the normalized URL, so the parser-added ``http://`` scheme never inflates
length or character counts. Structural fields (hostname, path, port, etc.)
are taken from the parsed result.

The extracted indicators are intended as inputs to a later scoring engine.
This module deliberately does **not** score, weight, or classify anything.
"""

from __future__ import annotations

import ipaddress

from phishing_url_analyzer.parser import parse_url

# ---------------------------------------------------------------------------
# Explainable configuration — small, documented, and easy to audit.
# ---------------------------------------------------------------------------

# Keywords commonly abused in phishing URLs to imply urgency or legitimacy.
# Matched as case-insensitive substrings of the original URL.
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "password",
    "signin",
    "confirm",
    "billing",
]

# Simple, documented thresholds. These are heuristics, not verdicts.
EXCESSIVE_LENGTH = 100   # url_length      > 100  -> excessive length
MANY_SUBDOMAINS = 3      # subdomain_count >= 3   -> many subdomains
MANY_DOTS = 5            # dot_count       >= 5   -> many dots
MANY_HYPHENS = 4         # hyphen_count    >= 4   -> many hyphens


def _is_ip_hostname(hostname: str) -> bool:
    """Return True if the hostname is a literal IPv4 or IPv6 address.

    Uses the standard library ``ipaddress`` module — this only parses the
    string and never performs a DNS lookup or any network activity.
    """
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_localhost(hostname: str) -> bool:
    """Return True if the hostname is localhost or a *.localhost name."""
    if not hostname:
        return False
    host = hostname.lower()
    return host == "localhost" or host.endswith(".localhost")


def _build_features(parsed: dict) -> dict:
    """Derive the indicator dictionary from a parsed-URL dict.

    Character counts are based on the trimmed original input; structural
    fields come from the parser. All lookups are defensive: on blank or
    invalid input, missing fields default to empty so extraction never raises.
    """
    # Count against the user's actual input, NOT the normalized URL, so the
    # parser-added "http://" scheme does not inflate lengths / char counts.
    original_url = parsed.get("original_url") or ""
    url_str = original_url.strip() if isinstance(original_url, str) else ""
    lowered = url_str.lower()

    hostname = parsed.get("hostname") or ""
    path = parsed.get("path") or ""
    query = parsed.get("query") or ""
    fragment = parsed.get("fragment") or ""
    subdomain = parsed.get("subdomain") or ""

    # Character-level counts over the trimmed original URL string.
    dot_count = url_str.count(".")
    hyphen_count = url_str.count("-")
    at_symbol_count = url_str.count("@")
    digit_count = sum(ch.isdigit() for ch in url_str)
    # "Special" = any non-alphanumeric character (a crude complexity signal).
    special_char_count = sum(1 for ch in url_str if not ch.isalnum())

    # A subdomain of "a.b.c" counts as 3 labels; "" counts as 0.
    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    suspicious_keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]

    return {
        # --- raw counts / lengths ---
        "url_length": len(url_str),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "at_symbol_count": at_symbol_count,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "subdomain_count": subdomain_count,
        # --- structural booleans ---
        "has_https": parsed.get("scheme") == "https",
        "uses_ip_hostname": _is_ip_hostname(hostname),
        "uses_localhost": _is_localhost(hostname),
        "has_port": parsed.get("port") is not None,
        "has_query": bool(query),
        "has_fragment": bool(fragment),
        "has_at_symbol": at_symbol_count > 0,
        # --- keyword indicators ---
        "has_suspicious_keyword": bool(suspicious_keywords_found),
        "suspicious_keywords_found": suspicious_keywords_found,
        # --- threshold-based indicators (see constants above) ---
        "has_excessive_length": len(url_str) > EXCESSIVE_LENGTH,
        "has_many_subdomains": subdomain_count >= MANY_SUBDOMAINS,
        "has_many_dots": dot_count >= MANY_DOTS,
        "has_many_hyphens": hyphen_count >= MANY_HYPHENS,
    }


def extract_features(url: str) -> dict:
    """Parse ``url`` and attach a nested ``features`` dictionary of indicators.

    The return value is the full :func:`parse_url` result plus one extra key,
    ``features``, holding the static indicators derived from it. On blank or
    invalid input, the parsed ``parse_error`` / ``is_valid_basic_url`` fields
    still apply and ``features`` is populated with safe, zeroed defaults.

    Args:
        url: The raw, user-provided URL string.

    Returns:
        A dict containing all parsed-URL fields plus a ``features`` sub-dict.
    """
    parsed = parse_url(url)
    result = dict(parsed)
    result["features"] = _build_features(parsed)
    return result