"""Explainable, rule-based risk scoring for the Phishing URL Risk Analyzer.

This module consumes the ``features`` produced by :func:`extract_features`
and turns them into a transparent risk assessment: a numeric score, a label,
the list of triggered indicators (each with its own point value and a
human-readable explanation), and a safety recommendation.

The scoring is **purely rule-based and static** — there is no machine
learning, and no network, DNS, or URL interaction of any kind. Every weight
and threshold is a named constant or an entry in a rules table so the reasoning
behind any score can be inspected and explained.
"""

from __future__ import annotations

from phishing_url_analyzer.features import extract_features

# ---------------------------------------------------------------------------
# Point weights — each rule's contribution to the risk score.
# ---------------------------------------------------------------------------
POINTS_MISSING_HTTPS = 10
POINTS_IP_HOSTNAME = 25
POINTS_LOCALHOST = 10
POINTS_PORT = 8
POINTS_AT_SYMBOL = 25
POINTS_KEYWORD_EACH = 8
POINTS_KEYWORD_CAP = 24
POINTS_EXCESSIVE_LENGTH = 15
POINTS_MANY_SUBDOMAINS = 15
POINTS_MANY_DOTS = 10
POINTS_MANY_HYPHENS = 10
POINTS_QUERY = 5
POINTS_FRAGMENT = 3

MAX_SCORE = 100

# ---------------------------------------------------------------------------
# Labels and their score bands.
# ---------------------------------------------------------------------------
LABEL_INVALID = "Invalid URL"
LABEL_LOW = "Low Risk"
LABEL_SUSPICIOUS = "Suspicious"
LABEL_PHISHING = "Likely Phishing"

# Upper bound (inclusive) of each band, in order.
_LOW_MAX = 24
_SUSPICIOUS_MAX = 59

_RECOMMENDATIONS = {
    LABEL_LOW: (
        "No major URL-based warning signs were detected. This is not a "
        "guarantee of safety — stay cautious with unexpected links."
    ),
    LABEL_SUSPICIOUS: (
        "This URL has some suspicious characteristics. Verify the sender and "
        "the domain carefully before clicking."
    ),
    LABEL_PHISHING: (
        "This URL shows strong phishing indicators. Do not enter credentials "
        "or sensitive information, and verify through an official source."
    ),
    LABEL_INVALID: (
        "The input is not a valid URL. Please enter a complete URL or domain "
        "(for example, https://example.com)."
    ),
}

# ---------------------------------------------------------------------------
# Fixed-point rules. Each has a condition over the feature dict and a fixed
# point value. Variable-point rules (suspicious keywords) are handled below.
# ---------------------------------------------------------------------------
_INDICATOR_RULES = [
    {
        "name": "Missing HTTPS",
        "points": POINTS_MISSING_HTTPS,
        "condition": lambda f: not f["has_https"],
        "explanation": (
            "The URL does not use HTTPS, which can expose users to "
            "interception or spoofing."
        ),
    },
    {
        "name": "IP address used as hostname",
        "points": POINTS_IP_HOSTNAME,
        "condition": lambda f: f["uses_ip_hostname"],
        "explanation": (
            "The hostname is a raw IP address rather than a domain name, a "
            "common trait of phishing and malicious links."
        ),
    },
    {
        "name": "Localhost or internal hostname",
        "points": POINTS_LOCALHOST,
        "condition": lambda f: f["uses_localhost"],
        "explanation": (
            "The hostname points to localhost or an internal-style name, "
            "which is unusual for a legitimate public link."
        ),
    },
    {
        "name": "Explicit port",
        "points": POINTS_PORT,
        "condition": lambda f: f["has_port"],
        "explanation": (
            "The URL specifies an explicit port, which legitimate sites "
            "rarely require and phishing pages sometimes use."
        ),
    },
    {
        "name": "'@' symbol in URL",
        "points": POINTS_AT_SYMBOL,
        "condition": lambda f: f["has_at_symbol"],
        "explanation": (
            "An '@' symbol can hide the real destination by placing the true "
            "host after credential-like text, a classic obfuscation trick."
        ),
    },
    {
        "name": "Excessive URL length",
        "points": POINTS_EXCESSIVE_LENGTH,
        "condition": lambda f: f["has_excessive_length"],
        "explanation": (
            "The URL is unusually long, which is often used to bury a "
            "deceptive domain or confuse the reader."
        ),
    },
    {
        "name": "Many subdomains",
        "points": POINTS_MANY_SUBDOMAINS,
        "condition": lambda f: f["has_many_subdomains"],
        "explanation": (
            "The URL contains many subdomains, which can be used to imitate a "
            "trusted brand within the address."
        ),
    },
    {
        "name": "Many dots",
        "points": POINTS_MANY_DOTS,
        "condition": lambda f: f["has_many_dots"],
        "explanation": (
            "The URL contains an unusually high number of dots, a pattern "
            "associated with deceptive or deeply nested hostnames."
        ),
    },
    {
        "name": "Many hyphens",
        "points": POINTS_MANY_HYPHENS,
        "condition": lambda f: f["has_many_hyphens"],
        "explanation": (
            "The URL contains many hyphens, which are often used in look-alike "
            "domains such as 'secure-login-bank'."
        ),
    },
    {
        "name": "Query string present",
        "points": POINTS_QUERY,
        "condition": lambda f: f["has_query"],
        "explanation": (
            "The URL includes a query string, which can carry tracking "
            "parameters or redirect instructions."
        ),
    },
    {
        "name": "Fragment present",
        "points": POINTS_FRAGMENT,
        "condition": lambda f: f["has_fragment"],
        "explanation": (
            "The URL includes a fragment, which can be used to manipulate what "
            "the page displays after loading."
        ),
    },
]


def _keyword_indicator(features: dict) -> dict | None:
    """Build the suspicious-keyword indicator, if any keywords were found.

    Points are ``POINTS_KEYWORD_EACH`` per unique keyword, capped at
    ``POINTS_KEYWORD_CAP``. Returns None when no keywords matched.
    """
    keywords = features.get("suspicious_keywords_found") or []
    if not keywords:
        return None
    points = min(len(keywords) * POINTS_KEYWORD_EACH, POINTS_KEYWORD_CAP)
    joined = ", ".join(keywords)
    return {
        "name": "Suspicious keyword(s)",
        "points": points,
        "explanation": (
            f"The URL contains security-sensitive keywords ({joined}) often "
            "used in phishing to impersonate login, banking, or account pages."
        ),
    }


def _label_for_score(score: int) -> str:
    """Map a numeric score to a risk label (valid URLs only)."""
    if score <= _LOW_MAX:
        return LABEL_LOW
    if score <= _SUSPICIOUS_MAX:
        return LABEL_SUSPICIOUS
    return LABEL_PHISHING


def score_url(url: str) -> dict:
    """Score a URL and return an explainable risk assessment.

    The return value is the full :func:`extract_features` result (parsed
    fields plus the nested ``features`` dict) augmented with:

        * ``risk_score``           – integer 0–100 (capped)
        * ``risk_label``           – one of the LABEL_* values
        * ``triggered_indicators`` – list of {name, points, explanation}
        * ``recommendation``       – human-readable safety guidance

    Blank or structurally invalid input is never scored as phishing: it
    returns a score of 0 and the ``Invalid URL`` label.

    Args:
        url: The raw, user-provided URL string.

    Returns:
        The augmented result dict.
    """
    result = extract_features(url)
    features = result.get("features", {})

    # Never score invalid/blank input as risky.
    if not result.get("is_valid_basic_url"):
        result["risk_score"] = 0
        result["risk_label"] = LABEL_INVALID
        result["triggered_indicators"] = []
        result["recommendation"] = _RECOMMENDATIONS[LABEL_INVALID]
        return result

    triggered = [
        {
            "name": rule["name"],
            "points": rule["points"],
            "explanation": rule["explanation"],
        }
        for rule in _INDICATOR_RULES
        if rule["condition"](features)
    ]

    keyword_indicator = _keyword_indicator(features)
    if keyword_indicator is not None:
        triggered.append(keyword_indicator)

    raw_score = sum(item["points"] for item in triggered)
    score = min(raw_score, MAX_SCORE)
    label = _label_for_score(score)

    result["risk_score"] = score
    result["risk_label"] = label
    result["triggered_indicators"] = triggered
    result["recommendation"] = _RECOMMENDATIONS[label]
    return result