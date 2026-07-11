"""Safe, static URL parsing for the Phishing URL Risk Analyzer.

This module converts a raw, user-provided URL string into structured
components. It performs **static string analysis only** — it never fetches,
resolves, or otherwise interacts with the URL or its host. No network calls,
no DNS lookups, no browser activity.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract

# Detects a leading URI scheme such as "http://", "https://", or "ftp://".
# We match on "scheme://" rather than trusting urlparse's scheme detection,
# because inputs like "example.com:8080/path" would otherwise be misread as
# using a "example.com" scheme.
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

# Applied only so urllib can parse scheme-less input like "example.com".
# This is a parsing convenience; it does not imply the URL uses HTTP.
_DEFAULT_SCHEME = "http://"

# suffix_list_urls=() forces tldextract to use its bundled public-suffix
# snapshot instead of fetching one over the network. This keeps parsing
# fully offline, consistent with the tool's static-analysis guarantee.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def _empty_result(url: str) -> dict:
    """Return the result dict with all fields defaulted (nothing parsed yet)."""
    return {
        "original_url": url,
        "normalized_url": None,
        "scheme": None,
        "netloc": None,
        "hostname": None,
        "port": None,
        "path": None,
        "query": None,
        "fragment": None,
        "subdomain": None,
        "domain": None,
        "suffix": None,
        "registered_domain": None,
        "has_scheme": False,
        "is_valid_basic_url": False,
        "parse_error": None,
    }


def parse_url(url: str) -> dict:
    """Parse a raw URL string into structured components without any network I/O.

    The input is trimmed and, if it lacks a scheme, given a temporary
    ``http://`` prefix so the standard library can parse it. The original
    string is always preserved in ``original_url``.

    Args:
        url: The raw, user-provided URL string.

    Returns:
        A dict with the following keys:
            original_url, normalized_url, scheme, netloc, hostname, port,
            path, query, fragment, subdomain, domain, suffix,
            registered_domain, has_scheme, is_valid_basic_url, parse_error

        On invalid or empty input, ``parse_error`` holds a human-readable
        message and ``is_valid_basic_url`` is ``False``.
    """
    result = _empty_result(url)

    if not isinstance(url, str):
        result["parse_error"] = "URL must be a string."
        return result

    trimmed = url.strip()
    if not trimmed:
        result["parse_error"] = "URL is empty."
        return result

    has_scheme = bool(_SCHEME_RE.match(trimmed))
    result["has_scheme"] = has_scheme

    normalized = trimmed if has_scheme else _DEFAULT_SCHEME + trimmed
    result["normalized_url"] = normalized

    try:
        parsed = urlparse(normalized)
    except ValueError as exc:
        result["parse_error"] = f"Could not parse URL: {exc}"
        return result

    result["scheme"] = parsed.scheme
    result["netloc"] = parsed.netloc
    result["hostname"] = parsed.hostname
    result["path"] = parsed.path
    result["query"] = parsed.query
    result["fragment"] = parsed.fragment

    # parsed.port raises ValueError for out-of-range or non-numeric ports.
    try:
        result["port"] = parsed.port
    except ValueError:
        result["port"] = None
        result["parse_error"] = "Invalid port in URL."

    ext = _extract(normalized)
    result["subdomain"] = ext.subdomain
    result["domain"] = ext.domain
    result["suffix"] = ext.suffix
    result["registered_domain"] = ext.top_domain_under_public_suffix

    # "Basic" validity: parsing succeeded and a hostname is present. This is a
    # deliberately permissive structural check — IP-address hosts, localhost,
    # and internal hostnames are all considered valid here. Whether such hosts
    # are *risky* is a separate concern handled by later milestones; the
    # public-suffix / registered-domain fields above remain available for that.
    result["is_valid_basic_url"] = bool(
        result["parse_error"] is None
        and result["hostname"]
    )

    return result