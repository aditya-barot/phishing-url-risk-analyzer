"""Unit tests for static URL feature extraction (Milestone 2)."""

from phishing_url_analyzer.features import extract_features


def test_normal_https_url():
    result = extract_features("https://www.example.com/home")
    f = result["features"]

    assert f["has_https"] is True
    assert f["uses_ip_hostname"] is False
    assert f["uses_localhost"] is False
    assert f["has_suspicious_keyword"] is False
    assert f["subdomain_count"] == 1
    assert f["has_excessive_length"] is False


def test_url_without_https():
    result = extract_features("http://example.com")
    f = result["features"]

    assert f["has_https"] is False
    assert result["scheme"] == "http"


def test_no_scheme_counts_use_original_input():
    # Counts must reflect the user input, NOT the parser-added "http://".
    result = extract_features("example.com")
    f = result["features"]

    assert result["normalized_url"].startswith("http://")
    assert f["url_length"] == len("example.com")   # 11, not 18
    assert f["special_char_count"] == 1             # just the dot
    assert f["has_https"] is False


def test_suspicious_keyword_detection():
    result = extract_features("http://secure-login.example.com/verify-account")
    f = result["features"]

    assert f["has_suspicious_keyword"] is True
    assert "login" in f["suspicious_keywords_found"]
    assert "verify" in f["suspicious_keywords_found"]
    assert "secure" in f["suspicious_keywords_found"]
    assert "account" in f["suspicious_keywords_found"]


def test_at_symbol_detection():
    result = extract_features("http://user@evil.example.com/login")
    f = result["features"]

    assert f["has_at_symbol"] is True
    assert f["at_symbol_count"] == 1


def test_ip_hostname_detection():
    result = extract_features("http://192.168.0.1/login")
    f = result["features"]

    assert f["uses_ip_hostname"] is True
    assert f["uses_localhost"] is False


def test_localhost_detection():
    result = extract_features("http://localhost:8000/home")
    f = result["features"]

    assert f["uses_localhost"] is True
    assert f["uses_ip_hostname"] is False
    assert f["has_port"] is True


def test_port_detection():
    result = extract_features("https://example.com:8443/home")
    f = result["features"]

    assert f["has_port"] is True
    assert result["port"] == 8443


def test_query_and_fragment_detection():
    result = extract_features("https://example.com/search?q=test#section")
    f = result["features"]

    assert f["has_query"] is True
    assert f["has_fragment"] is True
    assert f["query_length"] > 0


def test_many_subdomains():
    result = extract_features("https://a.b.c.example.com/home")
    f = result["features"]

    assert f["subdomain_count"] >= 3
    assert f["has_many_subdomains"] is True


def test_many_hyphens_detection():
    result = extract_features("http://a-b-c-d-e.example.com/home")
    f = result["features"]

    assert f["hyphen_count"] >= 4
    assert f["has_many_hyphens"] is True


def test_many_dots_detection():
    result = extract_features("http://a.b.c.d.e.example.com/home")
    f = result["features"]

    assert f["dot_count"] >= 5
    assert f["has_many_dots"] is True


def test_excessive_url_length():
    long_url = "https://example.com/" + ("a" * 100)
    result = extract_features(long_url)
    f = result["features"]

    assert f["url_length"] > 100
    assert f["has_excessive_length"] is True


def test_blank_invalid_input():
    result = extract_features("")
    f = result["features"]

    assert result["is_valid_basic_url"] is False
    assert result["parse_error"] is not None
    assert f["url_length"] == 0
    assert f["has_suspicious_keyword"] is False