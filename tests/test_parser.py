"""Unit tests for the safe URL parser (Milestone 1)."""

from phishing_url_analyzer.parser import parse_url


def test_normal_https_url():
    result = parse_url("https://www.example.com/login")

    assert result["scheme"] == "https"
    assert result["hostname"] == "www.example.com"
    assert result["path"] == "/login"
    assert result["subdomain"] == "www"
    assert result["domain"] == "example"
    assert result["suffix"] == "com"
    assert result["registered_domain"] == "example.com"
    assert result["has_scheme"] is True
    assert result["is_valid_basic_url"] is True
    assert result["parse_error"] is None


def test_url_without_scheme():
    result = parse_url("example.com")

    assert result["has_scheme"] is False
    assert result["normalized_url"].startswith("http://")
    assert result["scheme"] == "http"
    assert result["hostname"] == "example.com"
    assert result["registered_domain"] == "example.com"
    assert result["is_valid_basic_url"] is True
    # The original input is preserved untouched.
    assert result["original_url"] == "example.com"


def test_url_with_subdomain():
    result = parse_url("https://mail.google.com")

    assert result["subdomain"] == "mail"
    assert result["domain"] == "google"
    assert result["suffix"] == "com"
    assert result["registered_domain"] == "google.com"


def test_url_with_path_and_query():
    result = parse_url("https://example.com/search?q=test&lang=en")

    assert result["path"] == "/search"
    assert result["query"] == "q=test&lang=en"
    assert result["fragment"] == ""


def test_url_with_port():
    result = parse_url("https://example.com:8443/home")

    assert result["hostname"] == "example.com"
    assert result["port"] == 8443
    assert result["path"] == "/home"
    assert result["netloc"] == "example.com:8443"


def test_blank_input():
    result = parse_url("   ")

    assert result["is_valid_basic_url"] is False
    assert result["parse_error"] is not None


def test_malformed_input():
    # A scheme with no host — parses structurally but has no hostname.
    result = parse_url("http://")

    assert result["is_valid_basic_url"] is False
    assert result["hostname"] is None


def test_ip_address_hostname_is_structurally_valid():
    result = parse_url("http://192.168.1.1/login")

    assert result["hostname"] == "192.168.1.1"
    assert result["is_valid_basic_url"] is True
    assert result["registered_domain"] == ""


def test_localhost_is_structurally_valid():
    result = parse_url("http://localhost:8000/admin")

    assert result["hostname"] == "localhost"
    assert result["port"] == 8000
    assert result["is_valid_basic_url"] is True
    assert result["registered_domain"] == ""


def test_invalid_hostname_syntax():
    # Junk input parses into a "hostname" but is not valid syntax.
    result = parse_url("!!!")

    assert result["is_valid_basic_url"] is False
    assert result["parse_error"] == "Invalid hostname syntax."