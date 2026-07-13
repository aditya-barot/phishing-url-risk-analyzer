"""Unit tests for the explainable risk scoring engine (Milestone 3)."""

from phishing_url_analyzer.scorer import score_url


def _names(result):
    return {ind["name"] for ind in result["triggered_indicators"]}


def test_low_risk_https_url():
    result = score_url("https://www.example.com/home")

    assert result["risk_label"] == "Low Risk"
    assert result["risk_score"] == 0
    assert result["triggered_indicators"] == []


def test_http_missing_https_points():
    result = score_url("http://example.com/home")

    assert "Missing HTTPS" in _names(result)
    assert result["risk_score"] == 10
    assert result["risk_label"] == "Low Risk"


def test_ip_hostname_increases_risk():
    result = score_url("http://192.168.0.1/home")

    assert "IP address used as hostname" in _names(result)
    assert result["risk_score"] >= 25


def test_at_symbol_increases_risk():
    result = score_url("http://user@evil.example.com/home")

    assert "'@' symbol in URL" in _names(result)
    assert result["risk_score"] >= 25


def test_suspicious_keywords_contribute_points():
    result = score_url("https://secure-login-verify.example.com/account")

    keyword_indicators = [
        ind for ind in result["triggered_indicators"]
        if ind["name"] == "Suspicious keyword(s)"
    ]
    assert len(keyword_indicators) == 1
    # 4 unique keywords -> 4 * 8 = 32, capped at 24.
    assert keyword_indicators[0]["points"] == 24


def test_excessive_length_contributes_points():
    result = score_url("https://example.com/" + ("a" * 100))

    assert "Excessive URL length" in _names(result)
    assert result["risk_score"] >= 15


def test_many_subdomains_dots_hyphens_contribute():
    result = score_url("http://a-b-c-d-e.f.g.h.example.com/home")
    names = _names(result)

    assert "Many subdomains" in names
    assert "Many dots" in names
    assert "Many hyphens" in names


def test_likely_phishing_example():
    result = score_url("http://login.secure-verify.example.com@10.0.0.1/account")

    assert result["risk_score"] >= 60
    assert result["risk_label"] == "Likely Phishing"


def test_invalid_blank_url():
    result = score_url("")

    assert result["risk_label"] == "Invalid URL"
    assert result["risk_score"] == 0
    assert result["triggered_indicators"] == []
    assert result["recommendation"]  # non-empty guidance


def test_score_capped_at_100():
    # Many strong indicators — raw points exceed 100.
    result = score_url(
        "http://secure-login.example.com@192.168.0.1"
        "/verify-account-update?confirm=1#x"
    )

    raw = sum(ind["points"] for ind in result["triggered_indicators"])
    assert raw > 100
    assert result["risk_score"] == 100


def test_triggered_indicators_have_name_points_explanation():
    result = score_url("http://example.com/home")

    assert len(result["triggered_indicators"]) >= 1
    for ind in result["triggered_indicators"]:
        assert set(ind.keys()) == {"name", "points", "explanation"}
        assert isinstance(ind["points"], int)
        assert isinstance(ind["explanation"], str) and ind["explanation"]


def test_result_preserves_features():
    result = score_url("https://www.example.com/home")

    assert "features" in result
    assert result["features"]["has_https"] is True
    # Parsed fields are preserved too.
    assert result["hostname"] == "www.example.com"


def test_suspicious_label_band():
    result = score_url("http://user@evil.example.com/home")

    assert result["risk_score"] >= 25
    assert result["risk_score"] <= 59
    assert result["risk_label"] == "Suspicious"


def test_invalid_hostless_url():
    result = score_url("http://")

    assert result["risk_label"] == "Invalid URL"
    assert result["risk_score"] == 0
    assert result["triggered_indicators"] == []