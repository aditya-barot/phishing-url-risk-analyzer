"""Streamlit interface for the Phishing URL Risk Analyzer.

A thin, local UI layer over :func:`score_url`. It takes a URL, runs the
existing static, rule-based analysis, and presents the result. It performs
no network activity of its own — it never fetches, visits, resolves, or
validates the URL externally. All analysis is the same static string
analysis used from Python.

Run locally with:  streamlit run app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# The analyzer package lives under ``src/`` (src layout). ``streamlit run``
# does not apply the pytest ``pythonpath`` setting, so make the package
# importable here. This only adjusts the import path — no code is changed.
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import streamlit as st

from phishing_url_analyzer.scorer import score_url

# Parsed-URL fields to show in the "Parsed URL details" section (i.e. the
# result keys that are neither the nested features nor the scoring outputs).
PARSED_KEYS = [
    "original_url",
    "normalized_url",
    "scheme",
    "netloc",
    "hostname",
    "port",
    "path",
    "query",
    "fragment",
    "subdomain",
    "domain",
    "suffix",
    "registered_domain",
    "has_scheme",
    "is_valid_basic_url",
    "parse_error",
]

# Maps each risk label to an emoji and the Streamlit callout to render it with.
_LABEL_STYLES = {
    "Low Risk": ("🟢", st.success),
    "Suspicious": ("🟠", st.warning),
    "Likely Phishing": ("🔴", st.error),
    "Invalid URL": ("⚪", st.info),
}


def _render_result(result: dict) -> None:
    """Render a scored result to the page."""
    label = result["risk_label"]
    score = result["risk_score"]

    # Invalid / blank input: show the guidance and stop — nothing to score.
    if label == "Invalid URL":
        st.info(f"⚪ **Invalid URL** — {result['recommendation']}")
        return

    emoji, callout = _LABEL_STYLES.get(label, ("", st.info))
    callout(f"{emoji}  **{label}**  —  Risk score: {score} / 100")
    st.progress(score / 100)

    st.subheader("Recommendation")
    st.write(result["recommendation"])

    st.subheader("Triggered indicators")
    indicators = result["triggered_indicators"]
    if indicators:
        for ind in indicators:
            st.markdown(
                f"- **{ind['name']}** (+{ind['points']}) — {ind['explanation']}"
            )
    else:
        st.write("No URL-based risk indicators were triggered.")

    with st.expander("Parsed URL details"):
        st.json({key: result.get(key) for key in PARSED_KEYS})

    with st.expander("Extracted static features"):
        st.json(result.get("features", {}))


def main() -> None:
    st.set_page_config(page_title="Phishing URL Risk Analyzer", page_icon="🛡️")

    st.title("🛡️ Phishing URL Risk Analyzer")
    st.write(
        "A defensive tool that inspects a URL string and returns an "
        "**explainable, rule-based risk assessment**. Analysis is fully "
        "**static** — the URL is *never* fetched, visited, resolved, or "
        "scraped. Only the text of the URL is examined."
    )
    st.caption(
        "For educational and defensive use. Results are heuristic guidance, "
        "not a guarantee of safety."
    )

    url = st.text_input(
        "Enter a URL to analyze",
        placeholder="https://example.com/login",
    )
    analyze = st.button("Analyze URL")

    if analyze:
        if url.strip():
            _render_result(score_url(url))
        else:
            st.warning("Please enter a URL to analyze.")


if __name__ == "__main__":
    main()