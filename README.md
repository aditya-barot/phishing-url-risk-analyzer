# Phishing URL Risk Analyzer

> **Status: 🟢 Milestone 2 complete.** The tool can now parse URLs and extract
> static, security-relevant indicators from them. Risk scoring and UI are not
> built yet.

A defensive cybersecurity tool that analyzes a URL and returns an **explainable,
URL-based risk assessment** — classifying it as *low risk*, *suspicious*, or
*likely phishing* using transparent, rule-based indicators.

This project is being built incrementally as a public portfolio piece. Each
milestone is committed separately to keep the history readable and honest about
what does and doesn't work yet.

---

## Motivation

Phishing remains one of the most common initial-access techniques in real-world
attacks. Many URL indicators of phishing are visible **before** a page is ever
loaded — suspicious character patterns, misleading subdomains, IP-address hosts,
excessive length, and lookalike domains, among others.

This tool focuses on those **static, URL-only signals**. It is intended as a
learning and demonstration project for URL analysis and explainable risk
scoring — not as a replacement for enterprise email security or threat
intelligence feeds.

## Current functionality

As of Milestone 1, the project can **safely parse a raw URL string into
structured components** using Python's standard library and `tldextract`.

Given a URL, `parse_url()` returns fields such as the scheme, hostname, port,
path, query, fragment, and the extracted `subdomain`, `domain`, `suffix`, and
`registered_domain`, along with basic validity flags and a `parse_error`
message for bad input.

As of Milestone 2, the project can also **extract static URL indicators** from
the parsed result via `extract_features()`. These include URL and hostname
length, path and query length, dot count, hyphen count, digit count,
special-character count, subdomain count, IP-address or localhost hosts,
presence of a port, query or fragment, an `@` symbol, and matches against a
small, documented list of suspicious keywords.

Character counts are based on the user's original input, not the normalized URL.
Extraction remains **fully static**: the tool does not fetch, visit, resolve,
scrape, or otherwise interact with any URL or host.

Risk scoring, final classification, and the Streamlit user interface are not
implemented yet.

## Implemented features

- [x] Accept a URL and safely parse it into structured components
- [x] Extract URL-based static indicators
- [x] Unit tests covering parsing and feature extraction

## Planned features

- [ ] Compute a transparent, weighted risk score
- [ ] Produce a human-readable explanation for each contributing signal
- [ ] Classify the URL as *low risk*, *suspicious*, or *likely phishing*
- [ ] Interactive Streamlit UI for entering a URL and viewing results
- [ ] Final documentation polish with screenshots and example outputs

## Planned tech stack

| Area              | Tool                                  |
| ----------------- | ------------------------------------- |
| Language          | Python 3.11+                          |
| URL parsing       | `urllib` standard library             |
| Domain parsing    | `tldextract`                          |
| UI                | `streamlit`                           |
| Testing           | `pytest`                              |
| Version control   | Git + GitHub                          |

## Project structure

```text
phishing-url-risk-analyzer/
├── src/
│   └── phishing_url_analyzer/
│       ├── parser.py          # Safe URL parsing logic
│       └── features.py        # Static URL indicator extraction
├── tests/
│   ├── test_parser.py         # Parser unit tests
│   └── test_features.py       # Feature extraction unit tests
├── data/                      # Sample/reference data
├── screenshots/               # UI screenshots for the README, added later
├── docs/                      # Design notes and documentation
├── requirements.txt           # Python dependencies
├── pyproject.toml             # Pytest configuration
├── .env.example               # Example environment variables
└── README.md
```

## Getting started development

```bash
# Clone the repository
git clone https://github.com/aditya-barot/phishing-url-risk-analyzer.git
cd phishing-url-risk-analyzer

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest
```

## Roadmap

| Milestone | Goal                                             | Status         |
| --------- | ------------------------------------------------ | -------------- |
| 0         | Project setup, structure, and documentation      | ✅ Complete    |
| 1         | Safe URL parsing into structured components      | ✅ Complete    |
| 2         | URL feature / indicator extraction               | ✅ Complete    |
| 3         | Explainable, weighted risk scoring               | ⏳ Planned     |
| 4         | Streamlit UI                                     | ⏳ Planned     |
| 5         | Test suite and documentation polish              | ⏳ Planned     |

## Disclaimer

This tool is for **educational and defensive** purposes only. It performs static
analysis of URL strings and does not fetch, visit, resolve, scrape, or interact
with any URL. It provides heuristic guidance and should not be relied upon as
the sole basis for security decisions.

## License

Released under the [MIT License](LICENSE).