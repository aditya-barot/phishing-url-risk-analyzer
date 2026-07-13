# Phishing URL Risk Analyzer

> **Status: 🟢 Milestone 3 complete.** The tool can now parse URLs, extract
> static indicators, and produce an explainable rule-based risk score from
> Python. A web UI is not built yet.

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

As of Milestone 3, the tool can also **produce an explainable risk score** via
`score_url()`. It applies a transparent, rule-based system to the extracted
features and returns a numeric `risk_score` from 0 to 100, a `risk_label`,
a list of `triggered_indicators`, and a safety `recommendation`.

Each triggered indicator includes its name, point value, and a plain-language
explanation. There is **no machine learning** and still **no network activity**:
every point is traceable to a documented rule. Blank or invalid input is reported
as `Invalid URL`, never as phishing.

The tool is currently usable from Python code. A Streamlit web interface is
planned next.

## Implemented features

- [x] Accept a URL and safely parse it into structured components
- [x] Extract URL-based static indicators
- [x] Compute a transparent, weighted risk score
- [x] Produce human-readable explanations for triggered indicators
- [x] Classify URLs as `Low Risk`, `Suspicious`, `Likely Phishing`, or `Invalid URL`
- [x] Unit tests covering parsing, feature extraction, and scoring

## Planned features

- [ ] Interactive Streamlit UI for entering a URL and viewing results
- [ ] Example inputs and outputs in the README
- [ ] Final documentation polish with screenshots
- [ ] Optional design notes explaining scoring rules and limitations

## Planned tech stack

| Area              | Tool                                  |
| ----------------- | ------------------------------------- |
| Language          | Python 3.11+                          |
| URL parsing       | `urllib` standard library             |
| Domain parsing    | `tldextract`                          |
| Scoring           | Rule-based Python logic               |
| UI                | `streamlit`                           |
| Testing           | `pytest`                              |
| Version control   | Git + GitHub                          |

## Project structure

```text
phishing-url-risk-analyzer/
├── src/
│   └── phishing_url_analyzer/
│       ├── parser.py          # Safe URL parsing logic
│       ├── features.py        # Static URL indicator extraction
│       └── scorer.py          # Explainable rule-based risk scoring
├── tests/
│   ├── test_parser.py         # Parser unit tests
│   ├── test_features.py       # Feature extraction unit tests
│   └── test_scorer.py         # Scoring engine unit tests
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

## Usage from Python

```python
from phishing_url_analyzer.scorer import score_url

result = score_url("http://secure-login.example.com/verify-account")

print(result["risk_score"])
print(result["risk_label"])
print(result["recommendation"])

for indicator in result["triggered_indicators"]:
    print(indicator["name"], indicator["points"])
    print(indicator["explanation"])
```

## Risk labels

| Label              | Score range | Meaning |
| ------------------ | ----------- | ------- |
| `Invalid URL`      | N/A         | Input could not be parsed as a usable URL or domain |
| `Low Risk`         | 0–24        | Few or no suspicious URL-based indicators detected |
| `Suspicious`       | 25–59       | Multiple warning signs detected; user should verify carefully |
| `Likely Phishing`  | 60–100      | Strong phishing-style indicators detected |

## Roadmap

| Milestone | Goal                                             | Status         |
| --------- | ------------------------------------------------ | -------------- |
| 0         | Project setup, structure, and documentation      | ✅ Complete    |
| 1         | Safe URL parsing into structured components      | ✅ Complete    |
| 2         | URL feature / indicator extraction               | ✅ Complete    |
| 3         | Explainable, weighted risk scoring               | ✅ Complete    |
| 4         | Streamlit UI                                     | ⏳ Planned     |
| 5         | Test suite and documentation polish              | ⏳ Planned     |

## Disclaimer

This tool is for **educational and defensive** purposes only. It performs static
analysis of URL strings and does not fetch, visit, resolve, scrape, or interact
with any URL. It provides heuristic guidance and should not be relied upon as
the sole basis for security decisions.

A low-risk result does not guarantee that a website is safe. A high-risk result
does not prove that a website is malicious. The output should be treated as
URL-based guidance only.

## License

Released under the [MIT License](LICENSE).