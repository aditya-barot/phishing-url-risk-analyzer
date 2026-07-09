# Phishing URL Risk Analyzer

> **Status: 🟡 Early setup (Milestone 0 complete).** Project scaffolding and
> environment are in place. Application logic is not implemented yet.

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

## Planned features

- [ ] Accept a URL and safely parse it into structured components
- [ ] Extract URL-based risk indicators (length, subdomain depth, IP-as-host,
      suspicious characters, lookalike/typosquat hints, etc.)
- [ ] Compute a transparent, weighted risk score
- [ ] Produce a **human-readable explanation** for each contributing signal
- [ ] Classify the URL as *low risk*, *suspicious*, or *likely phishing*
- [ ] Interactive Streamlit UI for entering a URL and viewing results
- [ ] Unit tests covering parsing, feature extraction, and scoring

> None of the above is implemented yet. This section is a roadmap, not a claim
> of current functionality.

## Planned tech stack

| Area              | Tool                                  |
| ----------------- | ------------------------------------- |
| Language          | Python 3.11+                          |
| URL parsing       | `urllib` (standard library)           |
| Domain parsing    | `tldextract`                          |
| UI                | `streamlit`                           |
| Testing           | `pytest`                              |
| Version control   | Git + GitHub                          |

## Project structure

```text
phishing-url-risk-analyzer/
├── src/
│   └── phishing_url_analyzer/   # Application package (logic added in later milestones)
├── tests/                       # Unit tests
├── data/                        # Sample/reference data (git-tracked via .gitkeep)
├── screenshots/                 # UI screenshots for the README (added later)
├── docs/                        # Design notes and documentation
├── requirements.txt             # Python dependencies
├── .env.example                 # Example environment variables
└── README.md
```

## Getting started (development)

> These steps set up the environment. There is no runnable application yet.

```bash
# Clone the repository
git clone https://github.com/aditya-barot/phishing-url-risk-analyzer.git
cd phishing-url-risk-analyzer

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\activate         # Windows (PowerShell)

# Install dependencies
pip install -r requirements.txt
```

## Roadmap

| Milestone | Goal                                             | Status         |
| --------- | ------------------------------------------------ | -------------- |
| 0         | Project setup, structure, and documentation      | ✅ Complete    |
| 1         | Safe URL parsing into structured components       | ⏳ Planned     |
| 2         | URL feature / indicator extraction                | ⏳ Planned     |
| 3         | Explainable, weighted risk scoring                | ⏳ Planned     |
| 4         | Streamlit UI                                      | ⏳ Planned     |
| 5         | Test suite and documentation polish               | ⏳ Planned     |

## Disclaimer

This tool is for **educational and defensive** purposes only. It performs static
analysis of URL strings and does not fetch, visit, or interact with any URL. It
provides heuristic guidance and should not be relied upon as the sole basis for
security decisions.

## License

Released under the [MIT License](LICENSE).