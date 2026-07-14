# Scoring Rules

This document describes how the Phishing URL Risk Analyzer turns a URL's static
indicators into a risk score and label. All logic lives in
`src/phishing_url_analyzer/scorer.py`; the values below mirror the constants
defined there.

The scoring is **entirely rule-based and static** — no machine learning, and no
network, DNS, or URL interaction. Every point is traceable to a rule.

## Risk labels and score ranges

The final (capped) score maps to a label:

| Score range | Label            |
| ----------- | ---------------- |
| 0–24        | Low Risk         |
| 25–59       | Suspicious       |
| 60–100      | Likely Phishing  |

Input that is blank or fails structural validation (e.g. `!!!`, invalid
hostname syntax) is reported as **Invalid URL** with a score of `0`. Invalid
input is **never** scored or labelled as phishing.

## Indicator weights

| Indicator | Condition | Points |
| --------- | --------- | ------ |
| Missing HTTPS | scheme is not `https` | +10 |
| IP address used as hostname | host is a literal IPv4/IPv6 address | +25 |
| localhost / `*.localhost` hostname | host is `localhost` or `*.localhost` | +10 |
| Explicit port | a port is present in the URL | +8 |
| `@` symbol in URL | URL contains `@` | +25 |
| Suspicious keyword(s) | each unique keyword found | +8 each, capped at +24 |
| Excessive URL length | length of the original URL > 100 | +15 |
| Many subdomains | subdomain label count ≥ 3 | +15 |
| Many dots | dot count ≥ 5 | +10 |
| Many hyphens | hyphen count ≥ 4 | +10 |
| Query string present | URL has a query string | +5 |
| Fragment present | URL has a fragment | +3 |

### Suspicious keywords

Matched as case-insensitive substrings of the original URL:

`login`, `verify`, `secure`, `account`, `update`, `bank`, `password`,
`signin`, `confirm`, `billing`

Each **unique** keyword contributes +8, and the keyword contribution is capped
at **+24** (i.e. three or more keywords count the same as three).

## Score cap

The sum of all triggered indicators is **capped at 100**. A URL that
accumulates more than 100 raw points is still reported as `100`. The list of
triggered indicators retains the true per-indicator points, so the raw total may
exceed the displayed score — this is intentional and visible in the output.

## Invalid input handling

If parsing fails or the hostname is not syntactically valid, `score_url`
returns:

- `risk_score`: `0`
- `risk_label`: `Invalid URL`
- `triggered_indicators`: `[]`
- `recommendation`: guidance to enter a complete, valid URL

A hostname is considered valid if it is a literal IP address, `localhost` /
`*.localhost`, or one or more dot-separated labels of 1–63 letters, digits, or
hyphens (not starting or ending with a hyphen).

## Limitations of heuristic scoring

- Weights and thresholds are **illustrative**, chosen for explainability rather
  than tuned against a labelled dataset. The score signals relative suspicion,
  not a probability of phishing.
- Keyword matching is a naive substring check, so legitimate URLs containing
  words like `login` or `account` will accrue points (false positives).
- Legitimate development patterns (explicit ports, IP hosts, `localhost`) are
  treated as risk signals.
- The tool analyses only the URL string — never page content, certificates,
  redirects, or reputation — so it **cannot confirm** whether a site is safe or
  malicious.