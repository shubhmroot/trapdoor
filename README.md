# Trapdoor

**Don't just detect the trap. Expose it.**

Trapdoor is an evidence-first phishing investigation lab. Paste a suspicious URL, email, or SMS to review the warning patterns its local rules detect and the reasons behind them.

> This repository contains a working MVP. The score is a transparent heuristic, not a probability. External reputation checks, AI explanations, and TinyFish browsing are not implemented in this version. No submitted URL is opened or fetched.

## What works

- Flask web application with URL, email, and SMS input modes.
- URL extraction and checks for IP-address hosts, plain HTTP, misleading `@` URL authority, unusual hostnames, encoded or punycode text, and brand names outside a recognized official domain.
- Message checks for urgency, credential requests, threats, and payment context.
- Deduplicated weighted findings, a bounded 0–100 heuristic score, readable evidence, and next-step guidance.
- Responsive interface with safe demonstration examples and an explicit unknown reputation state.
- JSON API at `POST /api/analyze` and health endpoint at `GET /api/health`.

## Run locally

Python 3.10 or newer is recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000). On macOS or Linux, activate the environment with `source .venv/bin/activate`.

No `.env` file or API key is required to run the MVP. The `.env.example` file documents that external providers are not configured.

## API example

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/analyze `
  -Method Post -ContentType 'application/json' `
  -Body '{"text":"URGENT: verify your account at http://paypal-security-check.example.test/login","input_type":"sms"}'
```

The response includes `verdict`, `risk_score`, `score_type`, `summary`, `findings`, extracted URL hosts, reputation status, and recommendations. Possible verdicts are `HIGH_RISK`, `MEDIUM_RISK`, `LOW_RISK`, and `NO_SIGNALS_FOUND`. A clean result means only that the current demo rules did not match; it does not mean safe.

## Safe demo cases

Use the included examples in the interface:

- **Routine update:** ordinary library notice, expected to produce no matched warning rules.
- **Urgent account alert:** uses the reserved `.test` domain and warning language to demonstrate message and URL rules. It is illustrative and not a live site.

Other useful manual inputs include `http://192.0.2.10/sign-in` (reserved documentation IP) and a normal reminder with no link. Never use real credentials or send sensitive personal information to a demo.

## How the score works

Each distinct rule contributes its documented weight in `app.py`. The score is capped at 100. Bands are currently 0 = no rule signals, 1–19 = low, 20–39 = medium, and 40+ = high. The weights and bands are demo choices, not calibrated probabilities or a validated detector. Findings retain their evidence and source so users can review each signal. Missing reputation data stays `not_checked`; it is never treated as benign evidence.

## Project structure

```text
trapdoor/
├── app.py                 # Flask routes and explainable analysis rules
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── script.js
```

## Request flow

```mermaid
flowchart LR
    A[Browser input] -->|POST /api/analyze| B[Flask API]
    B --> C[URL and message rules]
    C --> D[Evidence and heuristic score]
    D -->|JSON report| A
```

## Architecture and security boundaries

The browser sends pasted text to the local Flask endpoint. The analysis code extracts URLs and applies deterministic rules. It does not perform DNS lookups, follow redirects, fetch page content, or query threat-intelligence services. Keep these boundaries in place if adding live lookups later; remote URL fetching needs isolation and strict controls to avoid server-side request forgery.

TinyFish and other external intelligence are future integrations. Add them only after reviewing the provider's current API documentation, terms, and credentials. Keep secrets in a local `.env` file, never commit that file, and never claim provider evidence until the integration actually returns it. AI explanations are also future work; any model should only explain findings returned by the rules and must not manufacture evidence.

## Team

- Shubham Raj — project lead
- Priyam Garg
- Rishabh Choudhary

## Next steps

- Calibrate rules against a documented, harmless evaluation set.
- Add a trusted reputation source with timestamps and explicit unavailable/error states.
- Consider TinyFish web evidence after API access and safe-fetch design are confirmed.
- Add AI-written summaries grounded only in detector output.
- Add report export and deployment after security and privacy review.

## License

No license has been selected. Add one only after the team decides how the project may be reused.

