# Suspicion 🛡️

**Suspicion** is a client-side scam and phishing message analyzer designed to help users identify deceptive communications before they act.

## Features

- **Heuristic Pattern Analysis**: Detects artificial urgency, coercion, sensitive data solicitation, deceptive links, corporate impersonation, and untraceable payment demands.
- **Lookalike Domain Identification**: Calculates Levenshtein string distance against top consumer brands (e.g. identifying `amaz0n-secure-login.tk` vs `amazon.com`).
- **Sender Address & Header Inspection**: Flags free webmail impersonation, numeric domain variations, SPF/DKIM/DMARC alignment failures, and reply-to discrepancies.
- **Incident Classification**: Identifies scam taxonomies such as Account Security Surcharges, Banking Fraud, Delivery Phishing, or Executive Impersonation.
- **Visual Evidence Highlighting**: Displays flagged text segments inline with interactive severity tooltips.
- **Emoji-Free Guidance**: Structured verification procedures with actionable security steps.
- **100% Client-Side Privacy**: Runs completely within the browser. No message content is ever transmitted to an external server.

## Getting Started

Open `index.html` directly in any modern web browser or serve locally:

```bash
python3 -m http.server 8000
```

Navigate to `http://localhost:8000`.

## Architecture & Typography

- **UI & Controls**: Inter
- **Message Inspection**: JetBrains Mono
- **Icons**: Scalable inline vector icons (SVG)
- **Theme**: Emerald Green with dark mode support
