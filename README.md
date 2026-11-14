# Suspicion 🛡️

**Suspicion** is a hybrid security analyzer combining deterministic heuristics with LLM semantic intelligence to detect phishing, smishing, and social engineering lures.

## Features

- **Dual-Layer Analysis Engine**:
  - **Deterministic Heuristics**: Regex pattern recognition, typosquatting domain analysis (Levenshtein distance), and SPF/DKIM/DMARC email header verification.
  - **AI Semantic Forensic Reasoning**: Evaluates psychological manipulation tactics (pretexting, artificial urgency, institutional authority) and generates tailored threat summaries and response action plans via Google Gemini LLM (with intelligent rule-based semantic synthesis fallback).
- **Zero-Dependency Python Backend**: Lightweight, portable backend (`server.py`) powered entirely by Python standard library.
- **Real-Time Visual Highlighting**: Inlines flagged phrases with contextual category tooltips.
- **Emoji-Free Guidance**: Structured, professional safety procedures.
- **Privacy First**: Deterministic analysis runs on-premises; external AI invocation is opt-in.

## Architecture

- **Backend**: Python 3 (`server.py`), native `http.server` + `urllib.request` REST pipeline.
- **API**: `POST /api/analyze`
- **Frontend**: Vanilla ES6+ HTML/CSS/JS, Inter + JetBrains Mono typography, scalable inline SVG icons.

## Running Locally

1. Start the backend server:
   ```bash
   python3 server.py
   ```
2. Navigate to `http://localhost:8000`.
3. (Optional) Enter your Gemini API key in **Advanced Settings** to activate neural LLM semantic inspection, or run in rule-based semantic mode without an API key.
