# VibeGuard 🛡️

**Security scanner for AI-generated code.**

Cursor, Claude Code, and Lovable write code fast — but they introduce predictable security vulnerabilities that developers miss because they didn't write the code themselves. VibeGuard catches them before they ship.

---

## What it detects

| # | Check | Severity |
|---|-------|----------|
| 1 | Hardcoded API keys & tokens | Critical |
| 2 | Client-side authentication logic | Critical |
| 3 | SQL injection via string concatenation | Critical |
| 4 | `eval()` / `exec()` with user input | Critical |
| 5 | Exposed database connection strings | Critical |
| 6 | Plain-text passwords / MD5 hashing | Critical |
| 7 | Wildcard CORS configuration | High |
| 8 | Missing rate limiting on auth endpoints | High |
| 9 | Public S3 / GCS / Azure Blob references | High |
| 10 | Unvalidated file upload handlers | High |
| 11 | Debug mode enabled in production | Medium |
| 12 | High-entropy strings (unknown secrets) | High |

---

## Quickstart

### CLI

```bash
git clone https://github.com/Ali2191/vibeguard.git
cd vibeguard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Scan a project:

```bash
# Fast scan — instant results
python -m cli.main scan ./your-project

# With built-in fix suggestions
python -m cli.main scan ./your-project --fix --no-ai

# With AI-powered fix suggestions (requires GEMINI_API_KEY)
python -m cli.main scan ./your-project --fix

# Critical issues only
python -m cli.main scan ./your-project --only critical

# Generate shareable HTML report
python -m cli.main scan ./your-project --fix --no-ai --report

# Raw JSON output
python -m cli.main scan ./your-project --json-out
```

### Web app

```bash
uvicorn api.app:app --reload --port 8000
```

Open http://localhost:8000, upload a ZIP of your project, get a shareable report.

### GitHub Action

Add this to `.github/workflows/vibeguard.yml` in any repo:

```yaml
name: VibeGuard Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run VibeGuard
        uses: Ali2191/vibeguard@main
        with:
          path: '.'
          severity: 'critical'
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
```

---

## Environment variables

Create a `.env` file in the project root:
```
GEMINI_API_KEY=your_gemini_api_key_here
```

Get a free Gemini API key at [aistudio.google.com](https://aistudio.google.com).

---

## Project structure

```
vibeguard/
├── core/
│   ├── scanner.py          # Orchestrates all pattern checks
│   ├── parser.py           # File ingestion and directory walking
│   └── patterns/
│       ├── secrets.py      # Hardcoded keys, entropy scoring
│       ├── auth.py         # Auth logic, password handling
│       ├── injection.py    # SQL injection, eval() abuse
│       ├── storage.py      # Exposed buckets, connection strings
│       └── config.py       # CORS, rate limiting, uploads, debug
├── models/
│   └── gemini_explainer.py # Gemini Flash fix suggestion layer
├── output/
│   ├── report.py           # HTML + JSON report generator
│   └── templates/
│       └── report.html     # Shareable report template
├── cli/
│   └── main.py             # CLI entry point
├── api/
│   └── app.py              # FastAPI web app
├── tests/
│   └── fixtures/           # Intentionally vulnerable test files
├── action.yml              # GitHub Action definition
└── requirements.txt
```

---

## Tech stack

- **Python 3.11+** — core engine
- **Click + Rich** — CLI interface
- **FastAPI** — web API and app
- **Gemini 2.0 Flash** — AI fix suggestions
- **Jinja2** — HTML report templating

---

## Roadmap

- [ ] GitHub URL scanning (no ZIP required)
- [ ] VS Code extension
- [ ] npm package support
- [ ] Hallucinated package detection (registry check)
- [ ] Claude Sonnet deep scan mode
- [ ] Webhook notifications (Slack, Discord)

---

## License

MIT
