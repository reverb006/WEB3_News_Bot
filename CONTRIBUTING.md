# Contributing to Web3 Security Radar

Contributions from smart-contract auditors, security researchers, and Web3 builders are welcome!

## Development Setup

```bash
git clone https://github.com/reverb006/WEB3_News_Bot.git
cd WEB3_News_Bot
python -m venv .venv
# Activate venv, then:
pip install -r requirements.txt
cp .env.example .env
```

## Running the Test Suite

All unit tests use in-memory SQLite and mocked AI/HTTP responses, so they run cleanly without API keys:

```bash
python -m pytest -v
```

## Adding New Intelligence Sources

1. Open `app/collectors/sources.py`.
2. Add a new `SourceConfig` entry to `SOURCES` with an appropriate `SourceType` and `reliability_score` (`0–100`).
3. Verify the RSS/Atom XML feed returns valid items with `python -m app.main collect`.
4. Never delete deprecated feeds — set `is_active=False` with a brief comment explaining why.

## Pull Request Checklist

- Keep secrets, `.env`, SQLite `.db` files, logs, and generated `reports/` or `pocs/` out of commits.
- Add or update unit tests in `tests/` for any new collector, scoring rule, API route, or bot handler.
- Ensure `python -m pytest` passes cleanly with zero failures.
