# Development Guide

> **This is a solo educational project.** External contributions, pull requests,
> and issues are not accepted. This document records internal conventions for the
> maintainer's reference.

---

## Local Setup (Windows)

```powershell
# Clone the repo
git clone https://github.com/wxnkai/marmot-nids.git
cd marmot-nids

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
uv pip install pydantic python-decouple httpx fastapi uvicorn websockets scapy
uv pip install pytest pytest-asyncio pytest-cov ruff black bandit

# Copy environment config
copy .env.example .env
# Edit .env — set SIGNATURE_HMAC_SECRET at minimum

# Run tests
pytest
```

### Linux Setup (Future)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pydantic python-decouple httpx fastapi uvicorn websockets scapy
pip install pytest pytest-asyncio pytest-cov ruff black bandit
cp .env.example .env
pytest
```

---

## Branch Naming

Branches follow the pattern `<type>/<short-description>`:

| Type | Purpose |
|------|---------|
| `feat/` | New feature or capability |
| `fix/` | Bug fix |
| `security/` | Security hardening |
| `refactor/` | Code restructure without behaviour change |
| `test/` | Test additions only |
| `docs/` | Documentation changes only |
| `chore/` | Tooling, CI, config, dependency updates |

---

## Commit Messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]
```

**Scopes:** `capture`, `detection`, `signature`, `llm`, `rag`, `blockchain`,
`api`, `dashboard`, `contracts`, `ci`, `deps`

---

## Code Standards

- **Type annotations:** All function signatures and class attributes must be fully annotated.
- **Docstrings:** Every module, class, and public method requires a docstring.
- **Security:** No hardcoded secrets, IPs, ports, or file paths — use `python-decouple`.
- **Formatting:** `black` for formatting, `ruff` for linting, `bandit` for security scanning.

### Running Checks

```powershell
# Format
black core/ tests/ scripts/

# Lint
ruff check core/ tests/ scripts/

# Security scan
bandit -c .banditrc -r core/ -ll

# Tests
pytest

# Tests with coverage
pytest --cov=core --cov-report=term-missing
```

---

## Testing Requirements

- Every new feature ships with unit tests.
- Tests must not require network access, Ollama, ChromaDB, or elevated privileges.
- Mock external services at the provider/engine boundary.
- Current suite: **217 tests**, all passing.
