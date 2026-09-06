# SecureNet Console

**Authorized network assessment toolkit** — CLI modules + live web console.

Port scanning, SSL/TLS certificate analysis, HTTP security header scoring, and DNS enumeration — with explicit authorization gates and public-console safety limits.

**Author:** Francis Ngumi Kuria

## Product principles

| Principle | Implementation |
|-----------|----------------|
| Authorized use only | Checkbox + API `authorized: true` required |
| Assist, don’t attack | No exploitation, no brute-force logins |
| Honest scope | Public console blocks private IPs / localhost / metadata |
| Explainable output | Grades, scores, missing headers, open ports |
| Dual interface | CLI for labs · Web console for demos |

## Modules

| Module | What it does |
|--------|----------------|
| **Port scanner** | Concurrent TCP connect scan; common ports or limited ranges |
| **SSL/TLS analyzer** | Cert CN/issuer, expiry, TLS version, advisory grade |
| **HTTP headers** | Weighted score for HSTS, CSP, XFO, etc. |
| **DNS enum** | Core records + light subdomain resolution |

## Quick start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn web.api:app --host 0.0.0.0 --port 8000
```

CLI (authorized targets only):

```bash
python securenet.py --ssl-check example.com
python securenet.py --http-headers https://example.com
```

## Deploy on Render

| Setting | Value |
|---------|--------|
| Build | `pip install -r requirements.txt` |
| Start | `uvicorn web.api:app --host 0.0.0.0 --port $PORT` |

**Why Render:** outbound TCP/TLS and Python runtime. Vercel/Netlify are a poor fit for network assessment tools.

## Legal

Only assess systems you own or have written authorization to test. Unauthorized access is illegal.

MIT License
