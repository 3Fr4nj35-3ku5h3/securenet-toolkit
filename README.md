# SecureNet Console

**Authorized network assessment toolkit** — CLI + web console.

Port scanning, SSL/TLS certificate analysis, HTTP security header scoring, and DNS enumeration, with explicit authorization gates and safety limits on the public console.

**Live demo:** [securenet-toolkit.onrender.com](https://securenet-toolkit.onrender.com/)  
**Author:** Francis Ngumi Kuria

---

## Product principles

| Principle | How it’s applied |
|-----------|------------------|
| Authorized use only | UI checkbox + API requires `"authorized": true` |
| Assist, don’t attack | No exploitation, no credential attacks |
| Honest scope | Public console blocks private IPs, localhost, and metadata hosts |
| Explainable output | Grades, scores, missing headers, open-port lists |
| Dual interface | CLI for labs · web console for interactive demos |

---

## Modules

| Module | Capability |
|--------|------------|
| **Port scanner** | Concurrent TCP connect scan (common set or limited ranges); optional banners |
| **SSL/TLS analyzer** | Certificate CN/issuer, expiry, TLS version, cipher, advisory grade |
| **HTTP headers** | Weighted score for HSTS, CSP, X-Frame-Options, and related headers |
| **DNS enumeration** | Core records + light subdomain resolution |

---

## Project layout

```text
securenet-toolkit/
├── securenet.py          # CLI entry
├── requirements.txt
├── modules/              # port, ssl, http, dns, network mapper
├── utils/                # logger, reporter, helpers
├── web/api.py            # FastAPI console API
└── static/index.html     # Web UI
