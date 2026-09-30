# Profiles — albert_server (curated any-iPhone)

`albert_server` uses **API/service** profile (not generic template).

| Profile | First deliverables | Validation |
| --- | --- | --- |
| **API/service (adopted)** | `albert_server.py` `POST /deviceservices/deviceActivation` + `drmHandshake`, `GET /health /ready /metrics /dashboard /firmware`, rate `100/min` `512K`, SQLite WAL `logs/activations.db` + `fairplay.key 0600`, `gunicorn 2×4` | `pytest 118 passed` (`albert` 12 + `security_gate` 14 + `activate_device` 12 + `bootstrap` 5 + `firmware` 5), `ruff`/`bandit` (`B303/B324 nosec` SHA1 ARS), `docker compose config`, `curl /health /ready` |
| Web app | `/dashboard` + `/firmware` HTML (same dark, 2s poll `/api/status` + `firmware` table) | `pytest` `test_firmware_page_html` + `curl /firmware` |
| Worker | `activate_device.py` retries `3` exponential `1s/2s/4s` + `X-Request-ID` | `direct --json` to `18090` |
| Library | `requirements.txt` pinned `flask3.0.0/cryptography48.0.1/pyOpenSSL26.2.0` + hashes via `pip-tools` (roadmap) | `pip check` |

Not adopted: `CLI/desktop` (`idevicerestore` via `libimobiledevice` external), `Infrastructure` (Cloudflare `docs/cloudflare-terraform.md` loopback first, no `infrastructure/terraform/cloudflare`).

Data: `activations` `producttype` dynamic (any `iPhoneXX,Y`), `firmware_cache.json` `0600` 1h TTL live `api.ipsw.me` + local `*.ipsw` overlay (curated 5→15 Pro `iPhone5,1`→`iPhone15,2` (13)).
