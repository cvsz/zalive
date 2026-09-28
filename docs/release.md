# Release — albert_server

## Versioning
SemVer recommended. Current `1.1-fixed` (health), next `v0.1.0` with `any iPhone curated XR+12/13/14/15` + `/firmware` live cache. Keep `CHANGELOG.md`.

## Release checklist
1. `GPG` commits `EDDSA CD57FEA` (all local commits signed), `pytest 18 passed`, `ruff/bandit 0`, `docker compose config ok`, `gunicorn --check-config`, `curl /health /ready /firmware`.
2. `CHANGELOG.md`: add `v0.1.0 2026-09-28` with any-iPhone + firmware pages + 5e04f52 merge.
3. Push `albert-server` branch then `main` to `cvsz/zalive` (`git push origin albert-server && git checkout main && git merge albert-server && git push origin main`), both GPG-signed.
4. Verify `https://github.com/cvsz/zalive` `main` shows `5e04f52` + `albert-server` branch.
5. Tag: `git tag -s v0.1.0 -m "albert-server any-iPhone + firmware"`; `git push origin v0.1.0`.
6. Publish only from trusted `ci.yml` (ruff+bandit+pytest).

## Rollback
- `git revert` merge commit `5e04f52` or `git checkout 429fff8`; keep `certs/fairplay.key 0600` persisted so activations remain.
- `logs/activations.db` Wal: `sqlite3 logs/activations.db "PRAGMA wal_checkpoint(TRUNCATE);"`
- Restore previous IPSW via `scripts/sha256_manifest.sh --check`.

## Signing
GPG `EDDSA 220A4C8CCC7D2D50 PHIPHAT PHOEMSUK` for git; Docker `cosign` not yet (roadmap).
