# ciphertrust-healthcheck

Self-contained Agent Skill

```bash
python scripts/healthcheck.py
python scripts/healthcheck.py --json
python scripts/healthcheck.py --html healthcheck-report.html
```

Requires `CM_BASE` and credentials (`CM_USERNAME`/`CM_PASSWORD`, or `CM_JWT` / `CM_REFRESH_TOKEN`). See [SKILL.md](SKILL.md). To retrieve a JWT token or a refresh token, see [references/auth.md](references/auth.md).

## Layout

```text
lib/cm_client.py
lib/healthcheck/
scripts/healthcheck.py
references/
```
