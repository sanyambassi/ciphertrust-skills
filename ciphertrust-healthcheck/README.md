# ciphertrust-healthcheck

Self-contained Agent Skill

```bash
python scripts/healthcheck.py
python scripts/healthcheck.py --json
```

Requires `CM_BASE` and credentials (`CM_USERNAME`/`CM_PASSWORD`, or `CM_JWT` / `CM_REFRESH_TOKEN`). See [SKILL.md](SKILL.md). To retrieve a JWT token or a refresh token, see [references/auth.md](references/auth.md).

## Layout

```text
lib/cm_client.py              # REST client
lib/healthcheck/              # modular checks + runner
scripts/healthcheck.py        # thin CLI entrypoint
references/                   # auth + checklist
```
