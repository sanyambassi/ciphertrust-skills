# ciphertrust-key-inventory

Self-contained Agent Skill

```bash
python scripts/inventory.py
python scripts/inventory.py --domain NAME
python scripts/inventory.py --html PATH
python scripts/inventory.py --json
python scripts/inventory.py --csv key-inventory.csv
```

Requires `CM_BASE` and credentials (`CM_USERNAME`/`CM_PASSWORD`, or `CM_JWT` / `CM_REFRESH_TOKEN`). See [SKILL.md](SKILL.md). To retrieve a JWT or refresh token, see [references/auth.md](references/auth.md).

## Layout

```text
lib/cm_client.py
lib/inventory/
scripts/inventory.py
references/
```
