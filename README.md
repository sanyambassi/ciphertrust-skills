# CipherTrust skills

Portable Agent Skills for Thales CipherTrust Manager.

Each skill folder is **self-contained** (one `SKILL.md` plus whatever that skill needs). Zip or install **one folder at a time** to use with AI agents and AI assistants.

| Skill | Purpose |
|-------|---------|
| `ciphertrust-healthcheck/` | Read-only health / posture for CipherTrust Manager |

## Use in Cursor

1. Copy `ciphertrust-healthcheck/` into a Cursor skills path:
   - Project: `.cursor/skills/ciphertrust-healthcheck/`
   - Personal: `~/.cursor/skills/ciphertrust-healthcheck/`
2. Set `CM_*` env variables (see Environment), restart Cursor, then run `/ciphertrust-healthcheck`.

See [Cursor Skills](https://cursor.com/help/customization/skills).

## Use in Claude

1. Zip **one** skill folder only (contents rooted at `ciphertrust-healthcheck/`).
2. Upload that zip as a skill (Claude allows exactly one `SKILL.md` per zip).
3. Provide `CM_*` env vars in an environment that can reach your CM host (Claude Code / local). Sandboxed chat often cannot reach appliance URLs. Do not test reachability with a GET to bare `CM_BASE` (`/api` 404 is normal); use the healthcheck script or `GET /v1/system/info` after auth.

## Credentials for a true healthcheck

**For complete / trustworthy results, use a read-only admin that can authenticate into every domain under `root`.** Domains the account cannot enter are skipped (keys, users, and related posture for those domains will be missing). Nested domains (a domain inside another under root) are uncommon; unless you specify a domain to log into for API calls, assume the check should cover all domains directly under root with that all-domain admin.

## Environment

| Variable | Required | Purpose |
|----------|----------|---------|
| `CM_BASE` | yes | `https://<host>/api` |
| `CM_USERNAME` + `CM_PASSWORD` | one of | Password login |
| `CM_JWT` or `CM_REFRESH_TOKEN` | one of | Auth Token login |
| `CM_CA_BUNDLE` | no | Private CA PEM — when set, TLS is verified with this CA |
| `CM_TLS_INSECURE` | no | Default **on** (skip cert verify). Set `0`/`false` to verify |

Set these at **user** or **machine/system** level (not a one-off terminal `export` / `$env:` — agents won’t see that). Restart the IDE afterward.

### Windows (user)

```powershell
[System.Environment]::SetEnvironmentVariable("CM_BASE", "https://cm.example.com/api", "User")
[System.Environment]::SetEnvironmentVariable("CM_USERNAME", "readonly_admin", "User")
[System.Environment]::SetEnvironmentVariable("CM_PASSWORD", "ChangeMe", "User")
[System.Environment]::SetEnvironmentVariable("CM_TLS_INSECURE", "1", "User")
```

### Windows (machine — admin PowerShell)

```powershell
[System.Environment]::SetEnvironmentVariable("CM_BASE", "https://cm.example.com/api", "Machine")
[System.Environment]::SetEnvironmentVariable("CM_USERNAME", "readonly_admin", "Machine")
[System.Environment]::SetEnvironmentVariable("CM_PASSWORD", "ChangeMe", "Machine")
[System.Environment]::SetEnvironmentVariable("CM_TLS_INSECURE", "1", "Machine")
```

### Linux (user)

```bash
mkdir -p ~/.config/environment.d
cat > ~/.config/environment.d/ciphertrust.conf <<'EOF'
CM_BASE=https://cm.example.com/api
CM_USERNAME=readonly_admin
CM_PASSWORD=ChangeMe
CM_TLS_INSECURE=1
EOF
```

### Linux (system)

```bash
sudo tee -a /etc/environment <<'EOF'
CM_BASE=https://cm.example.com/api
CM_USERNAME=readonly_admin
CM_PASSWORD=ChangeMe
CM_TLS_INSECURE=1
EOF
```

## Run healthcheck

```bash
cd ciphertrust-healthcheck
python scripts/healthcheck.py
python scripts/healthcheck.py --json
```

Exit codes: `0` OK · `1` DEGRADED · `2` CRITICAL / UNREACHABLE.

## Contributing

Open a PR with a clear description of the change. Keep each skill self-contained (one `SKILL.md`); never commit hosts, credentials, tokens, or `.env` files.

To add a skill: create `ciphertrust-<name>/` with its own `SKILL.md` and local `lib/` / `scripts/` / `references/` (no `../` to siblings at runtime), then add a row to the table above.

## License

See [LICENSE](LICENSE).
