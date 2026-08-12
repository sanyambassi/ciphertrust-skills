# CipherTrust skills

Portable Agent Skills for Thales CipherTrust Manager.

Each skill folder is **self-contained** (one `SKILL.md` plus whatever that skill needs). Zip or install **one folder at a time** to use with AI agents and AI assistants.

| Skill | Purpose |
|-------|---------|
| `ciphertrust-healthcheck/` | Read-only health / posture for CipherTrust Manager |
| `ciphertrust-key-inventory/` | Read-only key inventory on CM (catalog, not a score) |

## Use with AI agents

These skills follow the open [Agent Skills](https://agentskills.io) format (`SKILL.md` + optional `scripts/` / `references/`). Install **one skill folder** at a time. Set `CM_*` (see Environment) in an environment that can reach your CipherTrust Manager host. Do not GET bare `CM_BASE`.

### Cursor

1. Copy the skill folder you want into a Cursor skills path, for example:
   - Project: `.cursor/skills/ciphertrust-healthcheck/` or `.cursor/skills/ciphertrust-key-inventory/`
   - Personal: `~/.cursor/skills/ciphertrust-healthcheck/` or `~/.cursor/skills/ciphertrust-key-inventory/`
2. Restart Cursor, then run `/ciphertrust-healthcheck` or `/ciphertrust-key-inventory`.

See [Cursor Skills](https://cursor.com/help/customization/skills).

### Claude

1. Zip **one** skill folder only (contents rooted at `ciphertrust-healthcheck/` or `ciphertrust-key-inventory/`).
2. Upload that zip as a skill (Claude allows exactly one `SKILL.md` per zip).
3. Prefer Claude Code / local tools that can reach your CM host and see `CM_*`.

See [Using skills in Claude](https://support.claude.com/en/articles/12512180-using-skills-in-claude).

### Google Antigravity (Gemini)

1. Copy the skill folder you want into:
   - Workspace: `<workspace>/.agents/skills/ciphertrust-healthcheck/` or `.../ciphertrust-key-inventory/`
   - Global: `~/.gemini/config/skills/ciphertrust-healthcheck/` or `.../ciphertrust-key-inventory/`
2. Restart or start a new conversation; the agent discovers skills by name/description.

See [Antigravity Skills](https://antigravity.google/docs/skills).

### OpenAI ChatGPT and Codex

Skills work in ChatGPT (desktop / Work) and Codex (CLI, IDE, desktop). Same folder layout: one skill directory with `SKILL.md`.

**Local / Codex**

1. Copy the skill folder you want into a Codex skills path, for example:
   - Repo: `.agents/skills/ciphertrust-healthcheck/` or `.agents/skills/ciphertrust-key-inventory/`
   - User: `~/.agents/skills/ciphertrust-healthcheck/` or `~/.agents/skills/ciphertrust-key-inventory/`
2. Restart Codex if needed. Invoke with `/skills`, `$ciphertrust-healthcheck`, `$ciphertrust-key-inventory`, or by describing a CM health check or key inventory.
3. Or install from a GitHub skill folder URL via `$skill-installer` (see [openai/skills](https://github.com/openai/skills)).

**ChatGPT**

1. Create or upload the skill (Skills in the sidebar, or ask ChatGPT to build/install from the folder).
2. Use `@` to pick the skill, or let ChatGPT match on the description.
3. A full run needs a host that can run the script and reach CM — use Codex CLI / desktop with local tools, not a sandboxed web chat alone.

See [Build skills](https://learn.chatgpt.com/docs/build-skills), [Using skills (Academy)](https://openai.com/academy/skills/), and [Skills in ChatGPT](https://help.openai.com/en/articles/20001066-skills-in-chatgpt).

## Credentials

**For complete results, use a read-only admin that can authenticate into every domain under `root`.** Domains the account cannot enter are skipped (those domains are missing from the report, not empty). Nested domains (a domain inside another under root) are uncommon; unless you specify a domain to log into for API calls, assume the run should cover all domains directly under root with that all-domain admin.

## Environment

| Variable | Required | Purpose |
|----------|----------|---------|
| `CM_BASE` | yes | `https://<host>/api` |
| `CM_USERNAME` + `CM_PASSWORD` | one of | Password login (needed for full per-domain key checks) |
| `CM_JWT` | one of | Existing access token (appliance checks; per-domain keys need password or refresh) |
| `CM_REFRESH_TOKEN` | one of | Refresh grant |
| `CM_CONNECTION` | no | Default `local_account` |
| `CM_DOMAIN` / `CM_AUTH_DOMAIN` | no | Omit to use CM default (typically `root`) |
| `CM_CA_BUNDLE` | no | Private CA PEM — when set, TLS is verified with this CA |
| `CM_TLS_INSECURE` | no | Default **on** (skip cert verify). Set `0`/`false` to verify |
| `CM_TIMEOUT` | no | HTTP timeout seconds (default 45) |

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

## Run key inventory

```bash
cd ciphertrust-key-inventory
python scripts/inventory.py
python scripts/inventory.py --domain NAME
python scripts/inventory.py --html PATH
python scripts/inventory.py --json
```

Exit codes: `0` completed · `2` unreachable / auth failed.

## Contributing

Open a PR with a clear description of the change. Keep each skill self-contained (one `SKILL.md`); never commit hosts, credentials, tokens, or `.env` files.

Authoring conventions for new skills: [AGENTS.md](AGENTS.md).

## License

[MIT](LICENSE).
