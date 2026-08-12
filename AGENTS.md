# Agent guidelines

Conventions for authoring and maintaining skills in this repository.
Users installing a skill do not need this file: see [README.md](README.md) for setup,
and each skill's `SKILL.md` for how that skill behaves at runtime.

## Layout

| Path | Purpose |
|------|---------|
| `ciphertrust-healthcheck/` | Read-only CipherTrust Manager health / posture skill |
| `ciphertrust-key-inventory/` | Read-only CipherTrust Manager key inventory skill |

## Skill structure

| Topic | Rule |
|-------|------|
| Self-contained | One `SKILL.md` per folder, with its own `lib/`, `scripts/`, `references/`. No `../` imports between skills at runtime |
| Frontmatter | `name` and `description` only; the description must say when to use the skill |
| Naming | Folder and `name` are `ciphertrust-<skill-name>` |
| Dependencies | Prefer the Python standard library so a skill runs without `pip install`. Optional extras (e.g. `cryptography` for cert parsing) must degrade gracefully — never hard-require a package |
| Secrets | Never commit hosts, credentials, tokens, or `.env`. Docs use placeholders (`cm.example.com`, `ChangeMe`) |
| Docs | Runtime behavior belongs in `SKILL.md`; setup belongs in `README.md`. Link instead of duplicating |

## Adding a skill

1. Create `ciphertrust-<name>/` with a `SKILL.md` and any local `lib/` / `scripts/` / `references/`.
2. Add a row to the skill table in [README.md](README.md).
3. Open a PR describing what the skill does and when an agent should load it.

## Before committing a change to a runner script

- `python -m py_compile ciphertrust-healthcheck/scripts/healthcheck.py ciphertrust-healthcheck/lib/cm_client.py`
- `python -m py_compile ciphertrust-key-inventory/scripts/inventory.py ciphertrust-key-inventory/lib/cm_client.py`
- Smoke test against a real appliance with `CM_*` set, then confirm output still matches that skill’s `SKILL.md`.
