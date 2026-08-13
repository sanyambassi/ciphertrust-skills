---
name: ciphertrust-key-inventory
description: >-
  Produce a full read-only Thales CipherTrust Manager key inventory over REST
  (per-domain catalog, system/internal keys, Akeyless Customer Fragments,
  weak crypto, lifecycle dates, exportable/deletable, CTE / LDT vs Standard
  policy compatibility, orphans, tabbed HTML report). Use when the user
  mentions CipherTrust, CipherTrust Manager, CM, CTM, Thales KMS, Thales key
  manager, or KeySecure, and asks for a key inventory, catalog of keys on CM,
  list of keys, weak keys, key lifecycle, exportable keys, CTE keys, LDT vs
  Standard keys, or Akeyless Customer Fragments — not appliance health or
  posture.
---

# CipherTrust Manager key inventory

Self-contained, read-only catalog of keys on CipherTrust Manager over REST.
This folder is the full skill — zip/upload **this directory** (one `SKILL.md`).

**Also known as:** CipherTrust, CipherTrust Manager, **CM**, **CTM**, Thales **KMS** /
key manager, KeySecure. Treat those names as this product (not AWS KMS / other KMSs
unless the user clearly means something else).

## Auth and safety

- Read `CM_*` from the environment only. Never invent hosts or credentials.
- Never print passwords, JWTs, refresh tokens, Prometheus scrape tokens, or key material.
- Prefer `GET`. Do not change CM config unless the user asks and confirms.
- Confirm before export, destroy, delete, revoke, archive, recover, reactivate, clone, or rotate.
- HTTPS only. TLS cert verify is **skipped by default** (`CM_TLS_INSECURE` defaults on). Set `CM_TLS_INSECURE=0` or `CM_CA_BUNDLE` to verify.

| Variable | Required | Purpose |
|----------|----------|---------|
| `CM_BASE` | yes | `https://<host>/api` |
| `CM_USERNAME` + `CM_PASSWORD` | one of | Password grant (needed for per-domain inventory) |
| `CM_JWT` | one of | Existing access token (current domain only unless password or refresh is set) |
| `CM_REFRESH_TOKEN` | one of | Refresh grant |
| `CM_CONNECTION` | no | Default `local_account` |
| `CM_DOMAIN` / `CM_AUTH_DOMAIN` | no | Omit to use CM default (typically `root`) |
| `CM_CA_BUNDLE` | no | TLS CA file — when set, verify with this CA |
| `CM_TLS_INSECURE` | no | Default on (skip cert verify). Set `0`/`false` to verify |
| `CM_TIMEOUT` | no | HTTP timeout seconds (default 45) |

Optional: mint a JWT/refresh token with curl — [references/auth.md](references/auth.md).

## Run

From this skill folder:

```bash
python scripts/inventory.py --html key-inventory-report.html
python scripts/inventory.py --json
python scripts/inventory.py --csv key-inventory.csv
```

Optional:

```bash
python scripts/inventory.py --domain-scope self
python scripts/inventory.py --domain NAME
python scripts/inventory.py --weak-only
python scripts/inventory.py --exclude-system
python scripts/inventory.py --cte-only
python scripts/inventory.py --about-to-change --window-days 30
python scripts/inventory.py --max-keys 5000
```

Always write HTML at the workspace root:

| Run | File |
|-----|------|
| All domains | `key-inventory-report.html` |
| `--domain NAME` | `key-inventory-<domain>.html` |

Pass `--html PATH` only if the user names a different file.

## Procedure

1. Confirm `CM_*` is available to the process. On Windows, if Process is empty, check User then Machine (`[Environment]::GetEnvironmentVariable(name,'User'|'Machine')`) and, if found, copy into the process (`$env:NAME=...`) before running the script — or ask the user to set User/Machine vars and restart the IDE. Do not guess credentials.
2. Do not GET bare `CM_BASE`. Run the inventory script.
3. Write HTML at the workspace root using the names above (or the path the user gave). `--domain` skips Prometheus and orphaned-key totals.
4. Present results using **How to present** below. Give the HTML path after the lists.
5. Do not export, destroy, delete, or otherwise change keys unless the user explicitly asks and confirms.

## How to present

Use this layout every time. Prefer the script’s tables and lists — do not invent a free-form summary.

**1. Header** (one short block):

```text
Key inventory
CM: <version>    Host: <hostname from CM_BASE>
Domains checked: <n>    skipped: <n>
Keys in checked domains: <n>
Version objects listed: <n>
Keys with more than one version: <n>
Keys with 3 or more versions: <n>
Total keys (including orphaned): <n>
Never exported: <n>
Never exportable: <n>
CTE keys: <n>    LDT: <n>    Standard: <n>
Akeyless Customer Fragments: <n>
```

**2. Totals table** — copy rows from the script’s `=== Totals by domain ===` block.

**3. Lists** — copy **System keys**, **Akeyless Customer Fragments**, **Weak keys**, **CTE keys**, and **Lifecycle** from the script. Always include Akeyless Customer Fragments (the list, or “none”). If the script says `N more in JSON/HTML`, keep that line and point at the file(s).

**4. Caveat** (when the script prints it): **domains checked** vs **domains skipped**. Skipped ≠ no keys in that domain.

**5. HTML report** — give the HTML file path.

**6. Stop.** No remediation, export, or delete unless asked.

## What it collects

| Area | What you get |
|------|----------------|
| Catalog | One row per key name: current version number, how many version objects were listed, algorithm, size/curve, state, dates, owner, exportable/deletable, usage, CTE metadata |
| System | `citrus-*` names, and `ks-*` names that have `meta.service_name` and no owner |
| Akeyless CF | In each checked domain, hunt `name=cf-*`. Classify `cf-<uuid>`. Usually Opaque Object, no owner. Not system keys |
| Weak | Full list: RSA &lt;2048, DES/3DES, AES/ARIA &lt;128, EC &lt;256 or a weak curve |
| CTE | Keys with a `meta.cte` section. `cte_versioned` true → LDT policies; false or not set → Standard policies |
| Lifecycle | Inactive latest version; activation / deactivation / protect-stop in `--window-days`; rotation due; never rotated and older than one year |
| Orphans | Orphaned keys by deleted-domain account (skipped on `--domain`) |
| Metrics | Total keys including orphaned (skipped on `--domain`) |

Per domain: authenticate with the token `domain` parameter, page keys in that domain with `fields=meta` and no default cap, hunt `citrus-*`, `ks-*` Opaque, and `cf-*`, and skip 401/403.

## Exit codes

| Result | Exit |
|--------|------|
| Inventory completed | 0 |
| Unreachable or auth failed | 2 |

## Out of scope (default run)

- Appliance health scoring
- Users, CTE clients, interfaces, licenses, backups, alarms
- Treating every `ks-*` name as a system key
- Treating every `cf-*` name as an Akeyless Customer Fragment
- Create / PATCH keys
- Export, destroy, delete, revoke, archive, recover, reactivate, clone, or rotate

## Layout (this skill)

```text
ciphertrust-key-inventory/
├── SKILL.md
├── README.md
├── lib/
│   ├── cm_client.py
│   └── inventory/
│       ├── __init__.py
│       ├── domains.py
│       ├── classify.py
│       ├── collect.py
│       ├── metrics.py
│       ├── report.py
│       ├── html_report.py
│       └── runner.py
├── references/auth.md
└── scripts/inventory.py
```
