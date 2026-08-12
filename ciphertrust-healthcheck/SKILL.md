---
name: ciphertrust-healthcheck
description: >-
  Run a read-only Thales CipherTrust Manager healthcheck over REST and produce
  an OK/DEGRADED/CRITICAL report (services, cluster, NTP, backups, licensing,
  interfaces, log forwarders, CAs, access control, keys, CTE, audit records).
  Use when the user mentions CipherTrust, CipherTrust Manager, CM, CTM,
  Thales KMS, Thales key manager, or KeySecure, and asks about health, posture,
  appliance status, triage, or whether the KMS/CM is healthy.
---

# CipherTrust Manager healthcheck

Self-contained, read-only CipherTrust Manager health assessment over REST.
This folder is the full skill — zip/upload **this directory** (one `SKILL.md`).

**Also known as:** CipherTrust, CipherTrust Manager, **CM**, **CTM**, Thales **KMS** /
key manager, KeySecure. Treat those names as this product (not AWS KMS / other KMSs
unless the user clearly means something else).

## Auth and safety

- Read `CM_*` from the environment only. Never invent hosts or credentials.
- Never print passwords, JWTs, refresh tokens, or Prometheus scrape tokens.
- Prefer `GET`. Do not change CM config unless the user asks and confirms.
- Confirm before delete, destroy, export, restore, or reset.
- HTTPS only. TLS cert verify is **skipped by default** (`CM_TLS_INSECURE` defaults on). Set `CM_TLS_INSECURE=0` or `CM_CA_BUNDLE` to verify.

| Variable | Required | Purpose |
|----------|----------|---------|
| `CM_BASE` | yes | `https://<host>/api` |
| `CM_USERNAME` + `CM_PASSWORD` | one of | Password grant (needed for full per-domain key checks) |
| `CM_JWT` | one of | Existing access token (appliance checks; per-domain keys need password or refresh) |
| `CM_REFRESH_TOKEN` | one of | Refresh grant |
| `CM_CONNECTION` | no | Default `local_account` |
| `CM_DOMAIN` / `CM_AUTH_DOMAIN` | no | Omit to use CM default (typically `root`) |
| `CM_CA_BUNDLE` | no | TLS CA file — when set, verify with this CA |
| `CM_TLS_INSECURE` | no | Default on (skip cert verify / `verify=False`). Set `0`/`false` to verify |
| `CM_TIMEOUT` | no | HTTP timeout seconds (default 45) |

Optional: mint a JWT/refresh token with curl — [references/auth.md](references/auth.md).

## Run

From this skill folder:

```bash
python scripts/healthcheck.py
python scripts/healthcheck.py --json
```

Optional:

```bash
python scripts/healthcheck.py --domain-scope self
python scripts/healthcheck.py --keys-mode both
python scripts/healthcheck.py --max-keys 5000
python scripts/healthcheck.py --max-users 500
python scripts/healthcheck.py --no-cte
```

Do not re-implement the check with ad-hoc HTTP calls. The script uses `lib/cm_client.py` in this folder.

## Procedure

1. Confirm `CM_*` is available to the process. On Windows, if Process is empty, check User then Machine (`[Environment]::GetEnvironmentVariable(name,'User'|'Machine')`) and, if found, copy into the process (`$env:NAME=...`) before running the script — or ask the user to set User/Machine vars and restart the IDE. Do not guess credentials.
2. Reachability: **do not** GET bare `CM_BASE` (e.g. `https://host/api`) — that often returns **404** and proves nothing useful. Prefer running the healthcheck script (it authenticates and calls real APIs). If you must preflight separately: obtain a token, then `GET $CM_BASE/v1/system/info` — **200** = reachable; connection/TLS/timeout errors = unreachable. Never treat a 404 on `/api` as success or failure of CM health.
3. Run the script above (prefer default human output; `--json` only if you need `posture`).
4. Present results using **How to present** below — do not invent a free-form summary.
5. Do not remediate unless the user explicitly asks and confirms.

## How to present

Use this layout every time. Prefer a markdown **table** for posture — not free-form prose.

**1. Header** (one short block):

```text
Overall: <OK|DEGRADED|CRITICAL|UNREACHABLE>  (exit <n>)
CM: <version>    Host: <hostname from CM_BASE>
```

**2. Posture table** — copy rows from the script’s `=== Posture table ===` block (or `posture.table` in `--json`). Columns:

| Area | Result | Summary |
|------|--------|---------|
| … | PASS/WARN/FAIL | **Plain English** from the script — do not invent `key=value` shorthand |

Rules for **Summary** / **Result**:
- Prefer the script’s text verbatim (including markdown `**bold**` and `<br>` line breaks).
- Summary clauses are separated with `<br>` so the cell is readable — keep those tags in the markdown table.
- Facts that drive **WARN** / **FAIL** are wrapped in `**...**` — keep those markers (e.g. `**disk not encrypted**`).
- Non-PASS **Result** cells are also bold (`**WARN**` / `**FAIL**`).
- Do not rename the third column back to “Highlights”.

**3. Keys caveat** (one line under the table): always say **domains checked** vs **domains skipped**; general vault sample is ≤ `--max-keys` per domain (inactive/state). Weak-key hunt also uses `keys2` filters (`algorithm` / `size` / `curveid`) so it is not limited to that sample alone. Domains skipped ≠ clean estate.

**4. Findings** — two short lists (bullets): **CRITICAL** then **WARNING** (all of them, or “none”). INFO only if it explains a SKIP.

**5. Stop.** No remediation unless asked.

## What it checks

Details: [references/checklist.md](references/checklist.md).

| Area | Examples |
|------|----------|
| Alive | Services, system info, cluster, NTP |
| Operations | Backups, alarms, licenses, SMTP, banner, RoT key age |
| Interfaces | Interface modes/TLS; web PQC TLS groups; leaf TLS cert expiry (`/interfaces/{name}/certificate`); log forwarders; SSH/SNMP/preboot; SMTP |
| Access | Password policies, LDAP TLS, users (locked / never-login / inactive / failed logins / top logins) |
| CAs | Per-domain local/external + appliance trusted cert expiry (expired CRITICAL; ≤30d WARNING; >30d INFO) |
| Keys | Prometheus vault DEK totals + per-domain vault scan (weak / inactive keys) |
| CTE | Client health, GuardPoints, Learn Mode (`--no-cte` to skip) |
| Audit | `ENABLE_RECORDS_DB_STORE`: if on → DB records; if off → note disabled + Loki `/v1/audit/loki/api/v1/query_range` |

### Keys

- Estate key count: Prometheus vault **DEK** totals when enabled (never the scrape token).
  Do not sum per-domain license `including_subdomains` series — that under/over-counts.
- Per domain (for weak/inactive keys + user hygiene): login with token `domain` parameter,
  page `/v1/vault/keys2/` (≤ `--max-keys`) and users (top 5 by `logins_count`, up to `--max-users`).
  Weak keys: also query `keys2` with `algorithm` / repeated `size` / `curveid` filters.
- Domain 401/403: skip and report that the domain could not be checked.

## Scoring

| Severity | Meaning |
|----------|---------|
| CRITICAL | Appliance failing or crypto floor broken (services down — not merely `disabled`, TCP mode `no-tls-*`, weak TLS minimum, expired license, expired interface TLS or CA cert, RoT key ≥ 12 months, Loki/server audit critical/fatal in last 7 days) |
| WARNING | Usable but needs attention (includes disk not encrypted, non-web interface modes other than `tls-cert-and-pw` / TCP, web without PQC TLS groups, TLS/CA certs ≤30 days left, RoT ≥ 6 months) → overall **DEGRADED** |
| INFO | Awareness only (includes web interface modes, preferred `tls-cert-and-pw`, web PQC enabled, TLS/CA certs with >30 days left); does not change overall |

| Overall | Exit |
|---------|------|
| OK | 0 |
| DEGRADED | 1 |
| CRITICAL or UNREACHABLE | 2 |

## Out of scope

- Changing CM configuration
- Downloading API definition files
- Dumping full audit tables (script uses filtered counts and samples)

## Layout (this skill)

```text
ciphertrust-healthcheck/
├── SKILL.md
├── README.md
├── lib/
│   ├── cm_client.py
│   └── healthcheck/
│       ├── __init__.py          # exports run, main, score
│       ├── context.py           # Finding, ReportCtx
│       ├── util.py              # dates, certs, safe_get, summaries
│       ├── modes.py             # interface mode labels, TLS/PQC constants
│       ├── domains.py           # resolve_domains, shared domain walk
│       ├── users.py             # user hygiene helpers
│       ├── keys.py              # weak key logic, metrics parsing
│       ├── posture.py           # posture table builder
│       ├── report.py            # score, print_human
│       ├── runner.py            # run(), main()
│       └── checks/
│           ├── appliance.py     # services, cluster, NTP, diskenc, RoT
│           ├── interfaces.py    # interfaces, log forwarders, notifications
│           ├── ops.py           # licensing, backups, alarms
│           ├── cas.py           # CA checks
│           ├── access.py        # password policies, LDAP
│           ├── inventory.py     # keys, metrics, orphaned, clients, quorum
│           ├── cte.py           # CTE
│           └── audit.py         # audit records / Loki
├── references/auth.md
├── references/checklist.md
└── scripts/healthcheck.py       # thin entrypoint → healthcheck.runner.main
```
