# Healthcheck checklist

Read-only CipherTrust Manager REST checks. Prefer the runner
`scripts/healthcheck.py` over ad-hoc calls.

## Severity model

| Severity | Meaning | Overall |
|----------|---------|---------|
| CRITICAL | Appliance failing, crypto floor broken, TCP interface mode, expired TLS/CA cert, or RoT key ≥ 12 months | CRITICAL |
| WARNING | Reachable and usable, but needs attention (non-preferred interface modes, TLS/CA ≤30 days left, RoT ≥ 6 months) | DEGRADED |
| INFO | Reported for awareness only | unchanged |

## System and cluster

1. Authenticate with `CM_*` (see this skill’s `SKILL.md`; optional token minting in `references/auth.md`).
2. `GET /v1/auth/self/user`, `GET /v1/auth/self/domains`
3. `GET /v1/system/info`
4. `GET /v1/system/services/status` — `disabled` → INFO (intentional); other non-`started` → CRITICAL
5. `GET /v1/cluster`, `/v1/cluster/summary`, `/v1/cluster/errors`, `/v1/nodes` — cluster errors → CRITICAL
6. `GET /v1/system/ntp/status`, `/v1/system/ntp/servers` — no sync peer / no servers → WARNING
7. `GET /v1/auth/banners/pre-auth` — empty → WARNING
8. `GET /v1/locker/diskenc/status` — disk encryption posture:
    - Not encrypted (`encryptionStatus` like `not encrypted` / no DEK) → WARNING
    - Encrypted → INFO; expect auto-created **preboot** interface (INFO if present; WARNING if missing while encrypted)
    - `attendedBoot` true → WARNING (manual passphrase at boot)
9. `GET /v1/system/rot-keys` — age **≥ 12 months** → CRITICAL; **≥ 6 months** → WARNING; otherwise INFO
10. `GET /v1/system/alarms` — active unacknowledged critical/error → CRITICAL; other active → WARNING
11. `GET /v1/notification/smtp-servers`, `/v1/notification/email-addresses`
12. Backups: `/v1/backupStatus`, `/v1/backups`, `/v1/backupkeys`, scheduler `database_backup` jobs
13. `GET /v1/system/metrics/prometheus/status` — disabled → WARNING

## Licensing

14. `GET /v1/licensing/licenses/`, `/v1/licensing/features/`
    - Expired active license or feature → CRITICAL
    - Trial or dated expiry within 30 days → WARNING (summarize; do not spam one finding per feature)

## Interfaces

15. `GET /v1/configs/interfaces/` (auth modes per Thales interface auth docs)
    - Enabled TCP mode `no-tls-*` (no TLS) → CRITICAL
    - Enabled `tls-cert-and-pw` (preferred) → INFO
    - Service interfaces present but none on `tls-cert-and-pw` → WARNING
    - `interface_type=web` non-TCP mode → INFO (web cannot use tls-cert-and-pw; only supported web mode)
    - Any other enabled auth mode (`unauth-tls-*`, `tls-pw-*`, `tls-cert-pw-opt`, …) → WARNING
    - SSH / SNMP interfaces (any count, including multiples): report configured name/port/enabled as INFO (no mode scoring; `mode` is null)
    - Preboot interface (auto when disk encryption is enabled): INFO when present; scored with disk encryption, not as a TLS mode finding
    - Weak minimum TLS (`tls_1_0`, `tls_1_1`, `ssl_v3`) → CRITICAL
    - Disabled interface → INFO
    - Web interface PQC: enabled web `tls_groups` with any of
      `X25519MLKEM768` / `SecP256r1MLKEM768` / `MLKEM512` / `MLKEM768` / `MLKEM1024`
      → INFO; none enabled → WARNING (classic groups only by default)
    - TLS server cert via `GET /v1/configs/interfaces/{name}/certificate` (leaf PEM):
      expired → CRITICAL; ≤30 days left → WARNING; >30 days → INFO
16. `GET /v1/configs/log-forwarders/` — none active → WARNING

## Access control

17. `GET /v1/usermgmt/pwdpolicies/` — weak length / no history / no lockout → WARNING; no password expiry → INFO
18. `GET /v1/connectionmgmt/services/ldap/connections`
    - `ldaps://` with `insecure_skip_verify` → CRITICAL
    - `ldaps://` with no root CA → WARNING
19. Users (paged per accessible domain when domain inventory runs; otherwise current token domain):
    locked, never logged in, inactive >30d, or failed logins → WARNING;
    report top 5 users by `logins_count` (INFO + Users header; ranked after paging)

## Domains and key usage

20. `GET /v1/domains` — `allow_user_management` / HSM-backed → INFO
21. `GET /v1/reports/orphaned-resources` — orphaned keys → WARNING
22. Quorum:
    - `GET /v1/quorum-mgmt/policy/status` (page fully; use API `total`) — policy `active: true` = **enabled** in GUI; report enabled / total policies
    - `GET /v1/quorum-mgmt/quorums` — count requests by state; report active / pre-active / total requests

## Certificate authorities

23. Local / external / trusted CAs (`notAfter`, `state`) — same validity scale as interface TLS certs:
    - Expired → CRITICAL
    - ≤30 days left → WARNING
    - >30 days left → INFO
    - Note in message when a CA is still referenced by an enabled interface

## Keys

24. Estate key count: scrape `GET /v1/system/metrics/prometheus` when enabled (never include scrape token).
    Report vault **DEK** totals — do not sum per-domain license
    `key_usage_count_including_subdomains` series (under/over-counts the estate).
25. Per domain (weak/inactive keys + user hygiene): authenticate with token `domain` parameter,
    then page `/v1/vault/keys2/` and `/v1/usermgmt/users/`
    - Weak RSA (< 2048) or AES (< 128) → WARNING
    - Highest key version inactive (not `Active`) → WARNING
    - User hygiene + top 5 by logins (see access control)
    - Domain auth 401/403 → skip and tell the user that domain could not be checked (not CRITICAL by itself)

## CTE (on by default; disable with `--no-cte`)

26. Clients: `NOT CONNECTED` with communication enabled → WARNING; `UNREGISTERED` / comm disabled → INFO
27. GuardPoints: `DISABLED` / `ERROR` → WARNING; `UNKNOWN` → INFO
28. Policies with `never_deny=true` (Learn Mode) → WARNING

## Audit records

Version gate: read `/v1/system/info` first. On **CM 2.24+**, database audit APIs were removed — skip `/v1/audit/records` and `/v1/audit/client-records` (`audit_records: SKIP`, INFO only). Rely on system alarms and log forwarders.

29. Server (pre-2.24): `/v1/audit/records` with `createdAfter` (last 7 days) — critical/fatal → CRITICAL; error → WARNING
30. Client (pre-2.24): `/v1/audit/client-records` — elevated counts → WARNING (time filters are not always honored)

## Overall result and exit codes

| Overall | Exit | Meaning |
|---------|------|---------|
| OK | 0 | No CRITICAL or WARNING findings |
| DEGRADED | 1 | WARNING findings only |
| CRITICAL | 2 | Any CRITICAL finding, auth failure, or core services down |
| UNREACHABLE | 2 | Network or TLS failure before API use |
