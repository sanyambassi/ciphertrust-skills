# CipherTrust skills

Each skill folder is **self-contained** and ready for any AI assistant that loads Agent Skills.

## Install / upload

Assistants that require **exactly one `SKILL.md` per zip**: zip **one skill folder** (not this whole repo).

| Skill folder | Upload when |
|--------------|-------------|
| `ciphertrust-healthcheck/` | Health / posture / triage for CipherTrust Manager (also called CM, CTM, CipherTrust, Thales KMS / key manager, KeySecure) |

## Layout

```text
ciphertrust-skills/
├── AGENTS.md
├── README.md
└── ciphertrust-healthcheck/
    ├── SKILL.md
    ├── lib/cm_client.py
    ├── references/
    └── scripts/healthcheck.py
```

## Healthcheck (quick)

From `ciphertrust-healthcheck/`:

```bash
export CM_BASE="https://cm.example.com/api"
export CM_USERNAME="..."
export CM_PASSWORD="..."
python scripts/healthcheck.py
```

Exit codes: `0` OK, `1` DEGRADED, `2` CRITICAL or UNREACHABLE.

Present healthcheck results using the skill’s **How to present** section (header + posture table **Area | Result | Summary** — copy script text including `**bold**` on WARN/FAIL drivers — + CRITICAL/WARNING lists). On Windows, if Process `CM_*` is empty, read User then Machine and promote into the process before running. Never invent credentials. Never echo secrets. Do not remediate without user confirmation.

**Reachability:** do not probe bare `CM_BASE` (`/api` often 404s). Run `scripts/healthcheck.py`, or preflight with auth + `GET /v1/system/info`.
