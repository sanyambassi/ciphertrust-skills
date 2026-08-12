"""Access control: password policies and LDAP."""
from __future__ import annotations

from cm_client import CmClient

from ..context import ReportCtx
from ..util import safe_get

def check_password_policies(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/usermgmt/pwdpolicies/")
    if err:
        ctx.section("password_policies", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    weak = []
    for p in resources:
        if not isinstance(p, dict):
            continue
        name = p.get("policy_name") or "unnamed"
        min_len = p.get("inclusive_min_total_length")
        history = p.get("password_history_threshold")
        lockout = p.get("failed_logins_lockout_thresholds")
        lifetime = p.get("password_lifetime")
        if isinstance(min_len, int) and min_len < 8:
            weak.append(name)
            ctx.add(
                "access",
                "access_pwd_policy_weak_min_length",
                "WARNING",
                f"Password policy '{name}' minimum length is {min_len} (<8).",
            )
        if history == 0:
            weak.append(name)
            ctx.add(
                "access",
                "access_pwd_policy_no_history",
                "WARNING",
                f"Password policy '{name}' has password reuse prevention disabled.",
            )
        if not lockout:
            weak.append(name)
            ctx.add(
                "access",
                "access_pwd_policy_no_lockout",
                "WARNING",
                f"Password policy '{name}' has account lockout disabled.",
            )
        if lifetime == 0:
            ctx.add(
                "access",
                "access_pwd_policy_no_expiry",
                "INFO",
                f"Password policy '{name}' does not enforce password expiration.",
            )
        if name != "global":
            ctx.add(
                "access",
                "access_pwd_policy_custom",
                "INFO",
                f"Custom password policy '{name}' is present.",
            )
    ctx.section(
        "password_policies",
        "WARN" if weak else "PASS",
        {"total": len(resources), "weak_policies": sorted(set(weak))},
        200,
    )


def check_ldap(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/connectionmgmt/services/ldap/connections?limit=100")
    if err:
        ctx.section("ldap_connections", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    issues = 0
    rows = []
    for conn in resources:
        if not isinstance(conn, dict):
            continue
        name = conn.get("name")
        url = str(conn.get("server_url") or "")
        rows.append(
            {
                "name": name,
                "server_url": url,
                "insecure_skip_verify": conn.get("insecure_skip_verify"),
                "has_root_ca": bool(any(x for x in (conn.get("root_cas") or []) if x)),
            }
        )
        if url.lower().startswith("ldaps://"):
            if conn.get("insecure_skip_verify") is True:
                issues += 1
                ctx.add(
                    "access",
                    "access_ldap_insecure_skip_verify",
                    "CRITICAL",
                    f"LDAP connection '{name}' has certificate verification disabled.",
                )
            root_cas = conn.get("root_cas") or []
            if not any(x for x in root_cas if x):
                issues += 1
                ctx.add(
                    "access",
                    "access_ldap_no_root_ca",
                    "WARNING",
                    f"LDAP connection '{name}' (ldaps) has no root_ca configured.",
                )
    ctx.section(
        "ldap_connections",
        "FAIL" if any(f.code == "access_ldap_insecure_skip_verify" for f in ctx.findings) else (
            "WARN" if issues else "PASS"
        ),
        {"total": len(resources), "connections": rows},
        200,
    )
