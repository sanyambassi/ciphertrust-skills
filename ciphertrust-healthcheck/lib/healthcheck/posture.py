"""Posture summary collection and markdown table builder."""
from __future__ import annotations

import re
from typing import Any

from .users import users_have_hygiene_issues

def _section_map(sections: list[dict]) -> dict[str, dict]:
    return {s["name"]: s for s in sections if isinstance(s, dict) and s.get("name")}


def _sec_detail(by: dict[str, dict], name: str) -> dict[str, Any] | None:
    s = by.get(name) or {}
    d = s.get("detail")
    return d if isinstance(d, dict) else None


def _sec_result(by: dict[str, dict], name: str) -> str | None:
    s = by.get(name)
    return s.get("result") if s else None


def _worst_result(*results: str | None) -> str | None:
    """Combine section results: FAIL > WARN > PASS > SKIP/other."""
    order = {"FAIL": 3, "WARN": 2, "PASS": 1, "SKIP": 0}
    best: str | None = None
    best_rank = -1
    for r in results:
        if not r:
            continue
        rank = order.get(str(r).upper(), 0)
        if rank > best_rank:
            best_rank = rank
            best = str(r).upper() if str(r).upper() in order else r
    return best


def collect_users_summary(sections: list[dict]) -> dict[str, Any]:
    """Roll up per-domain / current-domain user scans for the report header."""
    by_domain: list[dict[str, Any]] = []
    totals = {
        "domains_with_users": 0,
        "users_total": 0,
        "locked": 0,
        "never_logged_in": 0,
        "inactive_30d": 0,
        "failed_logins_not_locked": 0,
    }
    for s in sections:
        name = s.get("name")
        detail = s.get("detail")
        if name == "keys_domains" and isinstance(detail, dict):
            for c in detail.get("checked") or []:
                if not isinstance(c, dict):
                    continue
                users = c.get("users") or {}
                if not users:
                    continue
                totals["domains_with_users"] += 1
                totals["users_total"] += int(users.get("total_reported") or users.get("scanned") or 0)
                for k in (
                    "locked",
                    "never_logged_in",
                    "inactive_30d",
                    "failed_logins_not_locked",
                ):
                    totals[k] += int(users.get(k) or 0)
                by_domain.append(
                    {
                        "domain": c.get("domain"),
                        "total": users.get("total_reported"),
                        "locked": users.get("locked"),
                        "never_logged_in": users.get("never_logged_in"),
                        "inactive_30d": users.get("inactive_30d"),
                        "failed_logins_not_locked": users.get("failed_logins_not_locked"),
                        "top_by_logins": users.get("top_by_logins") or [],
                    }
                )
        elif name == "users_access" and isinstance(detail, dict) and "error" not in detail:
            totals["domains_with_users"] += 1
            totals["users_total"] += int(detail.get("total_reported") or detail.get("scanned") or 0)
            for k in (
                "locked",
                "never_logged_in",
                "inactive_30d",
                "failed_logins_not_locked",
            ):
                totals[k] += int(detail.get(k) or 0)
            by_domain.append(
                {
                    "domain": "(current token)",
                    "total": detail.get("total_reported"),
                    "locked": detail.get("locked"),
                    "never_logged_in": detail.get("never_logged_in"),
                    "inactive_30d": detail.get("inactive_30d"),
                    "failed_logins_not_locked": detail.get("failed_logins_not_locked"),
                    "top_by_logins": detail.get("top_by_logins") or [],
                }
            )
    return {"totals": totals, "by_domain": by_domain, "result": None}


def collect_keys_summary(sections: list[dict]) -> dict[str, Any]:
    by = _section_map(sections)
    metrics = _sec_detail(by, "keys_metrics") or {}
    domains = _sec_detail(by, "keys_domains") or {}
    checked = domains.get("checked") or []
    weak = sum(int(c.get("weak_count") or 0) for c in checked if isinstance(c, dict))
    non_active = sum(int(c.get("non_active_count") or 0) for c in checked if isinstance(c, dict))
    keys_total = sum(int(c.get("total_reported") or 0) for c in checked if isinstance(c, dict))
    keys_unique = sum(int(c.get("unique") or 0) for c in checked if isinstance(c, dict))
    by_domain = [
        {
            "domain": c.get("domain"),
            "total": c.get("total_reported"),
            "unique": c.get("unique"),
            "weak": c.get("weak_count"),
            "non_active": c.get("non_active_count"),
        }
        for c in checked
        if isinstance(c, dict)
    ]
    result = _sec_result(by, "keys_domains") or _sec_result(by, "keys_metrics")
    deks_by_state = metrics.get("deks_by_state") or {}
    deks_total = metrics.get("deks_total")
    if deks_total is None and isinstance(deks_by_state, dict) and deks_by_state:
        deks_total = sum(int(v or 0) for v in deks_by_state.values())
    return {
        "result": result,
        "metrics": {
            "enabled": metrics.get("enabled"),
            # Estate vault count from Prom DEK gauges (not a sum of per-domain
            # license_manager including_subdomains series — that under/over-counts).
            "deks_total": deks_total,
            "key_usage_estate": metrics.get("key_usage_estate"),
            "domains_with_key_usage": metrics.get("domains_with_key_usage"),
            "deks_by_state": deks_by_state,
            "keks_total": metrics.get("keks_total"),
            "top_domains": metrics.get("key_usage_top_domains") or [],
        }
        if metrics
        else None,
        "domains": {
            "listed": domains.get("domains_listed"),
            "checked": domains.get("checked_count"),
            "skipped": domains.get("skipped_count"),
            "keys_total": keys_total,
            "keys_unique": keys_unique,
            "weak": weak,
            "non_active": non_active,
            "by_domain": by_domain,
        }
        if domains
        else None,
    }


def collect_posture_summary(sections: list[dict]) -> dict[str, Any]:
    """Compact rollup of every major health area for agents and human headers."""
    by = _section_map(sections)
    users = collect_users_summary(sections)
    # Derive users.result from hygiene totals
    ut = users.get("totals") or {}
    if users.get("by_domain"):
        users["result"] = "WARN" if users_have_hygiene_issues(ut) else "PASS"
    else:
        users["result"] = "SKIP"

    info = _sec_detail(by, "system_info") or {}
    svc = _sec_detail(by, "services_status") or {}
    cluster = _sec_detail(by, "cluster") or {}
    cluster_errs = _sec_detail(by, "cluster_errors") or {}
    nodes = _sec_detail(by, "nodes") or {}
    ntp = _sec_detail(by, "ntp") or {}
    rot = _sec_detail(by, "rot_keys") or {}
    lic = _sec_detail(by, "licensing_licenses") or {}
    lic_feat = _sec_detail(by, "licensing_features") or {}
    alarms = _sec_detail(by, "alarms") or {}
    iface = _sec_detail(by, "interfaces") or {}
    fwd = _sec_detail(by, "log_forwarders") or {}
    notif = _sec_detail(by, "notifications") or {}
    backups = _sec_detail(by, "backups_list") or {}
    backup_sched = _sec_detail(by, "backup_scheduler") or {}
    backup_status = _sec_detail(by, "backup_status") or {}
    diskenc = _sec_detail(by, "diskenc") or _sec_detail(by, "disk_encryption") or {}
    banner = _sec_detail(by, "banner_pre_auth") or {}
    ca_local = _sec_detail(by, "ca_local") or {}
    ca_ext = _sec_detail(by, "ca_external") or {}
    ca_trust = _sec_detail(by, "ca_trusted") or {}
    orphan = _sec_detail(by, "orphaned_resources") or {}
    quorum = _sec_detail(by, "quorum_policies") or {}
    clients = _sec_detail(by, "registered_clients") or {}
    cte = _sec_detail(by, "cte_clients") or {}
    cte_pol = _sec_detail(by, "cte_policies") or {}
    audit = _sec_detail(by, "audit_records") or {}
    ldap = _sec_detail(by, "ldap_connections") or {}
    pwd = _sec_detail(by, "password_policies") or {}
    domains = _sec_detail(by, "domains") or {}

    def _ca_block(d: dict[str, Any] | None, result: str | None) -> dict[str, Any] | None:
        if d is None and result is None:
            return None
        d = d or {}
        return {
            "result": result,
            "total": d.get("total"),
            "expired": len(d.get("expired") or []),
            "expired_in_use": len(d.get("expired_in_use") or []),
            "expiring_soon": len(d.get("expiring_soon") or []),
            "ok": len(d.get("ok") or []),
        }

    keys = collect_keys_summary(sections)

    return {
        "appliance": {
            "result": _worst_result(
                _sec_result(by, "services_status"),
                _sec_result(by, "system_info"),
                _sec_result(by, "disk_encryption"),
                _sec_result(by, "ntp"),
                _sec_result(by, "cluster"),
                _sec_result(by, "cluster_errors"),
                _sec_result(by, "banner_pre_auth"),
            ),
            "version": info.get("version"),
            "model": info.get("model"),
            "uptime": info.get("uptime"),
            "services_total": svc.get("total"),
            "services_started": svc.get("started"),
            "services_disabled": len(svc.get("disabled") or []),
            "services_disabled_names": [
                str(d.get("name"))
                for d in (svc.get("disabled") or [])
                if isinstance(d, dict) and d.get("name")
            ],
            "services_not_started": len(svc.get("not_started") or []),
            "services_not_started_names": [
                str(d.get("name"))
                for d in (svc.get("not_started") or [])
                if isinstance(d, dict) and d.get("name")
            ],
            "cluster": cluster.get("status_description")
            or cluster.get("status_code"),
            "cluster_status_code": cluster.get("status_code"),
            "cluster_nodes": nodes.get("total")
            if nodes.get("total") is not None
            else nodes.get("count"),
            "cluster_errors": cluster_errs.get("count"),
            "cluster_error_reasons": cluster_errs.get("reasons") or [],
            "ntp_synchronized": ntp.get("ntpq_synced"),
            "disk_encryption": diskenc.get("encryptionStatus"),
            "disk_encrypted": diskenc.get("encrypted"),
            "disk_encrypting": diskenc.get("encrypting"),
            "disk_enc_state": diskenc.get("state"),
            "attended_boot": diskenc.get("attendedBoot"),
            "preboot_interfaces": len(diskenc.get("preboot_interfaces") or []),
            "banner_configured": banner.get("configured"),
        },
        "rot_keys": {
            "result": _sec_result(by, "rot_keys"),
            "total": rot.get("total"),
            "older_than_12m": len(rot.get("older_than_12m") or []),
            "older_than_6m": len(rot.get("older_than_6m") or []),
            "keys": rot.get("keys") or [],
        },
        "licensing": {
            "result": _sec_result(by, "licensing_licenses") or _sec_result(by, "licensing_features"),
            "active": lic.get("active_count"),
            "expired": len(lic.get("expired") or []),
            "expiring_soon": len(lic.get("expiring_soon") or []),
            "trials_expiring_soon": len(lic.get("trials_expiring_soon") or lic_feat.get("trials_expiring_soon") or []),
        },
        "alarms": {
            "result": _sec_result(by, "alarms"),
            "total": alarms.get("total"),
            "active_unacknowledged": alarms.get("active_unacknowledged"),
            "critical_active": alarms.get("active_critical")
            if alarms.get("active_critical") is not None
            else len(alarms.get("critical_sample") or []),
            "warning_active": alarms.get("active_warning")
            if alarms.get("active_warning") is not None
            else len(alarms.get("warning_sample") or []),
            "info_active": alarms.get("active_info"),
            "active_by_severity": alarms.get("active_by_severity"),
        },
        "network": {
            "result": _sec_result(by, "interfaces"),
            "interfaces_total": iface.get("total"),
            "tcp_mode": len(iface.get("tcp_modes") or iface.get("cleartext_modes") or []),
            "cleartext": len(iface.get("tcp_modes") or iface.get("cleartext_modes") or []),
            "mode_warn": len(iface.get("mode_warn") or []),
            "mode_preferred": len(iface.get("mode_preferred") or []),
            "no_mutual_auth_pw": bool(iface.get("no_mutual_auth_pw")),
            "mode_web_ok": len(iface.get("mode_web_ok") or []),
            "unauth_tls": len(iface.get("unauth_tls_modes") or []),  # legacy subset
            "ssh_interfaces": len(iface.get("ssh_interfaces") or []),
            "ssh_enabled": sum(
                1 for x in (iface.get("ssh_interfaces") or []) if x.get("enabled")
            ),
            "snmp_interfaces": len(iface.get("snmp_interfaces") or []),
            "snmp_enabled": sum(
                1 for x in (iface.get("snmp_interfaces") or []) if x.get("enabled")
            ),
            "preboot_interfaces": len(iface.get("preboot_interfaces") or []),
            "preboot_enabled": sum(
                1 for x in (iface.get("preboot_interfaces") or []) if x.get("enabled")
            ),
            "weak_tls": len(iface.get("weak_tls") or []),
            "web_pqc_ok": len(iface.get("web_pqc_ok") or []),
            "web_no_pqc": len(iface.get("web_no_pqc") or iface.get("no_pqc") or []),
            "tls_certs_expired": len(iface.get("tls_certs_expired") or []),
            "tls_certs_expiring_soon": len(iface.get("tls_certs_expiring_soon") or []),
            "tls_certs_ok": len(iface.get("tls_certs_ok") or []),
            "log_forwarders_active": fwd.get("active"),
            "smtp_servers": notif.get("smtp_servers"),
            "email_addresses": notif.get("email_addresses"),
        },
        "certificates": {
            "local": _ca_block(ca_local, _sec_result(by, "ca_local")),
            "external": _ca_block(ca_ext, _sec_result(by, "ca_external")),
            "trusted": {
                "result": _sec_result(by, "ca_trusted"),
                "total": ca_trust.get("total"),
                "expired": len(ca_trust.get("expired") or []),
                "expiring_soon": len(ca_trust.get("expiring_soon") or []),
                "ok": len(ca_trust.get("ok") or []),
                "skipped": ca_trust.get("skipped"),
                "reason": ca_trust.get("reason"),
            }
            if ca_trust or _sec_result(by, "ca_trusted")
            else None,
            "domains_checked": ca_local.get("domains_checked"),
            "domains_skipped": ca_local.get("domains_skipped"),
            "by_domain": ca_local.get("by_domain") or ca_ext.get("by_domain"),
        },
        "backups": {
            "result": _sec_result(by, "backups_list") or _sec_result(by, "backup_scheduler"),
            "count": backups.get("total"),
            "system_count": backups.get("system_count"),
            "domain_count": backups.get("domain_count"),
            "by_domain": backups.get("by_domain"),
            "latest_status": backup_status.get("status"),
            "schedule_enabled": backup_sched.get("enabled"),
        },
        "access": {
            "password_policies": _sec_result(by, "password_policies"),
            "pwd_weak_count": len(pwd.get("weak_policies") or []) if pwd else None,
            "pwd_total": pwd.get("total") if pwd else None,
            "ldap": {
                "result": _sec_result(by, "ldap_connections"),
                "total": ldap.get("total"),
                "insecure_skip_verify": sum(
                    1
                    for c in (ldap.get("connections") or [])
                    if isinstance(c, dict) and c.get("insecure_skip_verify") is True
                ),
            }
            if ldap or _sec_result(by, "ldap_connections")
            else None,
            "domains_total": domains.get("total")
            if domains and domains.get("total") is not None
            else (domains.get("count") if domains else None),
        },
        "users": users,
        "keys": keys,
        "orphaned": {
            "result": _sec_result(by, "orphaned_resources"),
            "orphaned_keys": orphan.get("total_orphaned_keys_count"),
        }
        if orphan or _sec_result(by, "orphaned_resources")
        else None,
        "quorum": {
            "result": _sec_result(by, "quorum_policies"),
            "enabled": quorum.get("enabled", quorum.get("active")),
            "total": quorum.get("total"),
            "active_requests": quorum.get("requests_active"),
            "pre_active_requests": quorum.get("requests_pre_active"),
            "total_requests": quorum.get("requests_total"),
            "requests_by_state": quorum.get("requests_by_state"),
        }
        if quorum or _sec_result(by, "quorum_policies")
        else None,
        "clients": {
            "result": _sec_result(by, "registered_clients"),
            "total": clients.get("total"),
        }
        if clients or _sec_result(by, "registered_clients")
        else None,
        "cte": {
            "result": _sec_result(by, "cte_clients") or _sec_result(by, "cte_policies"),
            "clients_total": cte.get("total"),
            "disconnected": len(cte.get("disconnected") or []),
            "unregistered_or_offline": len(cte.get("unregistered_or_offline") or []),
            "guardpoints_not_active": len(cte.get("guardpoints_not_active") or []),
            "learn_mode_policies": len(cte_pol.get("learn_mode_policies") or []),
        }
        if cte or cte_pol or _sec_result(by, "cte_clients")
        else None,
        "audit": {
            "result": _sec_result(by, "audit_records"),
            "skipped": bool(audit.get("skipped")),
            "reason": audit.get("reason"),
            "source": audit.get("source"),
            "db_store": audit.get("db_store"),
            "db_store_note": audit.get("db_store_note"),
            "server_counts": audit.get("server_counts"),
            "client_counts": audit.get("client_counts"),
            "cm_version": audit.get("cm_version"),
        }
        if audit or _sec_result(by, "audit_records")
        else None,
        "section_results": {
            name: s.get("result") for name, s in by.items() if s.get("result")
        },
    }


def _md_bold(text: str, when: bool = True) -> str:
    """Wrap in markdown bold when ``when`` is true (agents render Summary as MD)."""
    if not when or text is None:
        return "" if text is None else str(text)
    s = str(text)
    if not s or (s.startswith("**") and s.endswith("**")):
        return s
    return f"**{s}**"


def _cap_summary_line(s: str) -> str:
    """Ensure each Summary line starts with an uppercase letter (after ** if bold)."""
    s = s.strip()
    if not s:
        return s
    # Keep domain / name labels intact (e.g. "root: 6", "childdomain1: skipped").
    if re.match(r"^[A-Za-z0-9_./-]+\s*:", s):
        return s
    if s.startswith("**") and len(s) > 2:
        # **disk not encrypted** -> **Disk not encrypted**
        inner = s[2:]
        end = ""
        if inner.endswith("**"):
            inner, end = inner[:-2], "**"
        if inner:
            inner = inner[0].upper() + inner[1:]
        return f"**{inner}{end}"
    return s[0].upper() + s[1:]


def _summary_lines(*parts: str | None) -> str:
    """Join Summary clauses with HTML line breaks for markdown table cells."""
    bits = [
        _cap_summary_line(str(p).strip().rstrip("."))
        for p in parts
        if p and str(p).strip()
    ]
    return "<br>".join(bits) + ("." if bits else "")


def _cluster_status_label(desc: str, code: str) -> str:
    """Map CM cluster status description/code to a short English label."""
    low = (desc or "").strip().lower()
    c = (code or "").strip().lower()
    aliases = {
        "r": "ready",
        "ready": "ready",
        "d": "down",
        "down": "down",
        "nr": "not ready",
        "not ready": "not ready",
        "degraded": "degraded",
        "joining": "joining",
        "leaving": "leaving",
    }
    if low in aliases:
        return aliases[low]
    if c in aliases:
        return aliases[c]
    if desc and low not in ("r", "nr", "d"):
        return desc.strip()
    return code.strip() or desc.strip() or "unknown"


def _cluster_summary_phrase(app: dict[str, Any]) -> str:
    """Human cluster line for Appliance Summary (status + why when unhealthy)."""
    desc = str(app.get("cluster") or "").strip()
    code = str(app.get("cluster_status_code") or "").strip()
    nodes = app.get("cluster_nodes")
    errs = app.get("cluster_errors")
    reasons = app.get("cluster_error_reasons") or []
    low = desc.lower()
    if not desc and not code:
        return "Cluster none"
    if low in ("none", "not clustered", "n/a") or code.lower() in ("none", "n"):
        return "Cluster none"
    status = _cluster_status_label(desc, code)
    head = f"Cluster {status}"
    if nodes is not None:
        head += f", {nodes} node(s)"
    err_n = int(errs) if errs is not None else 0
    if err_n > 0:
        why = "; ".join(str(r) for r in reasons[:3]) if reasons else None
        if why:
            return f"{head}: {_md_bold(why)}"
        return f"{head}: {_md_bold(f'{err_n} node(s) reporting errors')}"
    if errs is not None:
        return f"{head}, 0 errors"
    return head


def _ca_summary_phrase(kind: str, block: dict[str, Any] | None) -> str:
    """Plain English for one CA class (local / external / trusted)."""
    if not block:
        return f"{kind}: not checked"
    total = block.get("total")
    expired = int(block.get("expired") or 0)
    soon = int(block.get("expiring_soon") or 0)
    ok = int(block.get("ok") or 0)
    if total == 0 or (total is None and expired == 0 and soon == 0 and ok == 0):
        return f"{kind}: none configured"
    bits = []
    if expired:
        bits.append(_md_bold(f"{expired} expired"))
    if soon:
        bits.append(_md_bold(f"{soon} expire within 30 days"))
    if ok:
        bits.append(f"{ok} valid (>30 days left)")
    if not bits and total is not None:
        bits.append(f"{total} total")
    head = f"{kind}: {total} total" if total is not None else f"{kind}:"
    return f"{head} - " + "; ".join(bits) if bits else head


def build_posture_table(posture: dict[str, Any]) -> list[dict[str, str]]:
    """Area / Result / Summary rows in plain English for agents to copy.

    Summary uses markdown ``**bold**`` on facts that drive WARN/FAIL so chat
    tables can emphasize them. Agents must preserve the asterisks.
    """
    rows: list[dict[str, str]] = []

    def add(area: str, result: Any, summary: str) -> None:
        r = str(result or "n/a")
        # Bold non-PASS results in the Result column for markdown tables
        if r.upper() in ("FAIL", "WARN", "CRITICAL"):
            r_out = _md_bold(r)
        else:
            r_out = r
        rows.append({"area": area, "result": r_out, "summary": summary})

    app = posture.get("appliance") or {}
    disk_state = str(app.get("disk_enc_state") or "").lower()
    disk_enc = app.get("disk_encrypted")
    if app.get("disk_encrypting") or disk_state == "encrypting":
        disk_s = "disk encryption in progress"
    elif disk_enc is True or disk_state == "encrypted":
        disk_s = "disk encrypted"
    elif disk_enc is False or disk_state == "not_encrypted":
        disk_s = _md_bold("disk not encrypted")
    else:
        disk_s = f"disk encryption status={app.get('disk_encryption')!r}"
    down_n = int(app.get("services_not_started") or 0)
    disabled_names = [
        str(n) for n in (app.get("services_disabled_names") or []) if n
    ]
    down_names = [
        str(n) for n in (app.get("services_not_started_names") or []) if n
    ]
    ntp_sync = app.get("ntp_synchronized")
    if ntp_sync is True:
        ntp_s = "NTP synchronized"
    elif ntp_sync is False:
        ntp_s = _md_bold("NTP not synchronized")
    else:
        ntp_s = "NTP status unavailable"
    banner_ok = bool(app.get("banner_configured"))
    attended = app.get("attended_boot") is True
    preboot_n = app.get("preboot_interfaces")
    cluster_s = _cluster_summary_phrase(app)
    svc_disabled_line = None
    if disabled_names:
        shown = ", ".join(disabled_names[:20])
        if len(disabled_names) > 20:
            shown += f" … +{len(disabled_names) - 20} more"
        svc_disabled_line = f"Disabled: {shown}"
    svc_down_line = None
    if down_n:
        if down_names:
            shown = ", ".join(down_names[:20])
            if len(down_names) > 20:
                shown += f" … +{len(down_names) - 20} more"
            svc_down_line = _md_bold(f"Down: {shown}")
        else:
            svc_down_line = _md_bold(f"{down_n} service(s) down")
    add(
        "Appliance",
        app.get("result"),
        _summary_lines(
            f"CM {app.get('version')}",
            f"Services {app.get('services_started')}/{app.get('services_total')} up",
            svc_disabled_line,
            svc_down_line,
            cluster_s,
            ntp_s,
            disk_s,
            _md_bold("attended boot enabled") if attended else None,
            f"Preboot interfaces={preboot_n}" if preboot_n is not None else None,
            "Login banner configured"
            if banner_ok
            else _md_bold("login banner missing"),
        ),
    )

    rot = posture.get("rot_keys") or {}
    rot_keys = rot.get("keys") or []
    ages = []
    for k in rot_keys[:5]:
        if isinstance(k, dict) and k.get("id") is not None:
            label = k.get("age_label") or _format_age_short(k.get("age_days"))
            if label == "n/a" and k.get("age_years") is not None:
                label = f"~{k.get('age_years')}y"
            ages.append(f"{k.get('id')} {label}")
    rot_bits = []
    if rot.get("older_than_12m"):
        rot_bits.append(
            _md_bold(f"{rot.get('older_than_12m')} key(s) >=12 months (critical)")
        )
    if rot.get("older_than_6m"):
        rot_bits.append(
            _md_bold(f"{rot.get('older_than_6m')} key(s) >=6 months (warn)")
        )
    if not rot_bits:
        rot_bits.append("all RoT keys younger than 6 months")
    add(
        "RoT",
        rot.get("result"),
        _summary_lines(
            f"{rot.get('total') or 0} root-of-trust key(s)",
            "; ".join(rot_bits) + (f" ({', '.join(ages)})" if ages else ""),
        ),
    )

    lic = posture.get("licensing") or {}
    lic_bits = [f"{lic.get('active') or 0} active licenses"]
    if lic.get("expired"):
        lic_bits.append(_md_bold(f"{lic.get('expired')} expired"))
    if lic.get("expiring_soon"):
        lic_bits.append(
            _md_bold(f"{lic.get('expiring_soon')} expire within 30 days")
        )
    if lic.get("trials_expiring_soon"):
        lic_bits.append(
            _md_bold(
                f"{lic.get('trials_expiring_soon')} trial feature(s) expire within 30 days"
            )
        )
    add("Licenses", lic.get("result"), _summary_lines(*lic_bits))

    alarms = posture.get("alarms") or {}
    au = int(alarms.get("active_unacknowledged") or 0)
    crit_a = int(alarms.get("critical_active") or 0)
    add(
        "Alarms",
        alarms.get("result"),
        _summary_lines(
            (
                _md_bold(f"{au} active (state=on)")
                if au
                else f"{au} active (state=on)"
            )
            + f" (of {alarms.get('total') or 0} listed)",
            (
                _md_bold(f"{crit_a} critical/error severity")
                if crit_a
                else f"{crit_a} critical/error severity"
            ),
            (
                _md_bold(f"{alarms.get('warning_active') or 0} warning severity")
                if alarms.get("warning_active")
                else f"{alarms.get('warning_active') or 0} warning severity"
            ),
            (
                f"{alarms.get('info_active')} info severity"
                if alarms.get("info_active") is not None
                else None
            ),
        ),
    )

    net = posture.get("network") or {}
    tcp_n = int(net.get("tcp_mode") or 0)
    warn_n = int(net.get("mode_warn") or 0)
    pref_n = int(net.get("mode_preferred") or 0)
    web_n = int(net.get("mode_web_ok") or 0)
    web_pqc_ok = int(net.get("web_pqc_ok") or 0)
    web_no_pqc = int(net.get("web_no_pqc") or 0)
    exp_n = int(net.get("tls_certs_expired") or 0)
    soon_n = int(net.get("tls_certs_expiring_soon") or 0)
    weak_n = int(net.get("weak_tls") or 0)
    if web_n or web_pqc_ok or web_no_pqc:
        if web_no_pqc:
            web_pqc_line = _md_bold(
                f"Web PQC not enabled ({web_no_pqc} web interface(s))"
            )
        elif web_pqc_ok:
            web_pqc_line = f"Web PQC enabled ({web_pqc_ok} web interface(s))"
        else:
            web_pqc_line = "Web PQC status unavailable"
    else:
        web_pqc_line = None
    add(
        "Interfaces",
        net.get("result"),
        _summary_lines(
            f"{net.get('interfaces_total') or 0} interfaces",
            (
                _md_bold(f"{tcp_n} TCP/no-TLS mode interface(s)")
                if tcp_n
                else f"{tcp_n} TCP/no-TLS mode interface(s)"
            ),
            (
                _md_bold(f"{warn_n} other TLS mode interface(s) to harden")
                if warn_n
                else f"{warn_n} other TLS mode interface(s) to harden"
            ),
            f"{web_n} web interface(s) OK",
            web_pqc_line,
            (
                _md_bold(
                    f"{pref_n} TLS enabled interface(s) require client cert "
                    f"(mutual auth) and password"
                )
                if (pref_n == 0 and (warn_n or tcp_n or net.get("no_mutual_auth_pw")))
                else (
                    f"{pref_n} TLS enabled interface(s) require client cert "
                    f"(mutual auth) and password"
                )
            ),
            f"SSH {net.get('ssh_enabled') or 0}/{net.get('ssh_interfaces') or 0} enabled",
            f"SNMP {net.get('snmp_enabled') or 0}/{net.get('snmp_interfaces') or 0} enabled",
            f"Preboot {net.get('preboot_enabled') or 0}/{net.get('preboot_interfaces') or 0}",
            "TLS certs: "
            + (_md_bold(f"{exp_n} expired") if exp_n else f"{exp_n} expired")
            + ", "
            + (
                _md_bold(f"{soon_n} expire within 30 days")
                if soon_n
                else f"{soon_n} expire within 30 days"
            )
            + f", {net.get('tls_certs_ok') or 0} ok",
            _md_bold(f"{weak_n} weak TLS minimum") if weak_n else None,
            f"{net.get('log_forwarders_active') or 0} active log forwarder(s)",
            f"{net.get('smtp_servers') or 0} SMTP server(s)",
        ),
    )

    certs = posture.get("certificates") or {}
    ca_result = _worst_result(
        (certs.get("local") or {}).get("result"),
        (certs.get("external") or {}).get("result"),
        (certs.get("trusted") or {}).get("result"),
    )
    ca_domain_lines: list[str | None] = []
    ca_checked = certs.get("domains_checked")
    ca_skipped = certs.get("domains_skipped")
    if ca_checked is not None or ca_skipped is not None:
        skip_bit = (
            _md_bold(f"skipped={ca_skipped or 0}")
            if (ca_skipped or 0) > 0
            else f"skipped={ca_skipped or 0}"
        )
        ca_domain_lines.append(
            f"Domains checked={ca_checked or 0}, {skip_bit}"
        )
    ca_by_dom = [d for d in (certs.get("by_domain") or []) if isinstance(d, dict)]
    if ca_by_dom:
        # Prefer reachable domains in the short posture sample.
        ca_by_dom = sorted(
            ca_by_dom,
            key=lambda d: (
                1 if d.get("skipped") or d.get("error") else 0,
                str(d.get("domain") or ""),
            ),
        )
        ca_domain_lines.append("Per domain:")
        for d in ca_by_dom[:12]:
            name = d.get("domain") or "?"
            if d.get("skipped"):
                ca_domain_lines.append(
                    f"{name}: skipped ({d.get('reason') or 'n/a'})"
                )
            elif d.get("error"):
                ca_domain_lines.append(f"{name}: error")
            else:
                loc = d.get("local") if isinstance(d.get("local"), dict) else {}
                ext = d.get("external") if isinstance(d.get("external"), dict) else {}
                loc_n = loc.get("total")
                ext_n = ext.get("total")
                loc_exp = int(loc.get("expired") or 0)
                ext_exp = int(ext.get("expired") or 0)
                loc_s = f"local={loc_n if loc_n is not None else '?'}"
                if loc_exp:
                    loc_s += f" ({_md_bold(f'{loc_exp} expired')})"
                ext_s = f"external={ext_n if ext_n is not None else '?'}"
                if ext_exp:
                    ext_s += f" ({_md_bold(f'{ext_exp} expired')})"
                ca_domain_lines.append(f"{name}: {loc_s}, {ext_s}")
        if len(ca_by_dom) > 12:
            ca_domain_lines.append(f"… +{len(ca_by_dom) - 12} more")
    trusted_block = certs.get("trusted")
    if isinstance(trusted_block, dict) and trusted_block.get("skipped"):
        trusted_phrase = (
            f"Trusted CAs: skipped ({trusted_block.get('reason') or 'n/a'})"
        )
    else:
        trusted_phrase = _ca_summary_phrase("Trusted CAs", trusted_block)
    add(
        "CAs",
        ca_result,
        _summary_lines(
            _ca_summary_phrase("Local CAs", certs.get("local")),
            _ca_summary_phrase("External CAs", certs.get("external")),
            trusted_phrase,
            *ca_domain_lines,
        ),
    )

    backups = posture.get("backups") or {}
    b_total = backups.get("count") or 0
    b_system = backups.get("system_count")
    b_domain = backups.get("domain_count")
    if b_system is not None or b_domain is not None:
        backup_count_line = (
            f"{b_total} backup(s) in configured domain "
            f"(system={b_system or 0}, domain={b_domain or 0})"
        )
    else:
        backup_count_line = f"{b_total} backup(s) in configured domain"
    backup_domain_lines: list[str | None] = []
    by_dom = [d for d in (backups.get("by_domain") or []) if isinstance(d, dict)]
    if by_dom:
        backup_domain_lines.append("Per domain:")
        for d in by_dom[:12]:
            name = d.get("domain") or "?"
            if d.get("skipped"):
                backup_domain_lines.append(
                    f"{name}: skipped ({d.get('reason') or 'n/a'})"
                )
            elif d.get("error"):
                backup_domain_lines.append(f"{name}: error")
            else:
                backup_domain_lines.append(
                    f"{name}: {d.get('total') or 0} "
                    f"(system={d.get('system_count') or 0}, "
                    f"domain={d.get('domain_count') or 0})"
                )
        if len(by_dom) > 12:
            backup_domain_lines.append(f"… +{len(by_dom) - 12} more")
    add(
        "Backups",
        backups.get("result"),
        _summary_lines(
            backup_count_line,
            f"Latest status={backups.get('latest_status') or 'n/a'}",
            f"{backups.get('schedule_enabled') or 0} schedule job(s) enabled",
            *backup_domain_lines,
        ),
    )

    access = posture.get("access") or {}
    ldap = access.get("ldap") or {}
    insecure = int(ldap.get("insecure_skip_verify") or 0)
    pwd_weak = int(access.get("pwd_weak_count") or 0)
    pwd_total = access.get("pwd_total")
    add(
        "Access",
        _worst_result(
            access.get("password_policies"),
            (ldap.get("result") if ldap else None),
        )
        or "PASS",
        _summary_lines(
            f"{access.get('domains_total') or 0} domain(s)",
            (
                _md_bold(f"{pwd_weak} weak password policy(ies)")
                if pwd_weak
                else (
                    f"{pwd_total} password policy(ies)"
                    if pwd_total is not None
                    else None
                )
            ),
            f"{ldap.get('total') or 0} LDAP connection(s)",
            (
                _md_bold(f"{insecure} with insecure TLS skip-verify")
                if insecure
                else f"{insecure} with insecure TLS skip-verify"
            ),
        ),
    )

    users = posture.get("users") or {}
    ut = users.get("totals") or {}
    locked = int(ut.get("locked") or 0)
    never = int(ut.get("never_logged_in") or 0)
    inactive = int(ut.get("inactive_30d") or 0)
    failed = int(ut.get("failed_logins_not_locked") or 0)
    add(
        "Users",
        users.get("result"),
        _summary_lines(
            f"Scanned {ut.get('domains_with_users') or 0} domain(s), "
            f"{ut.get('users_total') or 0} user(s)",
            _md_bold(f"{locked} locked") if locked else f"{locked} locked",
            (
                _md_bold(f"{never} never logged in")
                if never
                else f"{never} never logged in"
            ),
            (
                _md_bold(f"{inactive} inactive >30 days")
                if inactive
                else f"{inactive} inactive >30 days"
            ),
            (
                _md_bold(f"{failed} with failed logins (not locked)")
                if failed
                else f"{failed} with failed logins (not locked)"
            ),
        ),
    )

    keys = posture.get("keys") or {}
    kd = keys.get("domains") or {}
    km = keys.get("metrics") or {}
    weak = int(kd.get("weak") or 0)
    inactive_k = int(kd.get("non_active") or 0)
    skipped = int(kd.get("skipped") or 0)
    deks_total = km.get("deks_total")
    if deks_total is not None:
        estate = f"Total Keys (Including orphaned)={deks_total}"
    elif km.get("enabled") is False:
        estate = "Prometheus metrics disabled"
    elif km:
        estate = "Total Keys unavailable"
    else:
        estate = "Total Keys not checked"
    add(
        "Keys",
        keys.get("result"),
        _summary_lines(
            estate,
            f"Domains checked={kd.get('checked')}, "
            + (
                _md_bold(f"skipped={skipped}")
                if skipped
                else f"skipped={skipped}"
            ),
            (
                _md_bold(f"weak keys in scanned domains={weak}")
                if weak
                else f"weak keys in scanned domains={weak}"
            ),
            (
                _md_bold(f"{inactive_k} key(s) whose latest version is not Active")
                if inactive_k
                else f"{inactive_k} key(s) whose latest version is not Active"
            ),
        ),
    )

    orphan = posture.get("orphaned") or {}
    if orphan:
        ok_n = int(orphan.get("orphaned_keys") or 0)
        add(
            "Orphaned",
            orphan.get("result"),
            (
                _md_bold(f"{ok_n} orphaned key(s) reported")
                if ok_n
                else f"{ok_n} orphaned key(s) reported"
            )
            + ".",
        )

    quorum = posture.get("quorum") or {}
    if quorum:
        en = int(quorum.get("enabled") or 0)
        tot_pol = int(quorum.get("total") or 0)
        act = int(quorum.get("active_requests") or 0)
        pre = int(quorum.get("pre_active_requests") or 0)
        tot_req = quorum.get("total_requests")
        by_st = quorum.get("requests_by_state") or {}
        open_n = act + pre
        # Closed/historical = everything not active/pre-active
        closed_bits = []
        for st, n in sorted(by_st.items()):
            if str(st).lower() in ("active", "pre-active", "pre_active", "preactive"):
                continue
            if n:
                closed_bits.append(f"{st}={n}")
        if open_n:
            open_line = (
                _md_bold(f"{act} waiting for approval (active)")
                if act
                else f"{act} waiting for approval (active)"
            )
            open_line += ", "
            open_line += (
                _md_bold(f"{pre} pre-active")
                if pre
                else f"{pre} pre-active"
            )
        else:
            open_line = "none waiting for approval"
        hist_line = None
        if tot_req is not None and int(tot_req) > open_n:
            closed_n = int(tot_req) - open_n
            hist_line = f"{closed_n} older/closed on file"
            if closed_bits:
                hist_line += f" ({', '.join(closed_bits)})"
        elif tot_req == 0 or tot_req is None:
            hist_line = "no approval requests on file"
        add(
            "Quorum",
            quorum.get("result"),
            _summary_lines(
                f"Quorum policies: {en} of {tot_pol} enabled",
                f"Approval requests: {open_line}",
                hist_line,
            ),
        )

    clients = posture.get("clients") or {}
    if clients:
        add(
            "Clients",
            clients.get("result"),
            f"{clients.get('total') or 0} registered client-management client(s).",
        )

    cte = posture.get("cte") or {}
    if cte:
        disc = int(cte.get("disconnected") or 0)
        unreg = int(cte.get("unregistered_or_offline") or 0)
        gp = int(cte.get("guardpoints_not_active") or 0)
        learn = int(cte.get("learn_mode_policies") or 0)
        add(
            "CTE",
            cte.get("result"),
            _summary_lines(
                f"{cte.get('clients_total') or 0} CTE client(s)",
                _md_bold(f"{disc} disconnected") if disc else f"{disc} disconnected",
                (
                    _md_bold(f"{unreg} unregistered/offline")
                    if unreg
                    else f"{unreg} unregistered/offline"
                ),
                (
                    _md_bold(f"{gp} GuardPoint(s) not active")
                    if gp
                    else f"{gp} GuardPoint(s) not active"
                ),
                (
                    _md_bold(f"{learn} polic(ies) in Learn Mode")
                    if learn
                    else f"{learn} polic(ies) in Learn Mode"
                ),
            ),
        )

    audit = posture.get("audit") or {}
    if audit:
        if audit.get("skipped"):
            add(
                "Audit",
                audit.get("result"),
                _summary_lines(
                    f"Skipped ({audit.get('reason') or 'n/a'})",
                    f"CM {audit.get('cm_version') or 'n/a'}",
                ),
            )
        else:
            sc = audit.get("server_counts") or {}
            cc = audit.get("client_counts") or {}
            s_err = int(sc.get("error") or 0)
            s_crit = int(sc.get("critical") or 0) + int(sc.get("fatal") or 0)
            c_err = int(cc.get("error") or 0)
            c_fatal = int(cc.get("fatal") or 0) + int(cc.get("critical") or 0)
            src = str(audit.get("source") or "audit")
            db_note = audit.get("db_store_note")
            if src == "loki":
                head = "Loki audit (7d)"
            elif src == "db":
                head = "DB audit (7d)"
            elif src == "none":
                head = "Audit unavailable"
            else:
                head = f"Audit ({src})"
            add(
                "Audit",
                audit.get("result"),
                _summary_lines(
                    db_note,
                    head,
                    "Server "
                    + (
                        _md_bold(f"critical/fatal={s_crit}")
                        if s_crit
                        else f"critical/fatal={s_crit}"
                    )
                    + ", "
                    + (_md_bold(f"error={s_err}") if s_err else f"error={s_err}"),
                    "Client "
                    + (
                        _md_bold(f"critical/fatal={c_fatal}")
                        if c_fatal
                        else f"critical/fatal={c_fatal}"
                    )
                    + ", "
                    + (_md_bold(f"error={c_err}") if c_err else f"error={c_err}"),
                ),
            )

    return rows
