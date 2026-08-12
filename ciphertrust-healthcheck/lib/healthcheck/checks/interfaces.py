"""Network interface, log forwarder, and notification checks."""
from __future__ import annotations

from typing import Any

from cm_client import CmClient, CmError

from ..context import ReportCtx
from ..modes import (
    PQC_GROUPS,
    PREFERRED_INTERFACE_MODE,
    WEAK_TLS,
    interface_mode_label,
    interface_mode_severity,
)
from ..util import (
    days_until,
    emit_cert_validity,
    parse_date,
    pem_leaf_not_after,
    safe_get,
)

def check_interfaces(ctx: ReportCtx, client: CmClient) -> None:
    # Default CM page is limit=10; always paginate so web/etc. are not dropped.
    try:
        data = client.get_paginated(
            "/v1/configs/interfaces/", limit=100, max_items=500
        )
    except CmError as err:
        ctx.section("interfaces", "FAIL", {"error": str(err)}, err.status)
        return
    resources = data.get("resources") or []
    tcp_mode: list[dict] = []
    mode_warn: list[dict] = []
    mode_preferred: list[dict] = []  # tls-cert-and-pw only
    mode_web_ok: list[dict] = []  # web platform-supported modes
    ssh_ifaces: list[dict] = []
    snmp_ifaces: list[dict] = []
    preboot_ifaces: list[dict] = []
    weak_tls = []
    disabled = []
    no_pqc = []  # web interfaces with no PQC TLS group enabled
    web_pqc_ok = []  # web interfaces with at least one PQC group enabled
    cert_expired = []
    cert_expiring = []
    cert_ok = []
    cert_errors = []
    rows = []
    for i in resources:
        if not isinstance(i, dict):
            continue
        name = i.get("name")
        enabled = i.get("enabled")
        itype = str(i.get("interface_type") or "").strip().lower() or None
        mode = (i.get("mode") or "").strip()
        mode_l = mode.lower()
        label = interface_mode_label(mode_l) if mode_l else None
        tls = str(i.get("minimum_tls_version") or "").lower()
        row = {
            "name": name,
            "port": i.get("port"),
            "enabled": enabled,
            "interface_type": itype,
            "mode": mode or None,
            "mode_label": label,
            "network_interface": i.get("network_interface"),
            "minimum_tls_version": i.get("minimum_tls_version"),
        }
        rows.append(row)
        if itype == "ssh":
            ssh_ifaces.append(
                {
                    "name": name,
                    "port": i.get("port"),
                    "enabled": bool(enabled),
                    "network_interface": i.get("network_interface"),
                }
            )
        elif itype == "snmp":
            snmp_ifaces.append(
                {
                    "name": name,
                    "port": i.get("port"),
                    "enabled": bool(enabled),
                    "network_interface": i.get("network_interface"),
                }
            )
        elif itype == "preboot" or str(name or "").lower() == "preboot":
            preboot_ifaces.append(
                {
                    "name": name,
                    "port": i.get("port"),
                    "enabled": bool(enabled),
                    "mode": mode or None,
                    "mode_label": label,
                    "network_interface": i.get("network_interface"),
                }
            )
        if not enabled:
            disabled.append(name)
            if itype not in ("ssh", "snmp", "preboot"):
                ctx.add("interfaces",
                    "net_interface_disabled",
                    "INFO",
                    f"Service interface '{name}' is DISABLED (often intentional).",
                )
        elif enabled and itype != "preboot":
            sev = interface_mode_severity(mode, interface_type=itype)
            entry = {
                "name": name,
                "interface_type": itype,
                "mode": mode or None,
                "mode_label": label,
            }
            if sev == "CRITICAL":
                tcp_mode.append(entry)
                ctx.add("interfaces",
                    "net_interface_tcp_mode",
                    "CRITICAL",
                    f"Service interface '{name}' uses TCP mode (no TLS): {label} "
                    f"({mode}).",
                )
            elif sev == "WARNING":
                mode_warn.append(entry)
                ctx.add("interfaces",
                    "net_interface_mode_warn",
                    "WARNING",
                    f"Service interface '{name}' mode is not tls-cert-and-pw: "
                    f"{label} ({mode}). Prefer tls-cert-and-pw.",
                )
            elif sev == "INFO":
                if itype == "web":
                    mode_web_ok.append(entry)
                    ctx.add("interfaces",
                        "net_interface_mode_web_ok",
                        "INFO",
                        f"Web interface '{name}' mode OK (platform-supported): "
                        f"{label} ({mode}).",
                    )
                else:
                    mode_preferred.append(entry)
                    ctx.add("interfaces",
                        "net_interface_mode_preferred",
                        "INFO",
                        f"Service interface '{name}' uses preferred mode: {label} "
                        f"({mode}).",
                    )
        if enabled and tls in WEAK_TLS:
            weak_tls.append({"name": name, "minimum_tls_version": tls})
            ctx.add("interfaces",
                "net_interface_weak_tls",
                "CRITICAL",
                f"Service interface '{name}' has weak minimum TLS '{tls}'.",
            )
        # PQC TLS groups apply to the web interface (Thales CM docs).
        tls_groups = i.get("tls_groups") or []
        if enabled and itype == "web":
            pqc = []
            if isinstance(tls_groups, list):
                for g in tls_groups:
                    if not isinstance(g, dict) or not g.get("enabled"):
                        continue
                    gname = str(g.get("group_name") or "").strip().lower()
                    if gname in PQC_GROUPS:
                        pqc.append(g.get("group_name"))
            if pqc:
                web_pqc_ok.append({"name": name, "groups": pqc[:8]})
                ctx.add("interfaces",
                    "net_web_pqc_enabled",
                    "INFO",
                    f"Web interface '{name}' has PQC TLS key-exchange enabled: "
                    f"{', '.join(str(x) for x in pqc[:8])}.",
                )
            else:
                no_pqc.append(name)
                ctx.add("interfaces",
                    "net_web_no_pqc",
                    "WARNING",
                    f"Web interface '{name}' has no PQC TLS key-exchange group "
                    f"enabled (classic groups only; enable e.g. X25519MLKEM768).",
                )

        if (
            enabled
            and name
            and not mode_l.startswith("no-tls")
            and mode_l not in ("", "none", "null")
        ):
            cdata, cerr = safe_get(client, f"/v1/configs/interfaces/{name}/certificate")
            if cerr:
                if cerr.status != 404:
                    cert_errors.append({"name": name, "error": str(cerr)})
                continue
            pem = ""
            if isinstance(cdata, dict):
                pem = cdata.get("certificates") or cdata.get("certificate") or ""
            if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem:
                cert_errors.append({"name": name, "error": "no PEM certificate in response"})
                continue
            not_after_dt = pem_leaf_not_after(pem)
            dleft = days_until(not_after_dt, ctx.now)
            na_s = not_after_dt.strftime("%Y-%m-%d") if not_after_dt else None
            row = {"name": name, "notAfter": na_s, "days_left": dleft}
            sev = emit_cert_validity(
                ctx,
                area="interfaces",
                code_prefix="net_iface_cert",
                label=f"Interface '{name}' TLS certificate",
                days_left=dleft,
                not_after=na_s,
            )
            if sev == "CRITICAL":
                cert_expired.append(row)
            elif sev == "WARNING":
                cert_expiring.append(row)
            elif sev == "INFO":
                cert_ok.append(row)
            rows[-1]["cert_notAfter"] = na_s
            rows[-1]["cert_days_left"] = dleft

    def _mgmt_iface_summary(kind: str, items: list[dict]) -> None:
        if not items:
            ctx.add("interfaces",
                f"net_{kind}_not_configured",
                "INFO",
                f"No {kind.upper()} interfaces are configured.",
            )
            return
        en = [x for x in items if x.get("enabled")]
        dis = [x for x in items if not x.get("enabled")]
        parts = []
        for x in items[:20]:
            state = "enabled" if x.get("enabled") else "disabled"
            port = x.get("port")
            nic = x.get("network_interface")
            bit = f"{x.get('name')} ({state}"
            if port is not None:
                bit += f", port {port}"
            if nic:
                bit += f", nic {nic}"
            bit += ")"
            parts.append(bit)
        msg = (
            f"{kind.upper()} configured: {len(items)} "
            f"(enabled={len(en)}, disabled={len(dis)}): "
            + "; ".join(parts)
        )
        if len(items) > 20:
            msg += f"; … +{len(items) - 20} more"
        msg += "."
        ctx.add("interfaces", f"net_{kind}_configured", "INFO", msg)

    _mgmt_iface_summary("ssh", ssh_ifaces)
    _mgmt_iface_summary("snmp", snmp_ifaces)
    # Prefer at least one service interface on tls-cert-and-pw (mutual auth + password).
    service_auth_modes = len(tcp_mode) + len(mode_warn) + len(mode_preferred)
    no_mutual_auth_pw = bool(service_auth_modes and not mode_preferred)
    if no_mutual_auth_pw:
        ctx.add("interfaces",
            "net_no_tls_cert_and_pw",
            "WARNING",
            "No TLS-enabled service interface requires client cert (mutual auth) "
            "and password (tls-cert-and-pw).",
        )
    if preboot_ifaces:
        en = [x for x in preboot_ifaces if x.get("enabled")]
        parts = []
        for x in preboot_ifaces[:10]:
            state = "enabled" if x.get("enabled") else "disabled"
            bit = f"{x.get('name')} ({state}"
            if x.get("port") is not None:
                bit += f", port {x.get('port')}"
            if x.get("mode"):
                bit += f", mode {x.get('mode')}"
            bit += ")"
            parts.append(bit)
        ctx.add("interfaces",
            "net_preboot_configured",
            "INFO",
            f"Preboot configured: {len(preboot_ifaces)} (enabled={len(en)}) — "
            f"auto-created when disk encryption is enabled: "
            + "; ".join(parts)
            + ".",
        )
    result = "FAIL" if (tcp_mode or weak_tls or cert_expired) else (
        "WARN"
        if (
            mode_warn
            or cert_expiring
            or cert_errors
            or no_pqc
            or no_mutual_auth_pw
        )
        else "PASS"
    )
    ctx.section(
        "interfaces",
        result,
        {
            "total": data.get("total", len(resources)),
            "enabled": sum(1 for r in rows if r.get("enabled")),
            "disabled": disabled,
            "tcp_modes": tcp_mode,
            "cleartext_modes": tcp_mode,
            "mode_warn": mode_warn,
            "mode_preferred": mode_preferred,
            "no_mutual_auth_pw": no_mutual_auth_pw,
            "mode_web_ok": mode_web_ok,
            "ssh_interfaces": ssh_ifaces,
            "snmp_interfaces": snmp_ifaces,
            "preboot_interfaces": preboot_ifaces,
            "unauth_tls_modes": [
                m for m in mode_warn if str(m.get("mode") or "").startswith("unauth-tls")
            ],
            "weak_tls": weak_tls,
            "web_pqc_ok": web_pqc_ok[:20],
            "web_no_pqc": no_pqc[:20],
            "no_pqc": no_pqc[:20],  # alias
            "tls_certs_expired": cert_expired,
            "tls_certs_expiring_soon": cert_expiring,
            "tls_certs_ok": cert_ok[:20],
            "tls_certs_errors": cert_errors[:10],
            "interfaces": rows,
        },
        200,
    )


def check_log_forwarders(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/configs/log-forwarders/")
    if err:
        data, err = safe_get(client, "/v1/configs/log-forwarders")
    if err:
        ctx.section("log_forwarders", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    active = [r for r in resources if isinstance(r, dict) and not r.get("disabled")]
    if not active:
        ctx.add("interfaces",
            "net_no_active_log_forwarders",
            "WARNING",
            "No active external log forwarders are configured.",
        )
        ctx.section(
            "log_forwarders",
            "WARN",
            {"total": len(resources), "active": 0},
            200,
        )
    else:
        ctx.section(
            "log_forwarders",
            "PASS",
            {
                "total": len(resources),
                "active": len(active),
                "names": [r.get("name") for r in active[:10]],
            },
            200,
        )


def check_notifications(ctx: ReportCtx, client: CmClient) -> None:
    smtp, serr = safe_get(client, "/v1/notification/smtp-servers")
    emails, eerr = safe_get(client, "/v1/notification/email-addresses")
    detail: dict[str, Any] = {}
    result = "PASS"
    if serr:
        detail["smtp_error"] = str(serr)
        result = "WARN"
        smtp_count = 0
    else:
        smtp_count = len((smtp or {}).get("resources") or [])
        detail["smtp_servers"] = smtp_count
        if smtp_count == 0:
            ctx.add("system", "smtp_missing", "WARNING", "No SMTP server configured for email alerting.")
            result = "WARN"
    if eerr:
        detail["email_error"] = str(eerr)
        result = "WARN"
    else:
        email_count = len((emails or {}).get("resources") or [])
        detail["email_addresses"] = email_count
        if smtp_count > 0 and email_count == 0:
            ctx.add(
                "system",
                "notification_emails_missing",
                "WARNING",
                "SMTP is configured but no notification email recipients are set.",
            )
            result = "WARN"
    ctx.section("notifications", result, detail, 200)
