"""Appliance checks: services, cluster, NTP, banner, disk encryption, RoT keys."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from cm_client import CmClient, CmError

from ..context import ReportCtx
from ..util import parse_date, safe_get, summarize_list

def check_services(ctx: ReportCtx, data: Any) -> None:
    services = []
    if isinstance(data, dict):
        services = data.get("services") or []
    disabled = []
    down = []
    for s in services:
        if not isinstance(s, dict):
            continue
        status = str(s.get("status") or "").lower()
        if status == "started":
            continue
        row = {"name": s.get("name"), "status": s.get("status")}
        if status == "disabled":
            disabled.append(row)
        else:
            down.append(row)
    detail = {
        "total": len(services),
        "started": len(services) - len(disabled) - len(down),
        "disabled": disabled[:20],
        "not_started": down[:20],
        "overall_status": data.get("status") if isinstance(data, dict) else None,
    }
    for s in disabled[:15]:
        ctx.add(
            "system",
            "svc_disabled",
            "INFO",
            f"Service '{s.get('name')}' is disabled (by configuration).",
        )
    for s in down[:15]:
        ctx.add(
            "system",
            "svc_not_started",
            "CRITICAL",
            f"Service '{s.get('name')}' is not started (status={s.get('status')}).",
        )
    result = "FAIL" if down else "PASS"
    ctx.section("services_status", result, detail, 200)


def _cluster_error_reason(msg: str) -> str:
    """Short plain-English label for a CM cluster/RAFT error message."""
    raw = (msg or "").strip()
    if not raw:
        return "unknown cluster error"
    m = raw.lower()
    if "no leader" in m:
        return "no etcd leader"
    if "no route to" in m or "failed to connect to remote peer" in m:
        return "peer unreachable"
    if "leased session" in m or ("lease" in m and "deadline" in m):
        return "etcd lease timeout"
    if "context deadline exceeded" in m:
        return "cluster RPC timeout"
    if "connection refused" in m:
        return "peer connection refused"
    # Keep RAFT/etcd suffix when present; truncate for Summary
    short = raw.split(":", 1)[-1].strip() if ":" in raw else raw
    short = re.sub(r"\s+", " ", short)
    return short[:72] + ("…" if len(short) > 72 else "")


def _extract_cluster_error_reasons(resources: list[Any]) -> list[str]:
    """Dedupe short reasons from /v1/cluster/errors resource entries."""
    reasons: list[str] = []
    seen: set[str] = set()
    for entry in resources:
        if not isinstance(entry, dict):
            continue
        msgs = entry.get("clusterErrors") or entry.get("errors") or []
        if isinstance(msgs, dict):
            msgs = [msgs]
        if not isinstance(msgs, list):
            continue
        for item in msgs:
            if isinstance(item, dict):
                text = str(item.get("errorMessage") or item.get("message") or "")
            else:
                text = str(item or "")
            reason = _cluster_error_reason(text)
            key = reason.lower()
            if key in seen:
                continue
            seen.add(key)
            reasons.append(reason)
    return reasons


def check_cluster(ctx: ReportCtx, client: CmClient) -> None:
    cluster, err = safe_get(client, "/v1/cluster")
    if err:
        ctx.section("cluster", "FAIL", {"error": str(err)}, err.status)
    else:
        status = (cluster or {}).get("status") or {}
        detail = {
            "nodeID": (cluster or {}).get("nodeID"),
            "status_code": status.get("code") if isinstance(status, dict) else status,
            "status_description": status.get("description") if isinstance(status, dict) else None,
        }
        ctx.section("cluster", "PASS", detail, 200)

    summary, err = safe_get(client, "/v1/cluster/summary")
    if err:
        ctx.section("cluster_summary", "WARN", {"error": str(err)}, err.status)
    else:
        ctx.section("cluster_summary", "PASS", summarize_list(summary), 200)

    errors, err = safe_get(client, "/v1/cluster/errors")
    if err:
        ctx.section("cluster_errors", "WARN", {"error": str(err)}, err.status)
    else:
        resources = []
        if isinstance(errors, dict):
            resources = errors.get("resources") or errors.get("errors") or []
            if not isinstance(resources, list):
                resources = [errors] if errors else []
        elif isinstance(errors, list):
            resources = errors
        if resources:
            reasons = _extract_cluster_error_reasons(resources)
            reason_txt = "; ".join(reasons[:4]) if reasons else "see cluster errors"
            ctx.add(
                "system",
                "cluster_errors",
                "CRITICAL",
                f"Cluster reports errors on {len(resources)} node(s)"
                + (f": {reason_txt}." if reason_txt else "."),
            )
            ctx.section(
                "cluster_errors",
                "FAIL",
                {
                    "count": len(resources),
                    "reasons": reasons,
                    "sample": resources[:5],
                },
                200,
            )
        else:
            ctx.section(
                "cluster_errors",
                "PASS",
                {"count": 0, "reasons": []},
                200,
            )

    nodes, err = safe_get(client, "/v1/nodes")
    if err:
        ctx.section("nodes", "WARN", {"error": str(err)}, err.status)
    else:
        ctx.section("nodes", "PASS", summarize_list(nodes), 200)


def check_ntp(ctx: ReportCtx, client: CmClient) -> None:
    status, err = safe_get(client, "/v1/system/ntp/status")
    servers, serr = safe_get(client, "/v1/system/ntp/servers")
    detail: dict[str, Any] = {}
    result = "PASS"
    if serr:
        detail["servers_error"] = str(serr)
        result = "WARN"
    else:
        resources = (servers or {}).get("resources") or []
        detail["servers"] = [r.get("host") for r in resources if isinstance(r, dict)]
        if not detail["servers"]:
            ctx.add("system", "ntp_no_servers", "WARNING", "No NTP servers are configured.")
            result = "WARN"
    if err:
        detail["status_error"] = str(err)
        result = "WARN"
    else:
        raw = ""
        if isinstance(status, dict):
            raw = str(status.get("ntpq -p") or "")
        detail["ntpq_synced"] = "*" in raw
        if raw and "*" not in raw:
            ctx.add(
                "system",
                "ntp_not_synced",
                "WARNING",
                "NTP does not show a synchronized peer (*).",
            )
            result = "WARN"
    ctx.section("ntp", result, detail, 200)


def check_banner(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/auth/banners/pre-auth")
    if err:
        ctx.section("banner_pre_auth", "WARN", {"error": str(err)}, err.status)
        return
    value = (data or {}).get("value") if isinstance(data, dict) else None
    if not (value and str(value).strip()):
        ctx.add(
            "system",
            "banner_missing",
            "WARNING",
            "Pre-authentication login banner is not configured.",
        )
        ctx.section("banner_pre_auth", "WARN", {"configured": False}, 200)
    else:
        ctx.section(
            "banner_pre_auth",
            "PASS",
            {"configured": True, "preview": str(value).strip()[:120]},
            200,
        )


def _disk_enc_state(data: dict[str, Any] | None) -> str:
    """Return encrypted | encrypting | not_encrypted | unknown from diskenc status."""
    if not isinstance(data, dict):
        return "unknown"
    status = str(data.get("encryptionStatus") or "").strip().lower()
    has_dek = data.get("hasDEK") is True
    # In-progress (ksctl shows "Encrypting..."); do not treat as fully encrypted yet.
    if status and (
        "encrypting" in status
        or "in progress" in status
        or "in-progress" in status
        or status in ("pending", "started")
    ):
        return "encrypting"
    if "not encrypt" in status or status in ("unencrypted", "none", "disabled"):
        return "not_encrypted"
    if has_dek:
        return "encrypted"
    if status in ("encrypted", "enabled", "complete", "completed", "done"):
        return "encrypted"
    if status and "encrypt" in status:
        # e.g. "encryption enabled" — avoid matching bare unknowns
        return "encrypted"
    if status:
        return "unknown"
    return "not_encrypted" if data.get("hasDEK") is False else "unknown"


def _disk_is_encrypted(data: dict[str, Any] | None) -> bool:
    """True only when disk encryption has completed (not merely in progress)."""
    return _disk_enc_state(data) == "encrypted"


def check_diskenc(ctx: ReportCtx, client: CmClient) -> None:
    """Disk encryption posture + preboot presence (auto when disk is encrypted)."""
    data, err = safe_get(client, "/v1/locker/diskenc/status")
    if err:
        ctx.section("disk_encryption", "WARN", {"error": str(err)}, err.status)
        return

    state = _disk_enc_state(data if isinstance(data, dict) else None)
    encrypted = state == "encrypted"
    encrypting = state == "encrypting"
    attended = (data or {}).get("attendedBoot") is True
    status = (data or {}).get("encryptionStatus")

    preboot: list[dict[str, Any]] = []
    try:
        idata = client.get_paginated(
            "/v1/configs/interfaces/", limit=100, max_items=500
        )
        for i in idata.get("resources") or []:
            if not isinstance(i, dict):
                continue
            itype = str(i.get("interface_type") or "").strip().lower()
            name = str(i.get("name") or "").strip().lower()
            if itype == "preboot" or name == "preboot":
                preboot.append(
                    {
                        "name": i.get("name"),
                        "port": i.get("port"),
                        "enabled": bool(i.get("enabled")),
                        "mode": i.get("mode"),
                        "network_interface": i.get("network_interface"),
                    }
                )
    except CmError:
        pass

    detail = {
        "encryptionStatus": status,
        "attendedBoot": (data or {}).get("attendedBoot"),
        "hasDEK": (data or {}).get("hasDEK"),
        "encrypted": encrypted,
        "encrypting": encrypting,
        "state": state,
        "preboot_interfaces": preboot,
    }

    if encrypting:
        ctx.add(
            "system",
            "diskenc_in_progress",
            "INFO",
            f"Disk encryption is in progress (status={status!r}, hasDEK="
            f"{(data or {}).get('hasDEK')}). API may be unavailable until restart "
            f"completes; preboot appears after encryption finishes.",
        )
    elif encrypted:
        ctx.add(
            "system",
            "diskenc_enabled",
            "INFO",
            f"Disk encryption is enabled (status={status!r}, hasDEK="
            f"{(data or {}).get('hasDEK')}).",
        )
        if preboot:
            en = sum(1 for p in preboot if p.get("enabled"))
            names = ", ".join(
                f"{p.get('name')}(enabled={p.get('enabled')}, port={p.get('port')})"
                for p in preboot[:10]
            )
            ctx.add(
                "system",
                "diskenc_preboot_present",
                "INFO",
                f"Preboot interface present ({len(preboot)}; enabled={en}) — "
                f"expected when disk encryption is on: {names}.",
            )
        else:
            ctx.add(
                "system",
                "diskenc_preboot_missing",
                "WARNING",
                "Disk encryption reports enabled but no preboot interface was found "
                "(preboot is normally auto-created when the disk is encrypted).",
            )
    else:
        ctx.add(
            "system",
            "diskenc_not_encrypted",
            "WARNING",
            f"Disk is not encrypted (status={status!r}, hasDEK="
            f"{(data or {}).get('hasDEK')}). Enable disk encryption for added "
            f"security; preboot interface appears when encryption is enabled.",
        )
        if preboot:
            ctx.add(
                "system",
                "diskenc_preboot_unexpected",
                "WARNING",
                "Preboot interface is present while diskenc status is not encrypted — "
                "verify disk encryption configuration.",
            )

    if attended:
        ctx.add(
            "system",
            "diskenc_attended_boot",
            "WARNING",
            "Disk encryption attendedBoot is ENABLED (manual passphrase at boot).",
        )

    # In-progress is informational (not a posture WARN); unfinished/not encrypted is.
    warn = (
        (state == "not_encrypted")
        or attended
        or (encrypted and not preboot)
        or ((not encrypted) and (not encrypting) and bool(preboot))
    )
    ctx.section("disk_encryption", "WARN" if warn else "PASS", detail, 200)


def _age_parts(age_days: int | float | None) -> tuple[int, int, int, int] | None:
    """Split age into (years, months, weeks, days). Uses 365d/y, 30d/mo, 7d/wk."""
    if age_days is None:
        return None
    rem = max(0, int(age_days))
    years, rem = divmod(rem, 365)
    months, rem = divmod(rem, 30)
    weeks, days = divmod(rem, 7)
    return years, months, weeks, days


def _format_age_parts(age_days: int | float | None, *, short: bool) -> str:
    """<1y → months, weeks, days; ≥1y → years, months, weeks, days."""
    parts = _age_parts(age_days)
    if parts is None:
        return "n/a" if short else "unknown age"
    years, months, weeks, days = parts

    def _u(n: int, short_u: str, long_one: str, long_many: str) -> str:
        if short:
            return f"{n}{short_u}"
        return f"{n} {long_one if n == 1 else long_many}"

    bits: list[str] = []
    if years >= 1:
        bits.append(_u(years, "y", "year", "years"))
        bits.append(_u(months, "mo", "month", "months"))
        bits.append(_u(weeks, "w", "week", "weeks"))
        bits.append(_u(days, "d", "day", "days"))
    else:
        # Under 1 year: months, weeks, days (always all three)
        bits.append(_u(months, "mo", "month", "months"))
        bits.append(_u(weeks, "w", "week", "weeks"))
        bits.append(_u(days, "d", "day", "days"))
    return " ".join(bits) if short else ", ".join(bits)


def _format_age_short(age_days: int | float | None) -> str:
    """Compact age for posture."""
    return _format_age_parts(age_days, short=True)


def _format_age_phrase(age_days: int | float | None) -> str:
    """Human age phrase for findings."""
    return _format_age_parts(age_days, short=False)


ROT_WARN_DAYS = 183   # >= 6 months → WARNING
ROT_CRIT_DAYS = 365   # >= 12 months → CRITICAL


def check_rot_keys(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/system/rot-keys")
    if err:
        ctx.section("rot_keys", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    ages = []
    for k in resources:
        if not isinstance(k, dict):
            continue
        created = parse_date(k.get("createdAt"))
        age = (ctx.now - created).days if created else None
        row = {
            "id": k.get("id"),
            "createdAt": k.get("createdAt"),
            "age_days": age,
            "age_years": round(age / 365.0, 2) if age is not None else None,
            "age_label": _format_age_short(age),
        }
        ages.append(row)
        if age is not None and age >= ROT_CRIT_DAYS:
            ctx.add(
                "system",
                "rot_key_critical_age",
                "CRITICAL",
                f"Root-of-Trust key '{k.get('id')}' is {_format_age_phrase(age)} "
                f"(threshold 12 months).",
            )
        elif age is not None and age >= ROT_WARN_DAYS:
            ctx.add(
                "system",
                "rot_key_old",
                "WARNING",
                f"Root-of-Trust key '{k.get('id')}' is {_format_age_phrase(age)} "
                f"(threshold 6 months).",
            )
        elif age is not None:
            ctx.add(
                "system",
                "rot_key_age",
                "INFO",
                f"Root-of-Trust key '{k.get('id')}' age is {_format_age_phrase(age)}.",
            )
    critical_age = [a for a in ages if (a.get("age_days") or 0) >= ROT_CRIT_DAYS]
    warn_age = [
        a
        for a in ages
        if ROT_WARN_DAYS <= (a.get("age_days") or 0) < ROT_CRIT_DAYS
    ]
    ctx.section(
        "rot_keys",
        "FAIL" if critical_age else ("WARN" if warn_age else "PASS"),
        {
            "total": (data or {}).get("total", len(resources)),
            "keys": ages,
            "older_than_12m": critical_age,
            "older_than_6m": warn_age,
            "older_than_3y": critical_age,
            "older_than_2y": warn_age,
        },
        200,
    )
