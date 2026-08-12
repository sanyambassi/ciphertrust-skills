"""Operations checks: licensing, backups, alarms."""
from __future__ import annotations

import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from cm_client import CmClient, CmError

from ..context import ReportCtx
from ..domains import DomainWalk, build_domain_walk
from ..modes import ALARM_CRITICAL_SEVS
from ..util import days_until, parse_date, safe_get

def _backup_scope_counts(resources: list[Any]) -> tuple[int, int, int]:
    """Return (total_scoped, system_count, domain_count) from backup resources."""
    system_n = 0
    domain_n = 0
    other_n = 0
    for b in resources:
        if not isinstance(b, dict):
            continue
        scope = str(b.get("scope") or "").lower()
        if scope == "system":
            system_n += 1
        elif scope == "domain":
            domain_n += 1
        else:
            other_n += 1
    return system_n + domain_n + other_n, system_n, domain_n


def _alarms_total(client: CmClient, **filters: Any) -> int | None:
    """Return alarms list ``total`` for the given filters (limit=1)."""
    parts = [f"{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}" for k, v in filters.items()]
    q = "&".join(parts + ["limit=1"])
    data, err = safe_get(client, f"/v1/system/alarms?{q}")
    if err or not isinstance(data, dict):
        return None
    try:
        return int(data.get("total") or 0)
    except (TypeError, ValueError):
        return None


def check_licensing(ctx: ReportCtx, client: CmClient) -> None:
    features, ferr = safe_get(client, "/v1/licensing/features/")
    licenses, lerr = safe_get(client, "/v1/licensing/licenses/")
    if ferr:
        ctx.section("licensing_features", "FAIL", {"error": str(ferr)}, ferr.status)
    else:
        expired_f = []
        expiring_f = []
        for feat in (features or {}).get("resources") or []:
            if not isinstance(feat, dict):
                continue
            name = feat.get("name")
            status = str(feat.get("status") or "").lower()
            sec = feat.get("trial_seconds_remaining") or 0
            days = int(sec) // 86400 if sec else None
            if status == "expired":
                expired_f.append(name)
                ctx.add(
                    "licensing",
                    "feature_expired",
                    "CRITICAL",
                    f"Licensed feature '{name}' is EXPIRED.",
                )
            elif days is not None and 0 <= days <= 30:
                expiring_f.append({"name": name, "trial_days_remaining": days})
        if expiring_f:
            min_days = min(x["trial_days_remaining"] for x in expiring_f)
            ctx.add(
                "licensing",
                "feature_trial_expiring",
                "WARNING",
                f"{len(expiring_f)} licensed feature trial(s) expire within 30 days "
                f"(soonest ~{min_days} days).",
            )
        ctx.section(
            "licensing_features",
            "FAIL" if expired_f else ("WARN" if expiring_f else "PASS"),
            {
                "total": (features or {}).get("total"),
                "expired": expired_f[:20],
                "trials_expiring_soon": expiring_f[:20],
            },
            200,
        )

    if lerr:
        ctx.section("licensing_licenses", "FAIL", {"error": str(lerr)}, lerr.status)
        return

    expired = []
    expiring = []
    trials_expiring = []
    active = 0
    for lic in (licenses or {}).get("resources") or []:
        if not isinstance(lic, dict):
            continue
        state = str(lic.get("state") or "").lower()
        if state == "inactive":
            continue
        active += 1
        feature = lic.get("feature") or lic.get("friendly_name")
        if state == "expired":
            expired.append(feature)
            ctx.add(
                "licensing",
                "license_expired",
                "CRITICAL",
                f"License for feature '{feature}' is EXPIRED.",
            )
            continue
        exp = lic.get("expiration")
        if exp and str(exp).strip().lower() != "no expiration":
            dt = parse_date(exp)
            dleft = days_until(dt, ctx.now)
            if dleft is not None and dleft < 0:
                expired.append(feature)
                ctx.add(
                    "licensing",
                    "license_expired",
                    "CRITICAL",
                    f"License for feature '{feature}' expired {abs(dleft)} days ago.",
                )
            elif dleft is not None and dleft <= 30:
                expiring.append({"feature": feature, "days_left": dleft})
                ctx.add(
                    "licensing",
                    "license_expiring",
                    "WARNING",
                    f"License for feature '{feature}' expires in {dleft} days.",
                )
        sec = lic.get("trial_seconds_remaining")
        if str(lic.get("type") or "").lower() == "trial" and isinstance(sec, (int, float)):
            days = int(sec) // 86400
            if 0 <= days <= 30:
                trials_expiring.append({"feature": feature, "trial_days_remaining": days})
    if trials_expiring:
        min_days = min(t["trial_days_remaining"] for t in trials_expiring)
        ctx.add(
            "licensing",
            "license_trial_expiring",
            "WARNING",
            f"{len(trials_expiring)} active trial license(s) expire within 30 days "
            f"(soonest ~{min_days} days).",
        )
    result = "FAIL" if expired else ("WARN" if (expiring or trials_expiring) else "PASS")
    ctx.section(
        "licensing_licenses",
        result,
        {
            "total": (licenses or {}).get("total"),
            "active_count": active,
            "expired": expired[:20],
            "expiring_soon": expiring[:20],
            "trials_expiring_soon": trials_expiring[:20],
        },
        200,
    )


def check_backups(
    ctx: ReportCtx,
    client: CmClient,
    domain_scope: str = "all",
    *,
    domain_walk: DomainWalk | None = None,
) -> None:
    status, _ = safe_get(client, "/v1/backupStatus")
    backups = None
    berr = None
    try:
        backups = client.get_paginated("/v1/backups", limit=100, max_items=500)
    except CmError as e:
        berr = e
    keys, kerr = safe_get(client, "/v1/backupkeys")
    jobs, jerr = safe_get(client, "/v1/scheduler/job-configs?limit=100")

    if status is not None:
        st = (status or {}).get("status")
        detail = {
            "status": st,
            "operation": (status or {}).get("operation"),
            "finished": (status or {}).get("finished"),
        }
        if st and str(st).lower() not in ("completed", "complete", "success", "successful"):
            ctx.add(
                "system",
                "backup_status_not_completed",
                "WARNING",
                f"Latest backup operation status is '{st}'.",
            )
            ctx.section("backup_status", "WARN", detail, 200)
        else:
            ctx.section("backup_status", "PASS", detail, 200)

    backup_key_states: dict[str, str] = {}
    if kerr:
        ctx.section("backup_keys", "WARN", {"error": str(kerr)}, kerr.status)
    else:
        resources = (keys or {}).get("resources") or []
        inactive = []
        for k in resources:
            if not isinstance(k, dict):
                continue
            kid = str(k.get("id"))
            state = str(k.get("state") or "").lower()
            backup_key_states[kid] = state
            if state and state != "active":
                inactive.append({"id": kid, "state": state})
                ctx.add(
                    "system",
                    "backup_key_inactive",
                    "WARNING",
                    f"Backup key '{kid}' is not active (state={state}).",
                )
        ctx.section(
            "backup_keys",
            "WARN" if inactive else "PASS",
            {"total": len(resources), "inactive": inactive},
            200,
        )

    by_domain: list[dict[str, Any]] = []
    walk = domain_walk if domain_walk is not None else build_domain_walk(client, domain_scope)
    if walk.can_login:
        for name in walk.domains:
            dclient = walk.clients.get(name)
            if dclient is not None:
                try:
                    page = dclient.get_paginated("/v1/backups", limit=100, max_items=500)
                    res = page.get("resources") or []
                    scoped_n, system_n, domain_n = _backup_scope_counts(res)
                    by_domain.append(
                        {
                            "domain": name,
                            "total": page.get("total", scoped_n),
                            "system_count": system_n,
                            "domain_count": domain_n,
                        }
                    )
                except CmError as e:
                    if e.status in (401, 403):
                        by_domain.append(
                            {
                                "domain": name,
                                "skipped": True,
                                "reason": "unauthorized",
                                "status": e.status,
                            }
                        )
                    else:
                        by_domain.append(
                            {
                                "domain": name,
                                "error": str(e),
                                "status": e.status,
                            }
                        )
            else:
                skip = next((s for s in walk.skips if s.get("domain") == name), None)
                if skip:
                    by_domain.append(
                        {
                            "domain": name,
                            "skipped": True,
                            "reason": skip.get("reason") or "unauthorized",
                            "status": skip.get("status"),
                        }
                    )
                else:
                    err = next((e for e in walk.errors if e.get("domain") == name), None)
                    by_domain.append(
                        {
                            "domain": name,
                            "error": str((err or {}).get("error") or "error"),
                            "status": (err or {}).get("status"),
                        }
                    )

    if berr:
        ctx.section("backups_list", "WARN", {"error": str(berr)}, berr.status)
    else:
        resources = (backups or {}).get("resources") or []
        total = (backups or {}).get("total", len(resources))
        _, system_count, domain_count = _backup_scope_counts(resources)
        list_detail: dict[str, Any] = {
            "total": total,
            "system_count": system_count,
            "domain_count": domain_count,
            "by_domain": by_domain or None,
            "note": (
                "scope=system is a full appliance backup; scope=domain is a "
                "domain-scoped backup (optional resourceTypes). Counts above are "
                "for the configured auth domain; by_domain is a per-domain listing."
            ),
        }
        if not resources:
            ctx.add("system", "backup_none", "WARNING", "No backups exist.")
            ctx.section("backups_list", "WARN", list_detail, 200)
        else:

            def _backup_created(b: Any) -> datetime:
                if not isinstance(b, dict):
                    return datetime.min.replace(tzinfo=timezone.utc)
                dt = parse_date(b.get("createdAt"))
                return dt or datetime.min.replace(tzinfo=timezone.utc)

            by_created = sorted(resources, key=_backup_created, reverse=True)
            newest = by_created[0]
            created = parse_date(newest.get("createdAt"))
            age_days = (ctx.now - created).days if created else None
            missing_key = []
            for b in resources:
                bk = b.get("backupKey")
                if bk and bk in backup_key_states and backup_key_states[bk] != "active":
                    missing_key.append(b.get("id"))
                elif bk and backup_key_states and bk not in backup_key_states:
                    ctx.add(
                        "system",
                        "backup_missing_key",
                        "CRITICAL",
                        f"Backup '{b.get('id')}' references missing backup key '{bk}'.",
                    )
                    missing_key.append(b.get("id"))
            if age_days is not None and age_days > 7:
                ctx.add(
                    "system",
                    "backup_stale",
                    "WARNING",
                    f"Newest backup is {age_days} days old (>7) "
                    f"(scope={newest.get('scope') or 'n/a'}).",
                )
            list_detail.update(
                {
                    "newest_createdAt": newest.get("createdAt"),
                    "newest_age_days": age_days,
                    "newest_scope": newest.get("scope"),
                    "newest_status": newest.get("status"),
                    "newest_id": newest.get("id"),
                    "sample": [
                        {
                            "id": b.get("id"),
                            "scope": b.get("scope"),
                            "status": b.get("status"),
                            "createdAt": b.get("createdAt"),
                            "description": b.get("description"),
                            "resourceTypes": b.get("resourceTypes"),
                        }
                        for b in by_created[:5]
                    ],
                }
            )
            ctx.section(
                "backups_list",
                "WARN" if (age_days and age_days > 7) or missing_key else "PASS",
                list_detail,
                200,
            )

    if jerr:
        ctx.section("backup_scheduler", "WARN", {"error": str(jerr)}, jerr.status)
    else:
        resources = (jobs or {}).get("resources") or []
        backup_jobs = [
            j
            for j in resources
            if isinstance(j, dict) and str(j.get("operation") or "") == "database_backup"
        ]
        enabled = [j for j in backup_jobs if not j.get("disabled")]
        if not enabled:
            ctx.add(
                "system",
                "backup_schedule_missing",
                "WARNING",
                "No enabled scheduled database_backup job found.",
            )
        ctx.section(
            "backup_scheduler",
            "WARN" if not enabled else "PASS",
            {
                "backup_jobs": len(backup_jobs),
                "enabled": len(enabled),
                "names": [j.get("name") for j in enabled[:10]],
            },
            200,
        )


def check_alarms(ctx: ReportCtx, client: CmClient) -> None:
    """Alarm posture using API filters for exact totals (not sample-list lengths)."""
    estate_total = _alarms_total(client)  # all states
    active_count = _alarms_total(client, state="on")
    # Severity breakdown among active (state=on)
    active_warning = _alarms_total(client, state="on", severity="warning")
    active_info = _alarms_total(client, state="on", severity="info")
    active_critical = _alarms_total(client, state="on", severity="critical")
    active_error = _alarms_total(client, state="on", severity="error")
    # Other elevated severities CM may use
    active_alert = _alarms_total(client, state="on", severity="alert")
    active_emergency = _alarms_total(client, state="on", severity="emergency")

    if active_count is None:
        # Fallback: first unfiltered page (may undercount)
        data, err = safe_get(client, "/v1/system/alarms?limit=100")
        if err:
            ctx.section("alarms", "FAIL", {"error": str(err)}, err.status)
            return
        resources = (data or {}).get("resources") or []
        active = [
            a
            for a in resources
            if isinstance(a, dict) and str(a.get("state") or "").lower() == "on"
        ]
        active_count = len(active)
        estate_total = (data or {}).get("total", estate_total)
        active_critical = sum(
            1
            for a in active
            if str(a.get("severity") or "").lower() in ALARM_CRITICAL_SEVS
        )
        active_warning = sum(
            1 for a in active if str(a.get("severity") or "").lower() == "warning"
        )
        active_info = sum(
            1 for a in active if str(a.get("severity") or "").lower() == "info"
        )
        active_error = sum(
            1 for a in active if str(a.get("severity") or "").lower() == "error"
        )
        ctx.add(
            "system",
            "alarms_filter_fallback",
            "INFO",
            "Could not filter alarms by state/severity; counts may be undercounted.",
        )

    crit_n = sum(
        int(x or 0)
        for x in (active_critical, active_error, active_alert, active_emergency)
    )
    warn_n = int(active_warning or 0)
    info_n = int(active_info or 0)
    active_n = int(active_count or 0)

    # Samples for report detail (not used as counts)
    crit_sample: list[dict] = []
    warn_sample: list[dict] = []
    by_name: Counter = Counter()
    try:
        page = client.get_paginated(
            "/v1/system/alarms?state=on", limit=100, max_items=500
        )
        for a in page.get("resources") or []:
            if not isinstance(a, dict):
                continue
            by_name[str(a.get("name") or "unnamed")] += 1
            sev = str(a.get("severity") or "").lower()
            row = {
                "name": a.get("name"),
                "severity": a.get("severity"),
                "description": (a.get("description") or "")[:160],
            }
            if sev in ALARM_CRITICAL_SEVS and len(crit_sample) < 10:
                crit_sample.append(row)
            elif sev == "warning" and len(warn_sample) < 10:
                warn_sample.append(row)
    except CmError:
        pass

    if crit_n:
        ctx.add(
            "system",
            "alarms_critical",
            "CRITICAL",
            f"{crit_n} active critical/error alarm(s) (among {active_n} active).",
        )
    elif active_n:
        ctx.add(
            "system",
            "alarms_active",
            "WARNING",
            f"{active_n} active alarm(s) (state=on).",
        )
    result = "FAIL" if crit_n else ("WARN" if active_n else "PASS")
    ctx.section(
        "alarms",
        result,
        {
            "total": estate_total,
            "active_unacknowledged": active_n,
            "active_by_severity": {
                "warning": warn_n,
                "info": info_n,
                "critical": int(active_critical or 0),
                "error": int(active_error or 0),
                "alert": int(active_alert or 0),
                "emergency": int(active_emergency or 0),
            },
            "active_critical": crit_n,
            "active_warning": warn_n,
            "active_info": info_n,
            "active_by_name": dict(by_name.most_common(15)),
            "critical_sample": crit_sample,
            "warning_sample": warn_sample,
            "note": (
                "Counts from API filters (state=on, severity=*). "
                "Samples are examples only; estate total includes on/off/unknown."
            ),
        },
        200,
    )
