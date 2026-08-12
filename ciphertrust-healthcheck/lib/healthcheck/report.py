"""Scoring and human-readable report output."""
from __future__ import annotations

import json
from typing import Any

from .context import ReportCtx
from .posture import build_posture_table

def score(ctx: ReportCtx) -> str:
    by = {s["name"]: s for s in ctx.sections}
    auth = by.get("auth", {})
    if auth.get("result") == "FAIL":
        detail = auth.get("detail") or {}
        if isinstance(detail, dict) and "Unreachable" in str(detail.get("error", "")):
            return "UNREACHABLE"
        return "CRITICAL"
    sev = {f.severity for f in ctx.findings}
    if "CRITICAL" in sev:
        return "CRITICAL"
    if by.get("services_status", {}).get("result") == "FAIL":
        return "CRITICAL"
    if by.get("system_info", {}).get("result") == "FAIL":
        return "CRITICAL"
    if "WARNING" in sev:
        return "DEGRADED"
    return "OK"


def _print_posture_header(report: dict) -> None:
    """Print Area | Result | Summary — agents must copy these Summary strings."""
    p = report.get("posture") or {}
    table = p.get("table") or build_posture_table(p)
    print("=== Posture table (copy into markdown: Area | Result | Summary) ===")
    print(
        "Keep markdown **bold** and <br> line breaks in Result/Summary. "
        "Do not invent key=value shorthand."
    )
    for row in table:
        print(f"{row.get('area')} | {row.get('result')} | {row.get('summary')}")
    # Optional domain detail under Users / Keys (not part of the 3-column table)
    users = p.get("users") or {}
    for d in (users.get("by_domain") or [])[:8]:
        top = d.get("top_by_logins") or []
        top_s = ", ".join(
            f"{t.get('username')}({t.get('logins_count')})"
            for t in top[:5]
            if isinstance(t, dict)
        )
        print(
            f"  (Users detail) {d.get('domain')}: "
            f"{d.get('total')} users; locked={d.get('locked')}; "
            f"never-login={d.get('never_logged_in')}; "
            f"inactive_30d={d.get('inactive_30d')}"
            + (f"; top logins: {top_s}" if top_s else "")
        )
    keys = p.get("keys") or {}
    kd = keys.get("domains") or {}
    for d in (kd.get("by_domain") or [])[:8]:
        print(
            f"  (Keys detail) {d.get('domain')}: total={d.get('total')}, "
            f"weak={d.get('weak')}, inactive={d.get('non_active')}"
        )
    backups = p.get("backups") or {}
    for d in (backups.get("by_domain") or [])[:12]:
        if not isinstance(d, dict):
            continue
        name = d.get("domain")
        if d.get("skipped"):
            print(
                f"  (Backups detail) {name}: skipped "
                f"({d.get('reason') or 'n/a'}; status={d.get('status')})"
            )
        elif d.get("error"):
            print(
                f"  (Backups detail) {name}: error "
                f"(status={d.get('status')}; {d.get('error')})"
            )
        else:
            print(
                f"  (Backups detail) {name}: total={d.get('total')}, "
                f"system={d.get('system_count')}, domain={d.get('domain_count')}"
            )
    certs = p.get("certificates") or {}
    for d in (certs.get("by_domain") or [])[:12]:
        if not isinstance(d, dict):
            continue
        name = d.get("domain")
        if d.get("skipped"):
            print(
                f"  (CAs detail) {name}: skipped "
                f"({d.get('reason') or 'n/a'}; status={d.get('status')})"
            )
        elif d.get("error"):
            print(
                f"  (CAs detail) {name}: error "
                f"(status={d.get('status')}; {d.get('error')})"
            )
        else:
            loc = d.get("local") if isinstance(d.get("local"), dict) else {}
            ext = d.get("external") if isinstance(d.get("external"), dict) else {}
            print(
                f"  (CAs detail) {name}: "
                f"local={loc.get('total')} (expired={loc.get('expired')}), "
                f"external={ext.get('total')} (expired={ext.get('expired')})"
            )
    print("=== End posture table ===")
    print()


def print_human(report: dict) -> None:
    print(f"Overall: {report.get('overall')}")
    print(f"Base:    {report.get('base', 'n/a')}")
    print(f"CM:      {report.get('cm_version') or 'n/a'}")
    print(f"Time:    {report.get('timestamp_utc')}")
    opts = report.get("options") or {}
    print(
        f"Options: domain_scope={opts.get('domain_scope')} keys_mode={opts.get('keys_mode')} "
        f"max_keys={opts.get('max_keys')} max_users={opts.get('max_users')}"
    )
    summary = report.get("summary") or {}
    print(
        f"Findings: critical={summary.get('critical', 0)} "
        f"warning={summary.get('warning', 0)} info={summary.get('info', 0)}"
    )
    print()
    _print_posture_header(report)
    crit = [f for f in report.get("findings", []) if f.get("severity") == "CRITICAL"]
    warn = [f for f in report.get("findings", []) if f.get("severity") == "WARNING"]
    info = [f for f in report.get("findings", []) if f.get("severity") == "INFO"]
    if crit:
        print("CRITICAL findings:")
        for f in crit[:40]:
            print(f"  - [{f.get('area')}] {f.get('message')}")
        print()
    if warn:
        print("WARNING findings:")
        for f in warn[:60]:
            print(f"  - [{f.get('area')}] {f.get('message')}")
        if len(warn) > 60:
            print(f"  ... +{len(warn) - 60} more")
        print()
    if info:
        print(f"INFO findings: {len(info)} (not scoring; see --json for full list)")
        for f in info[:12]:
            print(f"  - [{f.get('area')}] {f.get('message')}")
        if len(info) > 12:
            print(f"  ... +{len(info) - 12} more")
        print()

    for s in report.get("sections", []):
        print(f"[{s['result']}] {s['name']} (HTTP {s.get('status')})")
        detail = s.get("detail")
        if s.get("name") == "keys_domains" and isinstance(detail, dict):
            print(
                f"       domains_listed={detail.get('domains_listed')} "
                f"checked={detail.get('checked_count')} skipped={detail.get('skipped_count')}"
            )
            if detail.get("note"):
                print(f"       note: {detail.get('note')}")
            for c in detail.get("checked") or []:
                users = c.get("users") or {}
                print(
                    f"       domain={c.get('domain')} keys_total={c.get('total_reported')} "
                    f"keys_unique={c.get('unique')} weak={c.get('weak_count')} "
                    f"users_total={users.get('total_reported')} "
                    f"locked={users.get('locked')} never_login={users.get('never_logged_in')} "
                    f"inactive_30d={users.get('inactive_30d')} "
                    f"failed_logins={users.get('failed_logins_not_locked')}"
                )
                top = users.get("top_by_logins") or []
                if top:
                    top_s = ", ".join(
                        f"{t.get('username')}({t.get('logins_count')})" for t in top
                    )
                    print(f"         top_by_logins: {top_s}")
            skipped = detail.get("skipped") or []
            if skipped:
                names = [x.get("domain") for x in skipped[:10]]
                print(f"       skipped_sample: {names}" + (" ..." if len(skipped) > 10 else ""))
            print()
            continue
        if s.get("name") == "users_access" and isinstance(detail, dict):
            print(
                f"       total={detail.get('total_reported')} scanned={detail.get('scanned')} "
                f"locked={detail.get('locked')} never_login={detail.get('never_logged_in')} "
                f"inactive_30d={detail.get('inactive_30d')} "
                f"failed_logins={detail.get('failed_logins_not_locked')}"
            )
            top = detail.get("top_by_logins") or []
            if top:
                top_s = ", ".join(
                    f"{t.get('username')}({t.get('logins_count')})" for t in top
                )
                print(f"       top_by_logins: {top_s}")
            print()
            continue
        if isinstance(detail, dict):
            for k, v in detail.items():
                if k in (
                    "interfaces",
                    "checked",
                    "skipped",
                    "sample",
                    "warning_sample",
                    "critical_sample",
                    "unhealthy",
                    "guardpoints_not_active",
                    "accounts_sample",
                    "key_usage_top_domains",
                    "samples",
                    "connections",
                    "top_by_logins",
                    "disconnected",
                    "unregistered_or_offline",
                ) and v:
                    print(f"       {k}: {json.dumps(v, default=str)[:450]}")
                elif k == "note" and v:
                    print(f"       note: {v}")
                else:
                    print(f"       {k}: {v}")
        else:
            print(f"       {detail}")
        print()
