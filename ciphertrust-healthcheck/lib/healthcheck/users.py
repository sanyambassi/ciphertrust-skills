"""User hygiene summaries and findings."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from cm_client import CmClient, CmError

from .context import ReportCtx
from .util import parse_date

def summarize_users(
    resources: list[Any],
    *,
    now: datetime,
    total_reported: Any = None,
    truncated: bool = False,
) -> dict[str, Any]:
    """Hygiene + top logins from a scanned user page set (client-side ranking)."""
    locked = never = inactive = failed = 0
    samples: dict[str, list] = defaultdict(list)
    ranked: list[dict[str, Any]] = []
    for u in resources:
        if not isinstance(u, dict):
            continue
        uname = u.get("username") or u.get("name")
        logins = int(u.get("logins_count") or 0)
        ranked.append(
            {
                "username": uname,
                "logins_count": logins,
                "last_login": u.get("last_login"),
                "failed_logins_count": u.get("failed_logins_count") or 0,
            }
        )
        if u.get("account_lockout_at"):
            locked += 1
            if len(samples["locked"]) < 8:
                samples["locked"].append(uname)
        last = parse_date(u.get("last_login"))
        if logins == 0 or u.get("last_login") in (None, ""):
            never += 1
            if len(samples["never_logged_in"]) < 8:
                samples["never_logged_in"].append(uname)
        elif last and (now - last).days > 30:
            inactive += 1
            if len(samples["inactive_30d"]) < 8:
                samples["inactive_30d"].append(uname)
        fails = u.get("failed_logins_count") or 0
        if fails and not u.get("account_lockout_at"):
            failed += 1
            if len(samples["failed_logins"]) < 8:
                samples["failed_logins"].append({"user": uname, "failed_logins_count": fails})
    ranked.sort(key=lambda r: (-(r.get("logins_count") or 0), str(r.get("username") or "")))
    return {
        "total_reported": total_reported if total_reported is not None else len(resources),
        "scanned": len(resources),
        "truncated": truncated,
        "locked": locked,
        "never_logged_in": never,
        "inactive_30d": inactive,
        "failed_logins_not_locked": failed,
        "top_by_logins": ranked[:5],
        "samples": dict(samples),
    }


def _sample_join(samples: dict[str, Any], key: str, limit: int = 5) -> str:
    vals = samples.get(key) or []
    return ", ".join(map(str, vals[:limit]))


def emit_user_findings(ctx: ReportCtx, domain: str | None, users: dict[str, Any]) -> None:
    """User hygiene is first-class health — elevate stale/unused accounts to WARNING."""
    prefix = f"[{domain}] " if domain else ""
    locked = users.get("locked") or 0
    never = users.get("never_logged_in") or 0
    inactive = users.get("inactive_30d") or 0
    failed = users.get("failed_logins_not_locked") or 0
    samples = users.get("samples") or {}
    top = users.get("top_by_logins") or []

    if locked:
        names = _sample_join(samples, "locked")
        msg = f"{prefix}{locked} user account(s) are locked out"
        if names:
            msg += f" - Usernames: {names}"
        ctx.add("access", "access_users_locked", "WARNING", msg + ".")
    if never:
        names = _sample_join(samples, "never_logged_in")
        msg = f"{prefix}{never} user account(s) have never logged in"
        if names:
            msg += f" - Usernames: {names}"
        ctx.add("access", "access_users_never_logged_in", "WARNING", msg + ".")
    if inactive:
        names = _sample_join(samples, "inactive_30d")
        msg = f"{prefix}{inactive} user account(s) inactive >30 days"
        if names:
            msg += f" - Usernames: {names}"
        ctx.add("access", "access_users_inactive", "WARNING", msg + ".")
    if failed:
        ctx.add(
            "access",
            "access_users_failed_logins",
            "WARNING",
            f"{prefix}{failed} user account(s) have failed login attempts (not locked).",
        )
    if top:
        top_s = ", ".join(
            f"{t.get('username')}({t.get('logins_count')})" for t in top[:5] if isinstance(t, dict)
        )
        if top_s:
            ctx.add(
                "access",
                "access_users_top_logins",
                "INFO",
                f"{prefix}Top users by logins: {top_s}.",
            )


def users_have_hygiene_issues(users: dict[str, Any] | None) -> bool:
    if not users:
        return False
    return bool(
        users.get("locked")
        or users.get("never_logged_in")
        or users.get("inactive_30d")
        or users.get("failed_logins_not_locked")
    )


def check_users_access(ctx: ReportCtx, client: CmClient, max_users: int) -> None:
    """Current-token domain only (used when per-domain inventory is not run)."""
    data = client.get_paginated("/v1/usermgmt/users/", limit=100, max_items=max_users)
    resources = data.get("resources") or []
    users = summarize_users(
        resources,
        now=ctx.now,
        total_reported=data.get("total"),
        truncated=bool(data.get("truncated")),
    )
    emit_user_findings(ctx, None, users)
    result = "WARN" if users_have_hygiene_issues(users) else "PASS"
    ctx.section("users_access", result, users, 200)
