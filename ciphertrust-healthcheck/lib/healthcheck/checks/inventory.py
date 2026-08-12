"""Inventory checks: keys, metrics, orphaned resources, clients, quorum."""
from __future__ import annotations

import urllib.request
from typing import Any

from cm_client import CmClient, CmError

from ..context import ReportCtx
from ..domains import DomainWalk, build_domain_walk
from ..keys import (
    analyze_keys,
    fetch_weak_key_candidates,
    parse_key_metrics,
)
from ..users import emit_user_findings, summarize_users, users_have_hygiene_issues
from ..util import safe_get

def check_metrics_keys(ctx: ReportCtx, client: CmClient) -> None:
    status, err = safe_get(client, "/v1/system/metrics/prometheus/status")
    if err:
        ctx.section("metrics_status", "WARN", {"error": str(err)}, err.status)
        ctx.section("keys_metrics", "WARN", {"note": "Could not read metrics status"}, None)
        return
    enabled = bool((status or {}).get("enabled"))
    ctx.section("metrics_status", "PASS", {"enabled": enabled}, 200)
    if not enabled:
        ctx.add("system", "metrics_disabled", "WARNING", "Prometheus metrics API is disabled.")
        ctx.section("keys_metrics", "WARN", {"enabled": False}, 200)
        return
    token = (status or {}).get("token")
    if not token:
        ctx.section(
            "keys_metrics",
            "WARN",
            {"enabled": True, "note": "Scrape token unavailable to this user"},
            200,
        )
        return
    try:
        url = f"{client.config.base}/v1/system/metrics/prometheus"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "text/plain"},
            method="GET",
        )
        with urllib.request.urlopen(req, context=client._ssl, timeout=client.config.timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        summary = parse_key_metrics(text)
        summary["enabled"] = True
        summary["scrape_bytes"] = len(text)
        ctx.section("keys_metrics", "PASS", summary, 200)
    except Exception as e:  # noqa: BLE001
        ctx.section("keys_metrics", "WARN", {"enabled": True, "error": str(e)}, None)


def check_orphaned(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/reports/orphaned-resources?limit=1000")
    if err:
        ctx.section("orphaned_resources", "WARN", {"error": str(err)}, err.status)
        return
    total = 0
    by_acct = []
    if isinstance(data, dict):
        total = int(data.get("total_orphaned_keys_count") or 0)
        by_acct = data.get("orphaned_keys_by_account") or data.get("resources") or []
    if total > 0:
        ctx.add(
            "keys",
            "keys_orphaned",
            "WARNING",
            f"{total} orphaned key(s) left behind from deleted domains.",
        )
    ctx.section(
        "orphaned_resources",
        "WARN" if total else "PASS",
        {
            "total_orphaned_keys_count": total,
            "accounts_sample": (by_acct[:10] if isinstance(by_acct, list) else by_acct),
        },
        200,
    )


def check_clients(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/client-management/clients?limit=50")
    if err:
        ctx.section("registered_clients", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    sample = [
        {
            "name": c.get("name"),
            "id": c.get("id"),
            "state": c.get("state") or c.get("status"),
            "created_at": c.get("created_at") or c.get("createdAt"),
        }
        for c in resources[:10]
        if isinstance(c, dict)
    ]
    ctx.section(
        "registered_clients",
        "PASS",
        {"total": (data or {}).get("total", len(resources)), "sample": sample},
        200,
    )


def check_quorum(ctx: ReportCtx, client: CmClient) -> None:
    """Quorum policies (enabled) and approval requests by state."""
    try:
        data = client.get_paginated("/v1/quorum-mgmt/policy/status", limit=100)
    except CmError as err:
        ctx.section("quorum_policies", "WARN", {"error": str(err)}, err.status)
        return
    resources = data.get("resources") or []
    total_policies = data.get("total")
    if not isinstance(total_policies, int):
        total_policies = len(resources)
    enabled = [
        r for r in resources if isinstance(r, dict) and r.get("active") is True
    ]
    enabled_ops = []
    for r in enabled:
        ops = r.get("operation") or []
        if isinstance(ops, list) and ops:
            enabled_ops.append(ops[0])
        elif r.get("profile"):
            enabled_ops.append(str(r.get("profile")))

    requests_total = 0
    requests_active = 0
    requests_pre_active = 0
    requests_by_state: dict[str, int] = {}
    try:
        qdata = client.get_paginated("/v1/quorum-mgmt/quorums", limit=100)
        qres = qdata.get("resources") or []
        requests_total = qdata.get("total") if isinstance(qdata.get("total"), int) else len(qres)
        for q in qres:
            if not isinstance(q, dict):
                continue
            st = str(q.get("state") or "unknown").lower()
            requests_by_state[st] = requests_by_state.get(st, 0) + 1
            if st == "active":
                requests_active += 1
            elif st in ("pre-active", "pre_active", "preactive"):
                requests_pre_active += 1
    except CmError:
        requests_total = -1  # unavailable

    if enabled:
        ctx.add(
            "quorum",
            "quorum_policies_enabled",
            "INFO",
            f"{len(enabled)} quorum policy(ies) enabled "
            f"(of {total_policies}): {', '.join(str(o) for o in enabled_ops[:12])}"
            + ("…" if len(enabled_ops) > 12 else "")
            + ".",
        )
    if requests_active or requests_pre_active:
        ctx.add(
            "quorum",
            "quorum_requests_open",
            "INFO",
            f"{requests_active} active and {requests_pre_active} pre-active "
            f"quorum request(s) (of {requests_total} listed).",
        )

    ctx.section(
        "quorum_policies",
        "PASS",
        {
            "total": total_policies,
            "enabled": len(enabled),
            "active": len(enabled),  # alias: CM API field name
            "enabled_operations": enabled_ops[:20],
            "requests_total": requests_total if requests_total >= 0 else None,
            "requests_active": requests_active if requests_total >= 0 else None,
            "requests_pre_active": requests_pre_active if requests_total >= 0 else None,
            "requests_by_state": requests_by_state or None,
        },
        200,
    )


def check_keys_domains(
    ctx: ReportCtx,
    client: CmClient,
    scope: str,
    max_keys: int,
    max_users: int,
    *,
    domain_walk: DomainWalk | None = None,
) -> None:
    walk = domain_walk if domain_walk is not None else build_domain_walk(client, scope)
    domains = walk.domains
    meta = walk.meta
    if not walk.can_login:
        ctx.section(
            "keys_domains",
            "WARN",
            {
                **meta,
                "note": "Domain-scoped key/user checks require CM_USERNAME+CM_PASSWORD (or refresh token).",
                "skipped": [{"domain": d, "reason": "no_password_auth"} for d in domains],
            },
            200,
        )
        return

    checked = []
    skipped = []
    errors = []
    for name in domains:
        dclient = walk.clients.get(name)
        if dclient is None:
            skip = next((s for s in walk.skips if s.get("domain") == name), None)
            if skip:
                skipped.append(
                    {
                        "domain": name,
                        "reason": skip.get("reason") or "unauthorized",
                        "status": skip.get("status"),
                        "message": skip.get("message"),
                        "note": f"Could not check domain '{name}' with provided credentials",
                    }
                )
            else:
                err = next((e for e in walk.errors if e.get("domain") == name), None)
                errors.append(
                    {
                        "domain": name,
                        "status": (err or {}).get("status"),
                        "error": str((err or {}).get("error") or "error"),
                    }
                )
            continue
        try:
            page = dclient.get_paginated("/v1/vault/keys2/", limit=100, max_items=max_keys)
            weak_candidates = fetch_weak_key_candidates(
                dclient, max_items=max(max_keys, 5000)
            )
            users_page = dclient.get_paginated(
                "/v1/usermgmt/users/", limit=100, max_items=max_users
            )
            analysis = analyze_keys(
                ctx,
                name,
                page.get("resources") or [],
                weak_keys=weak_candidates,
            )
            analysis["total_reported"] = page.get("total")
            analysis["truncated"] = page.get("truncated")
            analysis["weak_filter_candidates"] = len(weak_candidates)
            users = summarize_users(
                users_page.get("resources") or [],
                now=ctx.now,
                total_reported=users_page.get("total"),
                truncated=bool(users_page.get("truncated")),
            )
            emit_user_findings(ctx, name, users)
            analysis["users"] = users
            checked.append(analysis)
        except CmError as e:
            body = e.body if isinstance(e.body, dict) else {}
            msg = body.get("message") if isinstance(body, dict) else None
            if e.status in (401, 403):
                skipped.append(
                    {
                        "domain": name,
                        "reason": "unauthorized",
                        "status": e.status,
                        "message": msg or str(e),
                        "note": f"Could not check domain '{name}' with provided credentials",
                    }
                )
            else:
                errors.append({"domain": name, "status": e.status, "error": str(e)})

    result = "PASS"
    user_warn = any(users_have_hygiene_issues(c.get("users") or {}) for c in checked)
    if any(c.get("weak_count") or c.get("non_active_count") for c in checked) or user_warn:
        result = "WARN"
    elif errors or (not checked and skipped):
        result = "WARN"

    ctx.section(
        "keys_domains",
        result,
        {
            **meta,
            "domains_listed": len(domains),
            "checked_count": len(checked),
            "skipped_count": len(skipped),
            "error_count": len(errors),
            "max_keys_per_domain": max_keys,
            "max_users_per_domain": max_users,
            "checked": checked,
            "skipped": skipped,
            "errors": errors,
            "note": (
                "Skipped domains mean this user cannot authenticate into them; "
                "not treated as appliance CRITICAL by themselves."
                if skipped
                else None
            ),
        },
        200,
    )
