"""Domain resolution and shared per-domain client walk."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

from cm_client import CmClient, CmError

from .context import ReportCtx
from .util import safe_get


def can_domain_login(client: CmClient) -> bool:
    return bool(
        (client.config.username and client.config.password) or client.config.refresh_token
    )


@dataclass
class DomainWalk:
    """One ``for_domain`` login per reachable domain."""

    domains: list[str]
    meta: dict[str, Any]
    can_login: bool
    clients: dict[str, CmClient] = field(default_factory=dict)
    skips: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


def build_domain_walk(client: CmClient, scope: str) -> DomainWalk:
    """Resolve domains once and authenticate into each (when credentials allow)."""
    can_login = can_domain_login(client)
    if can_login:
        domains, meta = resolve_domains(client, scope)
    else:
        cur = client.config.domain or "current"
        domains = [cur]
        meta = {"scope": scope, "note": "JWT-only: current token domain only"}

    walk = DomainWalk(domains=domains, meta=dict(meta), can_login=can_login)
    for name in domains:
        if not can_login:
            walk.clients[name] = client
            continue
        try:
            walk.clients[name] = client.for_domain(name)
        except CmError as e:
            if e.status in (401, 403):
                body = e.body if isinstance(e.body, dict) else {}
                walk.skips.append(
                    {
                        "domain": name,
                        "reason": "unauthorized",
                        "status": e.status,
                        "message": body.get("message") if isinstance(body, dict) else None,
                    }
                )
            else:
                walk.errors.append(
                    {"domain": name, "status": e.status, "error": str(e)}
                )
    return walk


def iter_domain_clients(
    client: CmClient, scope: str
) -> Iterator[tuple[str, CmClient | None, CmError | None]]:
    """Yield ``(domain_name, dclient|None, error|None)``. One ``for_domain`` per domain."""
    walk = build_domain_walk(client, scope)
    skip_by = {s["domain"]: s for s in walk.skips}
    err_by = {e["domain"]: e for e in walk.errors}
    for name in walk.domains:
        if name in walk.clients:
            yield name, walk.clients[name], None
        elif name in skip_by:
            s = skip_by[name]
            yield name, None, CmError(
                s.get("message") or "unauthorized",
                status=int(s.get("status") or 403),
            )
        elif name in err_by:
            e = err_by[name]
            yield name, None, CmError(str(e.get("error") or "error"), status=e.get("status"))
        else:
            yield name, None, CmError("domain client unavailable", status=None)

def resolve_domains(client: CmClient, scope: str) -> tuple[list[str], dict[str, Any]]:
    meta: dict[str, Any] = {"scope": scope}
    self_names: list[str] = []
    try:
        self_data = client.get("/v1/auth/self/domains")
        for d in (self_data or {}).get("resources") or []:
            if isinstance(d, dict) and (d.get("name") or d.get("id")):
                self_names.append(str(d.get("name") or d.get("id")))
        meta["self_domains_total"] = (self_data or {}).get("total", len(self_names))
    except CmError as e:
        meta["self_domains_error"] = str(e)

    if scope == "all":
        try:
            all_data = client.get_paginated("/v1/domains", limit=100, max_items=1000)
            all_names = []
            for d in all_data.get("resources") or []:
                if isinstance(d, dict) and (d.get("name") or d.get("id")):
                    all_names.append(str(d.get("name") or d.get("id")))
            meta["all_domains_total"] = all_data.get("total")
            return list(dict.fromkeys(all_names + self_names)), meta
        except CmError as e:
            meta["all_domains_error"] = str(e)
            meta["note"] = "Could not list /v1/domains; falling back to self/domains"
            return self_names, meta
    return self_names, meta


def check_domains_meta(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/domains?limit=1000")
    if err:
        ctx.section("domains", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    user_mgmt = []
    hsm_backed = []
    for d in resources:
        if not isinstance(d, dict):
            continue
        name = d.get("name")
        if d.get("allow_user_management"):
            user_mgmt.append(name)
            ctx.add(
                "domains",
                "domain_user_mgmt",
                "INFO",
                f"Domain '{name}' has allow_user_management enabled.",
            )
        hsm = d.get("hsm_connection_id") or d.get("kek_label") or (
            d.get("meta") if isinstance(d.get("meta"), dict) else None
        )
        if isinstance(hsm, dict) and (hsm.get("hsm_connection_id") or hsm.get("kek_label")):
            hsm_backed.append(name)
            ctx.add(
                "domains",
                "domain_hsm_backed",
                "INFO",
                f"Domain '{name}' appears HSM-backed.",
            )
        elif d.get("hsm_connection_id") or d.get("kek_label"):
            hsm_backed.append(name)
            ctx.add(
                "domains",
                "domain_hsm_backed",
                "INFO",
                f"Domain '{name}' appears HSM-backed.",
            )
    ctx.section(
        "domains",
        "PASS",
        {
            "total": (data or {}).get("total", len(resources)),
            "allow_user_management": user_mgmt[:20],
            "hsm_backed": hsm_backed[:20],
        },
        200,
    )
