from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cm_client import CmClient, CmError


def can_domain_login(client: CmClient) -> bool:
    return bool(
        (client.config.username and client.config.password) or client.config.refresh_token
    )


@dataclass
class DomainWalk:
    domains: list[str]
    meta: dict[str, Any]
    can_login: bool
    clients: dict[str, CmClient] = field(default_factory=dict)
    skips: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


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
            return self_names, meta
    return self_names, meta


def build_domain_walk(
    client: CmClient, scope: str, only: str | None = None
) -> DomainWalk:
    can_login = can_domain_login(client)
    if can_login:
        domains, meta = resolve_domains(client, scope)
    else:
        cur = client.config.domain or "current"
        domains = [cur]
        meta = {"scope": scope, "note": "JWT-only: current token domain only"}
    if only:
        want = only.strip()
        domains = [d for d in domains if d == want]
        if not domains:
            domains = [want]
        meta["filter_domain"] = want

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
