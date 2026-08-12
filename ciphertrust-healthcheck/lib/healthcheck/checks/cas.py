"""Certificate authority checks (local, external, trusted)."""
from __future__ import annotations

from typing import Any

from cm_client import CmClient, CmError

from ..context import ReportCtx
from ..domains import DomainWalk, build_domain_walk
from ..util import days_until, emit_cert_validity, parse_date, safe_get

def _interface_referenced_ca_ids(client: CmClient) -> set[str]:
    """CA ids/uris referenced by enabled interfaces (auto_gen + trusted_cas)."""
    refs: set[str] = set()
    try:
        data = client.get_paginated(
            "/v1/configs/interfaces/", limit=100, max_items=500
        )
    except CmError:
        return refs
    for i in data.get("resources") or []:
        if not isinstance(i, dict) or not i.get("enabled"):
            continue
        ag = i.get("auto_gen_ca_id")
        if ag:
            refs.add(str(ag))
            if ":" in str(ag):
                refs.add(str(ag).rsplit(":", 1)[-1])
        trusted = i.get("trusted_cas") or {}
        if isinstance(trusted, dict):
            for bucket in trusted.values():
                if isinstance(bucket, list):
                    for item in bucket:
                        refs.add(str(item))
                        if ":" in str(item):
                            refs.add(str(item).rsplit(":", 1)[-1])
    return refs


def _ca_is_referenced(ca: dict, refs: set[str]) -> bool:
    for key in ("id", "uri", "name"):
        val = ca.get(key)
        if val and str(val) in refs:
            return True
        if val and ":" in str(val) and str(val).rsplit(":", 1)[-1] in refs:
            return True
    return False


def _score_domain_cas(
    ctx: ReportCtx,
    *,
    domain: str,
    kind: str,
    resources: list[Any],
    refs: set[str],
) -> dict[str, Any]:
    """Score one domain's local or external CA list; emit findings with [domain]."""
    expired: list[dict] = []
    expiring: list[dict] = []
    ok: list[dict] = []
    for ca in resources:
        if not isinstance(ca, dict):
            continue
        name = ca.get("name") or ca.get("id")
        state = str(ca.get("state") or "").lower()
        after = parse_date(ca.get("notAfter"))
        dleft = days_until(after, ctx.now)
        if state == "expired" and dleft is None:
            dleft = -1
        in_use = _ca_is_referenced(ca, refs)
        row = {
            "domain": domain,
            "name": name,
            "state": ca.get("state"),
            "notAfter": ca.get("notAfter"),
            "days_left": dleft,
            "referenced_by_interface": in_use,
        }
        label = f"[{domain}] {kind.title()} CA '{name}'"
        if in_use:
            label += " (referenced by enabled interface)"
        sev = emit_cert_validity(
            ctx,
            area="ca",
            code_prefix=f"ca_{kind}",
            label=label,
            days_left=dleft,
            not_after=str(ca.get("notAfter") or "")[:32] or None,
        )
        if sev == "CRITICAL":
            expired.append(row)
        elif sev == "WARNING":
            expiring.append(row)
        elif sev == "INFO":
            ok.append(row)
    return {
        "total": len(resources),
        "expired": expired,
        "expiring_soon": expiring,
        "ok": ok,
    }


def _check_trusted_cas(ctx: ReportCtx, client: CmClient) -> None:
    """Trusted CAs are appliance-scoped; subdomains often return 403."""
    trusted, err = safe_get(client, "/v1/trusted-cas/?limit=100")
    if err:
        if err.status in (401, 403):
            ctx.section(
                "ca_trusted",
                "PASS",
                {
                    "total": 0,
                    "expired": [],
                    "expiring_soon": [],
                    "ok": [],
                    "skipped": True,
                    "reason": "unauthorized",
                    "status": err.status,
                    "note": "Trusted CAs require appliance/root privileges; skipped.",
                },
                err.status,
            )
            return
        ctx.section("ca_trusted", "WARN", {"error": str(err)}, err.status)
        return
    resources = (trusted or {}).get("resources") or []
    expired: list[dict] = []
    expiring: list[dict] = []
    ok: list[dict] = []
    for ca in resources:
        if not isinstance(ca, dict):
            continue
        details = ca.get("ca_details") if isinstance(ca.get("ca_details"), dict) else ca
        name = ca.get("name") or details.get("name") or ca.get("id")
        after = parse_date(details.get("notAfter") or ca.get("notAfter"))
        dleft = days_until(after, ctx.now)
        na = details.get("notAfter") or ca.get("notAfter")
        row = {"name": name, "days_left": dleft, "notAfter": na}
        sev = emit_cert_validity(
            ctx,
            area="ca",
            code_prefix="ca_trusted",
            label=f"Trusted CA '{name}'",
            days_left=dleft,
            not_after=str(na)[:32] if na else None,
        )
        if sev == "CRITICAL":
            expired.append(row)
        elif sev == "WARNING":
            expiring.append(row)
        elif sev == "INFO":
            ok.append(row)
    ctx.section(
        "ca_trusted",
        "FAIL" if expired else ("WARN" if expiring else "PASS"),
        {
            "total": (trusted or {}).get("total", len(resources)),
            "expired": expired,
            "expiring_soon": expiring,
            "ok": ok[:20],
        },
        200,
    )


def check_cas(
    ctx: ReportCtx,
    client: CmClient,
    domain_scope: str = "all",
    *,
    domain_walk: DomainWalk | None = None,
) -> None:
    """Local/external CAs are domain-scoped — scan each reachable domain.

    Trusted CAs are checked once on the auth client (appliance/root); subdomain
    tokens often get 403 for ``/v1/trusted-cas``.
    """
    refs = _interface_referenced_ca_ids(client)
    _check_trusted_cas(ctx, client)

    walk = domain_walk if domain_walk is not None else build_domain_walk(client, domain_scope)
    domains = walk.domains

    by_domain: list[dict[str, Any]] = []
    agg: dict[str, dict[str, list]] = {
        "local": {"expired": [], "expiring_soon": [], "ok": []},
        "external": {"expired": [], "expiring_soon": [], "ok": []},
    }
    totals = {"local": 0, "external": 0}
    checked = 0
    skipped = 0

    for name in domains:
        dclient = walk.clients.get(name)
        if dclient is None:
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
                skipped += 1
            else:
                err = next((e for e in walk.errors if e.get("domain") == name), None)
                by_domain.append(
                    {
                        "domain": name,
                        "error": str((err or {}).get("error") or "error"),
                        "status": (err or {}).get("status"),
                    }
                )
                skipped += 1
            continue

        row: dict[str, Any] = {"domain": name}
        for kind, path in (
            ("local", "/v1/ca/local-cas?limit=100"),
            ("external", "/v1/ca/external-cas?limit=100"),
        ):
            data, err = safe_get(dclient, path)
            if err:
                row[kind] = {
                    "error": str(err),
                    "status": err.status,
                }
                continue
            resources = (data or {}).get("resources") or []
            scored = _score_domain_cas(
                ctx,
                domain=name,
                kind=kind,
                resources=resources,
                refs=refs,
            )
            api_total = (data or {}).get("total", scored["total"])
            totals[kind] += int(api_total or 0)
            for bucket in ("expired", "expiring_soon", "ok"):
                agg[kind][bucket].extend(scored[bucket])
            row[kind] = {
                "total": api_total,
                "expired": len(scored["expired"]),
                "expiring_soon": len(scored["expiring_soon"]),
                "ok": len(scored["ok"]),
            }
        by_domain.append(row)
        checked += 1

    note = (
        "Local/external CAs are per-domain. Totals sum domains checked; "
        f"skipped={skipped} (unauthorized does not mean clean). "
        "Trusted CAs are appliance-scoped."
    )
    for kind in ("local", "external"):
        expired = agg[kind]["expired"]
        expiring = agg[kind]["expiring_soon"]
        ok = agg[kind]["ok"]
        result = "FAIL" if expired else ("WARN" if expiring else "PASS")
        if not checked and skipped:
            result = "WARN"
        ctx.section(
            f"ca_{kind}",
            result,
            {
                "total": totals[kind],
                "domains_checked": checked,
                "domains_skipped": skipped,
                "expired": expired,
                "expired_in_use": [
                    r for r in expired if r.get("referenced_by_interface")
                ],
                "expiring_soon": expiring,
                "ok": ok[:20],
                "by_domain": by_domain,
                "note": note,
            },
            200,
        )
