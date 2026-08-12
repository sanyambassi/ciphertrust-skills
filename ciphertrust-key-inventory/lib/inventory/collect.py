from __future__ import annotations

import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cm_client import CmClient, CmError

from .classify import catalog_row, collapse_versions
from .domains import DomainWalk, build_domain_walk
from .metrics import parse_key_metrics

_UNDERSIZED_SYM_SIZES = tuple(range(8, 128, 8))
_WEAK_EC_CURVE_IDS = (
    "secp224r1",
    "secp224k1",
    "secp192r1",
    "secp192k1",
    "secp160r1",
    "secp160k1",
    "secp160r2",
    "secp128r1",
    "secp128r2",
    "secp112r1",
    "secp112r2",
    "brainpoolP224r1",
    "brainpoolP224t1",
    "brainpoolP192r1",
    "brainpoolP192t1",
    "brainpoolP160r1",
    "brainpoolP160t1",
    "prime192v1",
    "sect163k1",
    "sect163r1",
    "sect163r2",
    "sect193r1",
    "sect193r2",
    "sect233k1",
    "sect233r1",
)


def _host(base: str) -> str:
    try:
        return urlparse(base).hostname or base or "n/a"
    except Exception:
        return base or "n/a"


def _keys2_path(**params: Any) -> str:
    parts = ["fields=meta"]
    for key, val in params.items():
        if val is None:
            continue
        if isinstance(val, (list, tuple)):
            for item in val:
                parts.append(
                    f"{urllib.parse.quote(str(key))}={urllib.parse.quote(str(item))}"
                )
        else:
            parts.append(
                f"{urllib.parse.quote(str(key))}={urllib.parse.quote(str(val))}"
            )
    return "/v1/vault/keys2/?" + "&".join(parts)


def _key_id(k: dict[str, Any]) -> str:
    kid = str(k.get("id") or k.get("uri") or "")
    if kid:
        return kid
    return f"{k.get('name')}|{k.get('version')}|{k.get('algorithm')}|{k.get('size')}"


def _merge_keys(*groups: list[Any]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for group in groups:
        for k in group:
            if not isinstance(k, dict):
                continue
            kid = _key_id(k)
            existing = by_id.get(kid)
            if existing is None or (not existing.get("meta") and k.get("meta")):
                by_id[kid] = k
    return list(by_id.values())


def _page_keys(client: CmClient, path: str, max_items: int | None) -> dict[str, Any]:
    return client.get_paginated(path, limit=100, max_items=max_items)


def _hunt_system_keys(client: CmClient, max_items: int | None) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for path in (
        _keys2_path(name="citrus-*"),
        _keys2_path(name="ks-*", objectType="Opaque Object"),
    ):
        try:
            page = _page_keys(client, path, max_items)
        except CmError:
            continue
        found.extend(k for k in (page.get("resources") or []) if isinstance(k, dict))
    return found


def _hunt_akeyless_cf(client: CmClient, max_items: int | None) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for path in (
        _keys2_path(name="cf-*"),
        _keys2_path(name="cf-*", objectType="Opaque Object"),
    ):
        try:
            page = _page_keys(client, path, max_items)
        except CmError:
            continue
        found.extend(k for k in (page.get("resources") or []) if isinstance(k, dict))
    return found


def _hunt_weak_keys(client: CmClient, max_items: int | None) -> list[dict[str, Any]]:
    queries = [
        _keys2_path(algorithm="RSA"),
        _keys2_path(algorithm="DESede"),
        _keys2_path(algorithm="DES"),
        _keys2_path(algorithm="3DES"),
        _keys2_path(algorithm="TDES"),
        _keys2_path(algorithm="ARIA"),
        _keys2_path(algorithm="EC"),
        _keys2_path(algorithm="ECDSA"),
        _keys2_path(algorithm="RSA", size=[512, 768, 1024, 1536, 1792]),
        _keys2_path(size=[512, 768, 1024]),
        _keys2_path(algorithm="AES", size=list(_UNDERSIZED_SYM_SIZES)),
        _keys2_path(algorithm="ARIA", size=list(_UNDERSIZED_SYM_SIZES)),
        _keys2_path(algorithm="DESede", size=[112, 128, 168, 192]),
        _keys2_path(algorithm="TDES", size=[112, 128, 168, 192]),
        _keys2_path(algorithm="EC", size=[112, 128, 160, 192, 224, 225, 233, 239]),
        _keys2_path(curveid=list(_WEAK_EC_CURVE_IDS)),
    ]
    found: list[dict[str, Any]] = []
    for path in queries:
        try:
            page = _page_keys(client, path, max_items)
        except CmError:
            continue
        found.extend(k for k in (page.get("resources") or []) if isinstance(k, dict))
    return found


def _label_names(data: Any) -> list[str]:
    resources = (data or {}).get("resources") if isinstance(data, dict) else data
    if not isinstance(resources, list):
        return []
    out: list[str] = []
    for item in resources:
        if isinstance(item, dict):
            name = item.get("name") or item.get("label") or item.get("id")
            if name:
                out.append(str(name))
        elif isinstance(item, str) and item:
            out.append(item)
    return out


def _fetch_labels(client: CmClient) -> dict[str, Any]:
    try:
        page = client.get_paginated("/v1/vault/key-labels/", limit=100, max_items=5000)
    except CmError as e:
        return {"error": str(e), "status": e.status, "labels": []}
    labels = _label_names(page)
    return {
        "total": page.get("total", len(labels)),
        "labels": labels,
        "truncated": bool(page.get("truncated")),
    }


def _identity(client: CmClient) -> dict[str, Any]:
    try:
        user = client.get("/v1/auth/self/user")
    except CmError as e:
        return {"error": str(e), "status": e.status}
    if not isinstance(user, dict):
        return {}
    return {
        "username": user.get("username") or user.get("name"),
        "user_id": user.get("user_id") or user.get("id"),
    }


def _system_info(client: CmClient) -> tuple[str | None, dict[str, Any]]:
    try:
        info = client.get("/v1/system/info")
    except CmError as e:
        return None, {"error": str(e), "status": e.status}
    if not isinstance(info, dict):
        return None, {}
    return (
        info.get("version"),
        {
            "version": info.get("version"),
            "model": info.get("model") or info.get("product_name"),
        },
    )


def scrape_metrics(client: CmClient) -> dict[str, Any]:
    try:
        status = client.get("/v1/system/metrics/prometheus/status")
    except CmError as e:
        return {"error": str(e), "status": e.status}
    enabled = bool((status or {}).get("enabled")) if isinstance(status, dict) else False
    if not enabled:
        return {"enabled": False}
    token = (status or {}).get("token") if isinstance(status, dict) else None
    if not token:
        return {"enabled": True, "note": "Scrape token unavailable to this user"}
    try:
        url = f"{client.config.base}/v1/system/metrics/prometheus"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "text/plain"},
            method="GET",
        )
        with urllib.request.urlopen(
            req, context=client._ssl, timeout=client.config.timeout
        ) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        summary = parse_key_metrics(text)
        summary["enabled"] = True
        return summary
    except Exception as e:
        return {"enabled": True, "error": str(e)}


def fetch_orphans(client: CmClient) -> dict[str, Any]:
    try:
        data = client.get("/v1/reports/orphaned-resources?limit=10000")
    except CmError as e:
        return {"error": str(e), "status": e.status}
    if not isinstance(data, dict):
        return {"total_orphaned_keys_count": 0, "orphaned_keys_by_account": []}
    by_acct = (
        data.get("orphaned_keys_by_account")
        or data.get("resources")
        or []
    )
    if not isinstance(by_acct, list):
        by_acct = []
    total = data.get("total_orphaned_keys_count")
    if total is None:
        total = data.get("total")
    if total is None:
        total = 0
        for row in by_acct:
            if isinstance(row, dict):
                total += int(
                    row.get("orphaned_keys_count")
                    or row.get("count")
                    or row.get("keys")
                    or 0
                )
    return {
        "total_orphaned_keys_count": int(total or 0),
        "orphaned_keys_by_account": by_acct,
        "truncated": bool(data.get("truncated")),
    }


def _domain_skip(walk: DomainWalk, name: str) -> dict[str, Any] | None:
    skip = next((s for s in walk.skips if s.get("domain") == name), None)
    if skip:
        return {
            "domain": name,
            "reason": skip.get("reason") or "unauthorized",
            "status": skip.get("status"),
            "message": skip.get("message"),
        }
    err = next((e for e in walk.errors if e.get("domain") == name), None)
    if err:
        return {
            "domain": name,
            "reason": "error",
            "status": err.get("status"),
            "error": str(err.get("error") or "error"),
        }
    return {
        "domain": name,
        "reason": "unavailable",
    }


def collect_domain_keys(
    dclient: CmClient,
    domain: str,
    *,
    max_keys: int | None,
    now: datetime,
    window_days: int,
) -> dict[str, Any]:
    page = _page_keys(dclient, _keys2_path(), max_keys)
    listed = [k for k in (page.get("resources") or []) if isinstance(k, dict)]
    hunts = [_hunt_system_keys(dclient, max_keys), _hunt_akeyless_cf(dclient, max_keys)]
    truncated = bool(page.get("truncated"))
    if truncated:
        hunts.append(_hunt_weak_keys(dclient, max_keys if max_keys is None else max(max_keys, 5000)))
    merged = _merge_keys(listed, *hunts)
    collapsed, version_counts = collapse_versions(merged)
    rows = []
    for k in collapsed:
        name = str(k.get("name") or "")
        nvers = version_counts.get(name, 1) if name else 1
        rows.append(
            catalog_row(
                domain, k, now=now, window_days=window_days, version_count=nvers
            )
        )
    labels = _fetch_labels(dclient)
    states: Counter = Counter()
    for row in rows:
        states[str(row.get("state") or "Unknown")] += 1
    return {
        "domain": domain,
        "raw": len(merged),
        "unique": len(rows),
        "version_objects": len(merged),
        "keys_multi_version": sum(
            1 for r in rows if (r.get("version") or 0) >= 1
        ),
        "keys_three_plus": sum(
            1 for r in rows if (r.get("version") or 0) >= 2
        ),
        "total_reported": page.get("total"),
        "truncated": truncated,
        "states": dict(states),
        "labels": labels,
        "catalog": rows,
    }


def collect(
    client: CmClient,
    *,
    domain_scope: str = "all",
    only_domain: str | None = None,
    max_keys: int | None = None,
    window_days: int = 30,
    include_metrics: bool = True,
    include_orphans: bool = True,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cm_version, info = _system_info(client)
    identity = _identity(client)
    walk = build_domain_walk(client, domain_scope, only=only_domain)

    checked: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    catalog: list[dict[str, Any]] = []
    truncated_any = False

    for name in walk.domains:
        dclient = walk.clients.get(name)
        if dclient is None:
            item = _domain_skip(walk, name)
            if item.get("reason") == "error":
                errors.append(item)
            else:
                skipped.append(item)
            continue
        try:
            result = collect_domain_keys(
                dclient,
                name,
                max_keys=max_keys,
                now=now,
                window_days=window_days,
            )
        except CmError as e:
            body = e.body if isinstance(e.body, dict) else {}
            msg = body.get("message") if isinstance(body, dict) else None
            item = {
                "domain": name,
                "status": e.status,
                "message": msg or str(e),
            }
            if e.status in (401, 403):
                item["reason"] = "unauthorized"
                skipped.append(item)
            else:
                item["reason"] = "error"
                item["error"] = str(e)
                errors.append(item)
            continue
        if result.get("truncated"):
            truncated_any = True
        catalog.extend(result.get("catalog") or [])
        checked.append({k: v for k, v in result.items() if k != "catalog"})

    report: dict[str, Any] = {
        "ok": True,
        "timestamp_utc": now.isoformat(),
        "base": client.config.base,
        "host": _host(client.config.base),
        "cm_version": cm_version,
        "system_info": info,
        "identity": identity,
        "options": {
            "domain_scope": domain_scope,
            "domain": only_domain,
            "max_keys": max_keys,
            "window_days": window_days,
            "include_metrics": include_metrics,
            "include_orphans": include_orphans,
        },
        "domains": {
            **walk.meta,
            "listed": len(walk.domains),
            "checked_count": len(checked),
            "skipped_count": len(skipped),
            "error_count": len(errors),
            "checked": checked,
            "skipped": skipped,
            "errors": errors,
        },
        "catalog": catalog,
        "truncated": truncated_any,
    }
    if only_domain:
        include_metrics = False
        include_orphans = False
        report["options"]["include_metrics"] = False
        report["options"]["include_orphans"] = False
    if include_metrics:
        report["metrics"] = scrape_metrics(client)
    if include_orphans:
        report["orphans"] = fetch_orphans(client)
    return report
