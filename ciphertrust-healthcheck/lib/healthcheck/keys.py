"""Vault key analysis and Prometheus metrics parsing."""
from __future__ import annotations

import re
import urllib.parse
from collections import Counter, defaultdict
from typing import Any

from cm_client import CmClient, CmError

from .context import ReportCtx
from .util import _LABEL_RE

def collapse_key_versions(keys: list[dict]) -> dict[str, dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for k in keys:
        name = k.get("name")
        if not name:
            continue
        grouped[str(name)].append(k)
    out: dict[str, dict] = {}
    for name, vers in grouped.items():
        best = max(vers, key=lambda x: int(x.get("version") or 0))
        out[name] = best
    return out


def _key_curve(k: dict[str, Any]) -> str:
    for field in ("curveId", "curveName", "curve", "ellipticCurve", "curve_id"):
        v = k.get(field)
        if v:
            return str(v)
    return ""


# CM keys2 algorithm= filter is case-sensitive (RSA works; rsa returns 0).
_WEAK_DES_ALGS = frozenset(
    {"DES", "DESEDE", "3DES", "TDES", "TRIPLEDES", "TDEA", "TDEA2", "TDEA3"}
)
# Undersized AES/ARIA: every 8-bit step below 128 (imports / odd sizes).
_UNDERSIZED_SYM_SIZES = tuple(range(8, 128, 8))
# CM-supported + common legacy weak EC curve IDs (docs Supported Key Algorithms).
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
_WEAK_EC_CURVE_TOKENS = (
    "secp224",
    "secp192",
    "secp160",
    "secp128",
    "secp112",
    "brainpoolp224",
    "brainpoolp192",
    "brainpoolp160",
    "prime192",
    "sect163",
    "sect193",
    "sect233",
)


def _is_weak_key(k: dict[str, Any]) -> tuple[bool, str]:
    """Weak per CM supported-algo tables + NIST-style floor.

    - RSA size < 2048 (docs deprecate RSA-512/1024)
    - Any DES / DESede / 3DES / TDES
    - AES or ARIA size < 128
    - EC with size < 256 or ~224-bit (and smaller) curves
    """
    alg = str(k.get("algorithm") or "").strip()
    alg_u = alg.upper().replace("-", "").replace("_", "")
    try:
        size = int(k.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    curve = _key_curve(k)
    curve_l = curve.lower()

    if alg_u in _WEAK_DES_ALGS or alg_u.startswith("DESEDE"):
        detail = f"{alg} (legacy/deprecated)"
        if size:
            detail = f"{alg} ({size} bits; legacy/deprecated)"
        return True, detail

    if alg_u == "RSA" and size and size < 2048:
        return True, f"{alg} ({size} bits)"

    if alg_u in ("AES", "ARIA") and size and size < 128:
        return True, f"{alg} ({size} bits)"

    if alg_u in ("EC", "ECDSA", "ECC"):
        # <256-bit ≈ below modern 128-bit security floor (aligns with RSA < 2048).
        weak_ec = bool(size and size < 256)
        if not weak_ec and curve_l:
            weak_ec = any(tok in curve_l for tok in _WEAK_EC_CURVE_TOKENS) or bool(
                re.search(r"(?<![0-9])(112|128|160|192|224)(?![0-9])", curve_l)
            )
        if weak_ec:
            if size and curve:
                return True, f"{alg} ({size} bits, {curve})"
            if size:
                return True, f"{alg} ({size} bits)"
            if curve:
                return True, f"{alg} ({curve})"
            return True, f"{alg} (undersized curve)"

    return False, ""


def _keys2_filter_path(**params: Any) -> str:
    """Build /v1/vault/keys2/ query; list values become repeated params (OR)."""
    parts: list[str] = []
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
    return "/v1/vault/keys2/?" + "&".join(parts) if parts else "/v1/vault/keys2/"


def fetch_weak_key_candidates(client: CmClient, *, max_items: int = 5000) -> list[dict]:
    """Server-side filters for likely-weak keys (avoids full-vault --max-keys cap).

    Strategy (algorithm filter is case-sensitive on CM):
    - Pull **all** RSA / DES-family / ARIA / EC (usually small sets), then classify.
    - AES vaults are huge → only request sizes &lt; 128.
    - Also query weak ``curveid`` values and RSA sizes 512/1024 as a belt-and-suspenders.
    """
    queries = [
        # Full algo pulls (canonical case) — classify client-side for size/curve rules
        _keys2_filter_path(algorithm="RSA"),
        _keys2_filter_path(algorithm="DESede"),
        _keys2_filter_path(algorithm="DES"),
        _keys2_filter_path(algorithm="3DES"),
        _keys2_filter_path(algorithm="TDES"),
        _keys2_filter_path(algorithm="*DES*"),
        _keys2_filter_path(algorithm="ARIA"),
        _keys2_filter_path(algorithm="EC"),
        _keys2_filter_path(algorithm="ECDSA"),
        # RSA weak sizes (docs: 512/1024 deprecated); catch even if alg filter fails
        _keys2_filter_path(algorithm="RSA", size=[512, 768, 1024, 1536, 1792]),
        _keys2_filter_path(size=[512, 768, 1024]),
        # Undersized AES/ARIA (every supported-odd size below 128)
        _keys2_filter_path(algorithm="AES", size=list(_UNDERSIZED_SYM_SIZES)),
        _keys2_filter_path(algorithm="ARIA", size=list(_UNDERSIZED_SYM_SIZES)),
        # DESede key sizes from docs (112/168) + parity forms (128/192) with alg set
        _keys2_filter_path(algorithm="DESede", size=[112, 128, 168, 192]),
        _keys2_filter_path(algorithm="TDES", size=[112, 128, 168, 192]),
        # EC weak sizes + CM-documented / legacy weak curves
        _keys2_filter_path(
            algorithm="EC", size=[112, 128, 160, 192, 224, 225, 233, 239]
        ),
        _keys2_filter_path(curveid=list(_WEAK_EC_CURVE_IDS)),
    ]
    by_id: dict[str, dict] = {}
    for path in queries:
        try:
            page = client.get_paginated(path, limit=100, max_items=max_items)
        except CmError:
            continue
        for k in page.get("resources") or []:
            if not isinstance(k, dict):
                continue
            kid = str(k.get("id") or k.get("uri") or "")
            if not kid:
                kid = f"{k.get('name')}|{k.get('version')}|{k.get('algorithm')}|{k.get('size')}"
            by_id[kid] = k
    return list(by_id.values())


def analyze_keys(
    ctx: ReportCtx,
    domain: str,
    keys: list[dict],
    *,
    weak_keys: list[dict] | None = None,
) -> dict:
    collapsed = collapse_key_versions([k for k in keys if isinstance(k, dict)])
    states: Counter = Counter()
    weak = []
    non_active = []
    for name, k in collapsed.items():
        state = str(k.get("state") or "Unknown")
        states[state] += 1
        if state != "Active":
            non_active.append({"name": name, "state": state, "version": k.get("version")})

    # Filter hunt + general sample (union) so nothing in either path is missed.
    if weak_keys is not None:
        weak_source = list(keys) + list(weak_keys)
    else:
        weak_source = keys
    weak_collapsed = collapse_key_versions(
        [k for k in weak_source if isinstance(k, dict)]
    )
    for name, k in weak_collapsed.items():
        is_weak, reason = _is_weak_key(k)
        if is_weak:
            weak.append(
                {
                    "name": name,
                    "algorithm": k.get("algorithm") or "",
                    "size": k.get("size") or 0,
                    "curve": _key_curve(k) or None,
                    "reason": reason,
                }
            )
    if non_active:
        ctx.add(
            "keys",
            "keys_non_active",
            "WARNING",
            f"[{domain}] {len(non_active)} key(s) have inactive (non-Active) highest version: "
            f"{', '.join(x['name'] for x in non_active[:5])}.",
        )
    if weak:
        for w in weak[:10]:
            ctx.add(
                "keys",
                "keys_weak_algorithm",
                "WARNING",
                f"[{domain}] Key '{w['name']}' has weak configuration: "
                f"{w.get('reason') or w['algorithm']}.",
            )
        if len(weak) > 10:
            ctx.add(
                "keys",
                "keys_weak_algorithm_more",
                "WARNING",
                f"[{domain}] {len(weak) - 10} additional weak key(s) omitted from detail.",
            )
    return {
        "domain": domain,
        "raw": len(keys),
        "unique": len(collapsed),
        "states": dict(states),
        "non_active_count": len(non_active),
        "weak_count": len(weak),
        "weak_sample": weak[:10],
        "non_active_sample": non_active[:10],
    }


def parse_key_metrics(text: str) -> dict[str, Any]:
    usage_by_domain: list[dict[str, Any]] = []
    deks_by_state: Counter = Counter()
    keks_total = None
    rotations = 0
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("ciphertrust_license_manager_key_usage_count_including_subdomains{"):
            try:
                head, val = line.rsplit(" ", 1)
                labels = {
                    m.group(1): m.group(2).replace('\\"', '"')
                    for m in _LABEL_RE.finditer(head[head.find("{") + 1 : head.rfind("}")])
                }
                usage_by_domain.append(
                    {
                        "domain": labels.get("domain_name") or labels.get("domain_id"),
                        "keys": int(float(val)),
                    }
                )
            except (ValueError, IndexError):
                continue
        elif line.startswith("ciphertrust_key_vault_deks_total{"):
            try:
                head, val = line.rsplit(" ", 1)
                labels = {
                    m.group(1): m.group(2).replace('\\"', '"')
                    for m in _LABEL_RE.finditer(head[head.find("{") + 1 : head.rfind("}")])
                }
                state = labels.get("state") or labels.get("NAEstate") or "unknown"
                deks_by_state[state] += int(float(val))
            except (ValueError, IndexError):
                continue
        elif line.startswith("ciphertrust_key_vault_keks_total{"):
            try:
                _, val = line.rsplit(" ", 1)
                keks_total = int(float(val))
            except (ValueError, IndexError):
                continue
        elif line.startswith("ciphertrust_key_vault_key_rotations{"):
            try:
                _, val = line.rsplit(" ", 1)
                rotations += int(float(val))
            except (ValueError, IndexError):
                continue
    usage_by_domain.sort(key=lambda r: (-(r.get("keys") or 0), str(r.get("domain"))))
    # Per-domain "including_subdomains" series must NOT be summed (double-count /
    # miss root). Prefer root's series; else the max rollup present in the scrape.
    key_usage_estate: int | None = None
    if usage_by_domain:
        rootish = next(
            (
                r
                for r in usage_by_domain
                if str(r.get("domain") or "").strip().lower() in ("root", "/", "")
            ),
            None,
        )
        if rootish is not None and rootish.get("keys") is not None:
            key_usage_estate = int(rootish["keys"])
        else:
            key_usage_estate = max(int(r.get("keys") or 0) for r in usage_by_domain)
    deks_total = sum(int(v or 0) for v in deks_by_state.values()) if deks_by_state else None
    return {
        "domains_with_key_usage": len(usage_by_domain),
        "key_usage_estate": key_usage_estate,
        "key_usage_top_domains": [r for r in usage_by_domain if (r.get("keys") or 0) > 0][:15],
        "deks_by_state": dict(deks_by_state),
        "deks_total": deks_total,
        "keks_total": keks_total,
        "key_rotations_total": rotations,
    }
