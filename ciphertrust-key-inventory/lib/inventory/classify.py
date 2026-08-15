from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

_WEAK_DES_ALGS = frozenset(
    {"DES", "DESEDE", "3DES", "TDES", "TRIPLEDES", "TDEA", "TDEA2", "TDEA3"}
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
_CITRUS_RE = re.compile(r"^citrus-[0-9a-fA-F-]{8,}$")
_KS_RE = re.compile(r"^ks-[0-9a-fA-F]{8,}$", re.IGNORECASE)
_CF_RE = re.compile(
    r"^cf-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    re.IGNORECASE,
)


def collapse_versions(keys: list[dict]) -> tuple[list[dict], dict[str, int]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    unnamed: list[dict] = []
    for k in keys:
        if not isinstance(k, dict):
            continue
        name = k.get("name")
        if not name:
            unnamed.append(k)
            continue
        grouped[str(name)].append(k)
    out: list[dict] = []
    counts: dict[str, int] = {}
    for name, vers in grouped.items():
        out.append(max(vers, key=lambda x: int(x.get("version") or 0)))
        counts[name] = len(vers)
    out.extend(unnamed)
    return out, counts


def key_curve(k: dict[str, Any]) -> str:
    for field in ("curveId", "curveName", "curve", "ellipticCurve", "curve_id"):
        v = k.get(field)
        if v:
            return str(v)
    return ""


def is_weak_key(k: dict[str, Any]) -> tuple[bool, str]:
    alg = str(k.get("algorithm") or "").strip()
    alg_u = alg.upper().replace("-", "").replace("_", "")
    try:
        size = int(k.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    curve = key_curve(k)
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


def owner_id(k: dict[str, Any]) -> str | None:
    meta = k.get("meta") if isinstance(k.get("meta"), dict) else {}
    raw = meta.get("ownerId") or k.get("ownerId")
    if raw in (None, "", False):
        return None
    return str(raw)


def service_name(k: dict[str, Any]) -> str | None:
    meta = k.get("meta") if isinstance(k.get("meta"), dict) else {}
    raw = meta.get("service_name")
    if raw in (None, "", False):
        return None
    return str(raw)


def cte_section(k: dict[str, Any]) -> dict[str, Any] | None:
    meta = k.get("meta") if isinstance(k.get("meta"), dict) else {}
    cte = meta.get("cte")
    return cte if isinstance(cte, dict) else None


def cte_fields(k: dict[str, Any]) -> dict[str, Any]:
    empty = {
        "cte": False,
        "cte_versioned": None,
        "cte_policy": None,
        "cte_encryption_mode": None,
    }
    cte = cte_section(k)
    if cte is None or not owner_id(k):
        return empty
    versioned = cte.get("cte_versioned")
    if versioned is True:
        cte_versioned: bool | None = True
        policy = "LDT"
    else:
        cte_versioned = False if versioned is False else None
        policy = "Standard"
    mode = cte.get("encryption_mode")
    return {
        "cte": True,
        "cte_versioned": cte_versioned,
        "cte_policy": policy,
        "cte_encryption_mode": str(mode) if mode not in (None, "") else None,
    }


def is_system_key(k: dict[str, Any]) -> tuple[bool, str]:
    name = str(k.get("name") or "")
    if _CITRUS_RE.match(name) or name.lower().startswith("citrus-"):
        return True, "citrus"
    if _KS_RE.match(name) or name.lower().startswith("ks-"):
        if service_name(k) and not owner_id(k):
            return True, "service"
    return False, ""


def is_akeyless_cf(k: dict[str, Any]) -> bool:
    return bool(_CF_RE.match(str(k.get("name") or "")))


def parse_date(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    if value.strip().lower() in ("no expiration", "never", "none"):
        return None
    clean = value.split(".")[0].rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def days_until(value: Any, now: datetime) -> int | None:
    dt = parse_date(value) if not isinstance(value, datetime) else value
    if not dt:
        return None
    return (dt - now).days


def _int(v: Any) -> int | None:
    try:
        if v is None or v == "":
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


def _aliases(k: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for a in k.get("aliases") or []:
        if isinstance(a, dict) and a.get("alias"):
            out.append(str(a.get("alias")))
        elif isinstance(a, str):
            out.append(a)
    return out


def _labels(k: dict[str, Any]) -> dict[str, Any] | None:
    lab = k.get("labels")
    return lab if isinstance(lab, dict) and lab else None


def catalog_row(
    domain: str,
    k: dict[str, Any],
    *,
    now: datetime,
    window_days: int,
    version_count: int = 1,
) -> dict[str, Any]:
    weak, weak_reason = is_weak_key(k)
    system, system_kind = is_system_key(k)
    akeyless_cf = is_akeyless_cf(k)
    state = str(k.get("state") or "")
    unexportable = bool(k.get("unexportable"))
    undeletable = bool(k.get("undeletable"))
    d_deact = days_until(k.get("deactivationDate"), now)
    d_pstop = days_until(k.get("protectStopDate"), now)
    d_act = days_until(k.get("activationDate"), now)
    rot_days = _int(k.get("rotationFrequencyDays"))
    created = parse_date(k.get("createdAt"))
    age_days = (now - created).days if created else None
    rot_due = bool(k.get("rotationDateReached"))
    if rot_days and rot_days > 0 and created:
        rot_due = rot_due or age_days >= rot_days
    about = False
    if d_deact is not None and 0 <= d_deact <= window_days:
        about = True
    if d_pstop is not None and 0 <= d_pstop <= window_days:
        about = True
    if d_act is not None and 0 <= d_act <= window_days:
        about = True
    if rot_due:
        about = True
    version = _int(k.get("version"))
    cte = cte_fields(k)
    return {
        "domain": domain,
        "name": k.get("name"),
        "id": k.get("id"),
        "uri": k.get("uri"),
        "algorithm": k.get("algorithm"),
        "size": k.get("size"),
        "curve": key_curve(k) or None,
        "objectType": k.get("objectType"),
        "state": state or None,
        "version": version,
        "version_count": int(version_count or 1),
        "createdAt": k.get("createdAt"),
        "updatedAt": k.get("updatedAt"),
        "activationDate": k.get("activationDate"),
        "deactivationDate": k.get("deactivationDate"),
        "protectStopDate": k.get("protectStopDate"),
        "archiveDate": k.get("archiveDate"),
        "age_days": age_days,
        "older_than_1y": bool(age_days is not None and age_days >= 365),
        "older_than_3y": bool(age_days is not None and age_days >= 365 * 3),
        "rotationFrequencyDays": rot_days,
        "rotationDateReached": bool(k.get("rotationDateReached")) or None,
        "exportable": not unexportable,
        "deletable": not undeletable,
        "neverExported": k.get("neverExported"),
        "neverExportable": k.get("neverExportable"),
        "usage": k.get("usage"),
        "usageMask": k.get("usageMask"),
        "ownerId": owner_id(k),
        "owner_name": None,
        "service_name": service_name(k),
        "aliases": _aliases(k),
        "labels": _labels(k),
        "emptyMaterial": bool(k.get("emptyMaterial")),
        "system": system,
        "system_kind": system_kind or None,
        "akeyless_cf": akeyless_cf,
        "weak": weak,
        "weak_reason": weak_reason or None,
        "inactive": state != "Active",
        "about_to_change": about,
        "days_to_deactivate": d_deact,
        "days_to_protect_stop": d_pstop,
        "days_to_activate": d_act,
        "rotation_due": rot_due,
        "never_rotated": version == 0,
        "cte": cte["cte"],
        "cte_versioned": cte["cte_versioned"],
        "cte_policy": cte["cte_policy"],
        "cte_encryption_mode": cte["cte_encryption_mode"],
    }
