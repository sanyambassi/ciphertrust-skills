from __future__ import annotations

import re
from collections import Counter
from typing import Any

_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
_ACCOUNT_UUID_RE = re.compile(
    r"kylo-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)


def _labels(head: str) -> dict[str, str]:
    start = head.find("{")
    end = head.rfind("}")
    if start < 0 or end < 0:
        return {}
    return {
        m.group(1): m.group(2).replace('\\"', '"')
        for m in _LABEL_RE.finditer(head[start + 1 : end])
    }


def _domain_label(account: str, id_to_name: dict[str, str]) -> str:
    if not account:
        return "unknown"
    match = _ACCOUNT_UUID_RE.search(account)
    if match:
        did = match.group(1).lower()
        return id_to_name.get(did) or did
    return "root"


def parse_key_metrics(text: str) -> dict[str, Any]:
    usage_by_domain: list[dict[str, Any]] = []
    deks_by_state: Counter = Counter()
    deks_by_algorithm: Counter = Counter()
    deks_by_account: Counter = Counter()
    keks_total = None
    rotations = 0
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("ciphertrust_license_manager_key_usage_count_including_subdomains{"):
            try:
                head, val = line.rsplit(" ", 1)
                labels = _labels(head)
                usage_by_domain.append(
                    {
                        "domain": labels.get("domain_name") or labels.get("domain_id"),
                        "domain_id": labels.get("domain_id"),
                        "keys": int(float(val)),
                    }
                )
            except (ValueError, IndexError):
                continue
        elif line.startswith("ciphertrust_key_vault_deks_total{"):
            try:
                head, val = line.rsplit(" ", 1)
                labels = _labels(head)
                n = int(float(val))
                state = labels.get("state") or labels.get("NAEstate") or "unknown"
                deks_by_state[state] += n
                deks_by_algorithm[labels.get("algorithm") or "unknown"] += n
                deks_by_account[labels.get("account") or ""] += n
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
    id_to_name = {
        str(r.get("domain_id") or "").strip().lower(): str(r.get("domain") or "").strip()
        for r in usage_by_domain
        if r.get("domain_id") and r.get("domain")
    }
    deks_by_domain_counts: Counter = Counter()
    for account, n in deks_by_account.items():
        deks_by_domain_counts[_domain_label(account, id_to_name)] += int(n or 0)
    deks_by_domain = [
        {"domain": name, "keys": int(n)}
        for name, n in deks_by_domain_counts.most_common()
        if n > 0
    ]
    deks_total = sum(int(v or 0) for v in deks_by_state.values()) if deks_by_state else None
    return {
        "domains_with_key_usage": len(usage_by_domain),
        "key_usage_estate": key_usage_estate,
        "key_usage_top_domains": [r for r in usage_by_domain if (r.get("keys") or 0) > 0][:15],
        "deks_by_state": dict(deks_by_state),
        "deks_by_algorithm": dict(deks_by_algorithm.most_common()),
        "deks_by_domain": deks_by_domain,
        "deks_total": deks_total,
        "keks_total": keks_total,
        "key_rotations_total": rotations,
    }
