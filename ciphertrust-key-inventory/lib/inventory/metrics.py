from __future__ import annotations

import re
from collections import Counter
from typing import Any

_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


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
