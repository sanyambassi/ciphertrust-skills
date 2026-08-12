from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .classify import is_akeyless_cf

CHAT_LIST_CAP = 100

_CSV_COLUMNS = [
    "domain",
    "name",
    "id",
    "uri",
    "algorithm",
    "size",
    "curve",
    "objectType",
    "state",
    "version",
    "version_count",
    "createdAt",
    "updatedAt",
    "activationDate",
    "deactivationDate",
    "protectStopDate",
    "archiveDate",
    "age_days",
    "rotationFrequencyDays",
    "rotationDateReached",
    "exportable",
    "deletable",
    "neverExported",
    "neverExportable",
    "usage",
    "usageMask",
    "ownerId",
    "service_name",
    "aliases",
    "labels",
    "emptyMaterial",
    "system",
    "system_kind",
    "akeyless_cf",
    "weak",
    "weak_reason",
    "inactive",
    "about_to_change",
    "days_to_deactivate",
    "days_to_protect_stop",
    "days_to_activate",
    "rotation_due",
    "never_rotated",
    "older_than_1y",
    "older_than_3y",
    "cte",
    "cte_versioned",
    "cte_policy",
    "cte_encryption_mode",
]


def filter_catalog(rows: list[dict[str, Any]], opts: dict[str, Any]) -> list[dict[str, Any]]:
    out = list(rows)
    alg = (opts.get("algorithm") or "").strip()
    if alg:
        want = alg.upper().replace("-", "").replace("_", "")
        out = [
            r
            for r in out
            if str(r.get("algorithm") or "").upper().replace("-", "").replace("_", "")
            == want
        ]
    state = (opts.get("state") or "").strip()
    if state:
        out = [r for r in out if str(r.get("state") or "") == state]
    if opts.get("weak_only"):
        out = [r for r in out if r.get("weak")]
    if opts.get("inactive_only"):
        out = [r for r in out if r.get("inactive")]
    if opts.get("exportable_only"):
        out = [r for r in out if r.get("exportable")]
    if opts.get("deletable_only"):
        out = [r for r in out if r.get("deletable")]
    if opts.get("about_to_change"):
        out = [r for r in out if r.get("about_to_change")]
    if opts.get("system_only"):
        out = [r for r in out if r.get("system")]
    if opts.get("exclude_system"):
        out = [r for r in out if not r.get("system")]
    if opts.get("cte_only"):
        out = [r for r in out if r.get("cte")]
    return out


def is_lifecycle(row: dict[str, Any]) -> bool:
    return bool(
        row.get("about_to_change")
        or row.get("inactive")
        or (row.get("never_rotated") and row.get("older_than_1y"))
        or row.get("older_than_3y")
    )


def lifecycle_reasons(row: dict[str, Any], window_days: int) -> list[str]:
    reasons: list[str] = []
    if row.get("inactive"):
        reasons.append(f"state {row.get('state') or 'inactive'}")
    d_deact = row.get("days_to_deactivate")
    if d_deact is not None and 0 <= int(d_deact) <= window_days:
        reasons.append(f"deactivates in {d_deact}d")
    d_pstop = row.get("days_to_protect_stop")
    if d_pstop is not None and 0 <= int(d_pstop) <= window_days:
        reasons.append(f"protect-stop in {d_pstop}d")
    d_act = row.get("days_to_activate")
    if d_act is not None and 0 <= int(d_act) <= window_days:
        reasons.append(f"activates in {d_act}d")
    if row.get("rotation_due"):
        reasons.append("rotation due")
    if row.get("never_rotated") and row.get("older_than_1y"):
        reasons.append("never rotated")
    if row.get("older_than_3y"):
        reasons.append("older than 3y")
    elif row.get("older_than_1y") and not row.get("never_rotated"):
        reasons.append("older than 1y")
    return reasons


def due_soon_label(window_days: int) -> str:
    n = int(window_days or 30)
    return f"Activate, deactivate, rotate ({n}d)"


def _count(rows: list[dict[str, Any]], key: str) -> int:
    return sum(1 for r in rows if r.get(key))


def build_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_domain: dict[str, dict[str, int]] = {}
    by_algorithm: Counter = Counter()
    by_state: Counter = Counter()
    by_type: Counter = Counter()
    by_kind: Counter = Counter()
    for r in rows:
        domain = str(r.get("domain") or "")
        slot = by_domain.setdefault(
            domain,
            {
                "keys": 0,
                "version_objects": 0,
                "keys_multi_version": 0,
                "keys_three_plus": 0,
                "system": 0,
                "akeyless_cf": 0,
                "weak": 0,
                "inactive": 0,
                "about_to_change": 0,
                "exportable": 0,
                "deletable": 0,
                "cte": 0,
                "cte_ldt": 0,
                "cte_standard": 0,
            },
        )
        slot["keys"] += 1
        slot["version_objects"] += int(r.get("version_count") or 1)
        if (r.get("version") or 0) >= 1:
            slot["keys_multi_version"] += 1
        if (r.get("version") or 0) >= 2:
            slot["keys_three_plus"] += 1
        if r.get("system"):
            slot["system"] += 1
        if r.get("akeyless_cf"):
            slot["akeyless_cf"] += 1
        if r.get("weak"):
            slot["weak"] += 1
        if r.get("inactive"):
            slot["inactive"] += 1
        if r.get("about_to_change"):
            slot["about_to_change"] += 1
        if r.get("exportable"):
            slot["exportable"] += 1
        if r.get("deletable"):
            slot["deletable"] += 1
        if r.get("cte"):
            slot["cte"] += 1
            if r.get("cte_policy") == "LDT":
                slot["cte_ldt"] += 1
            else:
                slot["cte_standard"] += 1
        alg = str(r.get("algorithm") or "unknown")
        by_algorithm[alg] += 1
        by_state[str(r.get("state") or "Unknown")] += 1
        by_type[str(r.get("objectType") or "unknown")] += 1
        if r.get("system"):
            by_kind[str(r.get("system_kind") or "system")] += 1
    domain_rows = [{"domain": name, **counts} for name, counts in by_domain.items()]
    domain_rows.sort(key=lambda d: (-int(d.get("keys") or 0), str(d.get("domain"))))
    return {
        "keys": len(rows),
        "version_objects": sum(int(r.get("version_count") or 1) for r in rows),
        "keys_multi_version": sum(1 for r in rows if (r.get("version") or 0) >= 1),
        "keys_three_plus": sum(1 for r in rows if (r.get("version") or 0) >= 2),
        "system": _count(rows, "system"),
        "akeyless_cf": _count(rows, "akeyless_cf"),
        "weak": _count(rows, "weak"),
        "inactive": _count(rows, "inactive"),
        "about_to_change": _count(rows, "about_to_change"),
        "lifecycle": sum(1 for r in rows if is_lifecycle(r)),
        "exportable": _count(rows, "exportable"),
        "deletable": _count(rows, "deletable"),
        "never_exported": _count(rows, "neverExported"),
        "never_exportable": _count(rows, "neverExportable"),
        "cte": _count(rows, "cte"),
        "cte_ldt": sum(1 for r in rows if r.get("cte") and r.get("cte_policy") == "LDT"),
        "cte_standard": sum(
            1 for r in rows if r.get("cte") and r.get("cte_policy") != "LDT"
        ),
        "by_domain": domain_rows,
        "by_algorithm": dict(by_algorithm.most_common()),
        "by_state": dict(by_state.most_common()),
        "by_object_type": dict(by_type.most_common()),
        "by_system_kind": dict(by_kind.most_common()),
    }


def apply_presentation(report: dict[str, Any], filter_opts: dict[str, Any]) -> dict[str, Any]:
    collected = list(report.get("catalog") or [])
    for r in collected:
        if isinstance(r, dict):
            r["akeyless_cf"] = is_akeyless_cf(r)
    shown = filter_catalog(collected, filter_opts)
    report["catalog_collected"] = len(collected)
    report["catalog"] = shown
    report["filters"] = {k: v for k, v in filter_opts.items() if v not in (None, False, "")}
    report["totals"] = build_totals(shown)
    return report


def _fmt_list(rows: list[str], total: int) -> list[str]:
    if total > CHAT_LIST_CAP:
        rows.append(f"... {total - CHAT_LIST_CAP} more in JSON/HTML")
    return rows


def print_human(report: dict[str, Any]) -> None:
    if not report.get("ok"):
        print("Key inventory")
        print(f"UNREACHABLE  (exit 2)")
        err = report.get("error") or "unreachable"
        print(err)
        return

    version = report.get("cm_version") or "n/a"
    host = report.get("host") or "n/a"
    domains = report.get("domains") or {}
    totals = report.get("totals") or {}
    catalog = [r for r in (report.get("catalog") or []) if isinstance(r, dict)]
    window = int((report.get("options") or {}).get("window_days") or 30)
    due_lbl = due_soon_label(window)
    collected = report.get("catalog_collected")
    shown = totals.get("keys", len(catalog))
    skipped = domains.get("skipped") or []
    errors = domains.get("errors") or []

    print("Key inventory")
    print(f"CM: {version}    Host: {host}")
    print(
        f"Domains checked: {domains.get('checked_count', 0)}    "
        f"skipped: {domains.get('skipped_count', 0)}"
        + (f"    errors: {domains.get('error_count')}" if domains.get("error_count") else "")
    )
    print(f"Keys in checked domains: {shown}")
    if collected is not None and collected != shown:
        print(f"Showing {shown} of {collected} after filters")
    print(f"Version objects listed: {totals.get('version_objects', shown)}")
    print(f"Keys with more than one version: {totals.get('keys_multi_version', 0)}")
    print(f"Keys with 3 or more versions: {totals.get('keys_three_plus', 0)}")
    if report.get("truncated"):
        print("Catalog truncated by --max-keys; raise the limit for a full key list.")
    metrics = report.get("metrics") or {}
    if isinstance(metrics, dict) and metrics.get("deks_total") is not None:
        print(f"Total keys (including orphaned): {metrics.get('deks_total')}")
    orphans = report.get("orphans") or {}
    if isinstance(orphans, dict) and orphans.get("total_orphaned_keys_count"):
        print(f"Orphaned keys: {orphans.get('total_orphaned_keys_count')}")
    print(f"Never exported: {totals.get('never_exported', 0)}")
    print(f"Never exportable: {totals.get('never_exportable', 0)}")
    print(
        f"CTE keys: {totals.get('cte', 0)}    "
        f"LDT: {totals.get('cte_ldt', 0)}    "
        f"Standard: {totals.get('cte_standard', 0)}"
    )
    print(f"AKeyless Customer Fragments: {totals.get('akeyless_cf', 0)}")

    print()
    print("=== Totals by domain ===")
    print(
        f"| Domain | Keys | Version objects | 2+ versions | 3+ versions | System | AKeyless CF | Weak | Inactive | {due_lbl} | Exportable | Deletable | CTE | LDT | Standard |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for row in totals.get("by_domain") or []:
        print(
            f"| {row.get('domain')} | {row.get('keys')} | {row.get('version_objects')} | "
            f"{row.get('keys_multi_version')} | {row.get('keys_three_plus')} | {row.get('system')} | "
            f"{row.get('akeyless_cf')} | {row.get('weak')} | {row.get('inactive')} | "
            f"{row.get('about_to_change')} | {row.get('exportable')} | {row.get('deletable')} | "
            f"{row.get('cte')} | {row.get('cte_ldt')} | {row.get('cte_standard')} |"
        )
    if not (totals.get("by_domain") or []):
        print("| (none) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |")

    system_rows = [r for r in catalog if r.get("system")]
    print()
    print(f"=== System keys ({len(system_rows)}) ===")
    if system_rows:
        lines = []
        for r in system_rows[:CHAT_LIST_CAP]:
            kind = r.get("system_kind") or "system"
            svc = f" {r.get('service_name')}" if r.get("service_name") else ""
            lines.append(f"- [{r.get('domain')}] {r.get('name')} ({kind}{svc})")
        print("\n".join(_fmt_list(lines, len(system_rows))))
    else:
        print("none")

    cf_rows = [r for r in catalog if r.get("akeyless_cf")]
    print()
    print(f"=== AKeyless Customer Fragments ({len(cf_rows)}) ===")
    if cf_rows:
        lines = []
        for r in cf_rows[:CHAT_LIST_CAP]:
            lines.append(f"- [{r.get('domain')}] {r.get('name')}")
        print("\n".join(_fmt_list(lines, len(cf_rows))))
    else:
        print("none")

    weak_rows = [r for r in catalog if r.get("weak")]
    print()
    print(f"=== Weak keys ({len(weak_rows)}) ===")
    if weak_rows:
        lines = []
        for r in weak_rows[:CHAT_LIST_CAP]:
            lines.append(
                f"- [{r.get('domain')}] {r.get('name')} — {r.get('weak_reason') or 'weak'}"
            )
        print("\n".join(_fmt_list(lines, len(weak_rows))))
    else:
        print("none")

    cte_rows = [r for r in catalog if r.get("cte")]
    cte_ldt = [r for r in cte_rows if r.get("cte_policy") == "LDT"]
    cte_std = [r for r in cte_rows if r.get("cte_policy") != "LDT"]
    print()
    print(f"=== CTE keys ({len(cte_rows)}) ===")
    if cte_rows:
        print(f"LDT Policy compatible {len(cte_ldt)}. Standard policy compatible {len(cte_std)}.")
        lines = []
        for r in cte_rows[:CHAT_LIST_CAP]:
            policy = r.get("cte_policy") or "Standard"
            mode = r.get("cte_encryption_mode")
            extra = f" · {mode}" if mode else ""
            lines.append(
                f"- [{r.get('domain')}] {r.get('name')} — {policy}{extra}"
            )
        print("\n".join(_fmt_list(lines, len(cte_rows))))
    else:
        print("none")

    life_change = [r for r in catalog if r.get("about_to_change")]
    life_inactive = [r for r in catalog if r.get("inactive")]
    life_old = [
        r
        for r in catalog
        if (r.get("never_rotated") and r.get("older_than_1y")) or r.get("older_than_3y")
    ]
    life_n = sum(1 for r in catalog if is_lifecycle(r))
    print()
    print(f"=== Lifecycle ({life_n}) ===")
    if life_n == 0:
        print("none")
    else:
        print(f"{due_lbl}: {len(life_change)}")
        print(f"Inactive latest version: {len(life_inactive)}")
        print(f"Never rotated / older than 1y: {len(life_old)}")
        notable = []
        seen = set()
        for r in life_change + life_inactive:
            kid = (r.get("domain"), r.get("id") or r.get("name"))
            if kid in seen:
                continue
            seen.add(kid)
            notable.append(r)
        if notable:
            lines = []
            for r in notable[:CHAT_LIST_CAP]:
                why = ", ".join(lifecycle_reasons(r, window)) or "lifecycle"
                lines.append(f"- [{r.get('domain')}] {r.get('name')} — {why}")
            print("\n".join(_fmt_list(lines, len(notable))))
        elif life_old:
            print("Names for never-rotated / old keys are in JSON/HTML.")

    if skipped:
        print()
        print(
            f"Skipped domains: {len(skipped)} (unauthorized or unreachable). "
            "Skipped is not an empty domain."
        )
    if errors:
        print()
        print(f"Domain errors: {len(errors)}")
        for e in errors[:20]:
            print(f"- [{e.get('domain')}] {e.get('error') or e.get('message') or e.get('reason')}")


def write_csv(rows: list[dict[str, Any]], path: str | Path) -> Path:
    out = Path(path)
    if out.suffix.lower() != ".csv":
        out = out.with_suffix(".csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            item = dict(row)
            aliases = item.get("aliases") or []
            item["aliases"] = "|".join(str(a) for a in aliases) if aliases else ""
            labels = item.get("labels")
            item["labels"] = json.dumps(labels, default=str) if labels else ""
            writer.writerow(item)
    return out.resolve()
