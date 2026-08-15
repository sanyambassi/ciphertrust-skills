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
    "owner_name",
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
    if row.get("system") or row.get("akeyless_cf"):
        return False
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
        reasons.append("never rotated and older than 1 year")
    if row.get("older_than_3y"):
        reasons.append("older than 3 years")
    elif row.get("older_than_1y") and not row.get("never_rotated"):
        reasons.append("older than 1 year")
    return reasons


def due_soon_label(window_days: int) -> str:
    n = int(window_days or 30)
    return f"Activate, deactivate, ProtectStop, rotate ({n}d)"


def _count(rows: list[dict[str, Any]], key: str) -> int:
    return sum(1 for r in rows if r.get(key))


def _row_name_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("domain") or ""), str(row.get("name") or row.get("id") or ""))


def _latest_per_name(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        key = _row_name_key(r)
        prev = best.get(key)
        if prev is None or int(r.get("version") or 0) > int(prev.get("version") or 0):
            best[key] = r
    return list(best.values())


def _version_name_buckets(name_counts: Counter) -> dict[str, int]:
    one = two = three = four_plus = 0
    for n in name_counts.values():
        if n <= 1:
            one += 1
        elif n == 2:
            two += 1
        elif n == 3:
            three += 1
        else:
            four_plus += 1
    return {
        "keys_one_version": one,
        "keys_two_versions": two,
        "keys_three_versions": three,
        "keys_four_plus": four_plus,
        "keys_multi_version": two + three + four_plus,
        "keys_three_plus": three + four_plus,
    }


def _empty_domain_slot() -> dict[str, int]:
    return {
        "keys": 0,
        "version_objects": 0,
        "keys_one_version": 0,
        "keys_two_versions": 0,
        "keys_three_versions": 0,
        "keys_four_plus": 0,
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
    }


def build_totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    objects = [r for r in rows if isinstance(r, dict)]
    unique_rows = _latest_per_name(objects)
    name_counts: Counter = Counter(_row_name_key(r) for r in objects)
    by_domain: dict[str, dict[str, int]] = {}
    by_algorithm: Counter = Counter()
    by_state: Counter = Counter()
    by_type: Counter = Counter()
    by_kind: Counter = Counter()

    def slot(domain: str) -> dict[str, int]:
        return by_domain.setdefault(domain, _empty_domain_slot())

    for r in objects:
        domain = str(r.get("domain") or "")
        s = slot(domain)
        s["version_objects"] += 1
        if r.get("system"):
            s["system"] += 1
            by_kind[str(r.get("system_kind") or "system")] += 1
        if r.get("akeyless_cf"):
            s["akeyless_cf"] += 1
        if r.get("weak"):
            s["weak"] += 1
        if r.get("inactive"):
            s["inactive"] += 1
        if r.get("about_to_change"):
            s["about_to_change"] += 1
        if r.get("exportable"):
            s["exportable"] += 1
        if r.get("deletable"):
            s["deletable"] += 1
        if r.get("cte"):
            s["cte"] += 1
            if r.get("cte_policy") == "LDT":
                s["cte_ldt"] += 1
            else:
                s["cte_standard"] += 1
        by_algorithm[str(r.get("algorithm") or "unknown")] += 1
        by_state[str(r.get("state") or "Unknown")] += 1
        by_type[str(r.get("objectType") or "unknown")] += 1

    for r in unique_rows:
        domain = str(r.get("domain") or "")
        s = slot(domain)
        s["keys"] += 1
        nvers = int(name_counts.get(_row_name_key(r), 1) or 1)
        if nvers <= 1:
            s["keys_one_version"] += 1
        elif nvers == 2:
            s["keys_two_versions"] += 1
            s["keys_multi_version"] += 1
        elif nvers == 3:
            s["keys_three_versions"] += 1
            s["keys_multi_version"] += 1
            s["keys_three_plus"] += 1
        else:
            s["keys_four_plus"] += 1
            s["keys_multi_version"] += 1
            s["keys_three_plus"] += 1
    domain_rows = [{"domain": name, **counts} for name, counts in by_domain.items()]
    domain_rows.sort(
        key=lambda d: (-int(d.get("version_objects") or 0), str(d.get("domain")))
    )
    return {
        "keys": len(unique_rows),
        "version_objects": len(objects),
        **_version_name_buckets(name_counts),
        "system": _count(objects, "system"),
        "akeyless_cf": _count(objects, "akeyless_cf"),
        "weak": _count(objects, "weak"),
        "inactive": _count(objects, "inactive"),
        "about_to_change": _count(objects, "about_to_change"),
        "lifecycle": sum(1 for r in objects if is_lifecycle(r)),
        "exportable": _count(objects, "exportable"),
        "deletable": _count(objects, "deletable"),
        "never_exported": _count(objects, "neverExported"),
        "never_exportable": _count(objects, "neverExportable"),
        "cte": _count(objects, "cte"),
        "cte_ldt": sum(1 for r in objects if r.get("cte") and r.get("cte_policy") == "LDT"),
        "cte_standard": sum(
            1 for r in objects if r.get("cte") and r.get("cte_policy") != "LDT"
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
            if r.get("cte") and not r.get("ownerId"):
                r["cte"] = False
                r["cte_versioned"] = None
                r["cte_policy"] = None
                r["cte_encryption_mode"] = None
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
    shown_objects = totals.get("version_objects", len(catalog))
    skipped = domains.get("skipped") or []
    errors = domains.get("errors") or []

    print("Key inventory")
    print(f"CM: {version}    Host: {host}")
    print(
        f"Domains checked: {domains.get('checked_count', 0)}    "
        f"skipped: {domains.get('skipped_count', 0)}"
        + (f"    errors: {domains.get('error_count')}" if domains.get("error_count") else "")
    )
    print(f"Versions: {shown_objects}")
    if collected is not None and collected != shown_objects:
        print(f"Showing {shown_objects} of {collected} versions after filters")
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
    print(f"Akeyless Customer Fragments: {totals.get('akeyless_cf', 0)}")

    print()
    print("=== Totals by domain ===")
    print(
        f"| Domain | Versions | System | Akeyless CF | Weak | Inactive | {due_lbl} | Exportable | Deletable | CTE | LDT | Standard |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for row in totals.get("by_domain") or []:
        print(
            f"| {row.get('domain')} | {row.get('version_objects')} | {row.get('system')} | "
            f"{row.get('akeyless_cf')} | {row.get('weak')} | {row.get('inactive')} | "
            f"{row.get('about_to_change')} | {row.get('exportable')} | {row.get('deletable')} | "
            f"{row.get('cte')} | {row.get('cte_ldt')} | {row.get('cte_standard')} |"
        )
    if not (totals.get("by_domain") or []):
        print("| (none) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |")

    print()
    print("=== Keys and Versions ===")
    print(f"Keys (unique names): {totals.get('keys', 0)}")
    print(f"Versions: {shown_objects}")
    print(f"1 version (ID 0 only): {totals.get('keys_one_version', 0)}")
    print(f"2 versions (IDs 0 and 1): {totals.get('keys_two_versions', 0)}")
    print(f"3 versions (IDs 0, 1, and 2): {totals.get('keys_three_versions', 0)}")
    print(f"3+ versions (ID 3 exists): {totals.get('keys_four_plus', 0)}")
    name_counts: Counter = Counter(_row_name_key(r) for r in catalog)
    multi = [(key, n) for key, n in name_counts.items() if n >= 2]
    multi.sort(key=lambda item: (-item[1], item[0][0], item[0][1]))
    if multi:
        lines = [
            f"- [{domain}] {name} — {n} versions"
            for (domain, name), n in multi[:CHAT_LIST_CAP]
        ]
        print("\n".join(_fmt_list(lines, len(multi))))
    else:
        print("none with 2+ versions")

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
    print(f"=== Akeyless Customer Fragments ({len(cf_rows)}) ===")
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

    life_rows = [r for r in catalog if is_lifecycle(r)]
    life_change = [r for r in life_rows if r.get("about_to_change")]
    life_inactive = [r for r in life_rows if r.get("inactive")]
    life_old = [
        r
        for r in life_rows
        if (r.get("never_rotated") and r.get("older_than_1y")) or r.get("older_than_3y")
    ]
    life_n = len(life_rows)
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
