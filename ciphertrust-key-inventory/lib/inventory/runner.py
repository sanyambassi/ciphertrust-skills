from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from cm_client import CmClient, CmError

from .collect import collect
from .html_report import _redact, write_html_report
from .report import apply_presentation, print_human, write_csv


def run(
    *,
    domain_scope: str = "all",
    domain: str | None = None,
    max_keys: int | None = None,
    window_days: int = 30,
    include_metrics: bool = True,
    include_orphans: bool = True,
    algorithm: str | None = None,
    state: str | None = None,
    weak_only: bool = False,
    inactive_only: bool = False,
    exportable_only: bool = False,
    deletable_only: bool = False,
    about_to_change: bool = False,
    system_only: bool = False,
    exclude_system: bool = False,
    cte_only: bool = False,
) -> dict[str, Any]:
    try:
        client = CmClient()
    except CmError as e:
        return {"ok": False, "error": str(e)}
    try:
        client.ensure_auth()
    except CmError as e:
        return {
            "ok": False,
            "base": client.config.base,
            "error": str(e),
            "status": e.status,
        }
    report = collect(
        client,
        domain_scope=domain_scope,
        only_domain=domain,
        max_keys=max_keys,
        window_days=window_days,
        include_metrics=include_metrics,
        include_orphans=include_orphans,
    )
    return apply_presentation(
        report,
        {
            "algorithm": algorithm,
            "state": state,
            "weak_only": weak_only,
            "inactive_only": inactive_only,
            "exportable_only": exportable_only,
            "deletable_only": deletable_only,
            "about_to_change": about_to_change,
            "system_only": system_only,
            "exclude_system": exclude_system,
            "cte_only": cte_only,
        },
    )


def _default_html_name(domain: str | None) -> str:
    if domain:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", domain.strip()) or "domain"
        return f"key-inventory-{safe}.html"
    return "key-inventory-report.html"


def _cache_report(report: dict[str, Any]) -> None:
    cache = Path(__file__).resolve().parents[2] / "reports" / "last-report.json"
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(
            json.dumps(_redact(report), indent=2, default=str), encoding="utf-8"
        )
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only CipherTrust Manager key inventory over REST."
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--csv",
        metavar="PATH",
        help="Write the catalog as CSV",
    )
    parser.add_argument(
        "--html",
        metavar="PATH",
        help="Write a tabbed HTML report (default: key-inventory-report.html, or key-inventory-<domain>.html with --domain)",
    )
    parser.add_argument(
        "--html-from",
        metavar="JSON",
        help="Rebuild HTML from a saved report JSON (no CM calls)",
    )
    parser.add_argument(
        "--domain-scope",
        choices=("self", "all"),
        default="all",
        help="Domains to inventory",
    )
    parser.add_argument("--domain", metavar="NAME", help="Restrict to one domain")
    parser.add_argument(
        "--max-keys",
        type=int,
        default=None,
        help="Max keys to page per domain (default: no cap)",
    )
    parser.add_argument(
        "--window-days",
        type=int,
        default=30,
        help="Lifecycle window for about-to-change dates (default 30)",
    )
    parser.add_argument("--algorithm", help="Filter catalog to this algorithm")
    parser.add_argument("--state", help="Filter catalog to this state")
    parser.add_argument("--weak-only", action="store_true")
    parser.add_argument("--inactive-only", action="store_true")
    parser.add_argument("--exportable-only", action="store_true")
    parser.add_argument("--deletable-only", action="store_true")
    parser.add_argument(
        "--about-to-change",
        action="store_true",
        help="Keys with activation, deactivation, protect-stop, or rotation due within --window-days",
    )
    parser.add_argument("--system-only", action="store_true")
    parser.add_argument("--exclude-system", action="store_true")
    parser.add_argument("--cte-only", action="store_true")
    parser.add_argument("--no-metrics", action="store_true")
    parser.add_argument("--no-orphans", action="store_true")
    args = parser.parse_args(argv)

    if args.html_from:
        report = json.loads(Path(args.html_from).read_text(encoding="utf-8"))
        report = apply_presentation(report, report.get("filters") or {})
        html_path = write_html_report(report, args.html or "key-inventory-report.html")
        print(f"HTML report: {html_path}")
        return 0

    report = run(
        domain_scope=args.domain_scope,
        domain=args.domain,
        max_keys=args.max_keys,
        window_days=args.window_days,
        include_metrics=not args.no_metrics,
        include_orphans=not args.no_orphans,
        algorithm=args.algorithm,
        state=args.state,
        weak_only=args.weak_only,
        inactive_only=args.inactive_only,
        exportable_only=args.exportable_only,
        deletable_only=args.deletable_only,
        about_to_change=args.about_to_change,
        system_only=args.system_only,
        exclude_system=args.exclude_system,
        cte_only=args.cte_only,
    )
    html_path = write_html_report(report, args.html or _default_html_name(args.domain))
    print(f"HTML report: {html_path}")
    _cache_report(report)
    if args.csv:
        csv_path = write_csv(report.get("catalog") or [], args.csv)
        print(f"CSV catalog: {csv_path}")
    if args.json:
        print(json.dumps(_redact(report), indent=2, default=str))
    else:
        print_human(report)
    if not report.get("ok"):
        return 2
    return 0
