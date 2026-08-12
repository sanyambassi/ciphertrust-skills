"""Healthcheck orchestration and CLI entrypoint."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cm_client import CmClient, CmError

from .checks.access import check_ldap, check_password_policies
from .checks.appliance import (
    check_banner,
    check_cluster,
    check_diskenc,
    check_ntp,
    check_rot_keys,
    check_services,
)
from .checks.audit import check_audit_records
from .checks.cas import check_cas
from .checks.cte import check_cte
from .checks.interfaces import (
    check_interfaces,
    check_log_forwarders,
    check_notifications,
)
from .checks.inventory import (
    check_clients,
    check_keys_domains,
    check_metrics_keys,
    check_orphaned,
    check_quorum,
)
from .checks.ops import check_alarms, check_backups, check_licensing
from .context import ReportCtx
from .domains import build_domain_walk, check_domains_meta
from .html_report import write_html_report
from .posture import build_posture_table, collect_posture_summary
from .report import print_human, score
from .users import check_users_access
from .util import parse_cm_version, safe_get, section_from_get, summarize_info, summarize_list, summarize_user


def run(
    domain_scope: str = "all",
    keys_mode: str = "both",
    max_keys: int = 2000,
    max_users: int = 500,
    include_cte: bool = True,
) -> dict:
    ctx = ReportCtx()
    report: dict[str, Any] = {
        "timestamp_utc": ctx.now.isoformat(),
        "overall": "UNKNOWN",
        "options": {
            "domain_scope": domain_scope,
            "keys_mode": keys_mode,
            "max_keys": max_keys,
            "max_users": max_users,
            "include_cte": include_cte,
        },
        "sections": ctx.sections,
        "findings": [],
        "summary": {},
    }
    try:
        client = CmClient()
        report["base"] = client.config.base
    except CmError as e:
        report["overall"] = "UNREACHABLE"
        ctx.section("auth", "FAIL", {"error": str(e)}, None)
        report["findings"] = [f.__dict__ for f in ctx.findings]
        return report

    try:
        client.ensure_auth()
        ctx.section("auth", "PASS", {"authenticated": True}, 200)
    except CmError as e:
        ctx.section("auth", "FAIL", {"error": str(e), "body": e.body}, e.status)
        report["overall"] = score(ctx)
        report["findings"] = [f.__dict__ for f in ctx.findings]
        return report

    section_from_get(ctx, client, "identity_self_user", "/v1/auth/self/user", summarize_user)
    section_from_get(ctx, client, "identity_self_domains", "/v1/auth/self/domains", summarize_list)

    info, info_err = safe_get(client, "/v1/system/info")
    cm_version = None
    if info_err:
        ctx.section(
            "system_info", "FAIL", {"error": str(info_err), "body": info_err.body}, info_err.status
        )
    else:
        ctx.section("system_info", "PASS", summarize_info(info), 200)
        if isinstance(info, dict):
            cm_version = info.get("version")
    report["cm_version"] = cm_version
    report["cm_version_parsed"] = (
        list(parse_cm_version(cm_version)) if parse_cm_version(cm_version) else None
    )

    svc, _ = safe_get(client, "/v1/system/services/status")
    if svc is not None:
        check_services(ctx, svc)
    else:
        ctx.section("services_status", "FAIL", {"error": "unavailable"}, None)

    check_cluster(ctx, client)
    check_ntp(ctx, client)
    check_banner(ctx, client)
    check_diskenc(ctx, client)
    check_rot_keys(ctx, client)
    check_licensing(ctx, client)
    check_interfaces(ctx, client)
    check_log_forwarders(ctx, client)
    check_notifications(ctx, client)

    domain_walk = build_domain_walk(client, domain_scope)
    check_backups(ctx, client, domain_scope=domain_scope, domain_walk=domain_walk)
    check_alarms(ctx, client)
    check_cas(ctx, client, domain_scope=domain_scope, domain_walk=domain_walk)
    check_password_policies(ctx, client)
    check_ldap(ctx, client)
    check_domains_meta(ctx, client)
    check_orphaned(ctx, client)
    check_quorum(ctx, client)
    check_clients(ctx, client)
    check_audit_records(ctx, client, cm_version=cm_version)
    if include_cte:
        check_cte(ctx, client)

    if keys_mode in ("metrics", "both"):
        check_metrics_keys(ctx, client)
    else:
        section_from_get(
            ctx,
            client,
            "metrics_status",
            "/v1/system/metrics/prometheus/status",
            lambda d: {"enabled": (d or {}).get("enabled")} if isinstance(d, dict) else d,
        )
    if keys_mode in ("domains", "both"):
        check_keys_domains(
            ctx,
            client,
            domain_scope,
            max_keys=max_keys,
            max_users=max_users,
            domain_walk=domain_walk,
        )
    else:
        try:
            check_users_access(ctx, client, max_users=max_users)
        except CmError as e:
            ctx.section("users_access", "WARN", {"error": str(e)}, e.status)

    report["overall"] = score(ctx)
    seen = set()
    uniq = []
    for f in ctx.findings:
        key = (f.code, f.message)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    ctx.findings = uniq
    report["findings"] = [f.__dict__ for f in ctx.findings]
    posture = collect_posture_summary(ctx.sections)
    posture["table"] = build_posture_table(posture)
    report["posture"] = posture
    report["users"] = posture.get("users") or {}
    report["summary"] = {
        "critical": sum(1 for f in ctx.findings if f.severity == "CRITICAL"),
        "warning": sum(1 for f in ctx.findings if f.severity == "WARNING"),
        "info": sum(1 for f in ctx.findings if f.severity == "INFO"),
        "sections_fail": sum(1 for s in ctx.sections if s["result"] == "FAIL"),
        "sections_warn": sum(1 for s in ctx.sections if s["result"] == "WARN"),
        "users": (report["users"] or {}).get("totals") or {},
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only CipherTrust Manager healthcheck over REST."
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--domain-scope",
        choices=("self", "all"),
        default="all",
        help="Domains to probe for keys/users",
    )
    parser.add_argument(
        "--keys-mode",
        choices=("metrics", "domains", "both", "none"),
        default="both",
        help="Global metrics and/or per-domain vault scan",
    )
    parser.add_argument(
        "--max-keys",
        type=int,
        default=2000,
        help="Max keys to page per accessible domain (weak/inactive scan)",
    )
    parser.add_argument(
        "--max-users",
        type=int,
        default=500,
        help="Max users to scan for access-control hygiene",
    )
    parser.add_argument(
        "--no-cte",
        action="store_true",
        help="Skip CTE client/policy/guardpoint checks",
    )
    parser.add_argument(
        "--html",
        metavar="PATH",
        help="Write a tabbed HTML report with per-area charts (open in a browser; print to PDF)",
    )
    parser.add_argument(
        "--html-from",
        metavar="JSON",
        help="Rebuild HTML from a saved report JSON (no CM calls)",
    )
    args = parser.parse_args(argv)
    if args.html_from:
        report = json.loads(Path(args.html_from).read_text(encoding="utf-8"))
        html_path = write_html_report(report, args.html or "healthcheck-report.html")
        print(f"HTML report: {html_path}")
        return 0
    report = run(
        domain_scope=args.domain_scope,
        keys_mode=args.keys_mode,
        max_keys=args.max_keys,
        max_users=args.max_users,
        include_cte=not args.no_cte,
    )
    if args.html:
        html_path = write_html_report(report, args.html)
        print(f"HTML report: {html_path}")
        cache = Path(__file__).resolve().parents[2] / "reports" / "last-report.json"
        try:
            from .html_report import _redact

            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(
                json.dumps(_redact(report), indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            pass
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_human(report)
    overall = report.get("overall")
    if overall in ("CRITICAL", "UNREACHABLE"):
        return 2
    if overall == "DEGRADED":
        return 1
    return 0
