"""Self-contained HTML healthcheck report with per-area tabs and charts.

Never embeds passwords, JWTs, refresh tokens, or Prometheus scrape tokens.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .posture import build_posture_table

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|jwt|authorization|refresh|scrape)",
    re.IGNORECASE,
)
_MD_FAIL = re.compile(r"\*\*\*(.+?)\*\*\*")
_MD_BOLD = re.compile(r"\*\*(.+?)\*\*")

# Finding code prefix -> posture tab (first match wins; longest prefixes first).
_CODE_TAB = (
    ("rot_key", "RoT"),
    ("diskenc_", "Appliance"),
    ("ntp_", "Appliance"),
    ("cluster_", "Appliance"),
    ("svc_", "Appliance"),
    ("banner_", "Appliance"),
    ("smtp_", "Interfaces"),
    ("notification_", "Interfaces"),
    ("backup_", "Backups"),
    ("alarms_", "Alarms"),
    ("feature_", "Licenses"),
    ("license_", "Licenses"),
    ("net_", "Interfaces"),
    ("access_users_", "Users"),
    ("access_pwd_", "Access"),
    ("access_ldap_", "Access"),
    ("keys_orphaned", "Orphaned"),
    ("keys_", "Keys"),
    ("quorum_", "Quorum"),
    ("cte_", "CTE"),
    ("records_", "Audit"),
    ("domain_", "Access"),
    ("metrics_", "Keys"),
    ("ca_", "CAs"),
)

_AREA_TAB = {
    "interfaces": "Interfaces",
    "licensing": "Licenses",
    "ca": "CAs",
    "cte": "CTE",
    "records": "Audit",
    "access": "Access",
    "keys": "Keys",
    "quorum": "Quorum",
    "system": "Appliance",
    "domains": "Access",
}

_SECTION_TAB = {
    "auth": "Appliance",
    "identity_self_user": "Users",
    "identity_self_domains": "Access",
    "system_info": "Appliance",
    "services_status": "Appliance",
    "cluster": "Appliance",
    "cluster_summary": "Appliance",
    "cluster_errors": "Appliance",
    "nodes": "Appliance",
    "ntp": "Appliance",
    "banner_pre_auth": "Appliance",
    "disk_encryption": "Appliance",
    "rot_keys": "RoT",
    "licensing_features": "Licenses",
    "licensing_licenses": "Licenses",
    "interfaces": "Interfaces",
    "log_forwarders": "Interfaces",
    "notifications": "Interfaces",
    "backup_status": "Backups",
    "backup_keys": "Backups",
    "backups_list": "Backups",
    "backup_scheduler": "Backups",
    "alarms": "Alarms",
    "ca_trusted": "CAs",
    "ca_local": "CAs",
    "ca_external": "CAs",
    "password_policies": "Access",
    "ldap_connections": "Access",
    "domains": "Access",
    "orphaned_resources": "Orphaned",
    "quorum_policies": "Quorum",
    "registered_clients": "Clients",
    "audit_records": "Audit",
    "cte_clients": "CTE",
    "cte_policies": "CTE",
    "metrics_status": "Keys",
    "keys_metrics": "Keys",
    "keys_domains": "Keys",
    "users_access": "Users",
}

_PAL = {
    "crit": "#b42318",
    "warn": "#c47d00",
    "info": "#175cd3",
    "pass": "#1b7f4e",
    "fail": "#b42318",
    "muted": "#8b949e",
}


def write_html_report(report: dict[str, Any], path: str | Path) -> Path:
    """Write a full HTML report. Returns the resolved path."""
    out = Path(path)
    if out.suffix.lower() != ".html":
        out = out.with_suffix(".html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(report), encoding="utf-8")
    return out.resolve()


def render_html(report: dict[str, Any]) -> str:
    overall = str(report.get("overall") or "UNKNOWN")
    base = str(report.get("base") or "")
    host = _host(base)
    version = str(report.get("cm_version") or "n/a")
    ts = str(report.get("timestamp_utc") or "")
    summary = report.get("summary") or {}
    posture = report.get("posture") or {}
    table = build_posture_table(posture)
    if not table:
        table = [r for r in (posture.get("table") or []) if isinstance(r, dict)]
    findings = [f for f in (report.get("findings") or []) if isinstance(f, dict)]
    sections = [s for s in (report.get("sections") or []) if isinstance(s, dict)]

    by_tab: dict[str, list[dict]] = {row.get("area"): [] for row in table if row.get("area")}
    by_tab.setdefault("Overview", [])
    unmatched: list[dict] = []
    for f in findings:
        tab = _finding_tab(f)
        if tab in by_tab:
            by_tab[tab].append(f)
        else:
            unmatched.append(f)
    by_tab["Overview"].extend(unmatched)

    charts = _tab_charts(report, table)
    charts_json = json.dumps(charts, default=str).replace("<", "\\u003c")

    sorted_rows = _sort_area_rows(table)
    nav_parts = [
        "<div class='nav-label'>Report</div>",
        _tab_button(
            "overview",
            "Overview",
            overall if overall in ("OK", "DEGRADED", "CRITICAL", "UNREACHABLE") else "WARN",
            result_label=overall,
        ),
    ]
    panels = [_overview_panel(report, sorted_rows, summary, by_tab, charts.get("overview") or [])]

    last_tone = None
    group_label = {"FAIL": "Fail", "WARN": "Warn", "PASS": "Pass", "MUTED": "Other"}
    for row in sorted_rows:
        area = str(row.get("area") or "")
        slug = _slug(area)
        result = _strip_result_md(row.get("result"))
        tone = _tab_tone(result)
        if tone != last_tone:
            nav_parts.append(f"<div class='nav-label'>{group_label.get(tone, tone)}</div>")
            last_tone = tone
        nav_parts.append(_tab_button(slug, area, result))
        panels.append(_area_panel(slug, row, by_tab.get(area) or [], charts.get(slug) or [], posture, sections))

    nav_parts.append("<div class='nav-label'>More</div>")
    nav_parts.append(_tab_button("raw", "Raw checks", "MUTED", result_label="JSON"))
    panels.append(_raw_panel(sections))

    return (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='utf-8'/>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'/>\n"
        f"<title>CipherTrust Manager healthcheck — {esc(overall)} — {esc(host)}</title>\n"
        "<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'></script>\n"
        f"<style>{_CSS}</style>\n</head>\n<body>\n"
        "<header>\n"
        "  <div class='head-top'><h1>CipherTrust Manager healthcheck</h1>\n"
        f"  <span class='badge {esc(overall)}'>{esc(overall)}</span></div>\n"
        "  <p class='meta'>\n"
        f"    CM {esc(version)} · {esc(host)} · {esc(ts)}\n"
        "  </p>\n"
        "</header>\n"
        "<div class='wrap'>\n"
        "<div class='layout'>\n"
        f"<nav class='tab-bar' role='tablist'>{''.join(nav_parts)}</nav>\n"
        "<main class='main'>\n"
        f"{''.join(panels)}\n"
        "<footer>CipherTrust Manager healthcheck</footer>\n"
        "</main>\n"
        "</div>\n"
        "</div>\n"
        f"<script>const DATA = {charts_json};\n{_JS}</script>\n"
        "</body>\n</html>\n"
    )


def _host(base: str) -> str:
    try:
        return urlparse(base).hostname or base or "n/a"
    except Exception:
        return base or "n/a"


def esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _md(text: Any) -> str:
    s = html.escape(str(text or ""))
    s = s.replace("&lt;br&gt;", "<br>").replace("&lt;br/&gt;", "<br>")
    s = _MD_FAIL.sub(r'<strong class="fail">\1</strong>', s)
    return _MD_BOLD.sub(r'<strong class="warn">\1</strong>', s)


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(name or "").lower()).strip("-")
    return s or "area"


def _strip_result_md(result: Any) -> str:
    return str(result or "").replace("**", "").strip()


def _n(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _finding_tab(finding: dict) -> str:
    code = str(finding.get("code") or "")
    for prefix, tab in _CODE_TAB:
        if code.startswith(prefix):
            return tab
    return _AREA_TAB.get(str(finding.get("area") or ""), "Overview")


def _tab_tone(result: str) -> str:
    r = (result or "").upper()
    if r in ("FAIL", "CRITICAL", "UNREACHABLE"):
        return "FAIL"
    if r in ("WARN", "WARNING", "DEGRADED"):
        return "WARN"
    if r in ("PASS", "OK"):
        return "PASS"
    return "MUTED"


def _sort_area_rows(table: list[dict]) -> list[dict]:
    rank = {"FAIL": 0, "WARN": 1, "PASS": 2, "MUTED": 3}
    return sorted(
        table,
        key=lambda r: (
            rank.get(_tab_tone(_strip_result_md(r.get("result"))), 9),
            str(r.get("area") or ""),
        ),
    )


def _tab_button(
    slug: str,
    label: str,
    result: str,
    result_label: str | None = None,
) -> str:
    tone = _tab_tone(result)
    shown = result_label or result
    return (
        f"<button type='button' class='tab-btn {tone}' role='tab' "
        f"id='tab-{esc(slug)}' data-tab='{esc(slug)}'>"
        f"<span class='name'>{esc(label)}</span>"
        f"<span class='st {tone}'>{esc(shown)}</span></button>"
    )


def _kpi(label: str, n: Any, cls: str) -> str:
    return (
        f"<div class='kpi {esc(cls)}'><div class='n'>{esc(n)}</div>"
        f"<div class='l'>{esc(label)}</div></div>"
    )


def _chart_box(cfg: dict) -> str:
    cid = esc(cfg.get("id"))
    height = _n(cfg.get("height")) or 220
    cap = str(cfg.get("caption") or "").strip()
    cap_html = f"<p class='caption'>{esc(cap)}</p>" if cap else ""
    return (
        f"<div class='chart-box' id='box-{cid}'>"
        f"<h3>{esc(cfg.get('title'))}</h3>"
        f"{cap_html}"
        f"<div class='chart-frame' style='height:{height}px'>"
        f"<canvas id='{cid}'></canvas></div></div>"
    )


def _findings_lists(items: list[dict], *, collapse_info: bool = True) -> str:
    crit = [f for f in items if f.get("severity") == "CRITICAL"]
    warn = [f for f in items if f.get("severity") == "WARNING"]
    info = [f for f in items if f.get("severity") == "INFO"]
    parts = [
        _findings_block("CRITICAL", crit, "crit-list"),
        _findings_block("WARNING", warn, "warn-list"),
    ]
    info_html = _findings_block("INFO", info, "info-list")
    if collapse_info and len(info) > 4:
        parts.append(
            f"<details class='info-fold'><summary>INFO findings ({len(info)})</summary>"
            f"{info_html}</details>"
        )
    else:
        parts.append(info_html)
    return "".join(parts)


def _findings_block(title: str, items: list[dict], cls: str) -> str:
    if not items:
        return ""
    lis = []
    for f in items:
        lis.append(f"<li>{_md(f.get('message'))}</li>")
    return (
        f"<div class='card {cls}'><h3>{esc(title)} ({len(items)})</h3>"
        f"<ul class='findings'>{''.join(lis)}</ul></div>"
    )


def _status_pills(items: list[dict]) -> str:
    crit = sum(1 for f in items if f.get("severity") == "CRITICAL")
    warn = sum(1 for f in items if f.get("severity") == "WARNING")
    info = sum(1 for f in items if f.get("severity") == "INFO")
    pills = []
    if crit:
        pills.append(f"<span class='pill crit'>{crit} critical</span>")
    if warn:
        pills.append(f"<span class='pill warn'>{warn} warning</span>")
    if info:
        pills.append(f"<span class='pill info'>{info} info</span>")
    if not pills:
        pills.append("<span class='pill'>no findings</span>")
    return f"<div class='status-pills'>{''.join(pills)}</div>"


def _overview_panel(
    report: dict,
    table: list[dict],
    summary: dict,
    by_tab: dict[str, list[dict]],
    overview_charts: list[dict],
) -> str:
    cards = []
    for row in table:
        area = str(row.get("area") or "")
        result = _strip_result_md(row.get("result"))
        tone = _tab_tone(result)
        items = by_tab.get(area) or []
        crit = sum(1 for f in items if f.get("severity") == "CRITICAL")
        warn = sum(1 for f in items if f.get("severity") == "WARNING")
        counts = []
        if crit:
            counts.append(f"{crit} crit")
        if warn:
            counts.append(f"{warn} warn")
        extra = f"<span class='sub'>{esc(' · '.join(counts))}</span>" if counts else ""
        cards.append(
            f"<button type='button' class='area-card {tone}' data-jump='{_slug(area)}'>"
            f"<span class='area-name'>{esc(area)}</span>"
            f"<span class='st {tone}'>{esc(result)}</span>{extra}</button>"
        )
    chart_html = "".join(_chart_box(c) for c in overview_charts)
    return (
        "<section class='tab-panel' id='panel-overview' role='tabpanel'>"
        "<div class='kpis'>"
        f"{_kpi('Critical', summary.get('critical', 0), 'crit')}"
        f"{_kpi('Warning', summary.get('warning', 0), 'warn')}"
        f"{_kpi('Info', summary.get('info', 0), 'info')}"
        f"{_kpi('Sections FAIL', summary.get('sections_fail', 0), '')}"
        f"{_kpi('Sections WARN', summary.get('sections_warn', 0), '')}"
        f"{_kpi('Checks', len(report.get('sections') or []), '')}"
        "</div>"
        f"<div class='charts'>{chart_html}</div>"
        "<h2>Areas</h2>"
        f"<div class='area-grid'>{''.join(cards)}</div>"
        "</section>"
    )


def _area_panel(
    slug: str,
    row: dict,
    items: list[dict],
    charts: list[dict],
    posture: dict,
    sections: list[dict],
) -> str:
    area = str(row.get("area") or "")
    result = _strip_result_md(row.get("result"))
    tone = _tab_tone(result)
    extra = _area_extras(area, posture, sections)
    chart_html = "".join(_chart_box(c) for c in charts)
    related = [
        s
        for s in sections
        if _SECTION_TAB.get(str(s.get("name") or "")) == area
    ]
    return (
        f"<section class='tab-panel' id='panel-{esc(slug)}' role='tabpanel' hidden>"
        f"<div class='panel-head'>"
        f"<div class='head-row'><h2>{esc(area)}</h2>"
        f"<span class='st {tone}'>{esc(result)}</span></div>"
        f"{_status_pills(items)}"
        f"<div class='summary'>{_md(row.get('summary'))}</div>"
        "</div>"
        f"<div class='charts'>{chart_html}</div>"
        f"{extra}"
        f"{_findings_lists(items)}"
        f"{_related_sections(related)}"
        "</section>"
    )


def _raw_panel(sections: list[dict]) -> str:
    return (
        "<section class='tab-panel' id='panel-raw' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Raw checks</h2></div></div>"
        f"{_sections_html(sections)}"
        "</section>"
    )


def _related_sections(sections: list[dict]) -> str:
    if not sections:
        return ""
    return (
        "<details class='raw-fold'><summary>Details "
        f"({len(sections)})</summary>{_sections_html(sections)}</details>"
    )


def _area_extras(area: str, posture: dict, sections: list[dict]) -> str:
    if area == "Users":
        return _users_table(posture)
    if area == "Keys":
        return _keys_table(posture)
    if area == "Backups":
        return _backups_table(posture)
    if area == "CAs":
        return _cas_table(posture)
    if area == "Interfaces":
        return _interfaces_table(sections)
    if area == "CTE":
        return _cte_table(sections)
    if area == "RoT":
        return _rot_table(sections)
    if area == "Licenses":
        return _licenses_table(sections)
    if area == "Alarms":
        return _alarms_table(sections)
    return ""


def _table(headers: list[str], rows: list[str], title: str) -> str:
    if not rows:
        return ""
    th = "".join(f"<th>{h}</th>" for h in headers)
    return (
        f"<div class='card'><h3>{esc(title)}</h3>"
        f"<div class='table-wrap'><table><thead><tr>{th}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></div>"
    )


def _users_table(posture: dict) -> str:
    rows = []
    for d in (posture.get("users") or {}).get("by_domain") or []:
        if not isinstance(d, dict):
            continue
        top = d.get("top_by_logins") or []
        top_s = ", ".join(
            f"{t.get('username')}({t.get('logins_count')})"
            for t in top
            if isinstance(t, dict)
        )
        rows.append(
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td><td>{esc(d.get('total'))}</td>"
            f"<td>{esc(d.get('locked'))}</td><td>{esc(d.get('never_logged_in'))}</td>"
            f"<td>{esc(d.get('inactive_30d'))}</td>"
            f"<td>{esc(d.get('failed_logins_not_locked'))}</td>"
            f"<td>{esc(top_s)}</td></tr>"
        )
    return _table(
        ["Domain", "Users", "Locked", "Never login", "Inactive >30d", "Failed logins", "Top logins"],
        rows,
        "Users by domain",
    )


def _keys_table(posture: dict) -> str:
    rows_data = [
        d
        for d in ((posture.get("keys") or {}).get("domains") or {}).get("by_domain") or []
        if isinstance(d, dict)
    ]
    if not rows_data:
        return ""
    max_total = max((_n(d.get("total")) for d in rows_data), default=0) or 1
    rows = []
    for d in rows_data:
        total = _n(d.get("total"))
        weak = _n(d.get("weak"))
        inactive = _n(d.get("non_active"))
        pct = min(100, round(100 * total / max_total))
        weak_cls = "fail" if weak else "ok"
        ina_cls = "warn" if inactive else "ok"
        rows.append(
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td>"
            "<td><div class='meter-wrap'>"
            f"<div class='meter' title='{esc(total)} keys'>"
            f"<span class='meter-fill' style='width:{pct}%'></span></div>"
            f"<span class='meter-n'>{esc(total)}</span></div></td>"
            f"<td>{esc(d.get('unique'))}</td>"
            f"<td><span class='badge-n {weak_cls}'>{esc(weak)}</span></td>"
            f"<td><span class='badge-n {ina_cls}'>{esc(inactive)}</span></td>"
            "</tr>"
        )
    return (
        "<div class='card'><h3>Keys by domain</h3>"
        "<div class='table-wrap'><table><thead><tr>"
        "<th>Domain</th><th>Total</th><th>Unique</th><th>Weak</th><th>Inactive</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div></div>"
    )


def _domain_status_rows(
    items: list[Any], cells_ok, empty_cols: int = 3
) -> tuple[list[str], list[str]]:
    ok_rows: list[str] = []
    skipped: list[str] = []
    blanks = "<td></td>" * empty_cols
    for d in items:
        if not isinstance(d, dict):
            continue
        if d.get("skipped") or d.get("error"):
            reason = d.get("reason") or d.get("error") or "n/a"
            skipped.append(
                "<tr>"
                f"<td>{esc(d.get('domain'))}</td>"
                f"<td>skipped ({esc(reason)}; {esc(d.get('status'))})</td>"
                f"{blanks}</tr>"
            )
        else:
            ok_rows.append(cells_ok(d))
    return ok_rows, skipped


def _skipped_fold(rows: list[str], headers: list[str], title: str) -> str:
    if not rows:
        return ""
    th = "".join(f"<th>{h}</th>" for h in headers)
    return (
        f"<details class='info-fold'><summary>{esc(title)} ({len(rows)})</summary>"
        f"<div class='card'><div class='table-wrap'><table><thead><tr>{th}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></div></details>"
    )


def _backups_table(posture: dict) -> str:
    def cells(d: dict) -> str:
        return (
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td><td>ok</td>"
            f"<td>{esc(d.get('total'))}</td>"
            f"<td>{esc(d.get('system_count'))}</td>"
            f"<td>{esc(d.get('domain_count'))}</td></tr>"
        )

    headers = ["Domain", "Status", "Total", "System", "Domain-scoped"]
    ok_rows, skipped = _domain_status_rows(
        (posture.get("backups") or {}).get("by_domain") or [], cells
    )
    return _table(headers, ok_rows, "Backups by domain") + _skipped_fold(
        skipped, headers, "Domains skipped (unauthorized)"
    )


def _cas_table(posture: dict) -> str:
    def cells(d: dict) -> str:
        loc = d.get("local") if isinstance(d.get("local"), dict) else {}
        ext = d.get("external") if isinstance(d.get("external"), dict) else {}
        return (
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td><td>ok</td>"
            f"<td>{esc(loc.get('total'))}</td><td>{esc(loc.get('expired'))}</td>"
            f"<td>{esc(ext.get('total'))}</td><td>{esc(ext.get('expired'))}</td></tr>"
        )

    headers = ["Domain", "Status", "Local", "Local expired", "External", "External expired"]
    ok_rows, skipped = _domain_status_rows(
        (posture.get("certificates") or {}).get("by_domain") or [], cells, empty_cols=4
    )
    return _table(headers, ok_rows, "CAs by domain") + _skipped_fold(
        skipped, headers, "Domains skipped (unauthorized)"
    )


def _sec_detail(sections: list[dict], name: str) -> dict:
    for s in sections:
        if s.get("name") == name and isinstance(s.get("detail"), dict):
            return s["detail"]
    return {}


def _interfaces_table(sections: list[dict]) -> str:
    detail = _sec_detail(sections, "interfaces")
    rows = []
    for i in detail.get("interfaces") or []:
        if not isinstance(i, dict):
            continue
        days = i.get("cert_days_left")
        if days is None:
            cert = "n/a"
        elif _n(days) < 0:
            cert = f"expired ({i.get('cert_notAfter')})"
        else:
            cert = f"{days}d ({i.get('cert_notAfter')})"
        rows.append(
            "<tr>"
            f"<td>{esc(i.get('name'))}</td>"
            f"<td>{esc(i.get('interface_type'))}</td>"
            f"<td>{esc(i.get('port'))}</td>"
            f"<td>{esc(i.get('mode_label') or i.get('mode'))}</td>"
            f"<td>{esc(i.get('minimum_tls_version'))}</td>"
            f"<td>{esc(cert)}</td></tr>"
        )
    return _table(
        ["Name", "Type", "Port", "Mode", "Min TLS", "Leaf cert"],
        rows,
        "Interfaces",
    )


def _cte_table(sections: list[dict]) -> str:
    detail = _sec_detail(sections, "cte_clients")
    rows = []
    seen = set()
    for key in ("disconnected", "unregistered_or_offline"):
        for c in detail.get(key) or []:
            if not isinstance(c, dict):
                continue
            name = c.get("name")
            if name in seen:
                continue
            seen.add(name)
            rows.append(
                "<tr>"
                f"<td>{esc(name)}</td>"
                f"<td>{esc(c.get('client_health_status'))}</td>"
                f"<td>{esc(c.get('communication_enabled'))}</td></tr>"
            )
    gp_rows = []
    for g in detail.get("guardpoints_not_active") or []:
        if not isinstance(g, dict):
            continue
        gp_rows.append(
            "<tr>"
            f"<td>{esc(g.get('client'))}</td>"
            f"<td>{esc(g.get('guard_path'))}</td>"
            f"<td>{esc(g.get('guard_point_state'))}</td></tr>"
        )
    return _table(
        ["Client", "Health", "Communication"],
        rows,
        "CTE clients needing attention",
    ) + _table(
        ["Client", "GuardPoint path", "State"],
        gp_rows,
        "GuardPoints not active",
    )


def _rot_table(sections: list[dict]) -> str:
    detail = _sec_detail(sections, "rot_keys")
    rows = []
    for k in detail.get("keys") or []:
        if not isinstance(k, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{esc(k.get('id'))}</td>"
            f"<td>{esc(k.get('createdAt'))}</td>"
            f"<td>{esc(k.get('age_label') or k.get('age_years'))}</td></tr>"
        )
    return _table(["Key", "Created", "Age"], rows, "Root-of-trust keys")


def _licenses_table(sections: list[dict]) -> str:
    feat = _sec_detail(sections, "licensing_features")
    rows = []
    for t in feat.get("trials_expiring_soon") or []:
        if not isinstance(t, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{esc(t.get('name'))}</td>"
            f"<td>{esc(t.get('trial_days_remaining'))}</td></tr>"
        )
    return _table(["Feature", "Trial days remaining"], rows, "Trials expiring within 30 days")


def _alarms_table(sections: list[dict]) -> str:
    detail = _sec_detail(sections, "alarms")
    by_name = detail.get("active_by_name") or {}
    rows = [
        f"<tr><td>{esc(name)}</td><td>{esc(count)}</td></tr>"
        for name, count in list(by_name.items())[:20]
    ]
    sample = detail.get("critical_sample") or []
    srows = []
    for a in sample:
        if not isinstance(a, dict):
            continue
        srows.append(
            "<tr>"
            f"<td>{esc(a.get('name'))}</td>"
            f"<td>{esc(a.get('severity'))}</td>"
            f"<td>{esc(a.get('description'))}</td></tr>"
        )
    return _table(["Alarm", "Active count"], rows, "Active alarms by name") + _table(
        ["Name", "Severity", "Description"],
        srows,
        "Critical alarms",
    )


def _sections_html(sections: list[dict]) -> str:
    blocks = []
    for s in sections:
        name = s.get("name") or "section"
        result = str(s.get("result") or "")
        status = s.get("status")
        tone = _tab_tone(result)
        body = esc(json.dumps(_redact(s.get("detail")), indent=2, default=str))
        open_attr = " open" if result in ("FAIL", "WARN") else ""
        blocks.append(
            f"<details class='section'{open_attr}>"
            f"<summary><span class='st {esc(tone)}'>{esc(result or 'n/a')}</span> "
            f"{esc(name)} · HTTP {esc(status)}</summary>"
            f"<div class='sec-body'><pre>{body}</pre></div></details>"
        )
    return "\n".join(blocks)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if _SECRET_KEY_RE.search(str(k)):
                out[k] = "[redacted]"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(value, list):
        return [_redact(x) for x in value]
    return value


def _doughnut(slug: str, title: str, caption: str, pairs: list[tuple[str, Any, str]], center_sub: str) -> dict | None:
    labels, values, colors = [], [], []
    for label, val, color in pairs:
        n = _n(val)
        if n <= 0:
            continue
        labels.append(f"{label}  {n}")
        values.append(n)
        colors.append(color)
    if not values:
        return None
    return {
        "id": f"ch-{slug}",
        "type": "doughnut",
        "title": title,
        "caption": caption,
        "labels": labels,
        "values": values,
        "colors": colors,
        "center": sum(values),
        "centerSub": center_sub,
    }


def _barh(
    slug: str,
    title: str,
    caption: str,
    labels: list[str],
    values: list[int],
    color: str,
    colors: list[str] | None = None,
) -> dict | None:
    kept: list[tuple[str, int, str]] = []
    for i, (label, val) in enumerate(zip(labels, values)):
        n = _n(val)
        if n <= 0:
            continue
        col = colors[i] if colors and i < len(colors) else color
        kept.append((str(label), n, col))
    if not kept:
        return None
    return {
        "id": f"ch-{slug}",
        "type": "bar",
        "title": title,
        "caption": caption,
        "labels": [p[0] for p in kept],
        "values": [p[1] for p in kept],
        "colors": [p[2] for p in kept],
        "height": max(180, 44 * len(kept) + 28),
    }


def _tab_charts(report: dict, table: list[dict]) -> dict[str, list[dict]]:
    summary = report.get("summary") or {}
    posture = report.get("posture") or {}
    app = posture.get("appliance") or {}
    alarms = posture.get("alarms") or {}
    net = posture.get("network") or {}
    certs = posture.get("certificates") or {}
    keys = posture.get("keys") or {}
    users = (posture.get("users") or {}).get("totals") or {}
    cte = posture.get("cte") or {}
    audit = posture.get("audit") or {}
    lic = posture.get("licensing") or {}
    backups = posture.get("backups") or {}
    sev = alarms.get("active_by_severity") or {}
    deks = (keys.get("metrics") or {}).get("deks_by_state") or {}
    kd = keys.get("domains") or {}
    loc = certs.get("local") or {}
    ext = certs.get("external") or {}
    tru = certs.get("trusted") or {}
    sc = audit.get("server_counts") or {}
    cc = audit.get("client_counts") or {}

    by_name = {}
    for s in report.get("sections") or []:
        if isinstance(s, dict) and s.get("name") == "alarms":
            by_name = (s.get("detail") or {}).get("active_by_name") or {}
            break

    cte_total = _n(cte.get("clients_total"))
    cte_disc = _n(cte.get("disconnected"))
    cte_unreg = _n(cte.get("unregistered_or_offline"))
    cte_ok = max(cte_total - cte_disc - cte_unreg, 0)

    rot_labels, rot_vals = [], []
    for s in report.get("sections") or []:
        if isinstance(s, dict) and s.get("name") == "rot_keys":
            for k in (s.get("detail") or {}).get("keys") or []:
                if isinstance(k, dict):
                    rot_labels.append(str(k.get("id") or "RoT"))
                    rot_vals.append(_n(round(float(k.get("age_years") or 0))))
            break

    out: dict[str, list[dict]] = {}

    def add(slug: str, cfg: dict | None) -> None:
        if cfg:
            out.setdefault(slug, []).append(cfg)

    add(
        "overview",
        _doughnut(
            "overview-findings",
            "Findings by severity",
            "",
            [
                ("CRITICAL", summary.get("critical"), _PAL["crit"]),
                ("WARNING", summary.get("warning"), _PAL["warn"]),
                ("INFO", summary.get("info"), _PAL["info"]),
            ],
            "findings",
        ),
    )
    area_fail = area_warn = area_pass = 0
    for row in table:
        if not isinstance(row, dict):
            continue
        r = _strip_result_md(row.get("result")).upper()
        if r in ("FAIL", "CRITICAL"):
            area_fail += 1
        elif r in ("WARN", "WARNING"):
            area_warn += 1
        elif r in ("PASS", "OK"):
            area_pass += 1
    add(
        "overview",
        _doughnut(
            "overview-areas",
            "Posture areas by result",
            "",
            [
                ("FAIL", area_fail, _PAL["fail"]),
                ("WARN", area_warn, _PAL["warn"]),
                ("PASS", area_pass, _PAL["pass"]),
            ],
            "areas",
        ),
    )
    add(
        _slug("Appliance"),
        _doughnut(
            "appliance-svc",
            "Services",
            "",
            [
                ("Started", app.get("services_started"), _PAL["pass"]),
                ("Disabled", app.get("services_disabled"), _PAL["muted"]),
                ("Down", app.get("services_not_started"), _PAL["fail"]),
            ],
            "services",
        ),
    )
    add(
        _slug("RoT"),
        _barh(
            "rot-age",
            "Root-of-trust age (years)",
            "",
            rot_labels,
            rot_vals,
            _PAL["fail"] if any(v >= 1 for v in rot_vals) else _PAL["pass"],
        ),
    )
    trials = _n(lic.get("trials_expiring_soon"))
    expired = _n(lic.get("expired"))
    active = _n(lic.get("active"))
    add(
        _slug("Licenses"),
        _doughnut(
            "licenses",
            "Active licenses",
            "",
            [
                ("OK", max(active - trials - expired, 0), _PAL["pass"]),
                ("Trial ≤30d", trials, _PAL["warn"]),
                ("Expired", expired, _PAL["fail"]),
            ],
            "active",
        ),
    )
    add(
        _slug("Alarms"),
        _doughnut(
            "alarms-sev",
            "Active alarms by severity",
            "",
            [
                ("Critical", alarms.get("critical_active") or sev.get("critical"), _PAL["crit"]),
                ("Error", sev.get("error"), _PAL["fail"]),
                ("Warning", alarms.get("warning_active") or sev.get("warning"), _PAL["warn"]),
                ("Info", alarms.get("info_active") or sev.get("info"), _PAL["info"]),
            ],
            "active",
        ),
    )
    anames = list(by_name.keys())[:8]
    add(
        _slug("Alarms"),
        _barh(
            "alarms-names",
            "Top active alarms",
            "",
            [str(n)[:40] for n in anames],
            [_n(by_name.get(n)) for n in anames],
            _PAL["warn"],
        ),
    )
    add(
        _slug("Interfaces"),
        _doughnut(
            "ifaces-certs",
            "Interface TLS certificates",
            "",
            [
                ("Expired", net.get("tls_certs_expired"), _PAL["fail"]),
                ("≤30 days", net.get("tls_certs_expiring_soon"), _PAL["warn"]),
                ("Valid", net.get("tls_certs_ok"), _PAL["pass"]),
            ],
            "certs",
        ),
    )
    add(
        _slug("CAs"),
        _doughnut(
            "cas",
            "Certificate authorities",
            "",
            [
                (
                    "Expired",
                    _n(loc.get("expired")) + _n(ext.get("expired")) + _n(tru.get("expired")),
                    _PAL["fail"],
                ),
                (
                    "≤30 days",
                    _n(loc.get("expiring_soon"))
                    + _n(ext.get("expiring_soon"))
                    + _n(tru.get("expiring_soon")),
                    _PAL["warn"],
                ),
                (
                    "Valid",
                    _n(loc.get("ok")) + _n(ext.get("ok")) + _n(tru.get("ok")),
                    _PAL["pass"],
                ),
            ],
            "CAs",
        ),
    )
    add(
        _slug("Backups"),
        _doughnut(
            "backups",
            "Backups",
            "",
            [
                ("System", backups.get("system_count"), _PAL["info"]),
                ("Domain-scoped", backups.get("domain_count"), _PAL["pass"]),
            ],
            "backups",
        ),
    )
    add(
        _slug("Users"),
        _barh(
            "users",
            "Users",
            "",
            ["Locked", "Never logged in", "Inactive >30d", "Failed logins"],
            [
                _n(users.get("locked")),
                _n(users.get("never_logged_in")),
                _n(users.get("inactive_30d")),
                _n(users.get("failed_logins_not_locked")),
            ],
            _PAL["warn"],
            colors=[_PAL["fail"], _PAL["warn"], _PAL["warn"], _PAL["info"]],
        ),
    )
    dek_pairs = [(str(k), v, None) for k, v in deks.items()]
    dek_colors = {
        "Active": _PAL["pass"],
        "Pre-Active": _PAL["info"],
        "Deactivated": _PAL["warn"],
        "Destroyed": _PAL["muted"],
        "Compromised": _PAL["fail"],
    }
    add(
        _slug("Keys"),
        _doughnut(
            "deks",
            "DEKs by state",
            "",
            [(k, v, dek_colors.get(k, _PAL["muted"])) for k, v, _ in dek_pairs],
            "DEKs",
        ),
    )
    krows = [d for d in (kd.get("by_domain") or []) if isinstance(d, dict)]
    add(
        _slug("Keys"),
        _barh(
            "keys-totals",
            "Keys by domain",
            "",
            [str(d.get("domain") or "") for d in krows],
            [_n(d.get("total")) for d in krows],
            _PAL["info"],
        ),
    )
    issue_labels: list[str] = []
    issue_vals: list[int] = []
    issue_cols: list[str] = []
    for d in krows:
        name = str(d.get("domain") or "")
        weak_n = _n(d.get("weak"))
        ina_n = _n(d.get("non_active"))
        if weak_n:
            issue_labels.append(f"{name} — weak")
            issue_vals.append(weak_n)
            issue_cols.append(_PAL["fail"])
        if ina_n:
            issue_labels.append(f"{name} — inactive")
            issue_vals.append(ina_n)
            issue_cols.append(_PAL["warn"])
    add(
        _slug("Keys"),
        _barh(
            "keys-issues",
            "Weak and inactive keys",
            "",
            issue_labels,
            issue_vals,
            _PAL["fail"],
            colors=issue_cols,
        ),
    )
    add(
        _slug("CTE"),
        _doughnut(
            "cte-clients",
            "CTE client health",
            "",
            [
                ("Healthy / other", cte_ok, _PAL["pass"]),
                ("Disconnected", cte_disc, _PAL["warn"]),
                ("Unregistered / offline", cte_unreg, _PAL["muted"]),
            ],
            "clients",
        ),
    )
    add(
        _slug("Audit"),
        _doughnut(
            "audit-server",
            "Server audit (7 days)",
            "",
            [
                ("Critical / fatal", _n(sc.get("critical")) + _n(sc.get("fatal")), _PAL["crit"]),
                ("Error", sc.get("error"), _PAL["warn"]),
            ],
            "server",
        ),
    )
    add(
        _slug("Audit"),
        _doughnut(
            "audit-client",
            "Client audit (7 days)",
            "",
            [
                ("Critical / fatal", _n(cc.get("critical")) + _n(cc.get("fatal")), _PAL["crit"]),
                ("Error", cc.get("error"), _PAL["warn"]),
            ],
            "client",
        ),
    )
    return out


_CSS = """
:root {
  --bg: #f4f5f7;
  --card: #fff;
  --ink: #1a1d23;
  --muted: #5c6570;
  --line: #d8dde3;
  --ok: #1b7f4e;
  --ok-bg: #e6f6ee;
  --warn: #9a6b00;
  --warn-bg: #fff4d6;
  --fail: #b42318;
  --fail-bg: #fdecea;
  --info: #175cd3;
  --info-bg: #eff4ff;
  --head: #0f2744;
}
* { box-sizing: border-box; }
body {
  margin: 0; font-family: Segoe UI, system-ui, sans-serif;
  color: var(--ink); background: var(--bg); line-height: 1.45;
}
header { background: var(--head); color: #fff; padding: 22px 32px 18px; }
header h1 { margin: 0; font-size: 22px; font-weight: 650; }
header .meta { color: #c5d0dc; font-size: 13px; margin: 8px 0 0; }
.head-top { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; }
.badge {
  display: inline-block; padding: 4px 10px; border-radius: 4px;
  font-weight: 700; letter-spacing: .04em; font-size: 13px;
}
.badge.OK, .badge.PASS { background: var(--ok); color: #fff; }
.badge.DEGRADED, .badge.WARN { background: #c47d00; color: #fff; }
.badge.CRITICAL, .badge.FAIL, .badge.UNREACHABLE { background: var(--fail); color: #fff; }
.badge.JSON { background: #3d4f66; color: #fff; }
.wrap { max-width: 1240px; margin: 0 auto; padding: 20px 24px 64px; }
.layout { display: grid; grid-template-columns: 200px minmax(0, 1fr); gap: 32px; align-items: start; }
.tab-bar {
  position: sticky; top: 12px;
  display: flex; flex-direction: column; gap: 0;
  background: transparent; padding: 0; border: none;
}
.nav-label {
  font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em;
  color: var(--muted); margin: 16px 0 4px; padding: 0 8px;
}
.nav-label:first-child { margin-top: 0; }
.tab-btn {
  display: flex; justify-content: space-between; align-items: baseline; gap: 10px;
  width: 100%; padding: 7px 8px; border: none; border-bottom: 1px solid transparent;
  border-radius: 0; background: transparent; cursor: pointer;
  min-width: 0; font: inherit; text-align: left; color: var(--ink);
}
.tab-btn:hover .name { color: var(--head); }
.tab-btn.active { box-shadow: none; border-bottom-color: var(--ink); }
.tab-btn.active .name { font-weight: 700; }
.tab-btn .name { font-weight: 500; font-size: 13px; color: var(--ink); }
.st { font-size: 11px; font-weight: 700; letter-spacing: .04em; white-space: nowrap; }
.st.FAIL, .tab-btn.FAIL .st { color: var(--fail); }
.st.WARN, .tab-btn.WARN .st { color: var(--warn); }
.st.PASS, .tab-btn.PASS .st { color: var(--ok); }
.st.MUTED, .tab-btn.MUTED .st { color: var(--muted); }
.tab-btn.FAIL, .tab-btn.WARN, .tab-btn.PASS, .tab-btn.MUTED { background: transparent; }
.tab-panel { padding-top: 0; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 0 0 18px; }
.kpi { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
.kpi .n { font-size: 26px; font-weight: 700; }
.kpi .l { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
.kpi.crit .n { color: var(--fail); }
.kpi.warn .n { color: var(--warn); }
.kpi.info .n { color: var(--info); }
h2 { font-size: 18px; margin: 8px 0 10px; }
h3 { font-size: 14px; margin: 0 0 8px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; margin: 0 0 16px; }
.chart-box { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px 10px; }
.chart-box h3 { margin: 0 0 2px; font-size: 14px; }
.caption, .chart-box .caption { color: var(--muted); font-size: 12px; margin: 0 0 8px; }
.chart-frame { position: relative; height: 220px; }
.panel-head { border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin-bottom: 14px; background: var(--card); }
.head-row { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.head-row h2 { margin: 0; }
.head-row .st { font-size: 13px; }
.summary { margin-top: 8px; font-size: 14px; }
.summary strong.fail { color: var(--fail); font-weight: 700; }
.summary strong.warn { color: var(--warn); font-weight: 700; }
.status-pills { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 8px; }
.pill { font-size: 12px; font-weight: 700; padding: 0; background: none; border: none; }
.pill.crit { color: var(--fail); }
.pill.warn { color: var(--warn); }
.pill.info { color: var(--info); }
.area-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0 28px; margin-bottom: 16px; }
.area-card {
  display: flex; flex-direction: row; justify-content: space-between; align-items: baseline;
  gap: 12px; text-align: left; padding: 9px 0;
  border: none; border-bottom: 1px solid var(--line); border-radius: 0;
  background: transparent; cursor: pointer; font: inherit; color: inherit;
}
.area-card.FAIL, .area-card.WARN, .area-card.PASS { background: transparent; }
.area-card .area-name { font-weight: 500; font-size: 13px; }
.area-card .sub { font-size: 11px; color: var(--muted); margin-left: auto; padding-right: 8px; }
.meter-wrap { display: flex; align-items: center; gap: 10px; min-width: 140px; }
.meter { flex: 1; height: 12px; background: #eef1f5; border-radius: 4px; overflow: hidden; }
.meter-fill { display: block; height: 100%; background: #175cd3; border-radius: 4px; }
.meter-n { font-weight: 700; font-size: 13px; min-width: 3.2em; text-align: right; }
.badge-n {
  display: inline-block; font-weight: 700; padding: 2px 8px; border-radius: 999px; font-size: 12px;
}
.badge-n.fail { background: var(--fail-bg); color: var(--fail); }
.badge-n.warn { background: var(--warn-bg); color: var(--warn); }
.badge-n.ok { background: var(--ok-bg); color: var(--ok); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #eef1f5; font-weight: 600; }
.findings { margin: 0; padding-left: 18px; }
.findings li { margin: 0 0 8px; }
.findings .area { color: var(--muted); font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.crit-list { background: var(--fail-bg); border-left: 4px solid var(--fail); }
.warn-list { background: var(--warn-bg); border-left: 4px solid var(--warn); }
.info-list { background: var(--info-bg); border-left: 4px solid var(--info); }
.caveat { font-size: 13px; color: var(--muted); margin: 8px 0 0; }
details.section, details.info-fold, details.raw-fold {
  border: 1px solid var(--line); border-radius: 6px; margin: 6px 0; background: var(--card);
}
details > summary { cursor: pointer; padding: 8px 12px; font-weight: 600; font-size: 13px; }
details[open] > summary { border-bottom: 1px solid var(--line); }
.sec-body { padding: 10px 12px; overflow-x: auto; }
.sec-body pre {
  margin: 0; white-space: pre-wrap; word-break: break-word;
  font-size: 12px; font-family: ui-monospace, Consolas, monospace;
}
footer { color: var(--muted); font-size: 12px; margin-top: 28px; }
@media (max-width: 800px) {
  .layout { grid-template-columns: 1fr; }
  .tab-bar { position: static; flex-direction: row; flex-wrap: wrap; gap: 4px 12px; padding-bottom: 12px; border-bottom: 1px solid var(--line); }
  .nav-label { width: 100%; margin: 10px 0 0; }
}
@media print {
  header, .badge, .st { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .layout { grid-template-columns: 1fr; }
  .tab-bar { display: none; }
  .tab-panel { display: block !important; break-after: page; }
  .chart-box { break-inside: avoid; }
}
"""

_JS = """
const PAL = { crit: '#b42318', warn: '#c47d00', info: '#175cd3', pass: '#1b7f4e', muted: '#8b949e' };
const centerText = {
  id: 'centerText',
  afterDraw(chart, _args, opts) {
    if (chart.config.type !== 'doughnut' || !opts || opts.text == null) return;
    const {ctx, chartArea} = chart;
    const x = (chartArea.left + chartArea.right) / 2;
    const y = (chartArea.top + chartArea.bottom) / 2;
    ctx.save();
    ctx.fillStyle = '#1a1d23';
    ctx.font = '700 22px Segoe UI, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(String(opts.text), x, y - 8);
    ctx.fillStyle = '#5c6570';
    ctx.font = '12px Segoe UI, system-ui, sans-serif';
    ctx.fillText(String(opts.sub || ''), x, y + 14);
    ctx.restore();
  }
};
const barValues = {
  id: 'barValues',
  afterDatasetsDraw(chart) {
    if (chart.config.type !== 'bar') return;
    const {ctx} = chart;
    const meta = chart.getDatasetMeta(0);
    ctx.save();
    ctx.fillStyle = '#1a1d23';
    ctx.font = '600 12px Segoe UI, system-ui, sans-serif';
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'left';
    meta.data.forEach((bar, i) => {
      const v = chart.data.datasets[0].data[i];
      if (v == null) return;
      ctx.fillText(String(v), bar.x + 8, bar.y);
    });
    ctx.restore();
  }
};
Chart.register(centerText, barValues);

function makeChart(cfg) {
  const canvas = document.getElementById(cfg.id);
  if (!canvas) return;
  const values = cfg.values || [];
  if (!values.length || values.every(v => !v)) {
    const box = document.getElementById('box-' + cfg.id);
    if (box) box.style.display = 'none';
    return;
  }
  const colors = cfg.colors && cfg.colors.length ? cfg.colors : [PAL.warn];
  if (cfg.type === 'doughnut') {
    new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: cfg.labels,
        datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }]
      },
      options: {
        cutout: '64%',
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { boxWidth: 12, padding: 12, font: { size: 12 } } },
          tooltip: { callbacks: { label: (c) => ' ' + c.label } },
          centerText: { text: cfg.center, sub: cfg.centerSub || '' }
        }
      }
    });
    return;
  }
  const barColors = colors.length === values.length ? colors : (colors[0] || PAL.warn);
  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: cfg.labels,
      datasets: [{
        data: values,
        backgroundColor: barColors,
        borderRadius: 4,
        barPercentage: 0.7,
        categoryPercentage: 0.7,
        maxBarThickness: 36
      }]
    },
    options: {
      indexAxis: 'y',
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (c) => ' ' + c.raw } },
        barValues: { enabled: true }
      },
      layout: { padding: { right: 36 } },
      scales: {
        x: {
          stacked: false,
          beginAtZero: true,
          grace: '12%',
          ticks: { precision: 0, maxTicksLimit: 6 },
          grid: { color: '#eef1f5' }
        },
        y: { stacked: false, grid: { display: false }, ticks: { font: { size: 13 } } }
      }
    }
  });
}

const rendered = {};
function renderTabCharts(slug) {
  if (rendered[slug]) return;
  rendered[slug] = true;
  (DATA[slug] || []).forEach(makeChart);
}

function showTab(slug) {
  const known = document.getElementById('panel-' + slug);
  if (!known) slug = 'overview';
  document.querySelectorAll('.tab-panel').forEach(p => { p.hidden = true; });
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === slug);
    b.setAttribute('aria-selected', b.dataset.tab === slug ? 'true' : 'false');
  });
  const panel = document.getElementById('panel-' + slug);
  if (panel) panel.hidden = false;
  const btn = document.getElementById('tab-' + slug);
  if (btn) btn.scrollIntoView({ inline: 'nearest', block: 'nearest' });
  renderTabCharts(slug);
  if (location.hash.replace('#','') !== slug) {
    history.replaceState(null, '', '#' + slug);
  }
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => showTab(btn.dataset.tab));
});
document.querySelectorAll('.area-card').forEach(btn => {
  btn.addEventListener('click', () => showTab(btn.dataset.jump));
});
window.addEventListener('hashchange', () => showTab(location.hash.replace('#','')));
window.addEventListener('beforeprint', () => {
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.hidden = false;
    renderTabCharts(p.id.replace('panel-', ''));
  });
});
showTab((location.hash || '#overview').replace('#',''));
"""
