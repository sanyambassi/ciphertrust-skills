from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .report import due_soon_label, is_lifecycle, lifecycle_reasons

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|jwt|authorization|refresh|scrape)",
    re.IGNORECASE,
)
_MD_FAIL = re.compile(r"\*\*\*(.+?)\*\*\*")
_MD_BOLD = re.compile(r"\*\*(.+?)\*\*")

_PAL = {
    "crit": "#b42318",
    "warn": "#c47d00",
    "info": "#175cd3",
    "pass": "#1b7f4e",
    "fail": "#b42318",
    "muted": "#8b949e",
}
_SLICE = (
    "#175cd3",
    "#1b7f4e",
    "#c47d00",
    "#7c3aed",
    "#0e7490",
    "#b42318",
)


def write_html_report(report: dict[str, Any], path: str | Path) -> Path:
    out = Path(path)
    if out.suffix.lower() != ".html":
        out = out.with_suffix(".html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(report), encoding="utf-8")
    return out.resolve()


def render_html(report: dict[str, Any]) -> str:
    host = str(report.get("host") or _host(str(report.get("base") or "")))
    version = str(report.get("cm_version") or "n/a")
    ts = str(report.get("timestamp_utc") or "")
    totals = report.get("totals") or {}
    keys_n = _n(totals.get("keys"))
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    estate = metrics.get("deks_total")
    estate_n = _n(estate) if estate is not None else None
    truncated = bool(report.get("truncated"))
    badge = "TRUNCATED" if truncated else (
        f"{estate_n} keys" if estate_n is not None else f"{keys_n} keys"
    )
    badge_cls = "DEGRADED" if truncated else "JSON"
    if not report.get("ok", True):
        badge = "UNREACHABLE"
        badge_cls = "UNREACHABLE"

    charts = _tab_charts(report)
    charts_json = json.dumps(charts, default=str).replace("<", "\\u003c")

    nav = [
        "<div class='nav-label'>Report</div>",
        _tab_button(
            "overview",
            "Overview",
            "MUTED",
            result_label=str(estate_n if estate_n is not None else keys_n),
        ),
        "<div class='nav-label'>Slices</div>",
        _tab_button(
            "system",
            "System",
            "MUTED",
            result_label=str(_n(totals.get("system"))),
        ),
        _tab_button(
            "akeyless",
            "Akeyless CF",
            "MUTED",
            result_label=str(_n(totals.get("akeyless_cf"))),
        ),
        _tab_button(
            "weak",
            "Weak",
            "WARN" if _n(totals.get("weak")) else "MUTED",
            result_label=str(_n(totals.get("weak"))),
        ),
        _tab_button(
            "cte",
            "CTE",
            "MUTED",
            result_label=str(_n(totals.get("cte"))),
        ),
        _tab_button(
            "lifecycle",
            "Lifecycle",
            "WARN" if _n(totals.get("lifecycle")) else "MUTED",
            result_label=str(_n(totals.get("lifecycle"))),
        ),
        _tab_button(
            "export",
            "Export/Delete",
            "MUTED",
            result_label=str(_n(totals.get("exportable"))),
        ),
        "<div class='nav-label'>More</div>",
        _tab_button(
            "domains",
            "Domains",
            "WARN" if _n((report.get("domains") or {}).get("skipped_count")) else "MUTED",
            result_label=str(_n((report.get("domains") or {}).get("checked_count"))),
        ),
        _tab_button(
            "catalog",
            "Catalog",
            "WARN" if truncated else "MUTED",
            result_label=str(keys_n),
        ),
        _tab_button("raw", "Raw", "MUTED", result_label="JSON"),
    ]
    panels = [
        _overview_panel(report),
        _system_panel(report),
        _akeyless_panel(report),
        _weak_panel(report),
        _cte_panel(report),
        _lifecycle_panel(report),
        _export_panel(report),
        _domains_panel(report),
        _catalog_panel(report),
        _raw_panel(report),
    ]
    return (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='utf-8'/>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'/>\n"
        f"<title>CipherTrust Manager key inventory — {esc(host)}</title>\n"
        "<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'></script>\n"
        f"<style>{_CSS}</style>\n</head>\n<body>\n"
        "<header>\n"
        "  <div class='head-top'><h1>CipherTrust Manager key inventory</h1>\n"
        f"  <span class='badge {esc(badge_cls)}'>{esc(badge)}</span></div>\n"
        "  <p class='meta'>\n"
        f"    CM {esc(version)} · {esc(host)} · {esc(ts)}\n"
        "  </p>\n"
        "</header>\n"
        "<div class='wrap'>\n"
        "<div class='layout'>\n"
        f"<nav class='tab-bar' role='tablist'>{''.join(nav)}</nav>\n"
        "<main class='main'>\n"
        f"{''.join(panels)}\n"
        "<footer>CipherTrust Manager key inventory</footer>\n"
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


def _n(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _tab_tone(result: str) -> str:
    r = (result or "").upper()
    if r in ("FAIL", "CRITICAL", "UNREACHABLE"):
        return "FAIL"
    if r in ("WARN", "WARNING", "DEGRADED", "TRUNCATED"):
        return "WARN"
    if r in ("PASS", "OK"):
        return "PASS"
    return "MUTED"


def _tab_button(
    slug: str,
    label: str,
    result: str,
    result_label: str | None = None,
) -> str:
    tone = _tab_tone(result)
    shown = result_label if result_label is not None else result
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
    return (
        f"<div class='chart-box' id='box-{cid}'>"
        f"<h3>{esc(cfg.get('title'))}</h3>"
        f"<div class='chart-frame' style='height:{height}px'>"
        f"<canvas id='{cid}'></canvas></div></div>"
    )


def _table(headers: list[str], rows: list[str], title: str) -> str:
    if not rows:
        return ""
    th = "".join(f"<th>{h}</th>" for h in headers)
    return (
        f"<div class='card'><h3>{esc(title)}</h3>"
        f"<div class='table-wrap'><table><thead><tr>{th}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></div>"
    )


def _catalog_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for r in (report.get("catalog") or []) if isinstance(r, dict)]


def _overview_panel(report: dict[str, Any]) -> str:
    totals = report.get("totals") or {}
    domains = report.get("domains") or {}
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    estate = metrics.get("deks_total")
    orphans = report.get("orphans") if isinstance(report.get("orphans"), dict) else {}
    charts = _tab_charts(report).get("overview") or []
    chart_html = "".join(_chart_box(c) for c in charts)
    domain_rows = []
    for d in totals.get("by_domain") or []:
        if not isinstance(d, dict):
            continue
        weak = _n(d.get("weak"))
        ina = _n(d.get("inactive"))
        domain_rows.append(
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td>"
            f"<td>{esc(d.get('keys'))}</td>"
            f"<td>{esc(d.get('version_objects'))}</td>"
            f"<td>{esc(d.get('keys_multi_version'))}</td>"
            f"<td>{esc(d.get('keys_three_plus'))}</td>"
            f"<td>{esc(d.get('system'))}</td>"
            f"<td>{esc(d.get('akeyless_cf'))}</td>"
            f"<td><span class='badge-n {'fail' if weak else 'ok'}'>{esc(weak)}</span></td>"
            f"<td><span class='badge-n {'warn' if ina else 'ok'}'>{esc(ina)}</span></td>"
            f"<td>{esc(d.get('about_to_change'))}</td>"
            f"<td>{esc(d.get('exportable'))}</td>"
            f"<td>{esc(d.get('deletable'))}</td>"
            f"<td>{esc(d.get('cte'))}</td>"
            f"<td>{esc(d.get('cte_ldt'))}</td>"
            f"<td>{esc(d.get('cte_standard'))}</td>"
            "</tr>"
        )
    orphan_rows = []
    for a in orphans.get("orphaned_keys_by_account") or []:
        if not isinstance(a, dict):
            continue
        orphan_rows.append(
            "<tr>"
            f"<td>{esc(a.get('account') or a.get('name') or a.get('id'))}</td>"
            f"<td>{esc(a.get('orphaned_keys_count') or a.get('count') or a.get('keys'))}</td>"
            "</tr>"
        )
    note = ""
    if report.get("truncated"):
        note = "<p class='caveat'>Catalog truncated by a key limit.</p>"
    collected = report.get("catalog_collected")
    shown = totals.get("keys")
    if collected is not None and collected != shown:
        note += f"<p class='caveat'>Showing {esc(shown)} of {esc(collected)} collected keys after filters.</p>"
    skipped_n = _n(domains.get("skipped_count"))
    if skipped_n:
        note += (
            f"<p class='caveat'>{esc(skipped_n)} domain(s) skipped. "
            "Skipped is not an empty domain. "
            "Keys in checked domains are only what this account could list; "
            "total keys (including orphaned) is the CM estate count.</p>"
        )
    elif estate is not None and _n(estate) != _n(shown):
        note += (
            "<p class='caveat'>Keys in checked domains are only what this account could list; "
            "total keys (including orphaned) is the CM estate count.</p>"
        )
    extra_kpis = ""
    if estate is not None:
        extra_kpis += _kpi("Total keys (including orphaned)", estate, "")
    if orphans.get("total_orphaned_keys_count"):
        extra_kpis += _kpi("Orphaned", orphans.get("total_orphaned_keys_count"), "warn")
    window = _n((report.get("options") or {}).get("window_days")) or 30
    due_lbl = due_soon_label(window)
    return (
        "<section class='tab-panel' id='panel-overview' role='tabpanel'>"
        "<div class='kpis'>"
        f"{extra_kpis}"
        f"{_kpi('Keys in checked domains', totals.get('keys', 0), '')}"
        f"{_kpi('Version objects listed', totals.get('version_objects', totals.get('keys', 0)), '')}"
        f"{_kpi('Keys with 2+ versions', totals.get('keys_multi_version', 0), '')}"
        f"{_kpi('Keys with 3+ versions', totals.get('keys_three_plus', 0), '')}"
        f"{_kpi('System', totals.get('system', 0), 'info')}"
        f"{_kpi('Akeyless CF', totals.get('akeyless_cf', 0), 'info' if _n(totals.get('akeyless_cf')) else '')}"
        f"{_kpi('Weak', totals.get('weak', 0), 'warn' if _n(totals.get('weak')) else '')}"
        f"{_kpi('Inactive', totals.get('inactive', 0), 'warn' if _n(totals.get('inactive')) else '')}"
        f"{_kpi(due_lbl, totals.get('about_to_change', 0), '')}"
        f"{_kpi('Exportable', totals.get('exportable', 0), '')}"
        f"{_kpi('Never exported', totals.get('never_exported', 0), '')}"
        f"{_kpi('Never exportable', totals.get('never_exportable', 0), '')}"
        f"{_kpi('CTE', totals.get('cte', 0), 'info' if _n(totals.get('cte')) else '')}"
        f"{_kpi('LDT', totals.get('cte_ldt', 0), '')}"
        f"{_kpi('Standard', totals.get('cte_standard', 0), '')}"
        f"{_kpi('Domains checked', domains.get('checked_count', 0), '')}"
        f"{_kpi('Domains skipped', domains.get('skipped_count', 0), 'warn' if skipped_n else '')}"
        "</div>"
        f"{note}"
        f"<div class='charts'>{chart_html}</div>"
        f"{_table(['Domain', 'Keys', 'Version objects', '2+ versions', '3+ versions', 'System', 'Akeyless CF', 'Weak', 'Inactive', due_lbl, 'Exportable', 'Deletable', 'CTE', 'LDT', 'Standard'], domain_rows, 'Totals by domain')}"
        f"{_table(['Account', 'Orphaned keys'], orphan_rows, 'Orphaned keys by account')}"
        "</section>"
    )


def _key_table(rows: list[dict[str, Any]], headers: list[str], cells, title: str) -> str:
    html_rows = [cells(r) for r in rows]
    return _table(headers, html_rows, title)


def _system_panel(report: dict[str, Any]) -> str:
    rows = [r for r in _catalog_rows(report) if r.get("system")]
    charts = _tab_charts(report).get("system") or []

    def cells(r: dict) -> str:
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"<td>{esc(r.get('name'))}</td>"
            f"<td>{esc(r.get('system_kind'))}</td>"
            f"<td>{esc(r.get('service_name'))}</td>"
            f"<td>{esc(r.get('objectType'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            "</tr>"
        )

    return (
        "<section class='tab-panel' id='panel-system' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>System</h2>"
        f"<span class='st MUTED'>{len(rows)}</span></div>"
        "<div class='summary'>Internal keys: citrus-* names, and ks-* names with a service name and no owner.</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_key_table(rows, ['Domain', 'Name', 'Kind', 'Service', 'Type', 'Algorithm', 'State'], cells, 'System keys')}"
        "</section>"
    )


def _akeyless_panel(report: dict[str, Any]) -> str:
    rows = [r for r in _catalog_rows(report) if r.get("akeyless_cf")]
    charts = _tab_charts(report).get("akeyless") or []

    def cells(r: dict) -> str:
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"<td>{esc(r.get('name'))}</td>"
            f"<td>{esc(r.get('objectType'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            f"<td>{esc(r.get('ownerId'))}</td>"
            "</tr>"
        )

    return (
        "<section class='tab-panel' id='panel-akeyless' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Akeyless Customer Fragments</h2>"
        f"<span class='st MUTED'>{len(rows)}</span></div>"
        "<div class='summary'>Names matching cf-&lt;uuid&gt; in each checked domain. Usually Opaque Object, no owner.</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_key_table(rows, ['Domain', 'Name', 'Type', 'Algorithm', 'State', 'Owner'], cells, 'Akeyless Customer Fragments')}"
        "</section>"
    )


def _weak_panel(report: dict[str, Any]) -> str:
    rows = [r for r in _catalog_rows(report) if r.get("weak")]
    charts = _tab_charts(report).get("weak") or []
    tone = "WARN" if rows else "MUTED"

    def cells(r: dict) -> str:
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"<td>{esc(r.get('name'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('size'))}</td>"
            f"<td>{esc(r.get('curve'))}</td>"
            f"<td>{esc(r.get('weak_reason'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            "</tr>"
        )

    return (
        "<section class='tab-panel' id='panel-weak' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Weak</h2>"
        f"<span class='st {tone}'>{len(rows)}</span></div>"
        "<div class='summary'>RSA below 2048 bits, DES/3DES, AES/ARIA below 128 bits, EC below 256 bits or a weak curve.</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_key_table(rows, ['Domain', 'Name', 'Algorithm', 'Size', 'Curve', 'Reason', 'State'], cells, 'Weak keys')}"
        "</section>"
    )


def _cte_versioned_label(r: dict[str, Any]) -> str:
    if not r.get("cte"):
        return ""
    if r.get("cte_versioned") is True:
        return "yes"
    if r.get("cte_versioned") is False:
        return "no"
    return "not set"


def _cte_panel(report: dict[str, Any]) -> str:
    rows = [r for r in _catalog_rows(report) if r.get("cte")]
    charts = _tab_charts(report).get("cte") or []
    ldt_n = sum(1 for r in rows if r.get("cte_policy") == "LDT")
    std_n = len(rows) - ldt_n

    def cells(r: dict) -> str:
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"<td>{esc(r.get('name'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            f"<td>{esc(r.get('version'))}</td>"
            f"<td>{esc(r.get('cte_encryption_mode'))}</td>"
            f"<td>{esc(_cte_versioned_label(r))}</td>"
            f"<td>{esc(r.get('cte_policy'))}</td>"
            "</tr>"
        )

    return (
        "<section class='tab-panel' id='panel-cte' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>CTE</h2>"
        f"<span class='st MUTED'>{len(rows)}</span></div>"
        "<div class='summary'>CipherTrust Transparent Encryption keys. "
        f"LDT Policy compatible {ldt_n}. "
        f"Standard policy compatible {std_n}.</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_key_table(rows, ['Domain', 'Name', 'Algorithm', 'State', 'Version', 'Encryption mode', 'CTE versioned', 'Policy'], cells, 'CTE keys')}"
        "</section>"
    )


def _lifecycle_panel(report: dict[str, Any]) -> str:
    window = _n((report.get("options") or {}).get("window_days")) or 30
    rows = [r for r in _catalog_rows(report) if is_lifecycle(r)]
    charts = _tab_charts(report).get("lifecycle") or []
    tone = "WARN" if rows else "MUTED"

    def cells(r: dict) -> str:
        why = ", ".join(lifecycle_reasons(r, window))
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"<td>{esc(r.get('name'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            f"<td>{esc(r.get('version'))}</td>"
            f"<td>{esc(r.get('createdAt'))}</td>"
            f"<td>{esc(r.get('deactivationDate'))}</td>"
            f"<td>{esc(r.get('protectStopDate'))}</td>"
            f"<td>{esc(why)}</td>"
            "</tr>"
        )

    return (
        "<section class='tab-panel' id='panel-lifecycle' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Lifecycle</h2>"
        f"<span class='st {tone}'>{len(rows)}</span></div>"
        f"<div class='summary'>Inactive latest version; activate, deactivate, protect-stop, or rotate due in {esc(window)} days; never rotated and older than one year.</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_key_table(rows, ['Domain', 'Name', 'State', 'Version', 'Created', 'Deactivate', 'Protect-stop', 'Why'], cells, 'Lifecycle')}"
        "</section>"
    )


def _export_panel(report: dict[str, Any]) -> str:
    catalog = _catalog_rows(report)
    exportable = [r for r in catalog if r.get("exportable")]
    deletable = [r for r in catalog if r.get("deletable")]
    never_exp = [r for r in catalog if r.get("neverExported")]
    never_able = [r for r in catalog if r.get("neverExportable")]
    charts = _tab_charts(report).get("export") or []

    def cells(r: dict) -> str:
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"<td>{esc(r.get('name'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            f"<td>{'yes' if r.get('exportable') else 'no'}</td>"
            f"<td>{'yes' if r.get('deletable') else 'no'}</td>"
            f"<td>{esc(r.get('neverExported'))}</td>"
            f"<td>{esc(r.get('neverExportable'))}</td>"
            "</tr>"
        )

    both = []
    seen = set()
    for r in exportable + deletable + never_exp + never_able:
        kid = (r.get("domain"), r.get("id") or r.get("name"))
        if kid in seen:
            continue
        seen.add(kid)
        both.append(r)
    return (
        "<section class='tab-panel' id='panel-export' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Export / Delete</h2></div>"
        f"<div class='summary'>Exportable {len(exportable)} · Deletable {len(deletable)} · Never exported {len(never_exp)} · Never exportable {len(never_able)}</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_key_table(both, ['Domain', 'Name', 'Algorithm', 'State', 'Exportable', 'Deletable', 'Never exported', 'Never exportable'], cells, 'Export attributes')}"
        "</section>"
    )


def _domains_panel(report: dict[str, Any]) -> str:
    domains = report.get("domains") or {}
    checked_rows = []
    for d in domains.get("checked") or []:
        if not isinstance(d, dict):
            continue
        labels = (d.get("labels") or {}).get("labels") if isinstance(d.get("labels"), dict) else []
        label_s = ", ".join(str(x) for x in (labels or [])[:12])
        if labels and len(labels) > 12:
            label_s += f" (+{len(labels) - 12})"
        trunc = "yes" if d.get("truncated") else "no"
        checked_rows.append(
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td>"
            f"<td>{esc(d.get('unique'))}</td>"
            f"<td>{esc(d.get('version_objects') or d.get('raw'))}</td>"
            f"<td>{esc(d.get('keys_multi_version'))}</td>"
            f"<td>{esc(d.get('keys_three_plus'))}</td>"
            f"<td>{esc(trunc)}</td>"
            f"<td>{esc(label_s)}</td>"
            "</tr>"
        )
    skip_rows = []
    for d in (domains.get("skipped") or []) + (domains.get("errors") or []):
        if not isinstance(d, dict):
            continue
        skip_rows.append(
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td>"
            f"<td>{esc(d.get('reason'))}</td>"
            f"<td>{esc(d.get('status'))}</td>"
            f"<td>{esc(d.get('message') or d.get('error'))}</td>"
            "</tr>"
        )
    return (
        "<section class='tab-panel' id='panel-domains' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Domains</h2>"
        f"<span class='st MUTED'>{esc(domains.get('checked_count', 0))} checked</span></div>"
        "</div>"
        f"{_table(['Domain', 'Keys', 'Version objects', '2+ versions', '3+ versions', 'Truncated', 'Labels'], checked_rows, 'Checked domains')}"
        f"{_table(['Domain', 'Reason', 'Status', 'Message'], skip_rows, 'Skipped or error')}"
        "</section>"
    )


def _catalog_panel(report: dict[str, Any]) -> str:
    rows = _catalog_rows(report)
    body = []
    for r in rows:
        weak_cls = "fail" if r.get("weak") else "ok"
        sys_cls = "warn" if r.get("system") else "ok"
        body.append(
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"<td>{esc(r.get('name'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('size'))}</td>"
            f"<td>{esc(r.get('curve'))}</td>"
            f"<td>{esc(r.get('objectType'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            f"<td>{esc(r.get('version'))}</td>"
            f"<td>{esc(r.get('version_count') or 1)}</td>"
            f"<td><span class='badge-n {sys_cls}'>{'yes' if r.get('system') else 'no'}</span></td>"
            f"<td>{'yes' if r.get('akeyless_cf') else 'no'}</td>"
            f"<td><span class='badge-n {weak_cls}'>{esc(r.get('weak_reason') or ('yes' if r.get('weak') else 'no'))}</span></td>"
            f"<td>{'yes' if r.get('cte') else 'no'}</td>"
            f"<td>{esc(r.get('cte_policy'))}</td>"
            f"<td>{'yes' if r.get('exportable') else 'no'}</td>"
            f"<td>{'yes' if r.get('deletable') else 'no'}</td>"
            f"<td>{esc(r.get('ownerId'))}</td>"
            f"<td>{esc(r.get('service_name'))}</td>"
            f"<td>{esc(r.get('createdAt'))}</td>"
            "</tr>"
        )
    headers = [
        ("Domain", 0),
        ("Name", None),
        ("Algorithm", 2),
        ("Size", None),
        ("Curve", None),
        ("Type", None),
        ("State", None),
        ("Version", None),
        ("Versions listed", None),
        ("System", None),
        ("Akeyless CF", None),
        ("Weak", None),
        ("CTE", None),
        ("Policy", 13),
        ("Exportable", None),
        ("Deletable", None),
        ("Owner", None),
        ("Service", None),
        ("Created", None),
    ]
    th_parts = []
    for label, sort_col in headers:
        if sort_col is None:
            th_parts.append(f"<th>{label}</th>")
        else:
            th_parts.append(
                f"<th data-sort='{sort_col}' class='sortable'>{label}</th>"
            )
    th = "".join(th_parts)
    table = (
        "<div class='card'><h3>Catalog</h3>"
        "<div class='cat-toolbar'>"
        "<input id='cat-filter' type='search' placeholder='Filter catalog'/>"
        "<label>Sort "
        "<select id='cat-sort'>"
        "<option value='0'>Domain</option>"
        "<option value='2'>Algorithm</option>"
        "<option value='13'>Policy</option>"
        "</select></label>"
        "<label>Rows "
        "<select id='cat-page-size'>"
        "<option value='25'>25</option>"
        "<option value='50' selected>50</option>"
        "<option value='100'>100</option>"
        "</select></label>"
        "<div id='cat-pager' class='cat-pager'></div>"
        "</div>"
        "<div class='table-wrap'><table id='cat-table'><thead><tr>"
        + th
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div></div>"
    )
    return (
        "<section class='tab-panel' id='panel-catalog' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Catalog</h2>"
        f"<span class='st MUTED'>{len(rows)}</span></div></div>"
        f"{table}"
        "</section>"
    )


def _raw_panel(report: dict[str, Any]) -> str:
    slim = dict(report)
    catalog = slim.get("catalog")
    if isinstance(catalog, list) and len(catalog) > 200:
        slim = dict(slim)
        slim["catalog"] = f"[{len(catalog)} keys — see Catalog tab]"
    body = esc(json.dumps(_redact(slim), indent=2, default=str))
    return (
        "<section class='tab-panel' id='panel-raw' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Raw</h2></div></div>"
        f"<div class='card'><div class='sec-body'><pre>{body}</pre></div></div>"
        "</section>"
    )


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


def _doughnut(slug: str, title: str, pairs: list[tuple[str, Any, str]], center_sub: str) -> dict | None:
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
    if len(colors) > 1 and len(set(colors)) == 1:
        colors = [_SLICE[i % len(_SLICE)] for i in range(len(colors))]
    return {
        "id": f"ch-{slug}",
        "type": "doughnut",
        "title": title,
        "labels": labels,
        "values": values,
        "colors": colors,
        "center": sum(values),
        "centerSub": center_sub,
        "height": 220,
    }


def _zero_doughnut(slug: str, title: str, label: str, center_sub: str) -> dict:
    return {
        "id": f"ch-{slug}",
        "type": "doughnut",
        "title": title,
        "labels": [f"{label}  0"],
        "values": [1],
        "colors": [_PAL["muted"]],
        "center": 0,
        "centerSub": center_sub,
        "height": 220,
        "empty": True,
    }


def _barh(slug: str, title: str, labels: list[str], values: list[int], color: str, colors: list[str] | None = None) -> dict | None:
    if not labels or not any(values):
        return None
    return {
        "id": f"ch-{slug}",
        "type": "bar",
        "title": title,
        "labels": labels,
        "values": values,
        "colors": colors or [color],
        "height": max(180, 28 * len(labels) + 40),
    }


def _tab_charts(report: dict[str, Any]) -> dict[str, list[dict]]:
    totals = report.get("totals") or {}
    catalog = _catalog_rows(report)
    out: dict[str, list[dict]] = {
        "overview": [],
        "system": [],
        "akeyless": [],
        "weak": [],
        "lifecycle": [],
        "cte": [],
        "export": [],
        "domains": [],
        "catalog": [],
        "raw": [],
    }

    def add(tab: str, cfg: dict | None) -> None:
        if cfg:
            out[tab].append(cfg)

    cf_n = _n(totals.get("akeyless_cf"))
    user_n = max(0, _n(totals.get("keys")) - _n(totals.get("system")) - cf_n)
    ownership = [
        ("System", totals.get("system"), _PAL["info"]),
        ("App/User", user_n, _PAL["pass"]),
    ]
    if cf_n:
        ownership.append(("Akeyless CF", cf_n, "#7c3aed"))
    add(
        "overview",
        _doughnut(
            "ov-system",
            "System vs App/User",
            ownership,
            "keys",
        ),
    )
    weak_n = _n(totals.get("weak"))
    add(
        "overview",
        _doughnut(
            "ov-weak",
            "Weak keys",
            [("Weak", weak_n, _PAL["fail"])],
            "keys",
        )
        if weak_n
        else _zero_doughnut("ov-weak", "Weak keys", "Weak", "keys"),
    )
    state_pairs = [
        (name, n, _PAL["pass"] if name == "Active" else _PAL["warn"])
        for name, n in (totals.get("by_state") or {}).items()
    ]
    add("overview", _doughnut("ov-state", "State", state_pairs, "keys"))
    cte_n = _n(totals.get("cte"))
    add(
        "overview",
        _doughnut(
            "ov-cte",
            "CTE keys",
            [
                ("LDT", totals.get("cte_ldt"), _PAL["info"]),
                ("Standard", totals.get("cte_standard"), _PAL["pass"]),
            ],
            "keys",
        )
        if cte_n
        else _zero_doughnut("ov-cte", "CTE keys", "CTE", "keys"),
    )
    alg_items = list((totals.get("by_algorithm") or {}).items())[:12]
    add(
        "overview",
        _barh(
            "ov-alg",
            "Algorithms",
            [str(k) for k, _ in alg_items],
            [_n(v) for _, v in alg_items],
            _PAL["info"],
        ),
    )
    domain_items = list(totals.get("by_domain") or [])[:20]
    add(
        "overview",
        _barh(
            "ov-dom",
            "Keys by domain",
            [str(d.get("domain")) for d in domain_items],
            [_n(d.get("keys")) for d in domain_items],
            _PAL["info"],
        ),
    )

    kind_items = list((totals.get("by_system_kind") or {}).items())
    add(
        "system",
        _doughnut(
            "sys-kind",
            "System kind",
            [(str(k), v, _PAL["info"]) for k, v in kind_items],
            "system",
        ),
    )

    cf_dom: dict[str, int] = {}
    for r in catalog:
        if r.get("akeyless_cf"):
            name = str(r.get("domain") or "unknown")
            cf_dom[name] = cf_dom.get(name, 0) + 1
    add(
        "akeyless",
        _doughnut(
            "cf-dom",
            "By domain",
            [(k, v, _PAL["info"]) for k, v in cf_dom.items()],
            "Akeyless CF",
        )
        if cf_dom
        else _zero_doughnut("cf-dom", "By domain", "Akeyless CF", "Akeyless CF"),
    )

    weak_alg: dict[str, int] = {}
    for r in catalog:
        if r.get("weak"):
            weak_alg[str(r.get("algorithm") or "unknown")] = weak_alg.get(
                str(r.get("algorithm") or "unknown"), 0
            ) + 1
    add(
        "weak",
        _doughnut(
            "weak-alg",
            "Weak by algorithm",
            [(k, v, _PAL["fail"]) for k, v in weak_alg.items()],
            "weak",
        ),
    )

    cte_mode: dict[str, int] = {}
    for r in catalog:
        if r.get("cte"):
            mode = str(r.get("cte_encryption_mode") or "unknown")
            cte_mode[mode] = cte_mode.get(mode, 0) + 1
    add(
        "cte",
        _doughnut(
            "cte-policy",
            "LDT vs Standard",
            [
                ("LDT", totals.get("cte_ldt"), _PAL["info"]),
                ("Standard", totals.get("cte_standard"), _PAL["pass"]),
            ],
            "CTE",
        ),
    )
    add(
        "cte",
        _doughnut(
            "cte-mode",
            "Encryption mode",
            [(k, v, _PAL["info"]) for k, v in cte_mode.items()],
            "keys",
        ),
    )

    life_inactive = sum(1 for r in catalog if r.get("inactive"))
    life_about = sum(1 for r in catalog if r.get("about_to_change"))
    life_old = sum(
        1
        for r in catalog
        if (r.get("never_rotated") and r.get("older_than_1y")) or r.get("older_than_3y")
    )
    add(
        "lifecycle",
        _barh(
            "life-mix",
            "Lifecycle mix",
            ["Inactive", "Activate, deactivate, rotate", "Old / never rotated"],
            [life_inactive, life_about, life_old],
            _PAL["warn"],
            colors=[_PAL["warn"], _PAL["info"], _PAL["muted"]],
        ),
    )
    add(
        "export",
        _barh(
            "exp-mix",
            "Export / delete",
            ["Exportable", "Deletable", "Never exported", "Never exportable"],
            [
                _n(totals.get("exportable")),
                _n(totals.get("deletable")),
                _n(totals.get("never_exported")),
                _n(totals.get("never_exportable")),
            ],
            _PAL["info"],
            colors=[_PAL["info"], _PAL["warn"], _PAL["muted"], _PAL["fail"]],
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
.kpi { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; min-width: 0; overflow: hidden; }
.kpi .n { font-size: 26px; font-weight: 700; }
.kpi .l { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; overflow-wrap: anywhere; }
.kpi.crit .n { color: var(--fail); }
.kpi.warn .n { color: var(--warn); }
.kpi.info .n { color: var(--info); }
h2 { font-size: 18px; margin: 8px 0 10px; }
h3 { font-size: 14px; margin: 0 0 8px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; margin: 0 0 16px; }
.chart-box { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px 10px; }
.chart-box h3 { margin: 0 0 2px; font-size: 14px; }
.chart-frame { position: relative; height: 220px; }
.panel-head { border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin-bottom: 14px; background: var(--card); }
.head-row { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.head-row h2 { margin: 0; }
.head-row .st { font-size: 13px; }
.summary { margin-top: 8px; font-size: 14px; }
.summary strong.fail { color: var(--fail); font-weight: 700; }
.summary strong.warn { color: var(--warn); font-weight: 700; }
.caveat { font-size: 13px; color: var(--muted); margin: 8px 0 0; }
.badge-n {
  display: inline-block; font-weight: 700; padding: 2px 8px; border-radius: 999px; font-size: 12px;
}
.badge-n.fail { background: var(--fail-bg); color: var(--fail); }
.badge-n.warn { background: var(--warn-bg); color: var(--warn); }
.badge-n.ok { background: var(--ok-bg); color: var(--ok); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #eef1f5; font-weight: 600; }
.table-wrap { overflow-x: auto; }
.cat-toolbar {
  display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px;
  margin: 0 0 12px;
}
.cat-toolbar input[type='search'], .cat-toolbar select {
  padding: 6px 8px; border: 1px solid var(--line); border-radius: 4px; font: inherit;
}
.cat-toolbar input[type='search'] { width: 100%; max-width: 280px; }
.cat-toolbar label { font-size: 13px; color: var(--muted); display: flex; align-items: center; gap: 6px; }
.cat-pager { display: flex; align-items: center; gap: 8px; margin-left: auto; font-size: 13px; }
.cat-pager button {
  padding: 4px 10px; border: 1px solid var(--line); border-radius: 4px;
  background: #fff; font: inherit; cursor: pointer;
}
.cat-pager button:disabled { opacity: .45; cursor: default; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--head); }
th.sortable.sort-asc::after { content: ' ↑'; font-size: 11px; }
th.sortable.sort-desc::after { content: ' ↓'; font-size: 11px; }
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
          tooltip: { callbacks: { label: (c) => cfg.empty ? (' ' + (cfg.labels && cfg.labels[0] || '0')) : (' ' + c.label) } },
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
window.addEventListener('hashchange', () => showTab(location.hash.replace('#','')));
window.addEventListener('beforeprint', () => {
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.hidden = false;
    renderTabCharts(p.id.replace('panel-', ''));
  });
  if (window.catalogShowAll) window.catalogShowAll();
});
window.addEventListener('afterprint', () => {
  if (window.catalogApply) window.catalogApply();
});

(function catalogPager() {
  const table = document.getElementById('cat-table');
  if (!table) return;
  const tbody = table.querySelector('tbody');
  const filterEl = document.getElementById('cat-filter');
  const sortEl = document.getElementById('cat-sort');
  const sizeEl = document.getElementById('cat-page-size');
  const pagerEl = document.getElementById('cat-pager');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  let page = 1;
  let sortCol = 0;
  let sortDir = 1;
  let printAll = false;

  function cell(tr, i) {
    return (tr.children[i] ? tr.children[i].textContent : '').trim();
  }
  function filtered() {
    const q = (filterEl && filterEl.value || '').toLowerCase();
    let list = rows;
    if (q) list = list.filter(tr => tr.textContent.toLowerCase().includes(q));
    list = list.slice().sort((a, b) => {
      const av = cell(a, sortCol).toLowerCase();
      const bv = cell(b, sortCol).toLowerCase();
      if (av < bv) return -1 * sortDir;
      if (av > bv) return 1 * sortDir;
      const an = cell(a, 1).toLowerCase();
      const bn = cell(b, 1).toLowerCase();
      if (an < bn) return -1;
      if (an > bn) return 1;
      return 0;
    });
    return list;
  }
  function markHeaders() {
    table.querySelectorAll('th.sortable').forEach(th => {
      th.classList.remove('sort-asc', 'sort-desc');
      if (String(th.dataset.sort) === String(sortCol)) {
        th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
      }
    });
  }
  function apply() {
    printAll = false;
    const list = filtered();
    const size = Math.max(1, parseInt(sizeEl && sizeEl.value, 10) || 50);
    const pages = Math.max(1, Math.ceil(list.length / size));
    if (page > pages) page = pages;
    const start = (page - 1) * size;
    const visible = new Set(list.slice(start, start + size));
    rows.forEach(tr => { tr.style.display = visible.has(tr) ? '' : 'none'; });
    if (pagerEl) {
      pagerEl.innerHTML = '';
      const info = document.createElement('span');
      const from = list.length ? start + 1 : 0;
      const to = Math.min(start + size, list.length);
      info.textContent = from + '\u2013' + to + ' of ' + list.length;
      const prev = document.createElement('button');
      prev.type = 'button';
      prev.textContent = 'Prev';
      prev.disabled = page <= 1;
      prev.addEventListener('click', () => { page -= 1; apply(); });
      const next = document.createElement('button');
      next.type = 'button';
      next.textContent = 'Next';
      next.disabled = page >= pages;
      next.addEventListener('click', () => { page += 1; apply(); });
      pagerEl.appendChild(prev);
      pagerEl.appendChild(info);
      pagerEl.appendChild(next);
    }
    markHeaders();
  }
  function showAll() {
    printAll = true;
    const list = filtered();
    const vis = new Set(list);
    rows.forEach(tr => { tr.style.display = vis.has(tr) ? '' : 'none'; });
  }
  window.catalogApply = apply;
  window.catalogShowAll = showAll;
  if (filterEl) filterEl.addEventListener('input', () => { page = 1; apply(); });
  if (sortEl) sortEl.addEventListener('change', () => {
    sortCol = parseInt(sortEl.value, 10) || 0;
    sortDir = 1;
    page = 1;
    apply();
  });
  if (sizeEl) sizeEl.addEventListener('change', () => { page = 1; apply(); });
  table.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = parseInt(th.dataset.sort, 10);
      if (sortCol === col) sortDir = -sortDir;
      else { sortCol = col; sortDir = 1; }
      if (sortEl) sortEl.value = String(sortCol);
      page = 1;
      apply();
    });
  });
  apply();
})();
showTab((location.hash || '#overview').replace('#',''));
"""
