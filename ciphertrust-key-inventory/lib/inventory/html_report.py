from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

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
_STATE_COLORS = {
    "active": _PAL["pass"],
    "pre-active": _PAL["info"],
    "preactive": _PAL["info"],
    "deactivated": _PAL["warn"],
    "destroyed": _PAL["muted"],
    "compromised": _PAL["fail"],
    "destroyed-compromised": "#7c3aed",
}


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
    catalog_rows = _catalog_rows(report)
    vers_n = _n(totals.get("version_objects") or totals.get("keys"))
    life_n = sum(1 for r in catalog_rows if is_lifecycle(r))
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    estate = metrics.get("deks_total")
    estate_n = _n(estate) if estate is not None else None
    truncated = bool(report.get("truncated"))
    badge = "TRUNCATED" if truncated else (
        f"{estate_n} versions" if estate_n is not None else f"{vers_n} versions"
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
            result_label=str(estate_n if estate_n is not None else vers_n),
        ),
        "<div class='nav-label'>Categories</div>",
        _tab_button(
            "catalog",
            "Catalog",
            "WARN" if truncated else "MUTED",
            result_label=str(vers_n),
        ),
        _tab_button(
            "system",
            "System/Internal Use Keys",
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
            "WARN" if life_n else "MUTED",
            result_label=str(life_n),
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
        _tab_button("raw", "Raw", "MUTED", result_label="JSON"),
    ]
    panels = [
        _overview_panel(report),
        _catalog_panel(report),
        _system_panel(report),
        _akeyless_panel(report),
        _weak_panel(report),
        _cte_panel(report),
        _lifecycle_panel(report),
        _export_panel(report),
        _domains_panel(report),
        _raw_panel(report),
        _key_detail_panel(report),
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


_KEY_WRAP_AFTER = 67  # ks-<64 hex> stays on one line; longer names wrap


def _cell_key_class(name: Any) -> str:
    if len(str(name or "")) > _KEY_WRAP_AFTER:
        return "cell-key cell-key-long"
    return "cell-key"


def _owner_label(r: dict[str, Any]) -> str:
    return str(r.get("owner_name") or r.get("ownerId") or "")


def _cell_key(
    name: Any,
    inner: str | None = None,
    *,
    mismatch: bool = False,
    title: str | None = None,
) -> str:
    body = esc(name) if inner is None else inner
    extra = " cell-owner-diff" if mismatch else ""
    tip = title if title is not None else (_OWNER_DIFF_TITLE if mismatch else "")
    tip_attr = f" title='{esc(tip)}'" if tip else ""
    return f"<td class='{_cell_key_class(name)}{extra}'{tip_attr}>{body}</td>"


def _child_key_inner(name: str, *, mismatch: bool = False) -> str:
    cls = "row-child-name owner-diff-name" if mismatch else "row-child-name"
    return f"<span class='{cls}'>{esc(name)}</span>"


def _why_badge_class(reason: str) -> str:
    low = (reason or "").lower()
    if "older than 3" in low:
        return "fail"
    if "never rotated" in low or "older than 1" in low:
        return "warn"
    return "ok"


def _why_badges(reasons: list[str]) -> str:
    parts = [
        f"<span class='badge-n {_why_badge_class(reason)}' title='{esc(reason)}'>{esc(reason)}</span>"
        for reason in reasons
    ]
    return f"<div class='why-cell'>{''.join(parts)}</div>" if parts else ""


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


_SCOPE_APPLIANCE = "Appliance Wide"
_SCOPE_ACCESSIBLE = "From Accessible Domains"
_ACCOUNT_UUID_RE = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)


def _orphan_count(row: dict[str, Any]) -> int:
    return _n(
        row.get("orphaned_key_count")
        or row.get("orphaned_keys_count")
        or row.get("count")
        or row.get("keys")
    )


def _orphan_account_label(row: dict[str, Any]) -> str:
    raw = str(row.get("account") or row.get("name") or row.get("id") or "")
    match = _ACCOUNT_UUID_RE.search(raw)
    return match.group(1) if match else raw


def _prom_keys_by_domain(report: dict[str, Any]) -> dict[str, int]:
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    out: dict[str, int] = {}
    for d in metrics.get("deks_by_domain") or []:
        if not isinstance(d, dict):
            continue
        name = str(d.get("domain") or "").strip()
        if name:
            out[name.lower()] = _n(d.get("keys"))
    return out


def _cant_fetch() -> str:
    return "<span class='na'>Can't fetch</span>"


_TRUNC_TIP = (
    "Yes: the REST key list was cut short (usually --max-keys), so counts are incomplete. "
    "No: the full list was collected. "
    "Can't fetch: this account could not list the domain."
)
_VERSION_ID_TIP = (
    "CM version IDs start at 0. 0 is the first version of the key. "
    "1 is the next after the first rotation, and so on. "
    "This is the version number from the API, not a count of versions."
)


def _th_truncated() -> str:
    return (
        "Truncated "
        f"<span class='info-tip' title='{esc(_TRUNC_TIP)}' "
        "aria-label='What Truncated means'>i</span>"
    )


def _th_version_id(label: str = "Version ID") -> str:
    return _info_tip(label, _VERSION_ID_TIP)


def _info_tip(label: str, tip: str) -> str:
    return (
        f"{esc(label)} "
        f"<span class='info-tip' title='{esc(tip)}' "
        f"aria-label='{esc(label)} details'>i</span>"
    )


def _about_to_change_tip(window_days: int) -> str:
    return (
        f"Activation, deactivation, or ProtectStop date within {int(window_days)} days, "
        "or rotation due (rotationDateReached, or age at or past rotationFrequencyDays)."
    )


def _short_domain(name: str, limit: int = 16) -> str:
    s = str(name or "")
    if _ACCOUNT_UUID_RE.fullmatch(s):
        return s[:8]
    if len(s) <= limit:
        return s
    return s[: limit - 1] + "…"


def _short_name(name: str, limit: int = _KEY_WRAP_AFTER) -> str:
    s = str(name or "")
    if len(s) <= limit:
        return s
    return s[: limit - 1] + "…"


def _kpi(label: str, n: Any, cls: str, tip: str | None = None) -> str:
    lab = esc(label)
    if tip:
        lab += (
            f" <span class='info-tip' title='{esc(tip)}' "
            f"aria-label='{esc(label)} details'>i</span>"
        )
    return (
        f"<div class='kpi {esc(cls)}'><div class='n'>{esc(n)}</div>"
        f"<div class='l'>{lab}</div></div>"
    )


def _kpi_pair(left_label: str, left_n: Any, right_label: str, right_n: Any) -> str:
    return (
        "<div class='kpi kpi-pair'>"
        f"<div class='pair-side'><div class='n'>{esc(left_n)}</div>"
        f"<div class='l'>{esc(left_label)}</div></div>"
        "<div class='pair-rel' aria-hidden='true'>→</div>"
        f"<div class='pair-side'><div class='n'>{esc(right_n)}</div>"
        f"<div class='l'>{esc(right_label)}</div></div>"
        "</div>"
    )


def _kpi_group(title: str, inner: str) -> str:
    if not inner:
        return ""
    return (
        f"<div class='kpi-group'>"
        f"<h3 class='kpi-group-title'>{esc(title)}</h3>"
        f"<div class='kpis'>{inner}</div>"
        f"</div>"
    )


def _chart_box(cfg: dict) -> str:
    cid = esc(cfg.get("id"))
    height = _n(cfg.get("height")) or 220
    caption = cfg.get("caption")
    cap = f"<p class='chart-cap'>{esc(caption)}</p>" if caption else ""
    tips = cfg.get("tips") or []
    if tips:
        cap += f"<p class='chart-tips'>{' · '.join(str(t) for t in tips)}</p>"
    center_html = ""
    if cfg.get("type") == "doughnut":
        center_html = (
            "<div class='chart-center'>"
            f"<div class='chart-center-n'>{esc(cfg.get('center'))}</div>"
            f"<div class='chart-center-s'>{esc(cfg.get('centerSub') or '')}</div>"
            "</div>"
        )
    box_total = ""
    if cfg.get("type") == "bar" and cfg.get("values"):
        shown = sum(_n(v) for v in (cfg.get("values") or []))
        box_total = f"<span class='chart-box-total' data-chart='{cid}'>{shown}</span>"
    wide = " chart-box-wide" if cfg.get("wide") else ""
    n_bars = len(cfg.get("labels") or []) if cfg.get("scroll") else 0
    col_w = _n(cfg.get("colWidth")) or 96
    inner_w = max(400, col_w * n_bars) if cfg.get("scroll") else 0
    frame_cls = "chart-frame chart-frame-x" if cfg.get("scroll") else "chart-frame"
    canvas = f"<canvas id='{cid}'></canvas>"
    if cfg.get("scroll"):
        canvas = (
            f"<div class='chart-scroll' id='scroll-{cid}' "
            f"style='width:{inner_w}px'>{canvas}</div>"
        )
    return (
        f"<div class='chart-box{wide}' id='box-{cid}'>"
        f"<h3>{esc(cfg.get('title'))}{box_total}</h3>"
        f"{cap}"
        f"<div class='{frame_cls}' style='height:{height}px'>"
        f"{center_html}"
        f"{canvas}</div></div>"
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


def _version_num(row: dict[str, Any]) -> int:
    try:
        raw = row.get("version")
        if raw in (None, ""):
            return -1
        return int(raw)
    except (TypeError, ValueError):
        return -1


_OWNER_DIFF_TITLE = "Owner differs from version ID 0"
_OWNER_DIFF_ANY_TITLE = (
    "One or more versions have an owner different from version ID 0"
)


def _owner_id(r: dict[str, Any]) -> str:
    return str(r.get("ownerId") or "").strip()


def _row_name_key(r: dict[str, Any]) -> tuple[str, str]:
    return (str(r.get("domain") or ""), str(r.get("name") or r.get("id") or ""))


def _baseline_owner_id(vers: list[dict[str, Any]]) -> str:
    if not vers:
        return ""
    zero = next((v for v in vers if _version_num(v) == 0), None)
    if zero is not None:
        return _owner_id(zero)
    return _owner_id(
        min(vers, key=lambda v: n if (n := _version_num(v)) >= 0 else 10**9)
    )


def _owner_baselines(rows: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    return {
        key: _baseline_owner_id(vers) for key, vers in _group_by_key_name(rows)
    }


def _owner_mismatch(r: dict[str, Any], baseline: str) -> bool:
    return _owner_id(r) != baseline


def _any_owner_mismatch(
    vers: list[dict[str, Any]], baseline: str | None = None
) -> bool:
    base = _baseline_owner_id(vers) if baseline is None else baseline
    return any(_owner_mismatch(v, base) for v in vers)


def _td(value: Any, *, mismatch: bool = False) -> str:
    if mismatch:
        return (
            f"<td class='cell-owner-diff' title='{esc(_OWNER_DIFF_TITLE)}'>"
            f"{esc(value)}</td>"
        )
    return f"<td>{esc(value)}</td>"


def _group_by_key_name(
    rows: list[dict[str, Any]],
) -> list[tuple[tuple[str, str], list[dict[str, Any]]]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in rows:
        key = (str(r.get("domain") or ""), str(r.get("name") or r.get("id") or ""))
        groups.setdefault(key, []).append(r)
    return list(groups.items())


def _row_toggle(n: int) -> str:
    if n <= 1:
        return ""
    return (
        "<button type='button' class='row-toggle' "
        "aria-expanded='false' aria-label='Show versions'></button>"
    )


_EXPAND_VERSION_CAP = 5
_KEY_LINK_TITLE = "Open all versions in a new tab"


def _key_hash(domain: str, name: str) -> str:
    return f"#key/{quote(domain, safe='')}/{quote(name, safe='')}"


def _key_link(domain: str, name: str, text: str | None = None) -> str:
    label = name if text is None else text
    return (
        f"<a class='key-link' href='{esc(_key_hash(domain, name))}' "
        f"target='_blank' rel='noopener noreferrer' "
        f"title='{esc(_KEY_LINK_TITLE)}'>{esc(label)}</a>"
    )


def _key_name_inner(domain: str, name: str, n: int) -> str:
    label = _key_link(domain, name) if n > 1 else esc(name)
    count = f"<span class='key-ver-count'>{n} versions</span>" if n > 1 else ""
    return (
        f"<span class='key-name-stack'>"
        f"<span class='key-name-line'>{_row_toggle(n)}{label}</span>"
        f"{count}"
        f"</span>"
    )


def _versions_newest_first(vers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(vers, key=_version_num, reverse=True)


def _expand_child_versions(vers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _versions_newest_first(vers)[:_EXPAND_VERSION_CAP]


def _key_search_blob(vers: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for v in vers:
        label = _version_label(v)
        if label:
            parts.append(label)
        state = str(v.get("state") or "").strip()
        if state:
            parts.append(state)
    return " ".join(parts)


def _more_versions_row(domain: str, name: str, gid: str, n: int, rest_cols: int) -> str:
    if n <= _EXPAND_VERSION_CAP:
        return ""
    return (
        f"<tr class='row-child row-more' data-group='{esc(gid)}'>"
        "<td></td>"
        f"<td class='cell-more'>Showing {_EXPAND_VERSION_CAP} of {n} versions · "
        f"{_key_link(domain, name, 'View all versions')}</td>"
        f"<td colspan='{rest_cols}'></td>"
        "</tr>"
    )


def _version_label(row: dict[str, Any]) -> str:
    raw = row.get("version")
    if raw in (None, ""):
        return ""
    return str(raw)


def _overview_panel(report: dict[str, Any]) -> str:
    totals = report.get("totals") or {}
    domains = report.get("domains") or {}
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    estate = metrics.get("deks_total")
    orphans = report.get("orphans") if isinstance(report.get("orphans"), dict) else {}
    charts = _tab_charts(report).get("overview") or []
    chart_html = "".join(_chart_box(c) for c in charts)
    orphan_rows = []
    for a in orphans.get("orphaned_keys_by_account") or []:
        if not isinstance(a, dict):
            continue
        orphan_rows.append(
            "<tr>"
            f"<td>{esc(_orphan_account_label(a))}</td>"
            f"<td>{esc(_orphan_count(a))}</td>"
            "</tr>"
        )
    note = ""
    if report.get("truncated"):
        note = "<p class='caveat'>Catalog truncated by a key limit.</p>"
    collected = report.get("catalog_collected")
    shown = totals.get("keys")
    shown_objects = totals.get("version_objects", shown)
    if collected is not None and collected != shown_objects:
        note += (
            f"<p class='caveat'>Showing {esc(shown_objects)} of {esc(collected)} "
            "collected versions after filters.</p>"
        )
    skipped_n = _n(domains.get("skipped_count"))
    if skipped_n:
        note += (
            f"<p class='caveat'>{esc(skipped_n)} domain(s) skipped. "
            "Skipped is not an empty domain. "
            "Versions from accessible domains are only what this account could list; "
            f"total keys (including orphaned) is the {_SCOPE_APPLIANCE} count.</p>"
        )
    elif estate is not None and _n(estate) != _n(shown_objects):
        note += (
            "<p class='caveat'>Versions from accessible domains are only what this account could list; "
            f"total keys (including orphaned) is the {_SCOPE_APPLIANCE} count.</p>"
        )
    if _estate_overview_charts(metrics):
        note += (
            f"<p class='caveat'>Total keys, State, Algorithms, and Versions by domain "
            f"use the {_SCOPE_APPLIANCE} Prometheus DEK count. "
            f"Other charts use versions {_SCOPE_ACCESSIBLE.lower()}.</p>"
        )
    wide = ""
    if estate is not None:
        wide += _kpi("Total keys (including orphaned)", estate, "")
    if orphans.get("total_orphaned_keys_count"):
        wide += _kpi("Orphaned", orphans.get("total_orphaned_keys_count"), "warn")
    window = _n((report.get("options") or {}).get("window_days")) or 30
    due_lbl = due_soon_label(window)
    accessible = (
        f"{_kpi('Versions', totals.get('version_objects', totals.get('keys', 0)), '')}"
        f"{_kpi('System', totals.get('system', 0), 'info')}"
        f"{_kpi('Akeyless CF', totals.get('akeyless_cf', 0), 'info' if _n(totals.get('akeyless_cf')) else '')}"
        f"{_kpi('Weak', totals.get('weak', 0), 'warn' if _n(totals.get('weak')) else '')}"
        f"{_kpi('Inactive', totals.get('inactive', 0), 'warn' if _n(totals.get('inactive')) else '')}"
        f"{_kpi(due_lbl, totals.get('about_to_change', 0), '', _about_to_change_tip(window))}"
        f"{_kpi('Exportable', totals.get('exportable', 0), '')}"
        f"{_kpi('Never exported', totals.get('never_exported', 0), '')}"
        f"{_kpi('Never exportable', totals.get('never_exportable', 0), '')}"
        f"{_kpi('CTE', totals.get('cte', 0), 'info' if _n(totals.get('cte')) else '')}"
        f"{_kpi('LDT', totals.get('cte_ldt', 0), '')}"
        f"{_kpi('Standard', totals.get('cte_standard', 0), '')}"
        f"{_kpi('Domains checked', domains.get('checked_count', 0), '')}"
        f"{_kpi('Domains skipped', domains.get('skipped_count', 0), 'warn' if skipped_n else '')}"
    )
    return (
        "<section class='tab-panel' id='panel-overview' role='tabpanel'>"
        f"{_kpi_group(_SCOPE_APPLIANCE, wide)}"
        f"{_kpi_group(_SCOPE_ACCESSIBLE, accessible)}"
        f"{note}"
        f"<div class='charts'>{chart_html}</div>"
        f"{_table(['Deleted domain', 'Orphaned keys'], orphan_rows, 'Orphaned keys by account')}"
        "<p class='caveat'>CM orphaned-resources returns the deleted-domain ID and a key count only. "
        "It does not include key names.</p>"
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
            f"{_cell_key(r.get('name'))}"
            f"<td>{esc(r.get('system_kind'))}</td>"
            f"<td>{esc(r.get('service_name'))}</td>"
            f"<td>{esc(r.get('objectType'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            "</tr>"
        )

    return (
        "<section class='tab-panel' id='panel-system' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>System/Internal Use Keys</h2>"
        f"<span class='st MUTED'>{len(rows)} versions</span></div>"
        "<div class='summary'>Internal keys: citrus-* names, and ks-* names with a service name and no owner.</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_key_table(rows, ['Domain', 'Name', 'Kind', 'Service', 'Type', 'Algorithm', 'State'], cells, 'System keys')}"
        "</section>"
    )


def _akeyless_panel(report: dict[str, Any]) -> str:
    rows = [r for r in _catalog_rows(report) if r.get("akeyless_cf")]
    charts = _tab_charts(report).get("akeyless") or []
    baselines = _owner_baselines(_catalog_rows(report))

    def cells(r: dict) -> str:
        mismatch = _owner_mismatch(r, baselines.get(_row_name_key(r), ""))
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"{_cell_key(r.get('name'))}"
            f"<td>{esc(r.get('objectType'))}</td>"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            f"{_td(_owner_label(r), mismatch=mismatch)}"
            "</tr>"
        )

    return (
        "<section class='tab-panel' id='panel-akeyless' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Akeyless Customer Fragments</h2>"
        f"<span class='st MUTED'>{len(rows)} versions</span></div>"
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
            f"{_cell_key(r.get('name'))}"
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
        f"<span class='st {tone}'>{len(rows)} versions</span></div>"
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
    baselines = _owner_baselines(_catalog_rows(report))

    def cells(r: dict) -> str:
        mismatch = _owner_mismatch(r, baselines.get(_row_name_key(r), ""))
        return (
            "<tr>"
            f"<td>{esc(r.get('domain'))}</td>"
            f"{_cell_key(r.get('name'))}"
            f"<td>{esc(r.get('algorithm'))}</td>"
            f"<td>{esc(r.get('state'))}</td>"
            f"{_td(_version_label(r), mismatch=mismatch)}"
            f"<td>{esc(r.get('cte_encryption_mode'))}</td>"
            f"<td>{esc(_cte_versioned_label(r))}</td>"
            f"<td>{esc(r.get('cte_policy'))}</td>"
            f"{_td(_owner_label(r), mismatch=mismatch)}"
            "</tr>"
        )

    body = "".join(cells(r) for r in rows)
    table = (
        "<div class='card'><h3>CTE keys</h3>"
        "<div class='cat-toolbar'>"
        "<input id='cte-filter' type='search' placeholder='Filter CTE keys'/>"
        "<label>Sort "
        "<select id='cte-sort'>"
        "<option value='0'>Domain</option>"
        "<option value='1'>Key</option>"
        "<option value='7'>Policy</option>"
        "</select></label>"
        "<label>Rows "
        "<select id='cte-page-size'>"
        "<option value='25'>25</option>"
        "<option value='50' selected>50</option>"
        "<option value='100'>100</option>"
        "</select></label>"
        "<div id='cte-pager' class='cat-pager'></div>"
        "</div>"
        "<div class='table-wrap'><table id='cte-table'><thead><tr>"
        "<th data-sort='0' class='sortable'>Domain</th>"
        "<th data-sort='1' class='sortable'>Key</th>"
        f"<th>Algorithm</th><th>State</th><th>{_th_version_id()}</th>"
        "<th>Encryption mode</th><th>CTE versioned</th>"
        "<th data-sort='7' class='sortable'>Policy</th>"
        "<th>Owner</th>"
        "</tr></thead><tbody>"
        + body
        + "</tbody></table></div>"
        "<div class='cat-pager-bar'><div id='cte-pager-bottom' class='cat-pager'></div></div>"
        "</div>"
    )
    return (
        "<section class='tab-panel' id='panel-cte' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>CTE</h2>"
        f"<span class='st MUTED'>{len(rows)} versions</span></div>"
        "<div class='summary'>CipherTrust Transparent Encryption keys. "
        f"LDT Policy compatible {ldt_n}. "
        f"Standard policy compatible {std_n}.</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{table}"
        "</section>"
    )


def _lifecycle_panel(report: dict[str, Any]) -> str:
    window = _n((report.get("options") or {}).get("window_days")) or 30
    catalog = _catalog_rows(report)
    rows = [r for r in catalog if is_lifecycle(r)]
    charts = _tab_charts(report).get("lifecycle") or []
    tone = "WARN" if rows else "MUTED"
    life_names = {
        (str(r.get("domain") or ""), str(r.get("name") or r.get("id") or ""))
        for r in rows
    }
    groups = sorted(
        (
            item
            for item in _group_by_key_name(catalog)
            if item[0] in life_names
        ),
        key=lambda kv: (-len(kv[1]), kv[0][0].lower(), kv[0][1].lower()),
    )

    def why_union(vers: list[dict]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for v in vers:
            if not is_lifecycle(v):
                continue
            for reason in lifecycle_reasons(v, window):
                if reason not in seen:
                    seen.add(reason)
                    out.append(reason)
        return out

    body_parts: list[str] = []
    for i, ((domain, name), vers) in enumerate(groups):
        vers_sorted = sorted(vers, key=_version_num, reverse=True)
        top = vers_sorted[0]
        gid = f"lg{i}"
        n = len(vers)
        life_n = sum(1 for v in vers if is_lifecycle(v))
        baseline = _baseline_owner_id(vers)
        any_diff = _any_owner_mismatch(vers, baseline)
        top_mismatch = _owner_mismatch(top, baseline)
        body_parts.append(
            f"<tr class='row-group' data-group='{gid}' data-life-n='{life_n}' "
            f"data-versions='{n}' data-search='{esc(_key_search_blob(vers_sorted))}'>"
            f"<td>{esc(domain)}</td>"
            f"{_cell_key(name, _key_name_inner(domain, name, n), mismatch=any_diff, title=_OWNER_DIFF_ANY_TITLE if any_diff else None)}"
            f"<td>{esc(n)}</td>"
            f"<td>{esc(top.get('state'))}</td>"
            f"{_td(_version_label(top), mismatch=top_mismatch)}"
            f"{_td(_owner_label(top), mismatch=top_mismatch)}"
            f"<td>{esc(top.get('createdAt'))}</td>"
            f"<td>{esc(top.get('deactivationDate'))}</td>"
            f"<td>{esc(top.get('protectStopDate'))}</td>"
            f"<td class='cell-why'>{_why_badges(why_union(vers))}</td>"
            "</tr>"
        )
        if n > 1:
            for v in _expand_child_versions(vers_sorted):
                why = (
                    _why_badges(lifecycle_reasons(v, window))
                    if is_lifecycle(v)
                    else ""
                )
                mismatch = _owner_mismatch(v, baseline)
                body_parts.append(
                    f"<tr class='row-child' data-group='{gid}'>"
                    "<td></td>"
                    f"{_cell_key(name, _child_key_inner(name, mismatch=mismatch), mismatch=mismatch)}"
                    "<td></td>"
                    f"<td>{esc(v.get('state'))}</td>"
                    f"{_td(_version_label(v), mismatch=mismatch)}"
                    f"{_td(_owner_label(v), mismatch=mismatch)}"
                    f"<td>{esc(v.get('createdAt'))}</td>"
                    f"<td>{esc(v.get('deactivationDate'))}</td>"
                    f"<td>{esc(v.get('protectStopDate'))}</td>"
                    f"<td class='cell-why'>{why}</td>"
                    "</tr>"
                )
            body_parts.append(_more_versions_row(domain, name, gid, n, 8))

    n_vers = len(rows)
    table = (
        "<div class='card'><h3>Lifecycle</h3>"
        "<p class='table-hint'>Expand shows the 5 newest versions. Open a key name for the full list.</p>"
        "<div class='cat-toolbar'>"
        "<input id='life-filter' type='search' placeholder='Filter lifecycle'/>"
        "<label>Sort "
        "<select id='life-sort'>"
        "<option value='2' selected>Versions</option>"
        "<option value='0'>Domain</option>"
        "<option value='1'>Key</option>"
        "<option value='3'>State</option>"
        "</select></label>"
        "<label>Rows "
        "<select id='life-page-size'>"
        "<option value='25'>25</option>"
        "<option value='50' selected>50</option>"
        "<option value='100'>100</option>"
        "</select></label>"
        "<div id='life-pager' class='cat-pager'></div>"
        "</div>"
        "<div class='table-wrap'><table id='life-table' data-sort-dir='desc'><thead><tr>"
        "<th data-sort='0' class='sortable'>Domain</th>"
        "<th data-sort='1' class='sortable'>Key</th>"
        "<th data-sort='2' class='sortable'>Versions</th>"
        "<th data-sort='3' class='sortable'>State</th>"
        f"<th>{_th_version_id()}</th><th>Owner</th><th>Created</th><th>Deactivate</th>"
        "<th>Protect-stop</th><th>Why</th>"
        "</tr></thead><tbody>"
        + "".join(body_parts)
        + "</tbody></table></div>"
        "<div class='cat-pager-bar'><div id='life-pager-bottom' class='cat-pager'></div></div>"
        "</div>"
    )
    return (
        "<section class='tab-panel' id='panel-lifecycle' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Lifecycle</h2>"
        f"<span class='st {tone}'>{esc(n_vers)} versions</span></div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{table}"
        "</section>"
    )


def _is_export_hit(r: dict[str, Any]) -> bool:
    return bool(
        r.get("exportable")
        or r.get("deletable")
        or r.get("neverExported")
        or r.get("neverExportable")
    )


def _export_attr_cells(r: dict[str, Any], *, mismatch: bool = False) -> str:
    return (
        f"<td>{esc(r.get('algorithm'))}</td>"
        f"<td>{esc(r.get('state'))}</td>"
        f"{_td(_version_label(r), mismatch=mismatch)}"
        f"{_td(_owner_label(r), mismatch=mismatch)}"
        f"<td>{'yes' if r.get('exportable') else 'no'}</td>"
        f"<td>{'yes' if r.get('deletable') else 'no'}</td>"
        f"<td>{esc(r.get('neverExported'))}</td>"
        f"<td>{esc(r.get('neverExportable'))}</td>"
    )


def _export_panel(report: dict[str, Any]) -> str:
    catalog = _catalog_rows(report)
    exportable = [r for r in catalog if r.get("exportable")]
    deletable = [r for r in catalog if r.get("deletable")]
    never_exp = [r for r in catalog if r.get("neverExported")]
    never_able = [r for r in catalog if r.get("neverExportable")]
    charts = _tab_charts(report).get("export") or []
    hit_names = {
        (str(r.get("domain") or ""), str(r.get("name") or r.get("id") or ""))
        for r in catalog
        if _is_export_hit(r)
    }
    groups = sorted(
        (item for item in _group_by_key_name(catalog) if item[0] in hit_names),
        key=lambda kv: (-len(kv[1]), kv[0][0].lower(), kv[0][1].lower()),
    )
    body_parts: list[str] = []
    for i, ((domain, name), vers) in enumerate(groups):
        vers_sorted = _versions_newest_first(vers)
        top = vers_sorted[0]
        n = len(vers)
        match_n = sum(1 for v in vers if _is_export_hit(v))
        gid = f"eg{i}"
        baseline = _baseline_owner_id(vers)
        any_diff = _any_owner_mismatch(vers, baseline)
        body_parts.append(
            f"<tr class='row-group' data-group='{gid}' data-match-n='{match_n}' "
            f"data-versions='{n}' data-search='{esc(_key_search_blob(vers_sorted))}'>"
            f"<td>{esc(domain)}</td>"
            f"{_cell_key(name, _key_name_inner(domain, name, n), mismatch=any_diff, title=_OWNER_DIFF_ANY_TITLE if any_diff else None)}"
            f"<td>{esc(n)}</td>"
            f"{_export_attr_cells(top, mismatch=_owner_mismatch(top, baseline))}"
            "</tr>"
        )
        if n > 1:
            for v in _expand_child_versions(vers_sorted):
                mismatch = _owner_mismatch(v, baseline)
                body_parts.append(
                    f"<tr class='row-child' data-group='{gid}'>"
                    "<td></td>"
                    f"{_cell_key(name, _child_key_inner(name, mismatch=mismatch), mismatch=mismatch)}"
                    "<td></td>"
                    f"{_export_attr_cells(v, mismatch=mismatch)}"
                    "</tr>"
                )
            body_parts.append(_more_versions_row(domain, name, gid, n, 9))
    table = (
        "<div class='card'><h3>Export attributes</h3>"
        "<p class='table-hint'>Expand shows the 5 newest versions. Open a key name for the full list.</p>"
        "<div class='cat-toolbar'>"
        "<input id='exp-filter' type='search' placeholder='Filter export / delete'/>"
        "<label>Sort "
        "<select id='exp-sort'>"
        "<option value='2' selected>Versions</option>"
        "<option value='0'>Domain</option>"
        "<option value='1'>Key</option>"
        "<option value='4'>State</option>"
        "</select></label>"
        "<label>Rows "
        "<select id='exp-page-size'>"
        "<option value='25'>25</option>"
        "<option value='50' selected>50</option>"
        "<option value='100'>100</option>"
        "</select></label>"
        "<div id='exp-pager' class='cat-pager'></div>"
        "</div>"
        "<div class='table-wrap'><table id='exp-table' data-sort-dir='desc'><thead><tr>"
        "<th data-sort='0' class='sortable'>Domain</th>"
        "<th data-sort='1' class='sortable'>Key</th>"
        "<th data-sort='2' class='sortable'>Versions</th>"
        "<th>Algorithm</th>"
        "<th data-sort='4' class='sortable'>State</th>"
        f"<th>{_th_version_id()}</th>"
        "<th>Owner</th>"
        "<th>Exportable</th><th>Deletable</th>"
        "<th>Never exported</th><th>Never exportable</th>"
        "</tr></thead><tbody>"
        + "".join(body_parts)
        + "</tbody></table></div>"
        "<div class='cat-pager-bar'><div id='exp-pager-bottom' class='cat-pager'></div></div>"
        "</div>"
    )
    return (
        "<section class='tab-panel' id='panel-export' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Export / Delete</h2></div>"
        f"<div class='summary'>Exportable {len(exportable)} · Deletable {len(deletable)} · Never exported {len(never_exp)} · Never exportable {len(never_able)}</div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{table}"
        "</section>"
    )


def _domains_panel(report: dict[str, Any]) -> str:
    domains = report.get("domains") or {}
    charts = _tab_charts(report).get("domains") or []
    checked_rows = []
    version_n = 0
    for d in domains.get("checked") or []:
        if not isinstance(d, dict):
            continue
        version_n += _n(d.get("version_objects") or d.get("raw"))
        trunc = "yes" if d.get("truncated") else "no"
        checked_rows.append(
            "<tr>"
            f"<td>{esc(d.get('domain'))}</td>"
            f"<td>{esc(d.get('version_objects') or d.get('raw'))}</td>"
            f"<td>{esc(trunc)}</td>"
            "</tr>"
        )
    skip_items = [
        d
        for d in (domains.get("skipped") or []) + (domains.get("errors") or [])
        if isinstance(d, dict)
    ]
    prom = _prom_keys_by_domain(report)
    has_prom = bool(prom) or (
        isinstance(report.get("metrics"), dict)
        and report["metrics"].get("deks_total") is not None
    )
    skip_items.sort(
        key=lambda d: (
            -_n(prom.get(str(d.get("domain") or "").lower())),
            str(d.get("domain") or ""),
        )
    )
    skip_keys = 0
    skip_rows = []
    na = _cant_fetch()
    for d in skip_items:
        name = str(d.get("domain") or "")
        if has_prom:
            keys = _n(prom.get(name.lower()))
            skip_keys += keys
            keys_cell = esc(keys)
        else:
            keys_cell = na
        skip_rows.append(
            "<tr>"
            f"<td>{esc(name)}</td>"
            f"<td>{keys_cell}</td>"
            f"<td>{na}</td>"
            "</tr>"
        )
    skip_note = ""
    if skip_rows:
        skip_note = (
            "<p class='caveat'>Could not list these domains over REST.</p>"
        )
    return (
        "<section class='tab-panel' id='panel-domains' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Domains</h2>"
        f"<span class='st MUTED'>{esc(version_n)} versions</span></div>"
        "</div>"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{_table(['Domain', 'Versions', _th_truncated()], checked_rows, 'Accessible domains')}"
        f"{_table(['Domain', 'Versions', _th_truncated()], skip_rows, 'Skipped or error')}"
        f"{skip_note}"
        "</section>"
    )


def _catalog_version_cells(r: dict[str, Any], *, mismatch: bool = False) -> str:
    weak_cls = "fail" if r.get("weak") else "ok"
    sys_cls = "warn" if r.get("system") else "ok"
    return (
        f"<td>{esc(r.get('algorithm'))}</td>"
        f"<td>{esc(r.get('size'))}</td>"
        f"<td>{esc(r.get('curve'))}</td>"
        f"<td>{esc(r.get('objectType'))}</td>"
        f"<td>{esc(r.get('state'))}</td>"
        f"{_td(_version_label(r), mismatch=mismatch)}"
        f"<td><span class='badge-n {sys_cls}'>{'yes' if r.get('system') else 'no'}</span></td>"
        f"<td>{'yes' if r.get('akeyless_cf') else 'no'}</td>"
        f"<td><span class='badge-n {weak_cls}'>{esc(r.get('weak_reason') or ('yes' if r.get('weak') else 'no'))}</span></td>"
        f"<td>{'yes' if r.get('cte') else 'no'}</td>"
        f"<td>{esc(r.get('cte_policy'))}</td>"
        f"<td>{'yes' if r.get('exportable') else 'no'}</td>"
        f"<td>{'yes' if r.get('deletable') else 'no'}</td>"
        f"{_td(_owner_label(r), mismatch=mismatch)}"
        f"<td>{esc(r.get('service_name'))}</td>"
        f"<td>{esc(r.get('createdAt'))}</td>"
    )


def _catalog_panel(report: dict[str, Any]) -> str:
    rows = _catalog_rows(report)
    totals = report.get("totals") or {}
    charts = _tab_charts(report).get("catalog") or []
    groups = sorted(
        _group_by_key_name(rows),
        key=lambda kv: (-len(kv[1]), kv[0][0].lower(), kv[0][1].lower()),
    )
    body_parts: list[str] = []
    for i, ((domain, name), vers) in enumerate(groups):
        vers_sorted = sorted(vers, key=_version_num, reverse=True)
        top = vers_sorted[0]
        n = len(vers)
        gid = f"cg{i}"
        baseline = _baseline_owner_id(vers)
        any_diff = _any_owner_mismatch(vers, baseline)
        body_parts.append(
            f"<tr class='row-group' data-group='{gid}' data-versions='{n}' "
            f"data-search='{esc(_key_search_blob(vers_sorted))}'>"
            f"<td>{esc(domain)}</td>"
            f"{_cell_key(name, _key_name_inner(domain, name, n), mismatch=any_diff, title=_OWNER_DIFF_ANY_TITLE if any_diff else None)}"
            f"<td>{esc(n)}</td>"
            f"{_catalog_version_cells(top, mismatch=_owner_mismatch(top, baseline))}"
            "</tr>"
        )
        if n > 1:
            for v in _expand_child_versions(vers_sorted):
                mismatch = _owner_mismatch(v, baseline)
                body_parts.append(
                    f"<tr class='row-child' data-group='{gid}'>"
                    "<td></td>"
                    f"{_cell_key(name, _child_key_inner(name, mismatch=mismatch), mismatch=mismatch)}"
                    "<td></td>"
                    f"{_catalog_version_cells(v, mismatch=mismatch)}"
                    "</tr>"
                )
            body_parts.append(_more_versions_row(domain, name, gid, n, 17))
    kpis = (
        f"<div class='kpis kpis-tight'>{_kpi_pair('Key names', totals.get('keys', 0), 'Version objects', totals.get('version_objects', len(rows)))}</div>"
        "<div class='kpis kpis-tight kpis-versions'>"
        f"{_kpi('Keys with 1 version', totals.get('keys_one_version', 0), '')}"
        f"{_kpi('Keys with 2 versions', totals.get('keys_two_versions', 0), '')}"
        f"{_kpi('Keys with 3 versions', totals.get('keys_three_versions', 0), '')}"
        f"{_kpi('Keys with 3+ versions', totals.get('keys_four_plus', 0), '')}"
        "</div>"
    )
    headers = [
        ("Domain", 0),
        ("Key", 1),
        ("Versions", 2),
        ("Algorithm", 3),
        ("Size", None),
        ("Curve", None),
        ("Type", None),
        ("State", 7),
        (_th_version_id(), None),
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
    table = (
        "<div class='card'><h3>Catalog</h3>"
        "<p class='table-hint'>Domain and key stay on the left. Scroll sideways for flags, owner, and dates. "
        "Expand shows the 5 newest versions. Open a key name for the full list. "
        "The key name is red if any version’s owner differs from version ID 0. "
        "That version’s Key, Version ID, and Owner are also red.</p>"
        "<div class='cat-toolbar'>"
        "<input id='cat-filter' type='search' placeholder='Filter catalog'/>"
        "<label>Sort "
        "<select id='cat-sort'>"
        "<option value='2' selected>Versions</option>"
        "<option value='0'>Domain</option>"
        "<option value='1'>Key</option>"
        "<option value='3'>Algorithm</option>"
        "<option value='7'>State</option>"
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
        "<div class='table-wrap'><table id='cat-table' data-sort-dir='desc'><thead><tr>"
        + "".join(th_parts)
        + "</tr></thead><tbody>"
        + "".join(body_parts)
        + "</tbody></table></div>"
        "<div class='cat-pager-bar'><div id='cat-pager-bottom' class='cat-pager'></div></div>"
        "</div>"
    )
    return (
        "<section class='tab-panel' id='panel-catalog' role='tabpanel' hidden>"
        "<div class='panel-head'><div class='head-row'><h2>Catalog</h2>"
        f"<span class='st MUTED'>{esc(len(rows))} versions</span></div>"
        "</div>"
        f"{kpis}"
        f"<div class='charts'>{''.join(_chart_box(c) for c in charts)}</div>"
        f"{table}"
        "</section>"
    )


def _key_detail_panel(report: dict[str, Any]) -> str:
    groups = sorted(
        (
            item
            for item in _group_by_key_name(_catalog_rows(report))
            if len(item[1]) > 1
        ),
        key=lambda kv: (-len(kv[1]), kv[0][0].lower(), kv[0][1].lower()),
    )
    articles: list[str] = []
    for (domain, name), vers in groups:
        ordered = _versions_newest_first(vers)
        n = len(ordered)
        baseline = _baseline_owner_id(vers)
        any_diff = _any_owner_mismatch(vers, baseline)
        h2_cls = " class='owner-diff-name'" if any_diff else ""
        rows = []
        for v in ordered:
            mismatch = _owner_mismatch(v, baseline)
            rows.append(
                "<tr>"
                f"<td>{esc(v.get('domain') or domain)}</td>"
                f"{_cell_key(v.get('name') or name, mismatch=mismatch)}"
                f"{_catalog_version_cells(v, mismatch=mismatch)}"
                "</tr>"
            )
        articles.append(
            f"<article class='key-page' hidden data-domain='{esc(domain)}' "
            f"data-name='{esc(name)}'>"
            "<div class='panel-head'><div class='head-row'>"
            f"<h2{h2_cls}>{esc(name)}</h2>"
            f"<span class='st MUTED'>{n} versions</span></div>"
            f"<div class='summary'>Domain {esc(domain)}. Every version object for this key, newest first. "
            "Version ID is 0-based (0 = first version). "
            "A version whose owner differs from version ID 0 is shown in red.</div></div>"
            "<div class='card'>"
            "<p class='table-hint'><a class='key-back' href='#catalog'>Back to Catalog</a></p>"
            "<div class='table-wrap'><table><thead><tr>"
            "<th>Domain</th><th>Key</th><th>Algorithm</th><th>Size</th><th>Curve</th>"
            "<th>Type</th><th>State</th>"
            f"<th>{_th_version_id()}</th>"
            "<th>System</th><th>Akeyless CF</th><th>Weak</th><th>CTE</th><th>Policy</th>"
            "<th>Exportable</th><th>Deletable</th><th>Owner</th><th>Service</th>"
            "<th>Created</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div></div></article>"
        )
    return (
        "<section class='tab-panel' id='panel-key' role='tabpanel' hidden>"
        + "".join(articles)
        + "<div id='key-missing' class='card' hidden><p>This key is not in the report.</p>"
        "<p class='table-hint'><a class='key-back' href='#catalog'>Back to Catalog</a></p></div>"
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


def _norm_state(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(name or "").strip().lower()).strip("-")


def _state_color(name: str, index: int = 0) -> str:
    return _STATE_COLORS.get(_norm_state(name), _SLICE[index % len(_SLICE)])


def _unique_colors(colors: list[str]) -> list[str]:
    if len(colors) <= 1:
        return colors
    used: set[str] = set()
    out: list[str] = []
    si = 0
    for color in colors:
        if color not in used:
            out.append(color)
            used.add(color)
            continue
        nxt = color
        for _ in range(len(_SLICE) * 2):
            cand = _SLICE[si % len(_SLICE)]
            si += 1
            if cand not in used:
                nxt = cand
                break
        out.append(nxt)
        used.add(nxt)
    return out


def _doughnut(
    slug: str,
    title: str,
    pairs: list[tuple[str, Any, str]],
    center_sub: str,
    *,
    include_count: bool = True,
    tooltip_value_unit: str | None = None,
) -> dict | None:
    labels, values, colors = [], [], []
    for label, val, color in pairs:
        n = _n(val)
        if n <= 0:
            continue
        labels.append(f"{label}  {n}" if include_count else str(label))
        values.append(n)
        colors.append(color)
    if not values:
        return None
    colors = _unique_colors(colors)
    out = {
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
    if tooltip_value_unit:
        out["tooltipValueUnit"] = tooltip_value_unit
    return out


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


def _barh(
    slug: str,
    title: str,
    labels: list[str],
    values: list[int],
    color: str,
    colors: list[str] | None = None,
    *,
    full_labels: list[str] | None = None,
    wide: bool = False,
) -> dict | None:
    if not labels or not any(values):
        return None
    shown = [str(x or "") for x in labels]
    full = [str(x or "") for x in (full_labels or labels)]
    key_labels = full_labels is not None
    cfg: dict[str, Any] = {
        "id": f"ch-{slug}",
        "type": "bar",
        "title": title,
        "labels": shown,
        "fullLabels": full,
        "values": values,
        "colors": colors or [color],
        "keyLabels": key_labels,
        "height": max(180, 28 * len(shown) + 40),
    }
    if wide:
        cfg["wide"] = True
    return cfg


def _barv(slug: str, title: str, labels: list[str], values: list[int], color: str) -> dict | None:
    if not labels or not any(values):
        return None
    return {
        "id": f"ch-{slug}",
        "type": "bar",
        "indexAxis": "x",
        "title": title,
        "labels": labels,
        "shortLabels": [_short_domain(x) for x in labels],
        "values": values,
        "colors": [color],
        "height": 320,
        "wide": True,
        "scroll": True,
        "colWidth": 96,
    }


def _bar_group(
    slug: str,
    title: str,
    labels: list[str],
    series: list[dict[str, Any]],
) -> dict | None:
    if not labels or not series:
        return None
    if not any(any(_n(v) for v in (ds.get("values") or [])) for ds in series):
        return None
    return {
        "id": f"ch-{slug}",
        "type": "bar",
        "indexAxis": "x",
        "title": title,
        "labels": labels,
        "shortLabels": [_short_domain(x) for x in labels],
        "datasets": series,
        "grouped": True,
        "height": 320,
        "wide": True,
        "scroll": True,
        "colWidth": 108,
    }


def _keys_by_domain_series(report: dict[str, Any]) -> tuple[list[str], list[int], str]:
    totals = report.get("totals") or {}
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    if _estate_overview_charts(metrics) and metrics.get("deks_by_domain"):
        pairs: list[tuple[str, int]] = []
        for d in metrics.get("deks_by_domain") or []:
            if not isinstance(d, dict):
                continue
            name = str(d.get("domain") or "")
            n = _n(d.get("keys"))
            if not name or n <= 0:
                continue
            pairs.append((name, n))
        pairs.sort(key=lambda p: (-p[1], p[0]))
        return [p[0] for p in pairs], [p[1] for p in pairs], _SCOPE_APPLIANCE
    domain_items = [
        d for d in (totals.get("by_domain") or []) if isinstance(d, dict)
    ]
    domain_items.sort(
        key=lambda d: (
            -_n(d.get("version_objects") or d.get("keys")),
            str(d.get("domain") or ""),
        ),
    )
    return (
        [str(d.get("domain") or "") for d in domain_items],
        [_n(d.get("version_objects") or d.get("keys")) for d in domain_items],
        _SCOPE_ACCESSIBLE,
    )


def _estate_overview_charts(metrics: dict[str, Any] | None) -> bool:
    if not isinstance(metrics, dict) or metrics.get("deks_total") is None:
        return False
    return bool(
        metrics.get("deks_by_state")
        or metrics.get("deks_by_algorithm")
        or metrics.get("deks_by_domain")
    )


def _caption(cfg: dict | None, text: str) -> dict | None:
    if cfg and text:
        cfg["caption"] = text
    return cfg


def _tab_charts(report: dict[str, Any]) -> dict[str, list[dict]]:
    totals = report.get("totals") or {}
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    catalog = _catalog_rows(report)
    window = _n((report.get("options") or {}).get("window_days")) or 30
    estate_charts = _estate_overview_charts(metrics)
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
    user_n = max(0, _n(totals.get("version_objects")) - _n(totals.get("system")) - cf_n)
    ownership = [
        ("System", totals.get("system"), _PAL["info"]),
        ("App/User", user_n, _PAL["pass"]),
    ]
    if cf_n:
        ownership.append(("Akeyless CF", cf_n, "#7c3aed"))
    add(
        "overview",
        _caption(
            _doughnut(
                "ov-system",
                "System vs App/User",
                ownership,
                "versions",
            ),
            _SCOPE_ACCESSIBLE,
        ),
    )
    weak_n = _n(totals.get("weak"))
    add(
        "overview",
        _caption(
            _doughnut(
                "ov-weak",
                "Weak keys",
                [("Weak", weak_n, _PAL["fail"])],
                "versions",
            )
            if weak_n
            else _zero_doughnut("ov-weak", "Weak keys", "Weak", "versions"),
            _SCOPE_ACCESSIBLE,
        ),
    )
    state_src = metrics.get("deks_by_state") if estate_charts else totals.get("by_state")
    state_pairs = [
        (name, n, _state_color(str(name), i))
        for i, (name, n) in enumerate((state_src or {}).items())
    ]
    add(
        "overview",
        _caption(
            _doughnut(
                "ov-state",
                "State",
                state_pairs,
                "estate" if estate_charts else "versions",
            ),
            _SCOPE_APPLIANCE if estate_charts else _SCOPE_ACCESSIBLE,
        ),
    )
    cte_n = _n(totals.get("cte"))
    add(
        "overview",
        _caption(
            _doughnut(
                "ov-cte",
                "CTE",
                [
                    ("LDT", totals.get("cte_ldt"), _PAL["info"]),
                    ("Standard", totals.get("cte_standard"), _PAL["pass"]),
                ],
                "versions",
            )
            if cte_n
            else _zero_doughnut("ov-cte", "CTE", "CTE", "versions"),
            _SCOPE_ACCESSIBLE,
        ),
    )
    if estate_charts and metrics.get("deks_by_algorithm"):
        alg_items = list((metrics.get("deks_by_algorithm") or {}).items())[:12]
        alg_cap = _SCOPE_APPLIANCE
    else:
        alg_items = list((totals.get("by_algorithm") or {}).items())[:12]
        alg_cap = _SCOPE_ACCESSIBLE
    add(
        "overview",
        _caption(
            _barh(
                "ov-alg",
                "Algorithms",
                [str(k) for k, _ in alg_items],
                [_n(v) for _, v in alg_items],
                _PAL["info"],
            ),
            alg_cap,
        ),
    )
    domain_labels, domain_vals, domain_cap = _keys_by_domain_series(report)
    add(
        "overview",
        _caption(
            _barv(
                "ov-dom",
                "Versions by domain",
                domain_labels,
                domain_vals,
                _PAL["info"],
            ),
            domain_cap,
        ),
    )
    add(
        "domains",
        _caption(
            _barv(
                "dom-keys",
                "Versions by domain",
                domain_labels,
                domain_vals,
                _PAL["info"],
            ),
            domain_cap,
        ),
    )
    checked_doms = [
        d
        for d in ((report.get("domains") or {}).get("checked") or [])
        if isinstance(d, dict) and str(d.get("domain") or "")
    ]
    checked_doms.sort(
        key=lambda d: (
            -_n(d.get("version_objects") or d.get("raw")),
            -_n(d.get("unique")),
            str(d.get("domain") or ""),
        )
    )
    name_groups = sorted(
        _group_by_key_name(catalog),
        key=lambda kv: (-len(kv[1]), kv[0][0].lower(), kv[0][1].lower()),
    )
    bucket = {"1": 0, "2": 0, "3–5": 0, "6–10": 0, "11+": 0}
    for _key, vers in name_groups:
        n = len(vers)
        if n <= 1:
            bucket["1"] += 1
        elif n == 2:
            bucket["2"] += 1
        elif n <= 5:
            bucket["3–5"] += 1
        elif n <= 10:
            bucket["6–10"] += 1
        else:
            bucket["11+"] += 1
    add(
        "catalog",
        _doughnut(
            "kver-bucket",
            "Keys by version count",
            [
                ("1 version", bucket["1"], _PAL["pass"]),
                ("2 versions", bucket["2"], _PAL["info"]),
                ("3–5 versions", bucket["3–5"], _PAL["warn"]),
                ("6–10 versions", bucket["6–10"], "#7c3aed"),
                ("11+ versions", bucket["11+"], _PAL["fail"]),
            ],
            "keys",
            include_count=False,
            tooltip_value_unit="keys",
        ),
    )
    top = [item for item in name_groups if len(item[1]) >= 2][:15]
    if top:
        add(
            "catalog",
            _caption(
                _barh(
                    "kver-top",
                    "Most versions",
                    [name for (_dom, name), _vers in top],
                    [len(vers) for _key, vers in top],
                    _PAL["info"],
                    full_labels=[name for (_dom, name), _vers in top],
                    wide=True,
                ),
                _SCOPE_ACCESSIBLE,
            ),
        )
    add(
        "catalog",
        _caption(
            _bar_group(
                "kver-uv",
                "Key names vs version objects by domain",
                [str(d.get("domain") or "") for d in checked_doms],
                [
                    {
                        "label": "Key names",
                        "values": [_n(d.get("unique")) for d in checked_doms],
                        "color": _PAL["info"],
                    },
                    {
                        "label": "Version objects",
                        "values": [
                            _n(d.get("version_objects") or d.get("raw"))
                            for d in checked_doms
                        ],
                        "color": _PAL["pass"],
                    },
                ],
            ),
            f"{_SCOPE_ACCESSIBLE}. A new key has 1 version (version ID 0). "
            "Equal bars = no rotations. Taller green = some names have been rotated.",
        ),
    )

    kind_items = list((totals.get("by_system_kind") or {}).items())
    add(
        "system",
        _caption(
            _doughnut(
                "sys-kind",
                "System kind",
                [(str(k), v, _PAL["info"]) for k, v in kind_items],
                "system",
            ),
            _SCOPE_ACCESSIBLE,
        ),
    )

    cf_dom: dict[str, int] = {}
    for r in catalog:
        if r.get("akeyless_cf"):
            name = str(r.get("domain") or "unknown")
            cf_dom[name] = cf_dom.get(name, 0) + 1
    add(
        "akeyless",
        _caption(
            _doughnut(
                "cf-dom",
                "By domain",
                [(k, v, _PAL["info"]) for k, v in cf_dom.items()],
                "Akeyless CF",
            )
            if cf_dom
            else _zero_doughnut("cf-dom", "By domain", "Akeyless CF", "Akeyless CF"),
            _SCOPE_ACCESSIBLE,
        ),
    )

    weak_alg: dict[str, int] = {}
    for r in catalog:
        if r.get("weak"):
            weak_alg[str(r.get("algorithm") or "unknown")] = weak_alg.get(
                str(r.get("algorithm") or "unknown"), 0
            ) + 1
    add(
        "weak",
        _caption(
            _doughnut(
                "weak-alg",
                "Weak by algorithm",
                [(k, v, _PAL["fail"]) for k, v in weak_alg.items()],
                "weak",
            ),
            _SCOPE_ACCESSIBLE,
        ),
    )

    cte_mode: dict[str, int] = {}
    cte_ldt_v = 0
    cte_std_v = 0
    for r in catalog:
        if not r.get("cte"):
            continue
        mode = str(r.get("cte_encryption_mode") or "unknown")
        cte_mode[mode] = cte_mode.get(mode, 0) + 1
        if r.get("cte_policy") == "LDT":
            cte_ldt_v += 1
        else:
            cte_std_v += 1
    add(
        "cte",
        _caption(
            _doughnut(
                "cte-policy",
                "LDT vs Standard",
                [
                    ("LDT", cte_ldt_v, _PAL["info"]),
                    ("Standard", cte_std_v, _PAL["pass"]),
                ],
                "versions",
            ),
            _SCOPE_ACCESSIBLE,
        ),
    )
    add(
        "cte",
        _caption(
            _doughnut(
                "cte-mode",
                "Encryption mode",
                [(k, v, _PAL["info"]) for k, v in cte_mode.items()],
                "versions",
            ),
            _SCOPE_ACCESSIBLE,
        ),
    )

    life_rows = [r for r in catalog if is_lifecycle(r)]
    life_inactive = sum(1 for r in life_rows if r.get("inactive"))
    life_about = sum(1 for r in life_rows if r.get("about_to_change"))
    life_old = sum(
        1
        for r in life_rows
        if (r.get("never_rotated") and r.get("older_than_1y")) or r.get("older_than_3y")
    )
    life_chart = _caption(
        _barh(
            "life-mix",
            "Lifecycle mix",
            ["Inactive", "Activate, deactivate, ProtectStop, rotate", "Old / never rotated"],
            [life_inactive, life_about, life_old],
            _PAL["warn"],
            colors=[_PAL["warn"], _PAL["info"], _PAL["muted"]],
        ),
        _SCOPE_ACCESSIBLE,
    )
    if life_chart:
        life_chart["tips"] = [
            _info_tip("Activate, deactivate, ProtectStop, rotate", _about_to_change_tip(window))
        ]
    add("lifecycle", life_chart)
    add(
        "export",
        _caption(
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
            _SCOPE_ACCESSIBLE,
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
.kpi-group { margin: 0 0 18px; }
.kpi-group-title {
  margin: 0 0 8px; font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
}
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 0; }
.kpis-tight { margin: 0 0 18px; }
.kpis-versions { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.kpi { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; min-width: 0; overflow: hidden; }
.kpi .n { font-size: 26px; font-weight: 700; }
.kpi .l { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; overflow-wrap: anywhere; }
.kpi-pair {
  display: flex; align-items: flex-end; gap: 14px;
  grid-column: span 2; max-width: 360px;
}
.kpis-tight > .kpi-pair { grid-column: auto; max-width: none; }
.kpi-pair .pair-side { min-width: 0; }
.kpi-pair .pair-rel {
  color: var(--muted); font-size: 22px; font-weight: 600; line-height: 1;
  padding-bottom: 16px;
}
.kpi.crit .n { color: var(--fail); }
.kpi.warn .n { color: var(--warn); }
.kpi.info .n { color: var(--info); }
h2 { font-size: 18px; margin: 8px 0 10px; }
h3 { font-size: 14px; margin: 0 0 8px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; margin: 0 0 16px; }
.chart-box-wide { grid-column: 1 / -1; }
.chart-box { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px 10px; }
.chart-box h3 { margin: 0 0 2px; font-size: 14px; display: flex; justify-content: space-between; align-items: baseline; gap: 10px; }
.chart-box-total { font-weight: 700; font-size: 16px; }
.chart-cap { margin: 0 0 8px; font-size: 12px; color: var(--muted); }
.chart-tips { margin: 0 0 8px; font-size: 12px; color: var(--ink); }
.kpi .l .info-tip { text-transform: none; letter-spacing: 0; }
.chart-frame { position: relative; height: 220px; }
.chart-frame-x { overflow-x: auto; overflow-y: hidden; }
.chart-scroll { position: relative; height: 100%; min-width: 100%; }
.chart-xlabels { position: absolute; left: 0; right: 0; bottom: 0; height: 112px; pointer-events: none; }
.chart-xlabel {
  position: absolute; top: 2px; white-space: nowrap;
  font-size: 10px; color: var(--ink); cursor: default; pointer-events: auto;
  transform: translateX(-100%) rotate(-45deg); transform-origin: top right;
}
.chart-center {
  position: absolute; left: 0; top: 0; z-index: 2; pointer-events: none;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  transform: translate(-50%, -50%); text-align: center;
}
.chart-center-n { font-weight: 700; font-size: 22px; line-height: 1.1; color: var(--ink); }
.chart-center-s { font-size: 12px; color: var(--muted); margin-top: 2px; }
.panel-head { border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin-bottom: 14px; background: var(--card); }
.head-row { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.head-row h2 { margin: 0; }
.head-row .st { font-size: 13px; }
.summary { margin-top: 8px; font-size: 14px; }
.summary strong.fail { color: var(--fail); font-weight: 700; }
.summary strong.warn { color: var(--warn); font-weight: 700; }
.caveat { font-size: 13px; color: var(--muted); margin: 8px 0 0; }
.na { color: var(--muted); font-weight: 400; }
.info-tip {
  display: inline-flex; align-items: center; justify-content: center;
  width: 14px; height: 14px; margin-left: 3px; border-radius: 50%;
  border: 1px solid var(--muted); color: var(--muted);
  font-size: 10px; font-weight: 700; font-style: italic; line-height: 1;
  cursor: help; vertical-align: middle;
}
.badge-n {
  display: inline-block; font-weight: 700; padding: 2px 8px; border-radius: 999px; font-size: 12px;
  white-space: nowrap;
}
.badge-n.fail { background: var(--fail-bg); color: var(--fail); }
.badge-n.warn { background: var(--warn-bg); color: var(--warn); }
.badge-n.ok { background: var(--ok-bg); color: var(--ok); }
.cell-why { min-width: 14rem; max-width: 28rem; }
.why-cell { display: flex; flex-wrap: wrap; gap: 4px; }
.why-cell .badge-n {
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  border-radius: 8px;
  line-height: 1.35;
}
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #eef1f5; font-weight: 600; }
.table-hint { margin: 0 0 10px; font-size: 13px; color: var(--muted); }
.table-wrap {
  overflow-x: auto;
  max-width: 100%;
  -webkit-overflow-scrolling: touch;
}
.table-wrap table {
  table-layout: auto;
  width: max-content;
  min-width: 100%;
  border-collapse: separate;
  border-spacing: 0;
}
.table-wrap th, .table-wrap td {
  white-space: nowrap;
  overflow-wrap: normal;
  word-break: normal;
  vertical-align: middle;
}
.table-wrap th:nth-child(1), .table-wrap td:nth-child(1),
.table-wrap th:nth-child(2), .table-wrap td:nth-child(2) {
  position: sticky;
  z-index: 2;
  background: #fff;
  box-shadow: 1px 0 0 var(--line);
}
.table-wrap th:nth-child(1), .table-wrap td:nth-child(1) { left: 0; min-width: 5.5rem; }
.table-wrap th:nth-child(2), .table-wrap td:nth-child(2) { left: var(--sticky-col1, 5.5rem); }
.table-wrap thead th:nth-child(1),
.table-wrap thead th:nth-child(2) { z-index: 3; background: #eef1f5; }
.table-wrap tbody tr.row-child td:nth-child(1),
.table-wrap tbody tr.row-child td:nth-child(2) { background: #f7f8fa; }
.table-wrap tbody tr:hover td { background: #f3f5f8; }
.table-wrap tbody tr:hover td:nth-child(1),
.table-wrap tbody tr:hover td:nth-child(2) { background: #f3f5f8; }
.table-wrap tbody tr.row-child:hover td,
.table-wrap tbody tr.row-child:hover td:nth-child(1),
.table-wrap tbody tr.row-child:hover td:nth-child(2) { background: #eef0f4; }
.table-wrap tbody tr.row-child td.cell-owner-diff:nth-child(2),
.table-wrap tbody tr.row-group td.cell-owner-diff:nth-child(2) { background: var(--fail-bg); }
.table-wrap tbody tr.row-child:hover td.cell-owner-diff:nth-child(2),
.table-wrap tbody tr.row-group:hover td.cell-owner-diff:nth-child(2) { background: #f8d0cc; }
.table-wrap td.cell-key {
  white-space: nowrap;
  min-width: 8rem;
  vertical-align: middle;
}
.key-name-stack { display: flex; flex-direction: column; align-items: flex-start; gap: 1px; min-width: 0; }
.key-name-line { display: inline-flex; align-items: flex-start; min-width: 0; }
.key-ver-count {
  display: block;
  color: var(--muted);
  font-weight: 400;
  font-size: 12px;
  line-height: 1.2;
  padding-left: 24px;
}
.table-wrap td.cell-key-long {
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
  max-width: 68ch;
  vertical-align: top;
}
.table-wrap td.cell-key-long .key-link,
.table-wrap td.cell-key-long .row-child-name {
  overflow-wrap: anywhere;
  word-break: break-word;
}
.table-wrap td.cell-why { white-space: normal; }
td.cell-owner-diff {
  color: var(--fail);
  font-weight: 600;
  background: var(--fail-bg);
}
.table-wrap tbody tr:hover td.cell-owner-diff,
.table-wrap tbody tr.row-child:hover td.cell-owner-diff {
  color: var(--fail);
  background: #f8d0cc;
}
a.key-link {
  color: inherit;
  text-decoration: none;
  border-bottom: 1px dotted currentColor;
}
a.key-link:hover { color: var(--info); border-bottom-color: var(--info); }
td.cell-owner-diff a.key-link:hover { color: var(--fail); border-bottom-color: var(--fail); }
h2.owner-diff-name { color: var(--fail); }
.cell-more {
  white-space: nowrap;
  color: var(--muted);
  font-size: 13px;
}
.cell-more .key-link { margin-left: 2px; }
a.key-back { color: var(--info); }
.cell-why, .why-cell { white-space: normal; }
.cell-num, .cell-ver { text-align: right; font-variant-numeric: tabular-nums; }
.row-toggle {
  display: inline-flex; width: 18px; height: 18px;
  align-items: center; justify-content: center;
  margin-right: 6px; border: 1px solid var(--line); border-radius: 3px;
  background: #fff; cursor: pointer; font-size: 12px; line-height: 1;
  vertical-align: top; margin-top: 2px; padding: 0; flex-shrink: 0;
}
.row-toggle::before { content: '+'; }
.row-group.open .row-toggle::before { content: '\\2212'; }
.row-child { background: #f7f8fa; }
.row-child td:first-child { box-shadow: inset 3px 0 0 var(--line); }
.row-child-name { color: var(--muted); padding-left: 26px; }
.row-child-name.owner-diff-name { color: var(--fail); font-weight: 600; }
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
.cat-pager-bar { display: flex; justify-content: flex-end; padding: 10px 0 0; }
.cat-pager-bar .cat-pager { margin-left: 0; }
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
const KEY_WRAP_AFTER = 67;

function wrapKeyLabel(name, cap) {
  const limit = cap == null ? KEY_WRAP_AFTER : cap;
  const s = String(name || '');
  if (s.length <= limit) return s;
  const lines = [];
  for (let i = 0; i < s.length; i += limit) lines.push(s.slice(i, i + limit));
  return lines;
}

function ellipsizeKeyLabel(name, cap) {
  const s = String(name || '');
  if (s.length <= cap) return s;
  return s.slice(0, Math.max(1, cap - 1)) + '\u2026';
}

function sliceVisible(chart, i) {
  if (typeof chart.getDataVisibility === 'function' && !chart.getDataVisibility(i)) return false;
  const meta = chart.getDatasetMeta(0);
  const el = meta && meta.data && meta.data[i];
  if (el && (el.hidden === true || el.skip === true)) return false;
  return true;
}

function visibleTotal(chart) {
  const ds = chart.data.datasets[0];
  if (!ds || !Array.isArray(ds.data)) return 0;
  let total = 0;
  ds.data.forEach((v, i) => {
    if (v == null) return;
    if (sliceVisible(chart, i)) total += Number(v) || 0;
  });
  return total;
}

function setChartTotal(chart) {
  const cfg = chart.$cfg || {};
  const total = cfg.empty ? (cfg.center == null ? 0 : cfg.center) : visibleTotal(chart);
  const canvas = chart.canvas;
  const frame = canvas && canvas.parentElement;
  if (frame && chart.config.type === 'doughnut') {
    let el = frame.querySelector('.chart-center');
    if (!el) {
      el = document.createElement('div');
      el.className = 'chart-center';
      el.innerHTML = '<div class="chart-center-n"></div><div class="chart-center-s"></div>';
      frame.appendChild(el);
    }
    const n = el.querySelector('.chart-center-n');
    const s = el.querySelector('.chart-center-s');
    if (n) n.textContent = String(total);
    if (s) s.textContent = cfg.centerSub || '';
    const area = chart.chartArea;
    if (area) {
      el.style.left = ((area.left + area.right) / 2) + 'px';
      el.style.top = ((area.top + area.bottom) / 2) + 'px';
    }
  }
  const boxTotal = document.querySelector('.chart-box-total[data-chart="' + (canvas && canvas.id) + '"]');
  if (boxTotal) boxTotal.textContent = String(total);
}

function tooltipItemVisible(item) {
  if (!item || item.raw == null) return false;
  return sliceVisible(item.chart, item.dataIndex);
}

function onLegendClick(_evt, item, legend) {
  const chart = legend.chart;
  if (chart.$cfg && chart.$cfg.empty) return;
  const idx = item.index;
  if (idx == null) return;
  chart.toggleDataVisibility(idx);
  const ds = chart.data.datasets[0];
  if (ds && (chart.config.type === 'bar' || chart.config.type === 'doughnut')) {
    if (!chart.$orig) chart.$orig = (ds.data || []).slice();
    ds.data[idx] = chart.getDataVisibility(idx) ? chart.$orig[idx] : null;
  }
  chart.update();
  setChartTotal(chart);
}

const syncTotals = {
  id: 'syncTotals',
  afterDraw(chart) {
    setChartTotal(chart);
  }
};
const barValues = {
  id: 'barValues',
  afterDatasetsDraw(chart) {
    if (chart.config.type !== 'bar') return;
    const opt = (chart.options.plugins && chart.options.plugins.barValues) || {};
    if (opt.enabled === false) return;
    const {ctx} = chart;
    const meta = chart.getDatasetMeta(0);
    const vertical = (chart.options.indexAxis || 'x') === 'x';
    ctx.save();
    ctx.fillStyle = '#1a1d23';
    ctx.font = '600 12px Segoe UI, system-ui, sans-serif';
    if (vertical) {
      ctx.textBaseline = 'bottom';
      ctx.textAlign = 'center';
    } else {
      ctx.textBaseline = 'middle';
      ctx.textAlign = 'left';
    }
    meta.data.forEach((bar, i) => {
      const v = chart.data.datasets[0].data[i];
      if (v == null) return;
      if (vertical) ctx.fillText(String(v), bar.x, bar.y - 4);
      else ctx.fillText(String(v), bar.x + 8, bar.y);
    });
    ctx.restore();
  }
};
const xLabels = {
  id: 'xLabels',
  afterLayout(chart) {
    if (chart.$cfg && chart.$cfg.indexAxis === 'x') placeXLabels(chart, chart.$cfg);
  }
};
Chart.register(syncTotals, barValues, xLabels);

function makeChart(cfg) {
  const canvas = document.getElementById(cfg.id);
  if (!canvas) return;
  const values = cfg.values || [];
  const grouped = !!(cfg.grouped && cfg.datasets && cfg.datasets.length);
  const empty = grouped
    ? cfg.datasets.every(ds => !(ds.values || []).some(v => v))
    : (!values.length || values.every(v => !v));
  if (empty) {
    const box = document.getElementById('box-' + cfg.id);
    if (box) box.style.display = 'none';
    return;
  }
  const colors = cfg.colors && cfg.colors.length ? cfg.colors : [PAL.warn];
  if (cfg.type === 'doughnut') {
    const chart = new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: cfg.labels,
        datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }]
      },
      options: {
        cutout: '64%',
        maintainAspectRatio: false,
        interaction: { mode: 'nearest', intersect: true },
        plugins: {
          legend: {
            position: 'right',
            onClick: onLegendClick,
            labels: { boxWidth: 12, padding: 12, font: { size: 12 } }
          },
          tooltip: {
            mode: 'nearest',
            intersect: true,
            filter: tooltipItemVisible,
            callbacks: {
              title: (items) => {
                if (cfg.tooltipValueUnit) return '';
                return items && items[0] ? items[0].label : '';
              },
              label: (c) => {
                if (cfg.empty) return ' ' + (cfg.labels && cfg.labels[0] || '0');
                const n = c.parsed;
                const name = String(c.label || '').trim();
                const base = name.replace(new RegExp('(?:\\s+)' + n + '$'), '').trim() || name;
                const unit = cfg.tooltipValueUnit ? ' ' + cfg.tooltipValueUnit : '';
                return ' ' + base + ': ' + n + unit;
              }
            }
          }
        }
      }
    });
    chart.$cfg = cfg;
    setChartTotal(chart);
    return;
  }
  const barColors = colors.length === values.length ? colors : (colors[0] || PAL.warn);
  const vertical = cfg.indexAxis === 'x';
  const nCats = (cfg.labels || []).length || values.length;
  if (vertical && cfg.scroll) {
    const inner = canvas.parentElement;
    if (inner && inner.classList.contains('chart-scroll')) {
      const frame = inner.parentElement;
      const need = nCats * (Number(cfg.colWidth) || 96);
      inner.style.width = Math.max(frame ? frame.clientWidth : 0, need) + 'px';
    }
  }
  const valueScale = {
    stacked: false,
    beginAtZero: true,
    grace: '12%',
    ticks: { precision: 0, maxTicksLimit: 6 },
    grid: { color: '#eef1f5' }
  };
  const categoryScale = {
    stacked: false,
    grid: { display: false },
    ticks: vertical
      ? { display: false, autoSkip: false }
      : { font: { size: 13 } }
  };
  if (vertical) {
    categoryScale.afterFit = function(scale) {
      scale.height = Math.max(scale.height, 112);
    };
  } else if (cfg.keyLabels) {
    categoryScale.ticks = {
      font: { size: 11 },
      autoSkip: false,
      callback: function(value) {
        return ellipsizeKeyLabel(this.getLabelForValue(value), 20);
      }
    };
    categoryScale.afterFit = function(scale) {
      scale.width = 128;
    };
    const mx = Math.max(0, ...values.map(Number));
    if (mx > 0) {
      valueScale.suggestedMax = mx;
      valueScale.grace = '6%';
    }
  }
  const datasets = grouped
    ? cfg.datasets.map(ds => ({
        label: ds.label || '',
        data: ds.values || [],
        backgroundColor: ds.color || PAL.info,
        borderRadius: 4,
        barPercentage: 0.85,
        categoryPercentage: 0.7,
        maxBarThickness: 28
      }))
    : [{
        data: values,
        backgroundColor: barColors,
        borderRadius: 4,
        barPercentage: 0.7,
        categoryPercentage: 0.7,
        maxBarThickness: 36
      }];
  const chart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: cfg.labels,
      datasets
    },
    options: {
      indexAxis: vertical ? 'x' : 'y',
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false,
        axis: vertical ? 'x' : 'y'
      },
      onClick: grouped ? undefined : function(evt, els, c) {
        const hits = c.getElementsAtEventForMode(
          evt, 'index', { intersect: false, axis: vertical ? 'x' : 'y' }, true
        );
        if (!hits.length) return;
        onLegendClick(evt, { index: hits[0].index }, { chart: c });
      },
      plugins: {
        legend: grouped
          ? { display: true, position: 'top', labels: { boxWidth: 12, font: { size: 12 } } }
          : { display: false },
        tooltip: {
          mode: 'index',
          intersect: false,
          filter: tooltipItemVisible,
          callbacks: {
            title(items) {
              const i = items && items[0] ? items[0].dataIndex : -1;
              const full = (cfg.fullLabels && cfg.fullLabels[i] != null)
                ? cfg.fullLabels[i]
                : ((cfg.labels && cfg.labels[i]) || (items[0] && items[0].label) || '');
              return wrapKeyLabel(full);
            },
            label: (c) => grouped
              ? (' ' + (c.dataset.label || '') + ': ' + c.raw)
              : (' ' + c.raw)
          }
        },
        barValues: { enabled: !grouped }
      },
      layout: { padding: vertical ? { top: 18, left: 28 } : { right: 36 } },
      scales: vertical
        ? { x: categoryScale, y: valueScale }
        : { x: valueScale, y: categoryScale }
    }
  });
  chart.$cfg = cfg;
  setChartTotal(chart);
  if (vertical) placeXLabels(chart, cfg);
}

function shortDomain(name) {
  const s = String(name || '');
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) {
    return s.slice(0, 8);
  }
  if (s.length <= 16) return s;
  return s.slice(0, 15) + '\u2026';
}

function placeXLabels(chart, cfg) {
  const host = chart.canvas && chart.canvas.parentElement;
  const x = chart.scales && chart.scales.x;
  if (!host || !x) return;
  let row = host.querySelector('.chart-xlabels');
  if (!row) {
    row = document.createElement('div');
    row.className = 'chart-xlabels';
    host.appendChild(row);
  }
  row.replaceChildren();
  const full = cfg.labels || [];
  const shorts = cfg.shortLabels || full.map(shortDomain);
  full.forEach((name, i) => {
    const el = document.createElement('span');
    el.className = 'chart-xlabel';
    el.textContent = shorts[i] || shortDomain(name);
    el.title = name;
    el.style.left = (chart.canvas.offsetLeft + x.getPixelForTick(i)) + 'px';
    row.appendChild(el);
  });
}

const rendered = {};
function renderTabCharts(slug) {
  if (rendered[slug]) return;
  rendered[slug] = true;
  (DATA[slug] || []).forEach(makeChart);
}

function currentHash() {
  return (location.hash || '#').replace(/^#/, '');
}

function findKeyPage(domain, name) {
  return Array.from(document.querySelectorAll('.key-page')).find(el =>
    el.getAttribute('data-domain') === domain && el.getAttribute('data-name') === name
  );
}

function showKeyPage(raw) {
  const rest = raw.slice(4);
  const cut = rest.indexOf('/');
  if (cut < 0) return false;
  let domain = '';
  let name = '';
  try {
    domain = decodeURIComponent(rest.slice(0, cut));
    name = decodeURIComponent(rest.slice(cut + 1));
  } catch (err) {
    return false;
  }
  const panel = document.getElementById('panel-key');
  const missing = document.getElementById('key-missing');
  if (!panel) return false;
  document.querySelectorAll('.tab-panel').forEach(p => { p.hidden = true; });
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  panel.hidden = false;
  document.querySelectorAll('.key-page').forEach(p => { p.hidden = true; });
  const page = findKeyPage(domain, name);
  if (missing) missing.hidden = !!page;
  if (page) page.hidden = false;
  pinLeadColumns(panel);
  if (currentHash() !== raw) history.replaceState(null, '', '#' + raw);
  return true;
}

function absolutizeKeyLinks() {
  const base = location.pathname + location.search;
  document.querySelectorAll('a.key-link').forEach(a => {
    const href = a.getAttribute('href') || '';
    if (href.startsWith('#key/')) a.setAttribute('href', base + href);
  });
}

function showTab(slug) {
  if (slug === 'key-versions') slug = 'catalog';
  if (slug && slug.startsWith('key/')) {
    if (showKeyPage(slug)) return;
    slug = 'catalog';
  }
  const known = document.getElementById('panel-' + slug);
  if (!known || slug === 'key') slug = 'overview';
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
  pinLeadColumns(panel);
  if (currentHash() !== slug) {
    history.replaceState(null, '', '#' + slug);
  }
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => showTab(btn.dataset.tab));
});
window.addEventListener('hashchange', () => showTab(location.hash.replace('#','')));
window.addEventListener('beforeprint', () => {
  const viewingKey = !!(document.getElementById('panel-key') && !document.getElementById('panel-key').hidden);
  document.querySelectorAll('.tab-panel').forEach(p => {
    if (p.id === 'panel-key') return;
    p.hidden = viewingKey;
    if (!viewingKey) renderTabCharts(p.id.replace('panel-', ''));
  });
  if (window.catalogShowAll && !viewingKey) window.catalogShowAll();
});
window.addEventListener('afterprint', () => {
  if (window.catalogApply) window.catalogApply();
});

function pinLeadColumns(root) {
  const scope = root || document;
  const wraps = scope.classList && scope.classList.contains('table-wrap')
    ? [scope]
    : Array.from(scope.querySelectorAll('.table-wrap'));
  wraps.forEach(wrap => {
    if (wrap.closest('[hidden]')) return;
    const cell = wrap.querySelector('thead th:nth-child(1), tbody td:nth-child(1)');
    if (!cell) return;
    const w = cell.getBoundingClientRect().width;
    if (w > 0) wrap.style.setProperty('--sticky-col1', Math.ceil(w) + 'px');
  });
}
window.addEventListener('resize', () => pinLeadColumns());

function tablePager(prefix) {
  const table = document.getElementById(prefix + '-table');
  if (!table) return null;
  const tbody = table.querySelector('tbody');
  const filterEl = document.getElementById(prefix + '-filter');
  const sortEl = document.getElementById(prefix + '-sort');
  const sizeEl = document.getElementById(prefix + '-page-size');
  const pagerEls = [prefix + '-pager', prefix + '-pager-bottom']
    .map(id => document.getElementById(id))
    .filter(Boolean);
  const groupRows = Array.from(tbody.querySelectorAll('tr.row-group'));
  const childRows = Array.from(tbody.querySelectorAll('tr.row-child'));
  const grouped = groupRows.length > 0;
  const rows = grouped ? groupRows : Array.from(tbody.querySelectorAll('tr'));
  let page = 1;
  let sortCol = sortEl ? (parseInt(sortEl.value, 10) || 0) : 0;
  let sortDir = table.dataset.sortDir === 'desc' ? -1 : 1;

  function cell(tr, i) {
    return (tr.children[i] ? tr.children[i].textContent : '').trim();
  }
  function sortVal(tr, i) {
    const t = cell(tr, i);
    if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
    return t.toLowerCase();
  }
  function childrenOf(tr) {
    if (!grouped) return [];
    const gid = tr.dataset.group;
    return childRows.filter(ch => ch.dataset.group === gid);
  }
  function matches(tr, q) {
    if (!q) return true;
    if (tr.textContent.toLowerCase().includes(q)) return true;
    if ((tr.dataset.search || '').toLowerCase().includes(q)) return true;
    return childrenOf(tr).some(ch => ch.textContent.toLowerCase().includes(q));
  }
  function filtered() {
    const q = (filterEl && filterEl.value || '').toLowerCase();
    let list = rows.filter(tr => matches(tr, q));
    list = list.slice().sort((a, b) => {
      const av = sortVal(a, sortCol);
      const bv = sortVal(b, sortCol);
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
  function reorder(list) {
    const frag = document.createDocumentFragment();
    const placed = new Set();
    function place(tr) {
      if (placed.has(tr)) return;
      placed.add(tr);
      frag.appendChild(tr);
      childrenOf(tr).forEach(ch => {
        placed.add(ch);
        frag.appendChild(ch);
      });
    }
    list.forEach(place);
    rows.forEach(place);
    childRows.forEach(ch => { if (!placed.has(ch)) frag.appendChild(ch); });
    tbody.appendChild(frag);
  }
  function syncChildren(visibleParents) {
    groupRows.forEach(tr => {
      const on = visibleParents.has(tr);
      const open = tr.classList.contains('open');
      const btn = tr.querySelector('.row-toggle');
      if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      childrenOf(tr).forEach(ch => {
        ch.style.display = on && open ? '' : 'none';
      });
    });
  }
  function apply() {
    const list = filtered();
    const size = Math.max(1, parseInt(sizeEl && sizeEl.value, 10) || 50);
    const pages = Math.max(1, Math.ceil(list.length / size));
    if (page > pages) page = pages;
    const start = (page - 1) * size;
    const visible = new Set(list.slice(start, start + size));
    reorder(list);
    rows.forEach(tr => { tr.style.display = visible.has(tr) ? '' : 'none'; });
    syncChildren(visible);
    pagerEls.forEach(pagerEl => {
      pagerEl.innerHTML = '';
      const info = document.createElement('span');
      const from = list.length ? start + 1 : 0;
      const to = Math.min(start + size, list.length);
      if (grouped) {
        const vers = list.reduce((n, tr) => {
          const matchN = parseInt(tr.dataset.matchN, 10);
          if (!Number.isNaN(matchN) && matchN > 0) return n + matchN;
          const lifeN = parseInt(tr.dataset.lifeN, 10);
          if (!Number.isNaN(lifeN) && lifeN > 0) return n + lifeN;
          const allN = parseInt(tr.dataset.versions, 10);
          if (!Number.isNaN(allN) && allN > 0) return n + allN;
          const ch = childrenOf(tr).filter(c => !c.classList.contains('row-more'));
          return n + (ch.length ? ch.length : 1);
        }, 0);
        info.textContent = from + '\u2013' + to + ' of ' + list.length + ' keys \u00b7 ' + vers + ' versions';
      } else {
        info.textContent = from + '\u2013' + to + ' of ' + list.length;
      }
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
    });
    markHeaders();
    pinLeadColumns(table.closest('.table-wrap'));
  }
  function showAll() {
    const list = filtered();
    const vis = new Set(list);
    groupRows.forEach(tr => tr.classList.add('open'));
    reorder(list);
    rows.forEach(tr => { tr.style.display = vis.has(tr) ? '' : 'none'; });
    syncChildren(vis);
  }
  tbody.addEventListener('click', (e) => {
    const btn = e.target.closest('.row-toggle');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    const tr = btn.closest('tr.row-group');
    tr.classList.toggle('open');
    const open = tr.classList.contains('open');
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    const on = tr.style.display !== 'none';
    childrenOf(tr).forEach(ch => {
      ch.style.display = on && open ? '' : 'none';
    });
  });
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
  return { apply, showAll };
}
const pagers = ['cat', 'cte', 'life', 'exp'].map(tablePager).filter(Boolean);
window.catalogApply = () => pagers.forEach(p => p.apply());
window.catalogShowAll = () => pagers.forEach(p => p.showAll());
absolutizeKeyLinks();
showTab((location.hash || '#overview').replace('#',''));
"""
