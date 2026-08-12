"""Audit records via DB store or Loki."""
from __future__ import annotations

import json
import urllib.parse
from datetime import timedelta
from typing import Any

from cm_client import CmClient, CmError

from ..context import ReportCtx
from ..util import cm_version_at_least, safe_get

def _loki_matrix_severity_counts(data: Any) -> dict[str, int]:
    """Parse Loki matrix ``sum by (severity) (count_over_time(...))`` into counts."""
    out: dict[str, int] = {}
    result = ((data or {}).get("data") or {}).get("result") or []
    if not isinstance(result, list):
        return out
    for series in result:
        if not isinstance(series, dict):
            continue
        sev = str((series.get("metric") or {}).get("severity") or "").lower()
        values = series.get("values") or []
        if not sev or not values:
            continue
        try:
            # step spans the full window → last bucket is the 7d count
            out[sev] = int(float(values[-1][1]))
        except (TypeError, ValueError, IndexError):
            continue
    return out


def _loki_query_range(
    client: CmClient,
    query: str,
    *,
    start_ns: int,
    end_ns: int,
    step: str | None = "168h",
    limit: int | None = None,
) -> tuple[Any | None, CmError | None]:
    params = {
        "query": query,
        "start": str(start_ns),
        "end": str(end_ns),
        "direction": "backward",
    }
    if step:
        params["step"] = step
    if limit is not None:
        params["limit"] = str(limit)
    path = "/v1/audit/loki/api/v1/query_range?" + urllib.parse.urlencode(params)
    return safe_get(client, path)


def _records_db_store_enabled(
    client: CmClient, cm_version: Any
) -> tuple[bool | None, str]:
    """Read ENABLE_RECORDS_DB_STORE. None = property/API not available."""
    data, err = safe_get(client, "/v1/configs/properties/ENABLE_RECORDS_DB_STORE")
    if err:
        if cm_version_at_least(cm_version, 2, 24) is True:
            return None, "removed"
        return None, f"unavailable ({err.status})"
    raw = str((data or {}).get("value") or "").strip().lower()
    if raw in ("true", "1", "yes", "on"):
        return True, "enabled"
    if raw in ("false", "0", "no", "off", ""):
        return False, "disabled"
    return False, f"disabled (value={raw!r})"


def _query_db_audit_counts(
    ctx: ReportCtx, client: CmClient, after: str
) -> tuple[dict[str, int], dict[str, int], list[dict], list[str]]:
    """Query legacy DB audit APIs for error/critical/fatal counts."""
    server_counts: dict[str, int] = {}
    client_counts: dict[str, int] = {}
    samples: list[dict] = []
    errors: list[str] = []
    for sev in ("error", "critical", "fatal"):
        data, err = safe_get(
            client, f"/v1/audit/records?limit=5&severity={sev}&createdAfter={after}"
        )
        if err:
            errors.append(f"server:{sev}:{err.status}")
            continue
        total = int((data or {}).get("total") or 0)
        if total:
            server_counts[sev] = total
            for r in (data or {}).get("resources") or []:
                if isinstance(r, dict) and len(samples) < 10:
                    samples.append(
                        {
                            "source": "server_db",
                            "severity": r.get("severity"),
                            "message": (r.get("message") or "")[:120],
                            "createdAt": r.get("createdAt"),
                            "username": r.get("username"),
                        }
                    )
    for sev in ("error", "critical", "fatal"):
        data, err = safe_get(client, f"/v1/audit/client-records?limit=5&severity={sev}")
        if err:
            errors.append(f"client:{sev}:{err.status}")
            continue
        total = int((data or {}).get("total") or 0)
        if total:
            client_counts[sev] = total
    return server_counts, client_counts, samples, errors


def _query_loki_audit_counts(
    client: CmClient, *, start_ns: int, end_ns: int
) -> tuple[dict[str, int], dict[str, int], list[dict], CmError | None]:
    """Query onboard Loki for 7d severity counts + elevated samples."""
    server_all: dict[str, int] = {}
    client_all: dict[str, int] = {}
    samples: list[dict] = []
    for job, bucket in (
        ("server_audit_records", server_all),
        ("client_audit_records", client_all),
    ):
        q = f'sum by (severity) (count_over_time({{job="{job}"}} | json [7d]))'
        data, err = _loki_query_range(
            client, q, start_ns=start_ns, end_ns=end_ns, step="168h"
        )
        if err:
            return {}, {}, [], err
        bucket.update(_loki_matrix_severity_counts(data))

    sample_q = '{job="server_audit_records"} | json | severity=~"error|critical|fatal"'
    sdata, _ = _loki_query_range(
        client, sample_q, start_ns=start_ns, end_ns=end_ns, step=None, limit=5
    )
    for stream in ((sdata or {}).get("data") or {}).get("result") or []:
        if not isinstance(stream, dict):
            continue
        for _ts, line in stream.get("values") or []:
            if len(samples) >= 5:
                break
            try:
                obj = json.loads(line) if isinstance(line, str) else {}
            except json.JSONDecodeError:
                obj = {}
            if isinstance(obj, dict):
                samples.append(
                    {
                        "source": "server_loki",
                        "severity": obj.get("severity"),
                        "message": str(obj.get("message") or "")[:120],
                        "createdAt": obj.get("createdAt"),
                        "username": (obj.get("principal") or {}).get("username")
                        if isinstance(obj.get("principal"), dict)
                        else obj.get("username"),
                    }
                )

    server = {k: int(server_all.get(k) or 0) for k in ("error", "critical", "fatal")}
    client = {k: int(client_all.get(k) or 0) for k in ("error", "critical", "fatal")}
    return server, client, samples, None


def _emit_audit_severity_findings(
    ctx: ReportCtx,
    *,
    source_label: str,
    server: dict[str, int],
    client: dict[str, int],
) -> tuple[int, int, int, int]:
    crit = int(server.get("critical") or 0) + int(server.get("fatal") or 0)
    err_n = int(server.get("error") or 0)
    c_crit = int(client.get("critical") or 0) + int(client.get("fatal") or 0)
    c_err = int(client.get("error") or 0)
    if crit:
        ctx.add(
            "records",
            "records_critical",
            "CRITICAL",
            f"{source_label} server audit (7d): critical/fatal={crit}.",
        )
    if err_n:
        ctx.add(
            "records",
            "records_error",
            "WARNING",
            f"{source_label} server audit (7d): error={err_n}.",
        )
    if c_crit or c_err:
        ctx.add(
            "records",
            "records_client_elevated",
            "WARNING",
            f"{source_label} client audit (7d): critical/fatal={c_crit}, error={c_err}.",
        )
    return crit, err_n, c_crit, c_err


def check_audit_records(
    ctx: ReportCtx,
    client: CmClient,
    cm_version: Any = None,
) -> None:
    """Two audit pipelines: Loki (always on) + optional DB store.

    - Read ``ENABLE_RECORDS_DB_STORE``.
    - If DB store **enabled**: score from DB ``/v1/audit/records`` (+ client).
    - If DB store **disabled**/removed: report that; score from Loki
      ``/v1/audit/loki/api/v1/query_range`` (jobs ``server_audit_records`` /
      ``client_audit_records``).
    """
    after = (ctx.now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_ns = int(ctx.now.timestamp() * 1_000_000_000)
    start_ns = end_ns - 7 * 24 * 3600 * 1_000_000_000

    db_on, db_status = _records_db_store_enabled(client, cm_version)

    if db_on is True:
        ctx.add(
            "records",
            "records_db_store_enabled",
            "INFO",
            "Database audit store is enabled (ENABLE_RECORDS_DB_STORE=true).",
        )
        server, client, samples, errors = _query_db_audit_counts(ctx, client, after)
        if errors and not server and not client:
            ctx.add(
                "records",
                "records_db_query_failed",
                "WARNING",
                "DB audit store is enabled but record APIs failed: "
                + "; ".join(errors[:6])
                + ".",
            )
            ctx.section(
                "audit_records",
                "WARN",
                {
                    "source": "db",
                    "db_store": "enabled",
                    "cm_version": cm_version,
                    "errors": errors,
                    "server_counts": {},
                    "client_counts": {},
                },
                None,
            )
            return
        crit, err_n, c_crit, c_err = _emit_audit_severity_findings(
            ctx, source_label="DB", server=server, client=client
        )
        result = "FAIL" if crit else ("WARN" if (err_n or c_crit or c_err) else "PASS")
        ctx.section(
            "audit_records",
            result,
            {
                "source": "db",
                "db_store": "enabled",
                "cm_version": cm_version,
                "server_window": "7d",
                "createdAfter": after,
                "server_counts": server,
                "client_counts": client,
                "sample": samples,
            },
            200,
        )
        return

    # DB store off / removed — do not treat empty DB totals as healthy audit.
    if db_status == "removed":
        db_note = "DB audit store not available (removed in CM 2.24+)"
    elif db_on is False:
        db_note = "DB audit store disabled"
        ctx.add(
            "records",
            "records_db_store_disabled",
            "INFO",
            "Database audit store is disabled (ENABLE_RECORDS_DB_STORE=false). "
            "Scoring uses Loki audit logs.",
        )
    else:
        db_note = f"DB audit store {db_status}"
        ctx.add(
            "records",
            "records_db_store_unknown",
            "INFO",
            f"Could not read ENABLE_RECORDS_DB_STORE ({db_status}); "
            "scoring uses Loki when available.",
        )

    server, client, samples, loki_err = _query_loki_audit_counts(
        client, start_ns=start_ns, end_ns=end_ns
    )
    if loki_err is not None:
        ctx.add(
            "records",
            "records_loki_unavailable",
            "WARNING",
            f"{db_note}; Loki audit query also unavailable ({loki_err}).",
        )
        ctx.section(
            "audit_records",
            "WARN",
            {
                "skipped": False,
                "source": "none",
                "db_store": db_status,
                "db_store_note": db_note,
                "loki_error": str(loki_err),
                "cm_version": cm_version,
                "server_counts": {},
                "client_counts": {},
            },
            loki_err.status,
        )
        return

    crit, err_n, c_crit, c_err = _emit_audit_severity_findings(
        ctx, source_label="Loki", server=server, client=client
    )
    result = "FAIL" if crit else ("WARN" if (err_n or c_crit or c_err) else "PASS")
    ctx.section(
        "audit_records",
        result,
        {
            "source": "loki",
            "db_store": db_status,
            "db_store_note": db_note,
            "cm_version": cm_version,
            "server_window": "7d",
            "createdAfter": after,
            "endpoint": "/v1/audit/loki/api/v1/query_range",
            "server_counts": server,
            "client_counts": client,
            "sample": samples,
        },
        200,
    )
