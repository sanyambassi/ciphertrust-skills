"""Shared helpers: dates, certs, HTTP wrappers, summaries."""
from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable

from cm_client import CmClient, CmError

from .context import ReportCtx

# Cert / CA validity scoring
CERT_WARN_DAYS = 30  # <= 30 days left → WARNING; > 30 → INFO; expired → CRITICAL
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


def parse_date(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    if value.strip().lower() in ("no expiration", "never", "none"):
        return None
    clean = value.split(".")[0].rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def days_until(dt: datetime | None, now: datetime) -> int | None:
    if not dt:
        return None
    return (dt - now).days


def cert_expiry_severity(days_left: int | None) -> str | None:
    """expired → CRITICAL; ≤30d → WARNING; >30d → INFO."""
    if days_left is None:
        return None
    if days_left < 0:
        return "CRITICAL"
    if days_left <= CERT_WARN_DAYS:
        return "WARNING"
    return "INFO"


def _first_pem_certificate(pem_bundle: str) -> str | None:
    m = _PEM_CERT_RE.search(pem_bundle or "")
    return m.group(0) if m else None


def pem_leaf_not_after(pem_bundle: str) -> datetime | None:
    """Return leaf cert notAfter (UTC). Stdlib + optional cryptography/openssl."""
    leaf = _first_pem_certificate(pem_bundle)
    if not leaf:
        return None
    try:
        from cryptography import x509  # type: ignore

        cert = x509.load_pem_x509_certificate(leaf.encode("utf-8"))
        na = getattr(cert, "not_valid_after_utc", None)
        if na is not None:
            return na if na.tzinfo else na.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after
        return na if na.tzinfo else na.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tmp:
            tmp.write(leaf)
            path = tmp.name
        try:
            out = subprocess.run(
                ["openssl", "x509", "-in", path, "-noout", "-enddate"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        if out.returncode == 0 and out.stdout:
            # openssl x509 -enddate → notAfter=<date>
            raw = out.stdout.strip().split("=", 1)[-1].strip()
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    except Exception:
        pass
    return _der_not_after_from_pem(leaf)


def _der_not_after_from_pem(pem: str) -> datetime | None:
    """Best-effort: find Validity.notAfter UTCTime/GeneralizedTime in DER."""
    try:
        body = re.sub(
            r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+",
            "",
            pem,
        )
        der = base64.b64decode(body)
    except Exception:
        return None
    # Scan for ASN.1 UTCTime (0x17) / GeneralizedTime (0x18) near Validity
    i = 0
    times: list[datetime] = []
    while i < len(der) - 2:
        tag = der[i]
        if tag in (0x17, 0x18):
            ln = der[i + 1]
            if ln & 0x80:
                i += 1
                continue
            start = i + 2
            end = start + ln
            if end > len(der):
                break
            s = der[start:end].decode("ascii", errors="ignore")
            try:
                if tag == 0x17 and len(s) >= 13:  # YYMMDDHHMMSSZ
                    yy = int(s[0:2])
                    year = 1900 + yy if yy >= 50 else 2000 + yy
                    dt = datetime(
                        year,
                        int(s[2:4]),
                        int(s[4:6]),
                        int(s[6:8]),
                        int(s[8:10]),
                        int(s[10:12]),
                        tzinfo=timezone.utc,
                    )
                    times.append(dt)
                elif tag == 0x18 and len(s) >= 15:  # YYYYMMDDHHMMSSZ
                    dt = datetime(
                        int(s[0:4]),
                        int(s[4:6]),
                        int(s[6:8]),
                        int(s[8:10]),
                        int(s[10:12]),
                        int(s[12:14]),
                        tzinfo=timezone.utc,
                    )
                    times.append(dt)
            except ValueError:
                pass
            i = end
            continue
        i += 1
    # Validity is notBefore then notAfter — use second time when present
    if len(times) >= 2:
        return times[1]
    return times[0] if times else None


def emit_cert_validity(
    ctx: ReportCtx,
    *,
    area: str,
    code_prefix: str,
    label: str,
    days_left: int | None,
    not_after: str | None = None,
) -> str | None:
    """Emit INFO/WARNING/CRITICAL for cert validity. Returns severity or None."""
    sev = cert_expiry_severity(days_left)
    if sev is None:
        return None
    if days_left is not None and days_left < 0:
        msg = f"{label} is expired"
        if not_after:
            msg += f" (notAfter={not_after})"
        msg += "."
        ctx.add(area, f"{code_prefix}_expired", "CRITICAL", msg)
    elif days_left is not None and days_left <= CERT_WARN_DAYS:
        ctx.add(
            area,
            f"{code_prefix}_expiring",
            "WARNING",
            f"{label} expires in {days_left} day(s)"
            + (f" (notAfter={not_after})" if not_after else "")
            + ".",
        )
    else:
        ctx.add(
            area,
            f"{code_prefix}_valid",
            "INFO",
            f"{label} valid for {days_left} day(s)"
            + (f" (notAfter={not_after})" if not_after else "")
            + ".",
        )
    return sev


def safe_get(client: CmClient, path: str) -> tuple[Any | None, CmError | None]:
    try:
        return client.get(path), None
    except CmError as e:
        return None, e


def section_from_get(
    ctx: ReportCtx,
    client: CmClient,
    name: str,
    path: str,
    summarize: Callable[[Any], Any],
) -> Any | None:
    data, err = safe_get(client, path)
    if err:
        ctx.section(name, "FAIL", {"error": str(err), "body": err.body}, err.status)
        return None
    ctx.section(name, "PASS", summarize(data), 200)
    return data


def summarize_user(data: Any) -> dict:
    if not isinstance(data, dict):
        return {"value": data}
    meta = data.get("user_metadata") or {}
    domain = (meta.get("current_domain") or {}) if isinstance(meta, dict) else {}
    return {
        "username": data.get("username"),
        "name": data.get("name"),
        "user_id": data.get("user_id"),
        "current_domain": domain.get("name") or domain.get("id"),
        "failed_logins_count": data.get("failed_logins_count"),
    }


def summarize_list(data: Any) -> dict:
    if not isinstance(data, dict):
        return {"value": data}
    resources = data.get("resources") if isinstance(data.get("resources"), list) else []
    return {"total": data.get("total", len(resources)), "count": len(resources)}


def summarize_info(data: Any) -> dict:
    if not isinstance(data, dict):
        return {"value": data}
    keys = ("name", "version", "version_suffix", "model", "uptime", "crypto_version")
    return {k: data.get(k) for k in keys if data.get(k) is not None}


def parse_cm_version(version: Any) -> tuple[int, int, int] | None:
    """Parse CM version string to (major, minor, patch).

    Accepts forms like ``2.25.0-beta6+53584``, ``2.24.0``, ``2.23``.
    """
    if not version or not isinstance(version, str):
        return None
    m = re.match(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def cm_version_at_least(version: Any, major: int, minor: int) -> bool | None:
    """Return True/False if version parses; None if unknown."""
    parsed = parse_cm_version(version)
    if parsed is None:
        return None
    return (parsed[0], parsed[1]) >= (major, minor)
