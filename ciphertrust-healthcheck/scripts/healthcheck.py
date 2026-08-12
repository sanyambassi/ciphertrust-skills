#!/usr/bin/env python3
"""Read-only CipherTrust Manager healthcheck over REST.

Alive + operational posture + domain-scoped inventory. Uses CM_* env vars.
Never logs secrets or scrape tokens.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

# Cert / CA validity scoring
CERT_WARN_DAYS = 30  # <= 30 days left → WARNING; > 30 → INFO; expired → CRITICAL
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def _ensure_cm_client_on_path() -> None:
    """Put skill-local lib/ on sys.path (optional CM_SKILLS_ROOT/lib fallback)."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[1] / "lib",
        here.parents[2] / "lib",
    ]
    env_root = os.environ.get("CM_SKILLS_ROOT")
    if env_root:
        candidates.append(Path(env_root) / "lib")
    for lib in candidates:
        if (lib / "cm_client.py").is_file():
            sys.path.insert(0, str(lib))
            return
    raise SystemExit(
        "Cannot find lib/cm_client.py (expected next to this skill under lib/)."
    )


_ensure_cm_client_on_path()
from cm_client import CmClient, CmError  # noqa: E402

# Interface auth modes: TCP → CRITICAL; tls-cert-and-pw → INFO;
# web (non-TCP) → INFO; other modes → WARNING.
PREFERRED_INTERFACE_MODE = "tls-cert-and-pw"
INTERFACE_MODE_LABELS = {
    "no-tls-pw-opt": "TCP mode (no TLS); password optional",
    "no-tls-pw-req": "TCP mode (no TLS); password required",
    "unauth-tls-pw-opt": "TLS, ignore client cert; password optional",
    "unauth-tls-pw-req": "TLS, ignore client cert; password required",
    "unauth-tls-opt-pw-opt": "TLS, ignore client cert; password optional",
    "tls-pw-opt": "TLS, verify client cert; password optional",
    "tls-pw-req": "TLS, verify client cert; password required",
    "tls-cert-pw-opt": "TLS, verify client cert; username from cert; auth optional",
    "tls-cert-and-pw": (
        "TLS, verify client cert; password required; "
        "cert username must match authentication request"
    ),
    "tls-cert-opt-pw-opt": "TLS; client cert optional; password optional",
}
WEAK_TLS = {"ssl_v3", "tls_1_0", "tls_1_1", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}


def interface_mode_label(mode: str) -> str:
    m = (mode or "").strip().lower()
    return INTERFACE_MODE_LABELS.get(m, mode or "unknown")


def interface_mode_severity(
    mode: str | None, *, interface_type: str | None = None
) -> str | None:
    """CRITICAL / WARNING / INFO for an enabled interface mode, or None if N/A."""
    m = (mode or "").strip().lower()
    if not m or m in ("none", "null"):
        return None  # ssh/snmp/etc. — no auth mode
    if m.startswith("no-tls"):
        return "CRITICAL"
    itype = (interface_type or "").strip().lower()
    if itype == "web":
        return "INFO"
    if m == PREFERRED_INTERFACE_MODE:
        return "INFO"
    return "WARNING"


PQC_GROUPS = {
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
}
ALARM_CRITICAL_SEVS = {"critical", "emergency", "alert", "error"}
SIGNIFICANT_RECORD_SEVS = {"error", "critical", "fatal"}
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


@dataclass
class Finding:
    area: str
    code: str
    severity: str  # CRITICAL | WARNING | INFO
    message: str


@dataclass
class ReportCtx:
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)

    def add(
        self,
        area: str,
        code: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            Finding(area=area, code=code, severity=severity, message=message)
        )

    def section(self, name: str, result: str, detail: Any, status: int | None = 200) -> None:
        self.sections.append(
            {"name": name, "result": result, "status": status, "detail": detail}
        )


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


# ---------------------------------------------------------------------------
# Posture analyzers
# ---------------------------------------------------------------------------


def check_services(ctx: ReportCtx, data: Any) -> None:
    services = []
    if isinstance(data, dict):
        services = data.get("services") or []
    disabled = []
    down = []
    for s in services:
        if not isinstance(s, dict):
            continue
        status = str(s.get("status") or "").lower()
        if status == "started":
            continue
        row = {"name": s.get("name"), "status": s.get("status")}
        if status == "disabled":
            disabled.append(row)
        else:
            down.append(row)
    detail = {
        "total": len(services),
        "started": len(services) - len(disabled) - len(down),
        "disabled": disabled[:20],
        "not_started": down[:20],
        "overall_status": data.get("status") if isinstance(data, dict) else None,
    }
    for s in disabled[:15]:
        ctx.add(
            "system",
            "svc_disabled",
            "INFO",
            f"Service '{s.get('name')}' is disabled (by configuration).",
        )
    for s in down[:15]:
        ctx.add(
            "system",
            "svc_not_started",
            "CRITICAL",
            f"Service '{s.get('name')}' is not started (status={s.get('status')}).",
        )
    result = "FAIL" if down else "PASS"
    ctx.section("services_status", result, detail, 200)


def check_cluster(ctx: ReportCtx, client: CmClient) -> None:
    cluster, err = safe_get(client, "/v1/cluster")
    if err:
        ctx.section("cluster", "FAIL", {"error": str(err)}, err.status)
    else:
        status = (cluster or {}).get("status") or {}
        detail = {
            "nodeID": (cluster or {}).get("nodeID"),
            "status_code": status.get("code") if isinstance(status, dict) else status,
            "status_description": status.get("description") if isinstance(status, dict) else None,
        }
        ctx.section("cluster", "PASS", detail, 200)

    summary, err = safe_get(client, "/v1/cluster/summary")
    if err:
        ctx.section("cluster_summary", "WARN", {"error": str(err)}, err.status)
    else:
        ctx.section("cluster_summary", "PASS", summarize_list(summary), 200)

    errors, err = safe_get(client, "/v1/cluster/errors")
    if err:
        ctx.section("cluster_errors", "WARN", {"error": str(err)}, err.status)
    else:
        resources = []
        if isinstance(errors, dict):
            resources = errors.get("resources") or errors.get("errors") or []
            if not isinstance(resources, list):
                resources = [errors] if errors else []
        elif isinstance(errors, list):
            resources = errors
        if resources:
            ctx.add(
                "system",
                "cluster_errors",
                "CRITICAL",
                f"Cluster reports {len(resources)} error(s).",
            )
            ctx.section("cluster_errors", "FAIL", {"count": len(resources), "sample": resources[:5]}, 200)
        else:
            ctx.section("cluster_errors", "PASS", {"count": 0}, 200)

    nodes, err = safe_get(client, "/v1/nodes")
    if err:
        ctx.section("nodes", "WARN", {"error": str(err)}, err.status)
    else:
        ctx.section("nodes", "PASS", summarize_list(nodes), 200)


def check_ntp(ctx: ReportCtx, client: CmClient) -> None:
    status, err = safe_get(client, "/v1/system/ntp/status")
    servers, serr = safe_get(client, "/v1/system/ntp/servers")
    detail: dict[str, Any] = {}
    result = "PASS"
    if serr:
        detail["servers_error"] = str(serr)
        result = "WARN"
    else:
        resources = (servers or {}).get("resources") or []
        detail["servers"] = [r.get("host") for r in resources if isinstance(r, dict)]
        if not detail["servers"]:
            ctx.add("system", "ntp_no_servers", "WARNING", "No NTP servers are configured.")
            result = "WARN"
    if err:
        detail["status_error"] = str(err)
        result = "WARN"
    else:
        raw = ""
        if isinstance(status, dict):
            raw = str(status.get("ntpq -p") or "")
        detail["ntpq_synced"] = "*" in raw
        if raw and "*" not in raw:
            ctx.add(
                "system",
                "ntp_not_synced",
                "WARNING",
                "NTP does not show a synchronized peer (*).",
            )
            result = "WARN"
    ctx.section("ntp", result, detail, 200)


def check_banner(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/auth/banners/pre-auth")
    if err:
        ctx.section("banner_pre_auth", "WARN", {"error": str(err)}, err.status)
        return
    value = (data or {}).get("value") if isinstance(data, dict) else None
    if not (value and str(value).strip()):
        ctx.add(
            "system",
            "banner_missing",
            "WARNING",
            "Pre-authentication login banner is not configured.",
        )
        ctx.section("banner_pre_auth", "WARN", {"configured": False}, 200)
    else:
        ctx.section(
            "banner_pre_auth",
            "PASS",
            {"configured": True, "preview": str(value).strip()[:120]},
            200,
        )


def _disk_is_encrypted(data: dict[str, Any] | None) -> bool:
    """Interpret /v1/locker/diskenc/status for encrypted vs not."""
    if not isinstance(data, dict):
        return False
    if data.get("hasDEK") is True:
        return True
    status = str(data.get("encryptionStatus") or "").strip().lower()
    if not status:
        return False
    if "not encrypt" in status or status in ("unencrypted", "none", "disabled"):
        return False
    return "encrypt" in status


def check_diskenc(ctx: ReportCtx, client: CmClient) -> None:
    """Disk encryption posture + preboot presence (auto when disk is encrypted)."""
    data, err = safe_get(client, "/v1/locker/diskenc/status")
    if err:
        ctx.section("disk_encryption", "WARN", {"error": str(err)}, err.status)
        return

    encrypted = _disk_is_encrypted(data if isinstance(data, dict) else None)
    attended = (data or {}).get("attendedBoot") is True
    status = (data or {}).get("encryptionStatus")

    preboot: list[dict[str, Any]] = []
    idata, ierr = safe_get(client, "/v1/configs/interfaces/")
    if not ierr:
        for i in (idata or {}).get("resources") or []:
            if not isinstance(i, dict):
                continue
            itype = str(i.get("interface_type") or "").strip().lower()
            name = str(i.get("name") or "").strip().lower()
            if itype == "preboot" or name == "preboot":
                preboot.append(
                    {
                        "name": i.get("name"),
                        "port": i.get("port"),
                        "enabled": bool(i.get("enabled")),
                        "mode": i.get("mode"),
                        "network_interface": i.get("network_interface"),
                    }
                )

    detail = {
        "encryptionStatus": status,
        "attendedBoot": (data or {}).get("attendedBoot"),
        "hasDEK": (data or {}).get("hasDEK"),
        "encrypted": encrypted,
        "preboot_interfaces": preboot,
    }

    if encrypted:
        ctx.add(
            "system",
            "diskenc_enabled",
            "INFO",
            f"Disk encryption is enabled (status={status!r}, hasDEK="
            f"{(data or {}).get('hasDEK')}).",
        )
        if preboot:
            en = sum(1 for p in preboot if p.get("enabled"))
            names = ", ".join(
                f"{p.get('name')}(enabled={p.get('enabled')}, port={p.get('port')})"
                for p in preboot[:10]
            )
            ctx.add(
                "system",
                "diskenc_preboot_present",
                "INFO",
                f"Preboot interface present ({len(preboot)}; enabled={en}) — "
                f"expected when disk encryption is on: {names}.",
            )
        else:
            ctx.add(
                "system",
                "diskenc_preboot_missing",
                "WARNING",
                "Disk encryption reports enabled but no preboot interface was found "
                "(preboot is normally auto-created when the disk is encrypted).",
            )
    else:
        ctx.add(
            "system",
            "diskenc_not_encrypted",
            "WARNING",
            f"Disk is not encrypted (status={status!r}, hasDEK="
            f"{(data or {}).get('hasDEK')}). Enable disk encryption for added "
            f"security; preboot interface appears when encryption is enabled.",
        )
        if preboot:
            ctx.add(
                "system",
                "diskenc_preboot_unexpected",
                "WARNING",
                "Preboot interface is present while diskenc status is not encrypted — "
                "verify disk encryption configuration.",
            )

    if attended:
        ctx.add(
            "system",
            "diskenc_attended_boot",
            "WARNING",
            "Disk encryption attendedBoot is ENABLED (manual passphrase at boot).",
        )

    warn = (not encrypted) or attended or (encrypted and not preboot) or (
        (not encrypted) and bool(preboot)
    )
    ctx.section("disk_encryption", "WARN" if warn else "PASS", detail, 200)


# RoT age thresholds (calendar-ish months)
ROT_WARN_DAYS = 183   # >= 6 months → WARNING
ROT_CRIT_DAYS = 365   # >= 12 months → CRITICAL


def check_rot_keys(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/system/rot-keys")
    if err:
        ctx.section("rot_keys", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    ages = []
    for k in resources:
        if not isinstance(k, dict):
            continue
        created = parse_date(k.get("createdAt"))
        age = (ctx.now - created).days if created else None
        row = {
            "id": k.get("id"),
            "createdAt": k.get("createdAt"),
            "age_days": age,
            "age_years": round(age / 365.0, 2) if age is not None else None,
        }
        ages.append(row)
        if age is not None and age >= ROT_CRIT_DAYS:
            ctx.add(
                "system",
                "rot_key_critical_age",
                "CRITICAL",
                f"Root-of-Trust key '{k.get('id')}' is {age} days old "
                f"(~{row['age_years']} years; threshold 12 months).",
            )
        elif age is not None and age >= ROT_WARN_DAYS:
            ctx.add(
                "system",
                "rot_key_old",
                "WARNING",
                f"Root-of-Trust key '{k.get('id')}' is {age} days old "
                f"(~{row['age_years']} years; threshold 6 months).",
            )
        elif age is not None:
            ctx.add(
                "system",
                "rot_key_age",
                "INFO",
                f"Root-of-Trust key '{k.get('id')}' age is {age} days "
                f"(~{row['age_years']} years).",
            )
    critical_age = [a for a in ages if (a.get("age_days") or 0) >= ROT_CRIT_DAYS]
    warn_age = [
        a
        for a in ages
        if ROT_WARN_DAYS <= (a.get("age_days") or 0) < ROT_CRIT_DAYS
    ]
    ctx.section(
        "rot_keys",
        "FAIL" if critical_age else ("WARN" if warn_age else "PASS"),
        {
            "total": (data or {}).get("total", len(resources)),
            "keys": ages,
            "older_than_12m": critical_age,
            "older_than_6m": warn_age,
            "older_than_3y": critical_age,
            "older_than_2y": warn_age,
        },
        200,
    )


def check_licensing(ctx: ReportCtx, client: CmClient) -> None:
    features, ferr = safe_get(client, "/v1/licensing/features/")
    licenses, lerr = safe_get(client, "/v1/licensing/licenses/")
    if ferr:
        ctx.section("licensing_features", "FAIL", {"error": str(ferr)}, ferr.status)
    else:
        expired_f = []
        expiring_f = []
        for feat in (features or {}).get("resources") or []:
            if not isinstance(feat, dict):
                continue
            name = feat.get("name")
            status = str(feat.get("status") or "").lower()
            sec = feat.get("trial_seconds_remaining") or 0
            days = int(sec) // 86400 if sec else None
            if status == "expired":
                expired_f.append(name)
                ctx.add(
                    "licensing",
                    "feature_expired",
                    "CRITICAL",
                    f"Licensed feature '{name}' is EXPIRED.",
                )
            elif days is not None and 0 <= days <= 30:
                expiring_f.append({"name": name, "trial_days_remaining": days})
        if expiring_f:
            min_days = min(x["trial_days_remaining"] for x in expiring_f)
            ctx.add(
                "licensing",
                "feature_trial_expiring",
                "WARNING",
                f"{len(expiring_f)} licensed feature trial(s) expire within 30 days "
                f"(soonest ~{min_days} days).",
            )
        ctx.section(
            "licensing_features",
            "FAIL" if expired_f else ("WARN" if expiring_f else "PASS"),
            {
                "total": (features or {}).get("total"),
                "expired": expired_f[:20],
                "trials_expiring_soon": expiring_f[:20],
            },
            200,
        )

    if lerr:
        ctx.section("licensing_licenses", "FAIL", {"error": str(lerr)}, lerr.status)
        return

    expired = []
    expiring = []
    trials_expiring = []
    active = 0
    for lic in (licenses or {}).get("resources") or []:
        if not isinstance(lic, dict):
            continue
        state = str(lic.get("state") or "").lower()
        if state == "inactive":
            continue
        active += 1
        feature = lic.get("feature") or lic.get("friendly_name")
        if state == "expired":
            expired.append(feature)
            ctx.add(
                "licensing",
                "license_expired",
                "CRITICAL",
                f"License for feature '{feature}' is EXPIRED.",
            )
            continue
        exp = lic.get("expiration")
        if exp and str(exp).strip().lower() != "no expiration":
            dt = parse_date(exp)
            dleft = days_until(dt, ctx.now)
            if dleft is not None and dleft < 0:
                expired.append(feature)
                ctx.add(
                    "licensing",
                    "license_expired",
                    "CRITICAL",
                    f"License for feature '{feature}' expired {abs(dleft)} days ago.",
                )
            elif dleft is not None and dleft <= 30:
                expiring.append({"feature": feature, "days_left": dleft})
                ctx.add(
                    "licensing",
                    "license_expiring",
                    "WARNING",
                    f"License for feature '{feature}' expires in {dleft} days.",
                )
        sec = lic.get("trial_seconds_remaining")
        if str(lic.get("type") or "").lower() == "trial" and isinstance(sec, (int, float)):
            days = int(sec) // 86400
            if 0 <= days <= 30:
                trials_expiring.append({"feature": feature, "trial_days_remaining": days})
    if trials_expiring:
        min_days = min(t["trial_days_remaining"] for t in trials_expiring)
        ctx.add(
            "licensing",
            "license_trial_expiring",
            "WARNING",
            f"{len(trials_expiring)} active trial license(s) expire within 30 days "
            f"(soonest ~{min_days} days).",
        )
    result = "FAIL" if expired else ("WARN" if (expiring or trials_expiring) else "PASS")
    ctx.section(
        "licensing_licenses",
        result,
        {
            "total": (licenses or {}).get("total"),
            "active_count": active,
            "expired": expired[:20],
            "expiring_soon": expiring[:20],
            "trials_expiring_soon": trials_expiring[:20],
        },
        200,
    )


def check_interfaces(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/configs/interfaces/")
    if err:
        ctx.section("interfaces", "FAIL", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    tcp_mode: list[dict] = []
    mode_warn: list[dict] = []
    mode_preferred: list[dict] = []  # tls-cert-and-pw only
    mode_web_ok: list[dict] = []  # web platform-supported modes
    ssh_ifaces: list[dict] = []
    snmp_ifaces: list[dict] = []
    preboot_ifaces: list[dict] = []
    weak_tls = []
    disabled = []
    no_pqc = []
    cert_expired = []
    cert_expiring = []
    cert_ok = []
    cert_errors = []
    rows = []
    for i in resources:
        if not isinstance(i, dict):
            continue
        name = i.get("name")
        enabled = i.get("enabled")
        itype = str(i.get("interface_type") or "").strip().lower() or None
        mode = (i.get("mode") or "").strip()
        mode_l = mode.lower()
        label = interface_mode_label(mode_l) if mode_l else None
        tls = str(i.get("minimum_tls_version") or "").lower()
        row = {
            "name": name,
            "port": i.get("port"),
            "enabled": enabled,
            "interface_type": itype,
            "mode": mode or None,
            "mode_label": label,
            "network_interface": i.get("network_interface"),
            "minimum_tls_version": i.get("minimum_tls_version"),
        }
        rows.append(row)
        if itype == "ssh":
            ssh_ifaces.append(
                {
                    "name": name,
                    "port": i.get("port"),
                    "enabled": bool(enabled),
                    "network_interface": i.get("network_interface"),
                }
            )
        elif itype == "snmp":
            snmp_ifaces.append(
                {
                    "name": name,
                    "port": i.get("port"),
                    "enabled": bool(enabled),
                    "network_interface": i.get("network_interface"),
                }
            )
        elif itype == "preboot" or str(name or "").lower() == "preboot":
            preboot_ifaces.append(
                {
                    "name": name,
                    "port": i.get("port"),
                    "enabled": bool(enabled),
                    "mode": mode or None,
                    "mode_label": label,
                    "network_interface": i.get("network_interface"),
                }
            )
        if not enabled:
            disabled.append(name)
            if itype not in ("ssh", "snmp", "preboot"):
                ctx.add(
                    "network",
                    "net_interface_disabled",
                    "INFO",
                    f"Service interface '{name}' is DISABLED (often intentional).",
                )
        elif enabled and itype != "preboot":
            sev = interface_mode_severity(mode, interface_type=itype)
            entry = {
                "name": name,
                "interface_type": itype,
                "mode": mode or None,
                "mode_label": label,
            }
            if sev == "CRITICAL":
                tcp_mode.append(entry)
                ctx.add(
                    "network",
                    "net_interface_tcp_mode",
                    "CRITICAL",
                    f"Service interface '{name}' uses TCP mode (no TLS): {label} "
                    f"({mode}).",
                )
            elif sev == "WARNING":
                mode_warn.append(entry)
                ctx.add(
                    "network",
                    "net_interface_mode_warn",
                    "WARNING",
                    f"Service interface '{name}' mode is not tls-cert-and-pw: "
                    f"{label} ({mode}). Prefer tls-cert-and-pw.",
                )
            elif sev == "INFO":
                if itype == "web":
                    mode_web_ok.append(entry)
                    ctx.add(
                        "network",
                        "net_interface_mode_web_ok",
                        "INFO",
                        f"Web interface '{name}' mode OK (platform-supported): "
                        f"{label} ({mode}).",
                    )
                else:
                    mode_preferred.append(entry)
                    ctx.add(
                        "network",
                        "net_interface_mode_preferred",
                        "INFO",
                        f"Service interface '{name}' uses preferred mode: {label} "
                        f"({mode}).",
                    )
        if enabled and tls in WEAK_TLS:
            weak_tls.append({"name": name, "minimum_tls_version": tls})
            ctx.add(
                "network",
                "net_interface_weak_tls",
                "CRITICAL",
                f"Service interface '{name}' has weak minimum TLS '{tls}'.",
            )
        tls_groups = i.get("tls_groups") or []
        if enabled and isinstance(tls_groups, list) and tls_groups:
            pqc = [
                g.get("group_name")
                for g in tls_groups
                if isinstance(g, dict)
                and g.get("group_name") in PQC_GROUPS
                and g.get("enabled")
            ]
            if not pqc:
                no_pqc.append(name)
                ctx.add(
                    "network",
                    "net_interface_no_pqc",
                    "INFO",
                    f"Service interface '{name}' has no PQC key-exchange group enabled.",
                )

        if (
            enabled
            and name
            and not mode_l.startswith("no-tls")
            and mode_l not in ("", "none", "null")
        ):
            cdata, cerr = safe_get(client, f"/v1/configs/interfaces/{name}/certificate")
            if cerr:
                if cerr.status != 404:
                    cert_errors.append({"name": name, "error": str(cerr)})
                continue
            pem = ""
            if isinstance(cdata, dict):
                pem = cdata.get("certificates") or cdata.get("certificate") or ""
            if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem:
                cert_errors.append({"name": name, "error": "no PEM certificate in response"})
                continue
            not_after_dt = pem_leaf_not_after(pem)
            dleft = days_until(not_after_dt, ctx.now)
            na_s = not_after_dt.strftime("%Y-%m-%d") if not_after_dt else None
            row = {"name": name, "notAfter": na_s, "days_left": dleft}
            sev = emit_cert_validity(
                ctx,
                area="network",
                code_prefix="net_iface_cert",
                label=f"Interface '{name}' TLS certificate",
                days_left=dleft,
                not_after=na_s,
            )
            if sev == "CRITICAL":
                cert_expired.append(row)
            elif sev == "WARNING":
                cert_expiring.append(row)
            elif sev == "INFO":
                cert_ok.append(row)
            rows[-1]["cert_notAfter"] = na_s
            rows[-1]["cert_days_left"] = dleft

    def _mgmt_iface_summary(kind: str, items: list[dict]) -> None:
        if not items:
            ctx.add(
                "network",
                f"net_{kind}_not_configured",
                "INFO",
                f"No {kind.upper()} interfaces are configured.",
            )
            return
        en = [x for x in items if x.get("enabled")]
        dis = [x for x in items if not x.get("enabled")]
        parts = []
        for x in items[:20]:
            state = "enabled" if x.get("enabled") else "disabled"
            port = x.get("port")
            nic = x.get("network_interface")
            bit = f"{x.get('name')} ({state}"
            if port is not None:
                bit += f", port {port}"
            if nic:
                bit += f", nic {nic}"
            bit += ")"
            parts.append(bit)
        msg = (
            f"{kind.upper()} configured: {len(items)} "
            f"(enabled={len(en)}, disabled={len(dis)}): "
            + "; ".join(parts)
        )
        if len(items) > 20:
            msg += f"; … +{len(items) - 20} more"
        msg += "."
        ctx.add("network", f"net_{kind}_configured", "INFO", msg)

    _mgmt_iface_summary("ssh", ssh_ifaces)
    _mgmt_iface_summary("snmp", snmp_ifaces)
    if preboot_ifaces:
        en = [x for x in preboot_ifaces if x.get("enabled")]
        parts = []
        for x in preboot_ifaces[:10]:
            state = "enabled" if x.get("enabled") else "disabled"
            bit = f"{x.get('name')} ({state}"
            if x.get("port") is not None:
                bit += f", port {x.get('port')}"
            if x.get("mode"):
                bit += f", mode {x.get('mode')}"
            bit += ")"
            parts.append(bit)
        ctx.add(
            "network",
            "net_preboot_configured",
            "INFO",
            f"Preboot configured: {len(preboot_ifaces)} (enabled={len(en)}) — "
            f"auto-created when disk encryption is enabled: "
            + "; ".join(parts)
            + ".",
        )
    result = "FAIL" if (tcp_mode or weak_tls or cert_expired) else (
        "WARN" if (mode_warn or cert_expiring or cert_errors) else "PASS"
    )
    ctx.section(
        "interfaces",
        result,
        {
            "total": len(resources),
            "enabled": sum(1 for r in rows if r.get("enabled")),
            "disabled": disabled,
            "tcp_modes": tcp_mode,
            "cleartext_modes": tcp_mode,
            "mode_warn": mode_warn,
            "mode_preferred": mode_preferred,
            "mode_web_ok": mode_web_ok,
            "ssh_interfaces": ssh_ifaces,
            "snmp_interfaces": snmp_ifaces,
            "preboot_interfaces": preboot_ifaces,
            "unauth_tls_modes": [
                m for m in mode_warn if str(m.get("mode") or "").startswith("unauth-tls")
            ],
            "weak_tls": weak_tls,
            "no_pqc": no_pqc[:20],
            "tls_certs_expired": cert_expired,
            "tls_certs_expiring_soon": cert_expiring,
            "tls_certs_ok": cert_ok[:20],
            "tls_certs_errors": cert_errors[:10],
            "interfaces": rows,
        },
        200,
    )


def check_log_forwarders(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/configs/log-forwarders/")
    if err:
        data, err = safe_get(client, "/v1/configs/log-forwarders")
    if err:
        ctx.section("log_forwarders", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    active = [r for r in resources if isinstance(r, dict) and not r.get("disabled")]
    if not active:
        ctx.add(
            "network",
            "net_no_active_log_forwarders",
            "WARNING",
            "No active external log forwarders are configured.",
        )
        ctx.section(
            "log_forwarders",
            "WARN",
            {"total": len(resources), "active": 0},
            200,
        )
    else:
        ctx.section(
            "log_forwarders",
            "PASS",
            {
                "total": len(resources),
                "active": len(active),
                "names": [r.get("name") for r in active[:10]],
            },
            200,
        )


def check_notifications(ctx: ReportCtx, client: CmClient) -> None:
    smtp, serr = safe_get(client, "/v1/notification/smtp-servers")
    emails, eerr = safe_get(client, "/v1/notification/email-addresses")
    detail: dict[str, Any] = {}
    result = "PASS"
    if serr:
        detail["smtp_error"] = str(serr)
        result = "WARN"
        smtp_count = 0
    else:
        smtp_count = len((smtp or {}).get("resources") or [])
        detail["smtp_servers"] = smtp_count
        if smtp_count == 0:
            ctx.add("system", "smtp_missing", "WARNING", "No SMTP server configured for email alerting.")
            result = "WARN"
    if eerr:
        detail["email_error"] = str(eerr)
        result = "WARN"
    else:
        email_count = len((emails or {}).get("resources") or [])
        detail["email_addresses"] = email_count
        if smtp_count > 0 and email_count == 0:
            ctx.add(
                "system",
                "notification_emails_missing",
                "WARNING",
                "SMTP is configured but no notification email recipients are set.",
            )
            result = "WARN"
    ctx.section("notifications", result, detail, 200)


def check_backups(ctx: ReportCtx, client: CmClient) -> None:
    status, _ = safe_get(client, "/v1/backupStatus")
    backups, berr = safe_get(client, "/v1/backups?limit=20")
    keys, kerr = safe_get(client, "/v1/backupkeys")
    jobs, jerr = safe_get(client, "/v1/scheduler/job-configs?limit=100")

    if status is not None:
        st = (status or {}).get("status")
        detail = {
            "status": st,
            "operation": (status or {}).get("operation"),
            "finished": (status or {}).get("finished"),
        }
        if st and str(st).lower() not in ("completed", "complete", "success", "successful"):
            ctx.add(
                "system",
                "backup_status_not_completed",
                "WARNING",
                f"Latest backup operation status is '{st}'.",
            )
            ctx.section("backup_status", "WARN", detail, 200)
        else:
            ctx.section("backup_status", "PASS", detail, 200)

    backup_key_states: dict[str, str] = {}
    if kerr:
        ctx.section("backup_keys", "WARN", {"error": str(kerr)}, kerr.status)
    else:
        resources = (keys or {}).get("resources") or []
        inactive = []
        for k in resources:
            if not isinstance(k, dict):
                continue
            kid = str(k.get("id"))
            state = str(k.get("state") or "").lower()
            backup_key_states[kid] = state
            if state and state != "active":
                inactive.append({"id": kid, "state": state})
                ctx.add(
                    "system",
                    "backup_key_inactive",
                    "WARNING",
                    f"Backup key '{kid}' is not active (state={state}).",
                )
        ctx.section(
            "backup_keys",
            "WARN" if inactive else "PASS",
            {"total": len(resources), "inactive": inactive},
            200,
        )

    if berr:
        ctx.section("backups_list", "WARN", {"error": str(berr)}, berr.status)
    else:
        resources = (backups or {}).get("resources") or []
        total = (backups or {}).get("total", len(resources))
        if not resources:
            ctx.add("system", "backup_none", "WARNING", "No backups exist.")
            ctx.section("backups_list", "WARN", {"total": 0}, 200)
        else:
            newest = resources[0]
            created = parse_date(newest.get("createdAt"))
            age_days = (ctx.now - created).days if created else None
            missing_key = []
            for b in resources:
                bk = b.get("backupKey")
                if bk and bk in backup_key_states and backup_key_states[bk] != "active":
                    missing_key.append(b.get("id"))
                elif bk and backup_key_states and bk not in backup_key_states:
                    ctx.add(
                        "system",
                        "backup_missing_key",
                        "CRITICAL",
                        f"Backup '{b.get('id')}' references missing backup key '{bk}'.",
                    )
                    missing_key.append(b.get("id"))
            if age_days is not None and age_days > 7:
                ctx.add(
                    "system",
                    "backup_stale",
                    "WARNING",
                    f"Newest backup is {age_days} days old (>7).",
                )
            ctx.section(
                "backups_list",
                "WARN" if (age_days and age_days > 7) or missing_key else "PASS",
                {
                    "total": total,
                    "newest_createdAt": newest.get("createdAt"),
                    "newest_age_days": age_days,
                    "sample": [
                        {
                            "id": b.get("id"),
                            "status": b.get("status"),
                            "createdAt": b.get("createdAt"),
                            "description": b.get("description"),
                        }
                        for b in resources[:3]
                    ],
                },
                200,
            )

    if jerr:
        ctx.section("backup_scheduler", "WARN", {"error": str(jerr)}, jerr.status)
    else:
        resources = (jobs or {}).get("resources") or []
        backup_jobs = [
            j
            for j in resources
            if isinstance(j, dict) and str(j.get("operation") or "") == "database_backup"
        ]
        enabled = [j for j in backup_jobs if not j.get("disabled")]
        if not enabled:
            ctx.add(
                "system",
                "backup_schedule_missing",
                "WARNING",
                "No enabled scheduled database_backup job found.",
            )
        ctx.section(
            "backup_scheduler",
            "WARN" if not enabled else "PASS",
            {
                "backup_jobs": len(backup_jobs),
                "enabled": len(enabled),
                "names": [j.get("name") for j in enabled[:10]],
            },
            200,
        )


def check_alarms(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/system/alarms?limit=100")
    if err:
        ctx.section("alarms", "FAIL", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    active = [
        a
        for a in resources
        if isinstance(a, dict)
        and str(a.get("state") or "").lower() == "on"
        and a.get("acknowledgedAt") is None
    ]
    by_name = Counter(str(a.get("name") or "unnamed") for a in active)
    crit = []
    warn = []
    for a in active:
        sev = str(a.get("severity") or "").lower()
        row = {
            "name": a.get("name"),
            "severity": a.get("severity"),
            "description": (a.get("description") or "")[:160],
        }
        if sev in ALARM_CRITICAL_SEVS:
            crit.append(row)
        else:
            warn.append(row)
    if crit:
        ctx.add(
            "system",
            "alarms_critical",
            "CRITICAL",
            f"{len(crit)} active critical/error alarm(s).",
        )
    elif active:
        ctx.add(
            "system",
            "alarms_active",
            "WARNING",
            f"{len(active)} active unacknowledged alarm(s).",
        )
    result = "FAIL" if crit else ("WARN" if active else "PASS")
    ctx.section(
        "alarms",
        result,
        {
            "total": (data or {}).get("total"),
            "returned": len(resources),
            "active_unacknowledged": len(active),
            "active_by_name": dict(by_name.most_common(10)),
            "critical_sample": crit[:10],
            "warning_sample": warn[:10],
        },
        200,
    )


def _interface_referenced_ca_ids(client: CmClient) -> set[str]:
    """CA ids/uris referenced by enabled interfaces (auto_gen + trusted_cas)."""
    refs: set[str] = set()
    data, err = safe_get(client, "/v1/configs/interfaces/")
    if err or not isinstance(data, dict):
        return refs
    for i in data.get("resources") or []:
        if not isinstance(i, dict) or not i.get("enabled"):
            continue
        ag = i.get("auto_gen_ca_id")
        if ag:
            refs.add(str(ag))
            if ":" in str(ag):
                refs.add(str(ag).rsplit(":", 1)[-1])
        trusted = i.get("trusted_cas") or {}
        if isinstance(trusted, dict):
            for bucket in trusted.values():
                if isinstance(bucket, list):
                    for item in bucket:
                        refs.add(str(item))
                        if ":" in str(item):
                            refs.add(str(item).rsplit(":", 1)[-1])
    return refs


def _ca_is_referenced(ca: dict, refs: set[str]) -> bool:
    for key in ("id", "uri", "name"):
        val = ca.get(key)
        if val and str(val) in refs:
            return True
        if val and ":" in str(val) and str(val).rsplit(":", 1)[-1] in refs:
            return True
    return False


def check_cas(ctx: ReportCtx, client: CmClient) -> None:
    """CA cert validity: expired CRITICAL; ≤30d WARNING; >30d INFO."""
    refs = _interface_referenced_ca_ids(client)
    for kind, path in (
        ("local", "/v1/ca/local-cas?limit=100"),
        ("external", "/v1/ca/external-cas?limit=100"),
    ):
        data, err = safe_get(client, path)
        if err:
            ctx.section(f"ca_{kind}", "WARN", {"error": str(err)}, err.status)
            continue
        resources = (data or {}).get("resources") or []
        expired: list[dict] = []
        expiring: list[dict] = []
        ok: list[dict] = []
        for ca in resources:
            if not isinstance(ca, dict):
                continue
            name = ca.get("name") or ca.get("id")
            state = str(ca.get("state") or "").lower()
            after = parse_date(ca.get("notAfter"))
            dleft = days_until(after, ctx.now)
            if state == "expired" and dleft is None:
                dleft = -1
            in_use = _ca_is_referenced(ca, refs)
            row = {
                "name": name,
                "state": ca.get("state"),
                "notAfter": ca.get("notAfter"),
                "days_left": dleft,
                "referenced_by_interface": in_use,
            }
            label = f"{kind.title()} CA '{name}'"
            if in_use:
                label += " (referenced by enabled interface)"
            sev = emit_cert_validity(
                ctx,
                area="ca",
                code_prefix=f"ca_{kind}",
                label=label,
                days_left=dleft,
                not_after=str(ca.get("notAfter") or "")[:32] or None,
            )
            if sev == "CRITICAL":
                expired.append(row)
            elif sev == "WARNING":
                expiring.append(row)
            elif sev == "INFO":
                ok.append(row)
        result = "FAIL" if expired else ("WARN" if expiring else "PASS")
        ctx.section(
            f"ca_{kind}",
            result,
            {
                "total": (data or {}).get("total", len(resources)),
                "expired": expired,
                "expired_in_use": [r for r in expired if r.get("referenced_by_interface")],
                "expiring_soon": expiring,
                "ok": ok[:20],
            },
            200,
        )

    trusted, err = safe_get(client, "/v1/trusted-cas/?limit=100")
    if err:
        ctx.section("ca_trusted", "WARN", {"error": str(err)}, err.status)
    else:
        resources = (trusted or {}).get("resources") or []
        expired = []
        expiring = []
        ok = []
        for ca in resources:
            if not isinstance(ca, dict):
                continue
            details = ca.get("ca_details") if isinstance(ca.get("ca_details"), dict) else ca
            name = ca.get("name") or details.get("name") or ca.get("id")
            after = parse_date(details.get("notAfter") or ca.get("notAfter"))
            dleft = days_until(after, ctx.now)
            na = details.get("notAfter") or ca.get("notAfter")
            row = {"name": name, "days_left": dleft, "notAfter": na}
            sev = emit_cert_validity(
                ctx,
                area="ca",
                code_prefix="ca_trusted",
                label=f"Trusted CA '{name}'",
                days_left=dleft,
                not_after=str(na)[:32] if na else None,
            )
            if sev == "CRITICAL":
                expired.append(row)
            elif sev == "WARNING":
                expiring.append(row)
            elif sev == "INFO":
                ok.append(row)
        ctx.section(
            "ca_trusted",
            "FAIL" if expired else ("WARN" if expiring else "PASS"),
            {
                "total": (trusted or {}).get("total", len(resources)),
                "expired": expired,
                "expiring_soon": expiring,
                "ok": ok[:20],
            },
            200,
        )


def check_password_policies(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/usermgmt/pwdpolicies/")
    if err:
        ctx.section("password_policies", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    weak = []
    for p in resources:
        if not isinstance(p, dict):
            continue
        name = p.get("policy_name") or "unnamed"
        min_len = p.get("inclusive_min_total_length")
        history = p.get("password_history_threshold")
        lockout = p.get("failed_logins_lockout_thresholds")
        lifetime = p.get("password_lifetime")
        if isinstance(min_len, int) and min_len < 8:
            weak.append(name)
            ctx.add(
                "access",
                "access_pwd_policy_weak_min_length",
                "WARNING",
                f"Password policy '{name}' minimum length is {min_len} (<8).",
            )
        if history == 0:
            weak.append(name)
            ctx.add(
                "access",
                "access_pwd_policy_no_history",
                "WARNING",
                f"Password policy '{name}' has password reuse prevention disabled.",
            )
        if not lockout:
            weak.append(name)
            ctx.add(
                "access",
                "access_pwd_policy_no_lockout",
                "WARNING",
                f"Password policy '{name}' has account lockout disabled.",
            )
        if lifetime == 0:
            ctx.add(
                "access",
                "access_pwd_policy_no_expiry",
                "INFO",
                f"Password policy '{name}' does not enforce password expiration.",
            )
        if name != "global":
            ctx.add(
                "access",
                "access_pwd_policy_custom",
                "INFO",
                f"Custom password policy '{name}' is present.",
            )
    ctx.section(
        "password_policies",
        "WARN" if weak else "PASS",
        {"total": len(resources), "weak_policies": sorted(set(weak))},
        200,
    )


def check_ldap(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/connectionmgmt/services/ldap/connections?limit=100")
    if err:
        ctx.section("ldap_connections", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    issues = 0
    rows = []
    for conn in resources:
        if not isinstance(conn, dict):
            continue
        name = conn.get("name")
        url = str(conn.get("server_url") or "")
        rows.append(
            {
                "name": name,
                "server_url": url,
                "insecure_skip_verify": conn.get("insecure_skip_verify"),
                "has_root_ca": bool(any(x for x in (conn.get("root_cas") or []) if x)),
            }
        )
        if url.lower().startswith("ldaps://"):
            if conn.get("insecure_skip_verify") is True:
                issues += 1
                ctx.add(
                    "access",
                    "access_ldap_insecure_skip_verify",
                    "CRITICAL",
                    f"LDAP connection '{name}' has certificate verification disabled.",
                )
            root_cas = conn.get("root_cas") or []
            if not any(x for x in root_cas if x):
                issues += 1
                ctx.add(
                    "access",
                    "access_ldap_no_root_ca",
                    "WARNING",
                    f"LDAP connection '{name}' (ldaps) has no root_ca configured.",
                )
    ctx.section(
        "ldap_connections",
        "FAIL" if any(f.code == "access_ldap_insecure_skip_verify" for f in ctx.findings) else (
            "WARN" if issues else "PASS"
        ),
        {"total": len(resources), "connections": rows},
        200,
    )


def summarize_users(
    resources: list[Any],
    *,
    now: datetime,
    total_reported: Any = None,
    truncated: bool = False,
) -> dict[str, Any]:
    """Hygiene + top logins from a scanned user page set (client-side ranking)."""
    locked = never = inactive = failed = 0
    samples: dict[str, list] = defaultdict(list)
    ranked: list[dict[str, Any]] = []
    for u in resources:
        if not isinstance(u, dict):
            continue
        uname = u.get("username") or u.get("name")
        logins = int(u.get("logins_count") or 0)
        ranked.append(
            {
                "username": uname,
                "logins_count": logins,
                "last_login": u.get("last_login"),
                "failed_logins_count": u.get("failed_logins_count") or 0,
            }
        )
        if u.get("account_lockout_at"):
            locked += 1
            if len(samples["locked"]) < 8:
                samples["locked"].append(uname)
        last = parse_date(u.get("last_login"))
        if logins == 0 or u.get("last_login") in (None, ""):
            never += 1
            if len(samples["never_logged_in"]) < 8:
                samples["never_logged_in"].append(uname)
        elif last and (now - last).days > 30:
            inactive += 1
            if len(samples["inactive_30d"]) < 8:
                samples["inactive_30d"].append(uname)
        fails = u.get("failed_logins_count") or 0
        if fails and not u.get("account_lockout_at"):
            failed += 1
            if len(samples["failed_logins"]) < 8:
                samples["failed_logins"].append({"user": uname, "failed_logins_count": fails})
    ranked.sort(key=lambda r: (-(r.get("logins_count") or 0), str(r.get("username") or "")))
    return {
        "total_reported": total_reported if total_reported is not None else len(resources),
        "scanned": len(resources),
        "truncated": truncated,
        "locked": locked,
        "never_logged_in": never,
        "inactive_30d": inactive,
        "failed_logins_not_locked": failed,
        "top_by_logins": ranked[:5],
        "samples": dict(samples),
    }


def _sample_join(samples: dict[str, Any], key: str, limit: int = 5) -> str:
    vals = samples.get(key) or []
    return ", ".join(map(str, vals[:limit]))


def emit_user_findings(ctx: ReportCtx, domain: str | None, users: dict[str, Any]) -> None:
    """User hygiene is first-class health — elevate stale/unused accounts to WARNING."""
    prefix = f"[{domain}] " if domain else ""
    locked = users.get("locked") or 0
    never = users.get("never_logged_in") or 0
    inactive = users.get("inactive_30d") or 0
    failed = users.get("failed_logins_not_locked") or 0
    samples = users.get("samples") or {}
    top = users.get("top_by_logins") or []

    if locked:
        sample = _sample_join(samples, "locked")
        msg = f"{prefix}{locked} user account(s) are locked out"
        if sample:
            msg += f" (sample: {sample})"
        ctx.add("access", "access_users_locked", "WARNING", msg + ".")
    if never:
        sample = _sample_join(samples, "never_logged_in")
        msg = f"{prefix}{never} user account(s) have never logged in (scanned set)"
        if sample:
            msg += f" (sample: {sample})"
        ctx.add("access", "access_users_never_logged_in", "WARNING", msg + ".")
    if inactive:
        sample = _sample_join(samples, "inactive_30d")
        msg = f"{prefix}{inactive} user account(s) inactive >30 days (scanned set)"
        if sample:
            msg += f" (sample: {sample})"
        ctx.add("access", "access_users_inactive", "WARNING", msg + ".")
    if failed:
        ctx.add(
            "access",
            "access_users_failed_logins",
            "WARNING",
            f"{prefix}{failed} user account(s) have failed login attempts (not locked).",
        )
    if top:
        top_s = ", ".join(
            f"{t.get('username')}({t.get('logins_count')})" for t in top[:5] if isinstance(t, dict)
        )
        if top_s:
            ctx.add(
                "access",
                "access_users_top_logins",
                "INFO",
                f"{prefix}Top users by logins: {top_s}.",
            )


def users_have_hygiene_issues(users: dict[str, Any] | None) -> bool:
    if not users:
        return False
    return bool(
        users.get("locked")
        or users.get("never_logged_in")
        or users.get("inactive_30d")
        or users.get("failed_logins_not_locked")
    )


def _section_map(sections: list[dict]) -> dict[str, dict]:
    return {s["name"]: s for s in sections if isinstance(s, dict) and s.get("name")}


def _sec_detail(by: dict[str, dict], name: str) -> dict[str, Any] | None:
    s = by.get(name) or {}
    d = s.get("detail")
    return d if isinstance(d, dict) else None


def _sec_result(by: dict[str, dict], name: str) -> str | None:
    s = by.get(name)
    return s.get("result") if s else None


def _worst_result(*results: str | None) -> str | None:
    """Combine section results: FAIL > WARN > PASS > SKIP/other."""
    order = {"FAIL": 3, "WARN": 2, "PASS": 1, "SKIP": 0}
    best: str | None = None
    best_rank = -1
    for r in results:
        if not r:
            continue
        rank = order.get(str(r).upper(), 0)
        if rank > best_rank:
            best_rank = rank
            best = str(r).upper() if str(r).upper() in order else r
    return best


def collect_users_summary(sections: list[dict]) -> dict[str, Any]:
    """Roll up per-domain / current-domain user scans for the report header."""
    by_domain: list[dict[str, Any]] = []
    totals = {
        "domains_with_users": 0,
        "users_total": 0,
        "locked": 0,
        "never_logged_in": 0,
        "inactive_30d": 0,
        "failed_logins_not_locked": 0,
    }
    for s in sections:
        name = s.get("name")
        detail = s.get("detail")
        if name == "keys_domains" and isinstance(detail, dict):
            for c in detail.get("checked") or []:
                if not isinstance(c, dict):
                    continue
                users = c.get("users") or {}
                if not users:
                    continue
                totals["domains_with_users"] += 1
                totals["users_total"] += int(users.get("total_reported") or users.get("scanned") or 0)
                for k in (
                    "locked",
                    "never_logged_in",
                    "inactive_30d",
                    "failed_logins_not_locked",
                ):
                    totals[k] += int(users.get(k) or 0)
                by_domain.append(
                    {
                        "domain": c.get("domain"),
                        "total": users.get("total_reported"),
                        "locked": users.get("locked"),
                        "never_logged_in": users.get("never_logged_in"),
                        "inactive_30d": users.get("inactive_30d"),
                        "failed_logins_not_locked": users.get("failed_logins_not_locked"),
                        "top_by_logins": users.get("top_by_logins") or [],
                    }
                )
        elif name == "users_access" and isinstance(detail, dict) and "error" not in detail:
            totals["domains_with_users"] += 1
            totals["users_total"] += int(detail.get("total_reported") or detail.get("scanned") or 0)
            for k in (
                "locked",
                "never_logged_in",
                "inactive_30d",
                "failed_logins_not_locked",
            ):
                totals[k] += int(detail.get(k) or 0)
            by_domain.append(
                {
                    "domain": "(current token)",
                    "total": detail.get("total_reported"),
                    "locked": detail.get("locked"),
                    "never_logged_in": detail.get("never_logged_in"),
                    "inactive_30d": detail.get("inactive_30d"),
                    "failed_logins_not_locked": detail.get("failed_logins_not_locked"),
                    "top_by_logins": detail.get("top_by_logins") or [],
                }
            )
    return {"totals": totals, "by_domain": by_domain, "result": None}


def collect_keys_summary(sections: list[dict]) -> dict[str, Any]:
    by = _section_map(sections)
    metrics = _sec_detail(by, "keys_metrics") or {}
    domains = _sec_detail(by, "keys_domains") or {}
    checked = domains.get("checked") or []
    weak = sum(int(c.get("weak_count") or 0) for c in checked if isinstance(c, dict))
    non_active = sum(int(c.get("non_active_count") or 0) for c in checked if isinstance(c, dict))
    keys_total = sum(int(c.get("total_reported") or 0) for c in checked if isinstance(c, dict))
    keys_unique = sum(int(c.get("unique") or 0) for c in checked if isinstance(c, dict))
    by_domain = [
        {
            "domain": c.get("domain"),
            "total": c.get("total_reported"),
            "unique": c.get("unique"),
            "weak": c.get("weak_count"),
            "non_active": c.get("non_active_count"),
        }
        for c in checked
        if isinstance(c, dict)
    ]
    result = _sec_result(by, "keys_domains") or _sec_result(by, "keys_metrics")
    return {
        "result": result,
        "metrics": {
            "enabled": metrics.get("enabled"),
            "key_usage_total": metrics.get("key_usage_total_reported"),
            "domains_with_key_usage": metrics.get("domains_with_key_usage"),
            "deks_by_state": metrics.get("deks_by_state"),
            "keks_total": metrics.get("keks_total"),
            "top_domains": metrics.get("key_usage_top_domains") or [],
        }
        if metrics
        else None,
        "domains": {
            "listed": domains.get("domains_listed"),
            "checked": domains.get("checked_count"),
            "skipped": domains.get("skipped_count"),
            "keys_total": keys_total,
            "keys_unique": keys_unique,
            "weak": weak,
            "non_active": non_active,
            "by_domain": by_domain,
        }
        if domains
        else None,
    }


def collect_posture_summary(sections: list[dict]) -> dict[str, Any]:
    """Compact rollup of every major health area for agents and human headers."""
    by = _section_map(sections)
    users = collect_users_summary(sections)
    # Derive users.result from hygiene totals
    ut = users.get("totals") or {}
    if users.get("by_domain"):
        users["result"] = "WARN" if users_have_hygiene_issues(ut) else "PASS"
    else:
        users["result"] = "SKIP"

    info = _sec_detail(by, "system_info") or {}
    svc = _sec_detail(by, "services_status") or {}
    cluster = _sec_detail(by, "cluster") or {}
    ntp = _sec_detail(by, "ntp") or {}
    rot = _sec_detail(by, "rot_keys") or {}
    lic = _sec_detail(by, "licensing_licenses") or {}
    lic_feat = _sec_detail(by, "licensing_features") or {}
    alarms = _sec_detail(by, "alarms") or {}
    iface = _sec_detail(by, "interfaces") or {}
    fwd = _sec_detail(by, "log_forwarders") or {}
    notif = _sec_detail(by, "notifications") or {}
    backups = _sec_detail(by, "backups_list") or {}
    backup_sched = _sec_detail(by, "backup_scheduler") or {}
    backup_status = _sec_detail(by, "backup_status") or {}
    diskenc = _sec_detail(by, "diskenc") or _sec_detail(by, "disk_encryption") or {}
    banner = _sec_detail(by, "banner_pre_auth") or {}
    ca_local = _sec_detail(by, "ca_local") or {}
    ca_ext = _sec_detail(by, "ca_external") or {}
    ca_trust = _sec_detail(by, "ca_trusted") or {}
    orphan = _sec_detail(by, "orphaned_resources") or {}
    capacity = _sec_detail(by, "capacity_report") or {}
    quorum = _sec_detail(by, "quorum_policies") or {}
    clients = _sec_detail(by, "registered_clients") or {}
    cte = _sec_detail(by, "cte_clients") or {}
    cte_pol = _sec_detail(by, "cte_policies") or {}
    audit = _sec_detail(by, "audit_records") or {}
    ldap = _sec_detail(by, "ldap_connections") or {}
    pwd = _sec_detail(by, "password_policies") or {}
    domains = _sec_detail(by, "domains") or {}

    def _ca_block(d: dict[str, Any] | None, result: str | None) -> dict[str, Any] | None:
        if d is None and result is None:
            return None
        d = d or {}
        return {
            "result": result,
            "total": d.get("total"),
            "expired": len(d.get("expired") or []),
            "expired_in_use": len(d.get("expired_in_use") or []),
            "expiring_soon": len(d.get("expiring_soon") or []),
            "ok": len(d.get("ok") or []),
        }

    keys = collect_keys_summary(sections)

    return {
        "appliance": {
            "result": _worst_result(
                _sec_result(by, "services_status"),
                _sec_result(by, "system_info"),
                _sec_result(by, "disk_encryption"),
                _sec_result(by, "ntp"),
                _sec_result(by, "cluster"),
                _sec_result(by, "cluster_errors"),
                _sec_result(by, "banner_pre_auth"),
            ),
            "version": info.get("version"),
            "model": info.get("model"),
            "uptime": info.get("uptime"),
            "services_total": svc.get("total"),
            "services_started": svc.get("started"),
            "services_disabled": len(svc.get("disabled") or []),
            "services_not_started": len(svc.get("not_started") or []),
            "cluster": cluster.get("status_code") or cluster.get("status_description"),
            "ntp_synchronized": ntp.get("ntpq_synced"),
            "disk_encryption": diskenc.get("encryptionStatus"),
            "disk_encrypted": diskenc.get("encrypted"),
            "attended_boot": diskenc.get("attendedBoot"),
            "preboot_interfaces": len(diskenc.get("preboot_interfaces") or []),
            "banner_configured": banner.get("configured"),
        },
        "rot_keys": {
            "result": _sec_result(by, "rot_keys"),
            "total": rot.get("total"),
            "older_than_12m": len(rot.get("older_than_12m") or []),
            "older_than_6m": len(rot.get("older_than_6m") or []),
            "keys": rot.get("keys") or [],
        },
        "licensing": {
            "result": _sec_result(by, "licensing_licenses") or _sec_result(by, "licensing_features"),
            "active": lic.get("active_count"),
            "expired": len(lic.get("expired") or []),
            "expiring_soon": len(lic.get("expiring_soon") or []),
            "trials_expiring_soon": len(lic.get("trials_expiring_soon") or lic_feat.get("trials_expiring_soon") or []),
        },
        "alarms": {
            "result": _sec_result(by, "alarms"),
            "total": alarms.get("total"),
            "active_unacknowledged": alarms.get("active_unacknowledged"),
            "critical_active": len(alarms.get("critical_sample") or []),
            "warning_active": len(alarms.get("warning_sample") or []),
        },
        "network": {
            "result": _sec_result(by, "interfaces"),
            "interfaces_total": iface.get("total"),
            "tcp_mode": len(iface.get("tcp_modes") or iface.get("cleartext_modes") or []),
            "cleartext": len(iface.get("tcp_modes") or iface.get("cleartext_modes") or []),
            "mode_warn": len(iface.get("mode_warn") or []),
            "mode_preferred": len(iface.get("mode_preferred") or []),
            "mode_web_ok": len(iface.get("mode_web_ok") or []),
            "unauth_tls": len(iface.get("unauth_tls_modes") or []),  # legacy subset
            "ssh_interfaces": len(iface.get("ssh_interfaces") or []),
            "ssh_enabled": sum(
                1 for x in (iface.get("ssh_interfaces") or []) if x.get("enabled")
            ),
            "snmp_interfaces": len(iface.get("snmp_interfaces") or []),
            "snmp_enabled": sum(
                1 for x in (iface.get("snmp_interfaces") or []) if x.get("enabled")
            ),
            "preboot_interfaces": len(iface.get("preboot_interfaces") or []),
            "preboot_enabled": sum(
                1 for x in (iface.get("preboot_interfaces") or []) if x.get("enabled")
            ),
            "weak_tls": len(iface.get("weak_tls") or []),
            "tls_certs_expired": len(iface.get("tls_certs_expired") or []),
            "tls_certs_expiring_soon": len(iface.get("tls_certs_expiring_soon") or []),
            "tls_certs_ok": len(iface.get("tls_certs_ok") or []),
            "log_forwarders_active": fwd.get("active"),
            "smtp_servers": notif.get("smtp_servers"),
            "email_addresses": notif.get("email_addresses"),
        },
        "certificates": {
            "local": _ca_block(ca_local, _sec_result(by, "ca_local")),
            "external": _ca_block(ca_ext, _sec_result(by, "ca_external")),
            "trusted": {
                "result": _sec_result(by, "ca_trusted"),
                "total": ca_trust.get("total"),
                "expired": len(ca_trust.get("expired") or []),
                "expiring_soon": len(ca_trust.get("expiring_soon") or []),
                "ok": len(ca_trust.get("ok") or []),
            }
            if ca_trust or _sec_result(by, "ca_trusted")
            else None,
        },
        "backups": {
            "result": _sec_result(by, "backups_list") or _sec_result(by, "backup_scheduler"),
            "count": backups.get("total"),
            "latest_status": backup_status.get("status"),
            "schedule_enabled": backup_sched.get("enabled"),
        },
        "access": {
            "password_policies": _sec_result(by, "password_policies"),
            "pwd_weak_count": len(pwd.get("weak_policies") or []) if pwd else None,
            "pwd_total": pwd.get("total") if pwd else None,
            "ldap": {
                "result": _sec_result(by, "ldap_connections"),
                "total": ldap.get("total"),
                "insecure_skip_verify": sum(
                    1
                    for c in (ldap.get("connections") or [])
                    if isinstance(c, dict) and c.get("insecure_skip_verify") is True
                ),
            }
            if ldap or _sec_result(by, "ldap_connections")
            else None,
            "domains_total": domains.get("total")
            if domains and domains.get("total") is not None
            else (domains.get("count") if domains else None),
        },
        "users": users,
        "keys": keys,
        "orphaned": {
            "result": _sec_result(by, "orphaned_resources"),
            "orphaned_keys": orphan.get("total_orphaned_keys_count"),
        }
        if orphan or _sec_result(by, "orphaned_resources")
        else None,
        "capacity": {
            "result": _sec_result(by, "capacity_report"),
            "domain_name": capacity.get("domain_name"),
            "key_usage_this_domain": capacity.get("key_usage_count_this_domain"),
            "key_usage_including_subdomains": capacity.get(
                "key_usage_count_including_subdomains"
            ),
            "subdomain_count": capacity.get("subdomain_count_including_subdomains"),
        }
        if capacity or _sec_result(by, "capacity_report")
        else None,
        "quorum": {
            "result": _sec_result(by, "quorum_policies"),
            "enabled": quorum.get("enabled", quorum.get("active")),
            "total": quorum.get("total"),
            "active_requests": quorum.get("requests_active"),
            "pre_active_requests": quorum.get("requests_pre_active"),
            "total_requests": quorum.get("requests_total"),
            "requests_by_state": quorum.get("requests_by_state"),
        }
        if quorum or _sec_result(by, "quorum_policies")
        else None,
        "clients": {
            "result": _sec_result(by, "registered_clients"),
            "total": clients.get("total"),
        }
        if clients or _sec_result(by, "registered_clients")
        else None,
        "cte": {
            "result": _sec_result(by, "cte_clients") or _sec_result(by, "cte_policies"),
            "clients_total": cte.get("total"),
            "disconnected": len(cte.get("disconnected") or []),
            "unregistered_or_offline": len(cte.get("unregistered_or_offline") or []),
            "guardpoints_not_active": len(cte.get("guardpoints_not_active") or []),
            "learn_mode_policies": len(cte_pol.get("learn_mode_policies") or []),
        }
        if cte or cte_pol or _sec_result(by, "cte_clients")
        else None,
        "audit": {
            "result": _sec_result(by, "audit_records"),
            "skipped": bool(audit.get("skipped")),
            "reason": audit.get("reason"),
            "server_counts": audit.get("server_counts"),
            "client_counts": audit.get("client_counts"),
            "cm_version": audit.get("cm_version"),
        }
        if audit or _sec_result(by, "audit_records")
        else None,
        "section_results": {
            name: s.get("result") for name, s in by.items() if s.get("result")
        },
    }


def _md_bold(text: str, when: bool = True) -> str:
    """Wrap in markdown bold when ``when`` is true (agents render Summary as MD)."""
    if not when or text is None:
        return "" if text is None else str(text)
    s = str(text)
    if not s or (s.startswith("**") and s.endswith("**")):
        return s
    return f"**{s}**"


def _cap_summary_line(s: str) -> str:
    """Ensure each Summary line starts with an uppercase letter (after ** if bold)."""
    s = s.strip()
    if not s:
        return s
    if s.startswith("**") and len(s) > 2:
        # **disk not encrypted** -> **Disk not encrypted**
        inner = s[2:]
        end = ""
        if inner.endswith("**"):
            inner, end = inner[:-2], "**"
        if inner:
            inner = inner[0].upper() + inner[1:]
        return f"**{inner}{end}"
    return s[0].upper() + s[1:]


def _summary_lines(*parts: str | None) -> str:
    """Join Summary clauses with HTML line breaks for markdown table cells."""
    bits = [
        _cap_summary_line(str(p).strip().rstrip("."))
        for p in parts
        if p and str(p).strip()
    ]
    return "<br>".join(bits) + ("." if bits else "")


def _ca_summary_phrase(kind: str, block: dict[str, Any] | None) -> str:
    """Plain English for one CA class (local / external / trusted)."""
    if not block:
        return f"{kind}: not checked"
    total = block.get("total")
    expired = int(block.get("expired") or 0)
    soon = int(block.get("expiring_soon") or 0)
    ok = int(block.get("ok") or 0)
    if total == 0 or (total is None and expired == 0 and soon == 0 and ok == 0):
        return f"{kind}: none configured"
    bits = []
    if expired:
        bits.append(_md_bold(f"{expired} expired"))
    if soon:
        bits.append(_md_bold(f"{soon} expire within 30 days"))
    if ok:
        bits.append(f"{ok} valid (>30 days left)")
    if not bits and total is not None:
        bits.append(f"{total} total")
    head = f"{kind}: {total} total" if total is not None else f"{kind}:"
    return f"{head} - " + "; ".join(bits) if bits else head


def build_posture_table(posture: dict[str, Any]) -> list[dict[str, str]]:
    """Area / Result / Summary rows in plain English for agents to copy.

    Summary uses markdown ``**bold**`` on facts that drive WARN/FAIL so chat
    tables can emphasize them. Agents must preserve the asterisks.
    """
    rows: list[dict[str, str]] = []

    def add(area: str, result: Any, summary: str) -> None:
        r = str(result or "n/a")
        # Bold non-PASS results in the Result column for markdown tables
        if r.upper() in ("FAIL", "WARN", "CRITICAL"):
            r_out = _md_bold(r)
        else:
            r_out = r
        rows.append({"area": area, "result": r_out, "summary": summary})

    app = posture.get("appliance") or {}
    disk_enc = app.get("disk_encrypted")
    if disk_enc is True:
        disk_s = "disk encrypted"
    elif disk_enc is False:
        disk_s = _md_bold("disk not encrypted")
    else:
        disk_s = f"disk encryption status={app.get('disk_encryption')!r}"
    down_n = int(app.get("services_not_started") or 0)
    ntp_sync = app.get("ntp_synchronized")
    if ntp_sync is True:
        ntp_s = "NTP synchronized"
    elif ntp_sync is False:
        ntp_s = _md_bold("NTP not synchronized")
    else:
        ntp_s = "NTP status unavailable"
    banner_ok = bool(app.get("banner_configured"))
    attended = app.get("attended_boot") is True
    preboot_n = app.get("preboot_interfaces")
    add(
        "Appliance",
        app.get("result"),
        _summary_lines(
            f"CM {app.get('version')}",
            f"Services {app.get('services_started')}/{app.get('services_total')} up"
            + (_md_bold(f" ({down_n} down)") if down_n else ""),
            f"Cluster {app.get('cluster') or 'none'}",
            ntp_s,
            disk_s,
            _md_bold("attended boot enabled") if attended else None,
            f"Preboot interfaces={preboot_n}" if preboot_n is not None else None,
            "Login banner configured"
            if banner_ok
            else _md_bold("login banner missing"),
        ),
    )

    rot = posture.get("rot_keys") or {}
    rot_keys = rot.get("keys") or []
    ages = []
    for k in rot_keys[:5]:
        if isinstance(k, dict) and k.get("id") is not None:
            ages.append(f"{k.get('id')} ~{k.get('age_years')}y")
    rot_bits = []
    if rot.get("older_than_12m"):
        rot_bits.append(
            _md_bold(f"{rot.get('older_than_12m')} key(s) >=12 months (critical)")
        )
    if rot.get("older_than_6m"):
        rot_bits.append(
            _md_bold(f"{rot.get('older_than_6m')} key(s) >=6 months (warn)")
        )
    if not rot_bits:
        rot_bits.append("all RoT keys younger than 6 months")
    add(
        "RoT",
        rot.get("result"),
        _summary_lines(
            f"{rot.get('total') or 0} root-of-trust key(s)",
            "; ".join(rot_bits) + (f" ({', '.join(ages)})" if ages else ""),
        ),
    )

    lic = posture.get("licensing") or {}
    lic_bits = [f"{lic.get('active') or 0} active licenses"]
    if lic.get("expired"):
        lic_bits.append(_md_bold(f"{lic.get('expired')} expired"))
    if lic.get("expiring_soon"):
        lic_bits.append(
            _md_bold(f"{lic.get('expiring_soon')} expire within 30 days")
        )
    if lic.get("trials_expiring_soon"):
        lic_bits.append(
            _md_bold(
                f"{lic.get('trials_expiring_soon')} trial feature(s) expire within 30 days"
            )
        )
    add("Licenses", lic.get("result"), _summary_lines(*lic_bits))

    alarms = posture.get("alarms") or {}
    au = int(alarms.get("active_unacknowledged") or 0)
    crit_a = int(alarms.get("critical_active") or 0)
    add(
        "Alarms",
        alarms.get("result"),
        _summary_lines(
            (
                _md_bold(f"{au} active unacknowledged")
                if au
                else f"{au} active unacknowledged"
            )
            + f" (of {alarms.get('total') or 0} listed)",
            (
                _md_bold(f"{crit_a} critical-severity among them")
                if crit_a
                else f"{crit_a} critical-severity among them"
            ),
            f"{alarms.get('warning_active') or 0} warning-severity samples",
        ),
    )

    net = posture.get("network") or {}
    tcp_n = int(net.get("tcp_mode") or 0)
    warn_n = int(net.get("mode_warn") or 0)
    exp_n = int(net.get("tls_certs_expired") or 0)
    soon_n = int(net.get("tls_certs_expiring_soon") or 0)
    weak_n = int(net.get("weak_tls") or 0)
    add(
        "Interfaces",
        net.get("result"),
        _summary_lines(
            f"{net.get('interfaces_total') or 0} interfaces",
            (
                _md_bold(f"{tcp_n} TCP/no-TLS (critical)")
                if tcp_n
                else f"{tcp_n} TCP/no-TLS (critical)"
            ),
            (
                _md_bold(f"{warn_n} other TLS modes to harden (warn)")
                if warn_n
                else f"{warn_n} other TLS modes to harden (warn)"
            ),
            f"{net.get('mode_web_ok') or 0} web mode OK",
            f"{net.get('mode_preferred') or 0} tls-cert-and-pw (preferred)",
            f"SSH {net.get('ssh_enabled') or 0}/{net.get('ssh_interfaces') or 0} enabled",
            f"SNMP {net.get('snmp_enabled') or 0}/{net.get('snmp_interfaces') or 0} enabled",
            f"Preboot {net.get('preboot_enabled') or 0}/{net.get('preboot_interfaces') or 0}",
            "TLS certs: "
            + (_md_bold(f"{exp_n} expired") if exp_n else f"{exp_n} expired")
            + ", "
            + (
                _md_bold(f"{soon_n} expire within 30 days")
                if soon_n
                else f"{soon_n} expire within 30 days"
            )
            + f", {net.get('tls_certs_ok') or 0} ok",
            _md_bold(f"{weak_n} weak TLS minimum") if weak_n else None,
            f"{net.get('log_forwarders_active') or 0} active log forwarder(s)",
            f"{net.get('smtp_servers') or 0} SMTP server(s)",
        ),
    )

    certs = posture.get("certificates") or {}
    ca_result = _worst_result(
        (certs.get("local") or {}).get("result"),
        (certs.get("external") or {}).get("result"),
        (certs.get("trusted") or {}).get("result"),
    )
    add(
        "CAs",
        ca_result,
        _summary_lines(
            _ca_summary_phrase("Local CAs", certs.get("local")),
            _ca_summary_phrase("External CAs", certs.get("external")),
            _ca_summary_phrase("Trusted CAs", certs.get("trusted")),
        ),
    )

    backups = posture.get("backups") or {}
    add(
        "Backups",
        backups.get("result"),
        _summary_lines(
            f"{backups.get('count') or 0} backup(s) on record",
            f"Latest status={backups.get('latest_status') or 'n/a'}",
            f"{backups.get('schedule_enabled') or 0} schedule job(s) enabled",
        ),
    )

    access = posture.get("access") or {}
    ldap = access.get("ldap") or {}
    insecure = int(ldap.get("insecure_skip_verify") or 0)
    pwd_weak = int(access.get("pwd_weak_count") or 0)
    pwd_total = access.get("pwd_total")
    add(
        "Access",
        _worst_result(
            access.get("password_policies"),
            (ldap.get("result") if ldap else None),
        )
        or "PASS",
        _summary_lines(
            f"{access.get('domains_total') or 0} domain(s)",
            (
                _md_bold(f"{pwd_weak} weak password policy(ies)")
                if pwd_weak
                else (
                    f"{pwd_total} password policy(ies)"
                    if pwd_total is not None
                    else None
                )
            ),
            f"{ldap.get('total') or 0} LDAP connection(s)",
            (
                _md_bold(f"{insecure} with insecure TLS skip-verify")
                if insecure
                else f"{insecure} with insecure TLS skip-verify"
            ),
        ),
    )

    users = posture.get("users") or {}
    ut = users.get("totals") or {}
    locked = int(ut.get("locked") or 0)
    never = int(ut.get("never_logged_in") or 0)
    inactive = int(ut.get("inactive_30d") or 0)
    failed = int(ut.get("failed_logins_not_locked") or 0)
    add(
        "Users",
        users.get("result"),
        _summary_lines(
            f"Scanned {ut.get('domains_with_users') or 0} domain(s), "
            f"{ut.get('users_total') or 0} user(s)",
            _md_bold(f"{locked} locked") if locked else f"{locked} locked",
            (
                _md_bold(f"{never} never logged in")
                if never
                else f"{never} never logged in"
            ),
            (
                _md_bold(f"{inactive} inactive >30 days")
                if inactive
                else f"{inactive} inactive >30 days"
            ),
            (
                _md_bold(f"{failed} with failed logins (not locked)")
                if failed
                else f"{failed} with failed logins (not locked)"
            ),
        ),
    )

    keys = posture.get("keys") or {}
    kd = keys.get("domains") or {}
    km = keys.get("metrics") or {}
    cap = posture.get("capacity") or {}
    weak = int(kd.get("weak") or 0)
    inactive_k = int(kd.get("non_active") or 0)
    skipped = int(kd.get("skipped") or 0)
    add(
        "Keys",
        keys.get("result") or cap.get("result"),
        _summary_lines(
            f"Key usage in login domain '{cap.get('domain_name') or 'current'}'="
            f"{cap.get('key_usage_this_domain')}",
            f"Including child domains={cap.get('key_usage_including_subdomains')}",
            f"Prometheus metrics total={km.get('key_usage_total')}",
            f"Domains checked={kd.get('checked')}, "
            + (
                _md_bold(f"skipped={skipped}")
                if skipped
                else f"skipped={skipped}"
            ),
            (
                _md_bold(f"weak keys in scanned domains={weak}")
                if weak
                else f"weak keys in scanned domains={weak}"
            ),
            (
                _md_bold(f"{inactive_k} key(s) whose latest version is not Active")
                if inactive_k
                else f"{inactive_k} key(s) whose latest version is not Active"
            ),
        ),
    )

    orphan = posture.get("orphaned") or {}
    if orphan:
        ok_n = int(orphan.get("orphaned_keys") or 0)
        add(
            "Orphaned",
            orphan.get("result"),
            (
                _md_bold(f"{ok_n} orphaned key(s) reported")
                if ok_n
                else f"{ok_n} orphaned key(s) reported"
            )
            + ".",
        )

    quorum = posture.get("quorum") or {}
    if quorum:
        en = int(quorum.get("enabled") or 0)
        tot_pol = int(quorum.get("total") or 0)
        act = int(quorum.get("active_requests") or 0)
        pre = int(quorum.get("pre_active_requests") or 0)
        tot_req = quorum.get("total_requests")
        by_st = quorum.get("requests_by_state") or {}
        open_n = act + pre
        # Closed/historical = everything not active/pre-active
        closed_bits = []
        for st, n in sorted(by_st.items()):
            if str(st).lower() in ("active", "pre-active", "pre_active", "preactive"):
                continue
            if n:
                closed_bits.append(f"{st}={n}")
        if open_n:
            open_line = (
                _md_bold(f"{act} waiting for approval (active)")
                if act
                else f"{act} waiting for approval (active)"
            )
            open_line += ", "
            open_line += (
                _md_bold(f"{pre} pre-active")
                if pre
                else f"{pre} pre-active"
            )
        else:
            open_line = "none waiting for approval"
        hist_line = None
        if tot_req is not None and int(tot_req) > open_n:
            closed_n = int(tot_req) - open_n
            hist_line = f"{closed_n} older/closed on file"
            if closed_bits:
                hist_line += f" ({', '.join(closed_bits)})"
        elif tot_req == 0 or tot_req is None:
            hist_line = "no approval requests on file"
        add(
            "Quorum",
            quorum.get("result"),
            _summary_lines(
                f"Quorum policies: {en} of {tot_pol} operations require approval "
                f"(enabled)",
                f"Approval requests: {open_line}",
                hist_line,
            ),
        )

    clients = posture.get("clients") or {}
    if clients:
        add(
            "Clients",
            clients.get("result"),
            f"{clients.get('total') or 0} registered client-management client(s).",
        )

    cte = posture.get("cte") or {}
    if cte:
        disc = int(cte.get("disconnected") or 0)
        unreg = int(cte.get("unregistered_or_offline") or 0)
        gp = int(cte.get("guardpoints_not_active") or 0)
        learn = int(cte.get("learn_mode_policies") or 0)
        add(
            "CTE",
            cte.get("result"),
            _summary_lines(
                f"{cte.get('clients_total') or 0} CTE client(s)",
                _md_bold(f"{disc} disconnected") if disc else f"{disc} disconnected",
                (
                    _md_bold(f"{unreg} unregistered/offline")
                    if unreg
                    else f"{unreg} unregistered/offline"
                ),
                (
                    _md_bold(f"{gp} GuardPoint(s) not active")
                    if gp
                    else f"{gp} GuardPoint(s) not active"
                ),
                (
                    _md_bold(f"{learn} polic(ies) in Learn Mode")
                    if learn
                    else f"{learn} polic(ies) in Learn Mode"
                ),
            ),
        )

    audit = posture.get("audit") or {}
    if audit:
        if audit.get("skipped"):
            add(
                "Audit",
                audit.get("result"),
                _summary_lines(
                    f"Skipped ({audit.get('reason') or 'n/a'})",
                    f"CM {audit.get('cm_version') or 'n/a'}",
                ),
            )
        else:
            sc = audit.get("server_counts") or {}
            cc = audit.get("client_counts") or {}
            s_err = int(sc.get("error") or 0)
            s_crit = int(sc.get("critical") or sc.get("fatal") or 0)
            c_err = int(cc.get("error") or 0)
            c_fatal = int(cc.get("fatal") or cc.get("critical") or 0)
            add(
                "Audit",
                audit.get("result"),
                _summary_lines(
                    "Recent DB audit (pre-2.24)",
                    "Server "
                    + (
                        _md_bold(f"critical/fatal={s_crit}")
                        if s_crit
                        else f"critical/fatal={s_crit}"
                    )
                    + ", "
                    + (_md_bold(f"error={s_err}") if s_err else f"error={s_err}"),
                    "Client "
                    + (_md_bold(f"fatal={c_fatal}") if c_fatal else f"fatal={c_fatal}")
                    + ", "
                    + (_md_bold(f"error={c_err}") if c_err else f"error={c_err}"),
                ),
            )

    return rows


def check_users_access(ctx: ReportCtx, client: CmClient, max_users: int) -> None:
    """Current-token domain only (used when per-domain inventory is not run)."""
    data = client.get_paginated("/v1/usermgmt/users/", limit=100, max_items=max_users)
    resources = data.get("resources") or []
    users = summarize_users(
        resources,
        now=ctx.now,
        total_reported=data.get("total"),
        truncated=bool(data.get("truncated")),
    )
    emit_user_findings(ctx, None, users)
    result = "WARN" if users_have_hygiene_issues(users) else "PASS"
    ctx.section("users_access", result, users, 200)


def collapse_key_versions(keys: list[dict]) -> dict[str, dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for k in keys:
        name = k.get("name")
        if not name:
            continue
        grouped[str(name)].append(k)
    out: dict[str, dict] = {}
    for name, vers in grouped.items():
        best = max(vers, key=lambda x: int(x.get("version") or 0))
        out[name] = best
    return out


def analyze_keys(ctx: ReportCtx, domain: str, keys: list[dict]) -> dict:
    collapsed = collapse_key_versions([k for k in keys if isinstance(k, dict)])
    states: Counter = Counter()
    weak = []
    non_active = []
    for name, k in collapsed.items():
        state = str(k.get("state") or "Unknown")
        states[state] += 1
        alg = k.get("algorithm") or ""
        size = k.get("size") or 0
        if state != "Active":
            non_active.append({"name": name, "state": state, "version": k.get("version")})
        if (alg == "RSA" and size and size < 2048) or (alg == "AES" and size and size < 128):
            weak.append({"name": name, "algorithm": alg, "size": size})
    if non_active:
        ctx.add(
            "keys",
            "keys_non_active",
            "WARNING",
            f"[{domain}] {len(non_active)} key(s) have inactive (non-Active) highest version "
            f"(sample: {', '.join(x['name'] for x in non_active[:5])}).",
        )
    if weak:
        for w in weak[:10]:
            ctx.add(
                "keys",
                "keys_weak_algorithm",
                "WARNING",
                f"[{domain}] Key '{w['name']}' has weak configuration: "
                f"{w['algorithm']} ({w['size']} bits).",
            )
        if len(weak) > 10:
            ctx.add(
                "keys",
                "keys_weak_algorithm_more",
                "WARNING",
                f"[{domain}] {len(weak) - 10} additional weak key(s) omitted from detail.",
            )
    return {
        "domain": domain,
        "raw": len(keys),
        "unique": len(collapsed),
        "states": dict(states),
        "non_active_count": len(non_active),
        "weak_count": len(weak),
        "weak_sample": weak[:10],
        "non_active_sample": non_active[:10],
    }


def resolve_domains(client: CmClient, scope: str) -> tuple[list[str], dict[str, Any]]:
    meta: dict[str, Any] = {"scope": scope}
    self_names: list[str] = []
    try:
        self_data = client.get("/v1/auth/self/domains")
        for d in (self_data or {}).get("resources") or []:
            if isinstance(d, dict) and (d.get("name") or d.get("id")):
                self_names.append(str(d.get("name") or d.get("id")))
        meta["self_domains_total"] = (self_data or {}).get("total", len(self_names))
    except CmError as e:
        meta["self_domains_error"] = str(e)

    if scope == "all":
        try:
            all_data = client.get_paginated("/v1/domains", limit=100, max_items=1000)
            all_names = []
            for d in all_data.get("resources") or []:
                if isinstance(d, dict) and (d.get("name") or d.get("id")):
                    all_names.append(str(d.get("name") or d.get("id")))
            meta["all_domains_total"] = all_data.get("total")
            return list(dict.fromkeys(all_names + self_names)), meta
        except CmError as e:
            meta["all_domains_error"] = str(e)
            meta["note"] = "Could not list /v1/domains; falling back to self/domains"
            return self_names, meta
    return self_names, meta


def check_domains_meta(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/domains?limit=1000")
    if err:
        ctx.section("domains", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    user_mgmt = []
    hsm_backed = []
    for d in resources:
        if not isinstance(d, dict):
            continue
        name = d.get("name")
        if d.get("allow_user_management"):
            user_mgmt.append(name)
            ctx.add(
                "domains",
                "domain_user_mgmt",
                "INFO",
                f"Domain '{name}' has allow_user_management enabled.",
            )
        hsm = d.get("hsm_connection_id") or d.get("kek_label") or (
            d.get("meta") if isinstance(d.get("meta"), dict) else None
        )
        if isinstance(hsm, dict) and (hsm.get("hsm_connection_id") or hsm.get("kek_label")):
            hsm_backed.append(name)
            ctx.add(
                "domains",
                "domain_hsm_backed",
                "INFO",
                f"Domain '{name}' appears HSM-backed.",
            )
        elif d.get("hsm_connection_id") or d.get("kek_label"):
            hsm_backed.append(name)
            ctx.add(
                "domains",
                "domain_hsm_backed",
                "INFO",
                f"Domain '{name}' appears HSM-backed.",
            )
    ctx.section(
        "domains",
        "PASS",
        {
            "total": (data or {}).get("total", len(resources)),
            "allow_user_management": user_mgmt[:20],
            "hsm_backed": hsm_backed[:20],
        },
        200,
    )


def check_keys_domains(
    ctx: ReportCtx,
    client: CmClient,
    scope: str,
    max_keys: int,
    max_users: int,
) -> None:
    domains, meta = resolve_domains(client, scope)
    can_login = bool(
        (client.config.username and client.config.password) or client.config.refresh_token
    )
    if not can_login:
        ctx.section(
            "keys_domains",
            "WARN",
            {
                **meta,
                "note": "Domain-scoped key/user checks require CM_USERNAME+CM_PASSWORD (or refresh token).",
                "skipped": [{"domain": d, "reason": "no_password_auth"} for d in domains],
            },
            200,
        )
        return

    checked = []
    skipped = []
    errors = []
    for name in domains:
        try:
            dclient = client.for_domain(name)
            page = dclient.get_paginated("/v1/vault/keys2/", limit=100, max_items=max_keys)
            users_page = dclient.get_paginated(
                "/v1/usermgmt/users/", limit=100, max_items=max_users
            )
            analysis = analyze_keys(ctx, name, page.get("resources") or [])
            analysis["total_reported"] = page.get("total")
            analysis["truncated"] = page.get("truncated")
            users = summarize_users(
                users_page.get("resources") or [],
                now=ctx.now,
                total_reported=users_page.get("total"),
                truncated=bool(users_page.get("truncated")),
            )
            emit_user_findings(ctx, name, users)
            analysis["users"] = users
            checked.append(analysis)
        except CmError as e:
            body = e.body if isinstance(e.body, dict) else {}
            msg = body.get("message") if isinstance(body, dict) else None
            if e.status in (401, 403):
                skipped.append(
                    {
                        "domain": name,
                        "reason": "unauthorized",
                        "status": e.status,
                        "message": msg or str(e),
                        "note": f"Could not check domain '{name}' with provided credentials",
                    }
                )
            else:
                errors.append({"domain": name, "status": e.status, "error": str(e)})

    result = "PASS"
    user_warn = any(users_have_hygiene_issues(c.get("users") or {}) for c in checked)
    if any(c.get("weak_count") or c.get("non_active_count") for c in checked) or user_warn:
        result = "WARN"
    elif errors or (not checked and skipped):
        result = "WARN"

    ctx.section(
        "keys_domains",
        result,
        {
            **meta,
            "domains_listed": len(domains),
            "checked_count": len(checked),
            "skipped_count": len(skipped),
            "error_count": len(errors),
            "max_keys_per_domain": max_keys,
            "max_users_per_domain": max_users,
            "checked": checked,
            "skipped": skipped,
            "errors": errors,
            "note": (
                "Skipped domains mean this user cannot authenticate into them; "
                "not treated as appliance CRITICAL by themselves."
                if skipped
                else None
            ),
        },
        200,
    )


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
    return {
        "domains_with_key_usage": len(usage_by_domain),
        "key_usage_total_reported": sum(r.get("keys") or 0 for r in usage_by_domain),
        "key_usage_top_domains": [r for r in usage_by_domain if (r.get("keys") or 0) > 0][:15],
        "deks_by_state": dict(deks_by_state),
        "keks_total": keks_total,
        "key_rotations_total": rotations,
    }


def check_metrics_keys(ctx: ReportCtx, client: CmClient) -> None:
    status, err = safe_get(client, "/v1/system/metrics/prometheus/status")
    if err:
        ctx.section("metrics_status", "WARN", {"error": str(err)}, err.status)
        ctx.section("keys_metrics", "WARN", {"note": "Could not read metrics status"}, None)
        return
    enabled = bool((status or {}).get("enabled"))
    ctx.section("metrics_status", "PASS", {"enabled": enabled}, 200)
    if not enabled:
        ctx.add("system", "metrics_disabled", "WARNING", "Prometheus metrics API is disabled.")
        ctx.section("keys_metrics", "WARN", {"enabled": False}, 200)
        return
    token = (status or {}).get("token")
    if not token:
        ctx.section(
            "keys_metrics",
            "WARN",
            {"enabled": True, "note": "Scrape token unavailable to this user"},
            200,
        )
        return
    try:
        url = f"{client.config.base}/v1/system/metrics/prometheus"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "text/plain"},
            method="GET",
        )
        with urllib.request.urlopen(req, context=client._ssl, timeout=client.config.timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        summary = parse_key_metrics(text)
        summary["enabled"] = True
        summary["scrape_bytes"] = len(text)
        ctx.section("keys_metrics", "PASS", summary, 200)
    except Exception as e:  # noqa: BLE001
        ctx.section("keys_metrics", "WARN", {"enabled": True, "error": str(e)}, None)


def check_orphaned(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/reports/orphaned-resources?limit=1000")
    if err:
        ctx.section("orphaned_resources", "WARN", {"error": str(err)}, err.status)
        return
    total = 0
    by_acct = []
    if isinstance(data, dict):
        total = int(data.get("total_orphaned_keys_count") or 0)
        by_acct = data.get("orphaned_keys_by_account") or data.get("resources") or []
    if total > 0:
        ctx.add(
            "keys",
            "keys_orphaned",
            "WARNING",
            f"{total} orphaned key(s) left behind from deleted domains.",
        )
    ctx.section(
        "orphaned_resources",
        "WARN" if total else "PASS",
        {
            "total_orphaned_keys_count": total,
            "accounts_sample": (by_acct[:10] if isinstance(by_acct, list) else by_acct),
        },
        200,
    )


def check_capacity(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/reports/capacity-report")
    if err:
        ctx.section("capacity_report", "WARN", {"error": str(err)}, err.status)
        return
    detail = {
        "domain_name": (data or {}).get("domain_name"),
        "key_usage_count_this_domain": (data or {}).get("key_usage_count_this_domain"),
        "key_usage_count_including_subdomains": (data or {}).get(
            "key_usage_count_including_subdomains"
        ),
        "subdomain_count_including_subdomains": (data or {}).get(
            "subdomain_count_including_subdomains"
        ),
    }
    ctx.section("capacity_report", "PASS", detail, 200)


def check_cte(ctx: ReportCtx, client: CmClient) -> None:
    clients, cerr = safe_get(client, "/v1/transparent-encryption/clients/?limit=100")
    policies, perr = safe_get(client, "/v1/transparent-encryption/policies/?limit=100")
    if cerr:
        ctx.section("cte_clients", "WARN", {"error": str(cerr)}, cerr.status)
        return
    resources = (clients or {}).get("resources") or []
    disconnected = []
    unregistered = []
    gp_bad = []
    for cl in resources:
        if not isinstance(cl, dict):
            continue
        health = str(cl.get("client_health_status") or "").upper()
        comm = bool(cl.get("communication_enabled"))
        row = {
            "name": cl.get("name"),
            "client_health_status": cl.get("client_health_status"),
            "communication_enabled": comm,
        }
        if health == "UNREGISTERED":
            unregistered.append(row)
            ctx.add(
                "cte",
                "cte_client_unregistered",
                "INFO",
                f"CTE client '{cl.get('name')}' is UNREGISTERED.",
            )
        elif health and health != "HEALTHY":
            # NOT CONNECTED / other — WARN only when communication is expected
            if comm:
                disconnected.append(row)
                ctx.add(
                    "cte",
                    "cte_client_disconnected",
                    "WARNING",
                    f"CTE client '{cl.get('name')}' health is '{cl.get('client_health_status')}' "
                    f"(communication enabled).",
                )
            else:
                unregistered.append(row)
                ctx.add(
                    "cte",
                    "cte_client_offline",
                    "INFO",
                    f"CTE client '{cl.get('name')}' health is '{cl.get('client_health_status')}' "
                    f"(communication disabled).",
                )
        cid = cl.get("id")
        if not cid:
            continue
        gp, gerr = safe_get(client, f"/v1/transparent-encryption/clients/{cid}/guardpoints/?limit=100")
        if gerr:
            continue
        for g in (gp or {}).get("resources") or []:
            st = str(g.get("guard_point_state") or g.get("state") or "")
            if st and st.upper() not in ("ACTIVE",):
                gp_bad.append(
                    {
                        "client": cl.get("name"),
                        "guard_path": g.get("guard_path"),
                        "guard_point_state": st,
                    }
                )
                sev = "WARNING" if st.upper() in ("DISABLED", "ERROR", "FAILED") else "INFO"
                ctx.add(
                    "cte",
                    "cte_guardpoint_not_active",
                    sev,
                    f"CTE GuardPoint on '{cl.get('name')}' path '{g.get('guard_path')}' is '{st}'.",
                )
    ctx.section(
        "cte_clients",
        "WARN" if (disconnected or any(g.get("guard_point_state", "").upper() in ("DISABLED", "ERROR", "FAILED") for g in gp_bad)) else "PASS",
        {
            "total": (clients or {}).get("total", len(resources)),
            "disconnected": disconnected[:20],
            "unregistered_or_offline": unregistered[:20],
            "guardpoints_not_active": gp_bad[:20],
        },
        200,
    )

    if perr:
        ctx.section("cte_policies", "WARN", {"error": str(perr)}, perr.status)
    else:
        learn = []
        for p in (policies or {}).get("resources") or []:
            if isinstance(p, dict) and p.get("never_deny") is True:
                learn.append(p.get("name"))
                ctx.add(
                    "cte",
                    "cte_policy_learn_mode",
                    "WARNING",
                    f"CTE policy '{p.get('name')}' has Learn Mode enabled (never_deny=true).",
                )
        ctx.section(
            "cte_policies",
            "WARN" if learn else "PASS",
            {
                "total": (policies or {}).get("total"),
                "learn_mode_policies": learn,
            },
            200,
        )


def check_clients(ctx: ReportCtx, client: CmClient) -> None:
    data, err = safe_get(client, "/v1/client-management/clients?limit=50")
    if err:
        ctx.section("registered_clients", "WARN", {"error": str(err)}, err.status)
        return
    resources = (data or {}).get("resources") or []
    sample = [
        {
            "name": c.get("name"),
            "id": c.get("id"),
            "state": c.get("state") or c.get("status"),
            "created_at": c.get("created_at") or c.get("createdAt"),
        }
        for c in resources[:10]
        if isinstance(c, dict)
    ]
    ctx.section(
        "registered_clients",
        "PASS",
        {"total": (data or {}).get("total", len(resources)), "sample": sample},
        200,
    )


def check_audit_records(
    ctx: ReportCtx,
    client: CmClient,
    cm_version: Any = None,
) -> None:
    """DB audit record APIs were removed in CM 2.24+; skip those versions."""
    after = (ctx.now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    at_least_224 = cm_version_at_least(cm_version, 2, 24)

    if at_least_224 is True:
        ctx.add(
            "records",
            "records_api_removed",
            "INFO",
            f"CM {cm_version}: database audit APIs removed in 2.24+; "
            "skipping /v1/audit/records and /v1/audit/client-records "
            "(use log forwarders / system alarms).",
        )
        ctx.section(
            "audit_records",
            "SKIP",
            {
                "skipped": True,
                "reason": "db_audit_removed",
                "since_cm": "2.24",
                "cm_version": cm_version,
                "alternatives": ["/v1/system/alarms", "/v1/configs/log-forwarders/"],
            },
            None,
        )
        return

    server_counts: dict[str, int] = {}
    client_counts: dict[str, int] = {}
    samples: list[dict] = []
    server_errors: list[str] = []
    client_errors: list[str] = []

    for sev in ("error", "critical", "fatal"):
        path = f"/v1/audit/records?limit=5&severity={sev}&createdAfter={after}"
        data, err = safe_get(client, path)
        if err:
            server_errors.append(f"{sev}:{err.status}")
            continue
        total = int((data or {}).get("total") or 0)
        if total:
            server_counts[sev] = total
            for r in (data or {}).get("resources") or []:
                if isinstance(r, dict) and len(samples) < 10:
                    samples.append(
                        {
                            "source": "server",
                            "severity": r.get("severity"),
                            "message": (r.get("message") or "")[:120],
                            "createdAt": r.get("createdAt"),
                            "username": r.get("username"),
                        }
                    )

    for sev in ("error", "critical", "fatal"):
        # createdAfter is not reliably honored on client-records on all versions
        path = f"/v1/audit/client-records?limit=5&severity={sev}"
        data, err = safe_get(client, path)
        if err:
            client_errors.append(f"{sev}:{err.status}")
            continue
        total = int((data or {}).get("total") or 0)
        if total:
            client_counts[sev] = total
            # Note: counts may include older-than-7d if API ignores time filters.

    # Unknown version + all GETs failed (e.g. 404) → do not fake PASS
    if (
        at_least_224 is None
        and not server_counts
        and not client_counts
        and server_errors
        and client_errors
        and all(e.endswith(":404") for e in server_errors + client_errors)
    ):
        ctx.add(
            "records",
            "records_api_unavailable",
            "INFO",
            "Audit record APIs returned 404 (likely CM 2.24+ without parseable version); skipped.",
        )
        ctx.section(
            "audit_records",
            "SKIP",
            {
                "skipped": True,
                "reason": "api_404",
                "cm_version": cm_version,
                "server_errors": server_errors,
                "client_errors": client_errors,
            },
            404,
        )
        return

    crit = sum(server_counts.get(s, 0) for s in ("critical", "fatal"))
    err_n = server_counts.get("error", 0)
    c_crit = sum(client_counts.get(s, 0) for s in ("critical", "fatal"))
    c_err = client_counts.get("error", 0)

    # Server records honor createdAfter → trustworthy 7d CRITICAL signal
    if crit:
        ctx.add(
            "records",
            "records_critical",
            "CRITICAL",
            f"Server audit records (7d): critical/fatal={crit}.",
        )
    if err_n:
        ctx.add(
            "records",
            "records_error",
            "WARNING",
            f"Server audit records (7d): error={err_n}.",
        )
    # Client-records often ignore createdAfter (unbounded history on some CM versions)
    if c_crit or c_err:
        ctx.add(
            "records",
            "records_client_elevated",
            "WARNING",
            f"Client audit records (time filter unreliable): critical/fatal={c_crit}, error={c_err}.",
        )

    result = "FAIL" if crit else ("WARN" if (err_n or c_crit or c_err) else "PASS")
    ctx.section(
        "audit_records",
        result,
        {
            "cm_version": cm_version,
            "server_window": "7d",
            "createdAfter": after,
            "server_counts": server_counts,
            "client_counts": client_counts,
            "client_window_note": "createdAfter may be ignored; treat as unbounded sample",
            "sample": samples,
        },
        200,
    )


def check_quorum(ctx: ReportCtx, client: CmClient) -> None:
    """Quorum policies (enabled) and approval requests by state."""
    try:
        data = client.get_paginated("/v1/quorum-mgmt/policy/status", limit=100)
    except CmError as err:
        ctx.section("quorum_policies", "WARN", {"error": str(err)}, err.status)
        return
    resources = data.get("resources") or []
    total_policies = data.get("total")
    if not isinstance(total_policies, int):
        total_policies = len(resources)
    enabled = [
        r for r in resources if isinstance(r, dict) and r.get("active") is True
    ]
    enabled_ops = []
    for r in enabled:
        ops = r.get("operation") or []
        if isinstance(ops, list) and ops:
            enabled_ops.append(ops[0])
        elif r.get("profile"):
            enabled_ops.append(str(r.get("profile")))

    requests_total = 0
    requests_active = 0
    requests_pre_active = 0
    requests_by_state: dict[str, int] = {}
    try:
        qdata = client.get_paginated("/v1/quorum-mgmt/quorums", limit=100)
        qres = qdata.get("resources") or []
        requests_total = qdata.get("total") if isinstance(qdata.get("total"), int) else len(qres)
        for q in qres:
            if not isinstance(q, dict):
                continue
            st = str(q.get("state") or "unknown").lower()
            requests_by_state[st] = requests_by_state.get(st, 0) + 1
            if st == "active":
                requests_active += 1
            elif st in ("pre-active", "pre_active", "preactive"):
                requests_pre_active += 1
    except CmError:
        requests_total = -1  # unavailable

    if enabled:
        ctx.add(
            "quorum",
            "quorum_policies_enabled",
            "INFO",
            f"{len(enabled)} quorum policy(ies) enabled "
            f"(of {total_policies}): {', '.join(str(o) for o in enabled_ops[:12])}"
            + ("…" if len(enabled_ops) > 12 else "")
            + ".",
        )
    if requests_active or requests_pre_active:
        ctx.add(
            "quorum",
            "quorum_requests_open",
            "INFO",
            f"{requests_active} active and {requests_pre_active} pre-active "
            f"quorum request(s) (of {requests_total} listed).",
        )

    ctx.section(
        "quorum_policies",
        "PASS",
        {
            "total": total_policies,
            "enabled": len(enabled),
            "active": len(enabled),  # alias: CM API field name
            "enabled_operations": enabled_ops[:20],
            "requests_total": requests_total if requests_total >= 0 else None,
            "requests_active": requests_active if requests_total >= 0 else None,
            "requests_pre_active": requests_pre_active if requests_total >= 0 else None,
            "requests_by_state": requests_by_state or None,
        },
        200,
    )


def score(ctx: ReportCtx) -> str:
    by = {s["name"]: s for s in ctx.sections}
    auth = by.get("auth", {})
    if auth.get("result") == "FAIL":
        detail = auth.get("detail") or {}
        if isinstance(detail, dict) and "Unreachable" in str(detail.get("error", "")):
            return "UNREACHABLE"
        return "CRITICAL"
    sev = {f.severity for f in ctx.findings}
    if "CRITICAL" in sev:
        return "CRITICAL"
    if by.get("services_status", {}).get("result") == "FAIL":
        return "CRITICAL"
    if by.get("system_info", {}).get("result") == "FAIL":
        return "CRITICAL"
    if "WARNING" in sev:
        return "DEGRADED"
    return "OK"


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
    check_backups(ctx, client)
    check_alarms(ctx, client)
    check_cas(ctx, client)
    check_password_policies(ctx, client)
    check_ldap(ctx, client)
    check_domains_meta(ctx, client)
    check_orphaned(ctx, client)
    check_capacity(ctx, client)
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
            ctx, client, domain_scope, max_keys=max_keys, max_users=max_users
        )
    else:
        # No per-domain loop: still report users for the current token domain
        try:
            check_users_access(ctx, client, max_users=max_users)
        except CmError as e:
            ctx.section("users_access", "WARN", {"error": str(e)}, e.status)

    report["overall"] = score(ctx)
    # Deduplicate findings by code+message for readability
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


def _print_posture_header(report: dict) -> None:
    """Print Area | Result | Summary — agents must copy these Summary strings."""
    p = report.get("posture") or {}
    table = p.get("table") or build_posture_table(p)
    print("=== Posture table (copy into markdown: Area | Result | Summary) ===")
    print(
        "Keep markdown **bold** and <br> line breaks in Result/Summary. "
        "Do not invent key=value shorthand."
    )
    for row in table:
        print(f"{row.get('area')} | {row.get('result')} | {row.get('summary')}")
    # Optional domain detail under Users / Keys (not part of the 3-column table)
    users = p.get("users") or {}
    for d in (users.get("by_domain") or [])[:8]:
        top = d.get("top_by_logins") or []
        top_s = ", ".join(
            f"{t.get('username')}({t.get('logins_count')})"
            for t in top[:5]
            if isinstance(t, dict)
        )
        print(
            f"  (Users detail) {d.get('domain')}: "
            f"{d.get('total')} users; locked={d.get('locked')}; "
            f"never-login={d.get('never_logged_in')}; "
            f"inactive_30d={d.get('inactive_30d')}"
            + (f"; top logins: {top_s}" if top_s else "")
        )
    keys = p.get("keys") or {}
    kd = keys.get("domains") or {}
    for d in (kd.get("by_domain") or [])[:8]:
        print(
            f"  (Keys detail) {d.get('domain')}: total={d.get('total')}, "
            f"weak={d.get('weak')}, inactive={d.get('non_active')}"
        )
    print("=== End posture table ===")
    print()


def print_human(report: dict) -> None:
    print(f"Overall: {report.get('overall')}")
    print(f"Base:    {report.get('base', 'n/a')}")
    print(f"CM:      {report.get('cm_version') or 'n/a'}")
    print(f"Time:    {report.get('timestamp_utc')}")
    opts = report.get("options") or {}
    print(
        f"Options: domain_scope={opts.get('domain_scope')} keys_mode={opts.get('keys_mode')} "
        f"max_keys={opts.get('max_keys')} max_users={opts.get('max_users')}"
    )
    summary = report.get("summary") or {}
    print(
        f"Findings: critical={summary.get('critical', 0)} "
        f"warning={summary.get('warning', 0)} info={summary.get('info', 0)}"
    )
    print()
    _print_posture_header(report)
    crit = [f for f in report.get("findings", []) if f.get("severity") == "CRITICAL"]
    warn = [f for f in report.get("findings", []) if f.get("severity") == "WARNING"]
    info = [f for f in report.get("findings", []) if f.get("severity") == "INFO"]
    if crit:
        print("CRITICAL findings:")
        for f in crit[:40]:
            print(f"  - [{f.get('area')}] {f.get('message')}")
        print()
    if warn:
        print("WARNING findings:")
        for f in warn[:60]:
            print(f"  - [{f.get('area')}] {f.get('message')}")
        if len(warn) > 60:
            print(f"  ... +{len(warn) - 60} more")
        print()
    if info:
        print(f"INFO findings: {len(info)} (not scoring; see --json for full list)")
        for f in info[:12]:
            print(f"  - [{f.get('area')}] {f.get('message')}")
        if len(info) > 12:
            print(f"  ... +{len(info) - 12} more")
        print()

    for s in report.get("sections", []):
        mark = {"PASS": "OK", "FAIL": "!!", "WARN": "~~"}.get(s["result"], s["result"])
        print(f"[{mark}] {s['name']} (HTTP {s.get('status')})")
        detail = s.get("detail")
        if s.get("name") == "keys_domains" and isinstance(detail, dict):
            print(
                f"       domains_listed={detail.get('domains_listed')} "
                f"checked={detail.get('checked_count')} skipped={detail.get('skipped_count')}"
            )
            if detail.get("note"):
                print(f"       note: {detail.get('note')}")
            for c in detail.get("checked") or []:
                users = c.get("users") or {}
                print(
                    f"       domain={c.get('domain')} keys_total={c.get('total_reported')} "
                    f"keys_unique={c.get('unique')} weak={c.get('weak_count')} "
                    f"users_total={users.get('total_reported')} "
                    f"locked={users.get('locked')} never_login={users.get('never_logged_in')} "
                    f"inactive_30d={users.get('inactive_30d')} "
                    f"failed_logins={users.get('failed_logins_not_locked')}"
                )
                top = users.get("top_by_logins") or []
                if top:
                    top_s = ", ".join(
                        f"{t.get('username')}({t.get('logins_count')})" for t in top
                    )
                    print(f"         top_by_logins: {top_s}")
            skipped = detail.get("skipped") or []
            if skipped:
                names = [x.get("domain") for x in skipped[:10]]
                print(f"       skipped_sample: {names}" + (" ..." if len(skipped) > 10 else ""))
            print()
            continue
        if s.get("name") == "users_access" and isinstance(detail, dict):
            print(
                f"       total={detail.get('total_reported')} scanned={detail.get('scanned')} "
                f"locked={detail.get('locked')} never_login={detail.get('never_logged_in')} "
                f"inactive_30d={detail.get('inactive_30d')} "
                f"failed_logins={detail.get('failed_logins_not_locked')}"
            )
            top = detail.get("top_by_logins") or []
            if top:
                top_s = ", ".join(
                    f"{t.get('username')}({t.get('logins_count')})" for t in top
                )
                print(f"       top_by_logins: {top_s}")
            print()
            continue
        if isinstance(detail, dict):
            for k, v in detail.items():
                if k in (
                    "interfaces",
                    "checked",
                    "skipped",
                    "sample",
                    "warning_sample",
                    "critical_sample",
                    "unhealthy",
                    "guardpoints_not_active",
                    "accounts_sample",
                    "key_usage_top_domains",
                    "samples",
                    "connections",
                    "top_by_logins",
                    "disconnected",
                    "unregistered_or_offline",
                ) and v:
                    print(f"       {k}: {json.dumps(v, default=str)[:450]}")
                elif k == "note" and v:
                    print(f"       note: {v}")
                else:
                    print(f"       {k}: {v}")
        else:
            print(f"       {detail}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
    args = parser.parse_args(argv)
    report = run(
        domain_scope=args.domain_scope,
        keys_mode=args.keys_mode,
        max_keys=args.max_keys,
        max_users=args.max_users,
        include_cte=not args.no_cte,
    )
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


if __name__ == "__main__":
    raise SystemExit(main())
