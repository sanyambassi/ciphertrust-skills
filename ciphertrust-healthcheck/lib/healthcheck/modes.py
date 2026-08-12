"""Interface mode labels and TLS/PQC constants."""
from __future__ import annotations

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

# Web TLS key-exchange groups (Thales CM PQC docs). Compared case-insensitively.
PQC_GROUPS = {
    "x25519mlkem768",
    "secp256r1mlkem768",
    "mlkem512",
    "mlkem768",
    "mlkem1024",
}
ALARM_CRITICAL_SEVS = {"critical", "emergency", "alert", "error"}
SIGNIFICANT_RECORD_SEVS = {"error", "critical", "fatal"}


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
