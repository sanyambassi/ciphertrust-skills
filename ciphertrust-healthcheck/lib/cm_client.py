"""Minimal CipherTrust Manager REST client for offline/air-gapped agents.

Reads CM_* environment variables. Never logs secrets.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from typing import Any


class CmError(Exception):
    def __init__(self, message: str, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


def _env_tls_insecure() -> bool:
    """Default True (skip cert verify). Set CM_TLS_INSECURE=0/false to verify."""
    raw = (os.environ.get("CM_TLS_INSECURE") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return True  # unset / unknown → skip verify


@dataclass
class CmConfig:
    base: str
    username: str | None = None
    password: str | None = None
    connection: str = "local_account"
    domain: str | None = None
    auth_domain: str | None = None
    auth_domain_path: str | None = None
    jwt: str | None = None
    refresh_token: str | None = None
    ca_bundle: str | None = None
    tls_insecure: bool = True
    timeout: float = 45.0

    @classmethod
    def from_env(cls) -> "CmConfig":
        base = (os.environ.get("CM_BASE") or "").rstrip("/")
        if not base:
            raise CmError("CM_BASE is required (e.g. https://cm.example.com/api)")
        return cls(
            base=base,
            username=os.environ.get("CM_USERNAME") or None,
            password=os.environ.get("CM_PASSWORD") or None,
            connection=os.environ.get("CM_CONNECTION") or "local_account",
            domain=os.environ.get("CM_DOMAIN") or None,
            auth_domain=os.environ.get("CM_AUTH_DOMAIN") or None,
            auth_domain_path=os.environ.get("CM_AUTH_DOMAIN_PATH") or None,
            jwt=os.environ.get("CM_JWT") or None,
            refresh_token=os.environ.get("CM_REFRESH_TOKEN") or None,
            ca_bundle=os.environ.get("CM_CA_BUNDLE") or None,
            tls_insecure=_env_tls_insecure(),
            timeout=float(os.environ.get("CM_TIMEOUT", "45")),
        )


class CmClient:
    def __init__(self, config: CmConfig | None = None):
        self.config = config or CmConfig.from_env()
        self._jwt = self.config.jwt
        self._ssl = self._build_ssl_context()

    def _build_ssl_context(self) -> ssl.SSLContext:
        # Prefer CM_CA_BUNDLE when set (implies verify with that CA).
        if self.config.ca_bundle:
            return ssl.create_default_context(cafile=self.config.ca_bundle)
        if self.config.tls_insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context()

    def ensure_auth(self) -> str:
        if self._jwt:
            return self._jwt
        if self.config.username and self.config.password:
            return self.login_password()
        if self.config.refresh_token:
            return self.login_refresh()
        raise CmError(
            "No credentials: set CM_JWT, or CM_USERNAME+CM_PASSWORD, or CM_REFRESH_TOKEN"
        )

    def login_password(self) -> str:
        body: dict[str, Any] = {
            "grant_type": "password",
            "username": self.config.username,
            "password": self.config.password,
            "connection": self.config.connection,
        }
        if self.config.domain:
            body["domain"] = self.config.domain
        if self.config.auth_domain_path:
            body["auth_domain_path"] = self.config.auth_domain_path
        elif self.config.auth_domain:
            body["auth_domain"] = self.config.auth_domain
        data = self.request("POST", "/v1/auth/tokens/", body=body, auth=False)
        jwt = data.get("jwt")
        if not jwt:
            raise CmError("Token response missing jwt", body=data)
        self._jwt = jwt
        return jwt

    def login_refresh(self) -> str:
        body: dict[str, Any] = {
            "grant_type": "refresh_token",
            "refresh_token": self.config.refresh_token,
        }
        if self.config.domain:
            body["domain"] = self.config.domain
        data = self.request("POST", "/v1/auth/tokens/", body=body, auth=False)
        jwt = data.get("jwt")
        if not jwt:
            raise CmError("Refresh response missing jwt", body=data)
        self._jwt = jwt
        return jwt

    def for_domain(self, domain: str) -> "CmClient":
        """Return a new client authenticated into ``domain`` (token ``domain`` param).

        Requires username/password (or refresh token). Does not mutate this client.
        """
        if not domain:
            raise CmError("domain name is required")
        cfg = replace(self.config, domain=domain, jwt=None)
        # Domain-scoped login needs password or refresh; carry refresh if present.
        other = CmClient(cfg)
        other.ensure_auth()
        return other

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        auth: bool = True,
        raw: bool = False,
    ) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.config.base}{path}"
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        if auth:
            token = self.ensure_auth()
            headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, context=self._ssl, timeout=self.config.timeout) as resp:
                payload = resp.read()
                if raw:
                    return payload
                if not payload:
                    return None
                try:
                    return json.loads(payload.decode("utf-8"))
                except json.JSONDecodeError:
                    return {"_raw": payload[:500].decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as e:
            err_body: Any
            raw_err = e.read()
            try:
                err_body = json.loads(raw_err.decode("utf-8")) if raw_err else None
            except json.JSONDecodeError:
                err_body = raw_err[:500].decode("utf-8", errors="replace") if raw_err else None
            raise CmError(f"HTTP {e.code} {method.upper()} {path}", status=e.code, body=err_body) from e
        except urllib.error.URLError as e:
            raise CmError(f"Unreachable {self.config.base}: {e.reason}") from e

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def get_paginated(
        self,
        path: str,
        *,
        limit: int = 100,
        max_items: int | None = None,
        resources_key: str = "resources",
    ) -> dict[str, Any]:
        """GET a list endpoint, following skip/limit until exhausted or max_items."""
        if "?" in path:
            base, qs = path.split("?", 1)
            # strip existing skip/limit from qs
            parts = [p for p in qs.split("&") if p and not p.startswith(("skip=", "limit="))]
            qs_prefix = "&".join(parts)
        else:
            base, qs_prefix = path, ""

        resources: list[Any] = []
        skip = 0
        total: Any = None
        while True:
            page_limit = limit
            if max_items is not None:
                remaining = max_items - len(resources)
                if remaining <= 0:
                    break
                page_limit = min(limit, remaining)
            q = f"skip={skip}&limit={page_limit}"
            if qs_prefix:
                q = f"{qs_prefix}&{q}"
            data = self.get(f"{base}?{q}")
            if not isinstance(data, dict):
                return {"total": total, "resources": resources, "truncated": False}
            if total is None:
                total = data.get("total")
            page = data.get(resources_key) or []
            if not isinstance(page, list) or not page:
                break
            resources.extend(page)
            skip += len(page)
            if max_items is not None and len(resources) >= max_items:
                break
            if total is not None and skip >= int(total):
                break
            if len(page) < page_limit:
                break
        truncated = bool(total is not None and len(resources) < int(total))
        if max_items is not None and total is not None and int(total) > max_items:
            truncated = True
        return {"total": total if total is not None else len(resources), "resources": resources, "truncated": truncated}
