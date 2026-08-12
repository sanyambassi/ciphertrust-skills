# Create a JWT or refresh token

Optional helper if you prefer `CM_JWT` / `CM_REFRESH_TOKEN` over username/password.
Placeholders only — never commit real hosts or tokens.

Examples use `curl -sSk` (`-s` silent, `-S` show errors, `-k` skip TLS verify — same default as `CM_TLS_INSECURE`). Drop `-k` when the CM cert is trusted (or use `--cacert` with your CA).

```bash
export CM_BASE="https://cm.example.com/api"
export CM_USERNAME="<user>"
export CM_PASSWORD="<password>"
export CM_CONNECTION="local_account"   # optional; LDAP format: connection_name|username
```

## Password grant (get `jwt` + often `refresh_token`)

```bash
curl -sSk -X POST "$CM_BASE/v1/auth/tokens/" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"password\",
    \"username\": \"$CM_USERNAME\",
    \"password\": \"$CM_PASSWORD\",
    \"connection\": \"${CM_CONNECTION:-local_account}\"
  }"
```

Copy from the JSON response, then either:

```bash
export CM_JWT="<jwt>"
# or
export CM_REFRESH_TOKEN="<refresh_token>"
```

Use one of those with `CM_BASE` and run `scripts/healthcheck.py` (or the skill). You can unset username/password after minting.

## Refresh grant (new `jwt` from an existing refresh token)

```bash
export CM_REFRESH_TOKEN="<refresh_token>"
curl -sSk -X POST "$CM_BASE/v1/auth/tokens/" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"refresh_token\",
    \"refresh_token\": \"$CM_REFRESH_TOKEN\"
  }"
```

```bash
export CM_JWT="<jwt from response>"
```

Note: full per-domain key checks work best with username/password or a refresh token; a bare `CM_JWT` is enough for most appliance checks.
