# Create a JWT or refresh token

```bash
export CM_BASE="https://cm.example.com/api"
export CM_USERNAME="<user>"
export CM_PASSWORD="<password>"
export CM_CONNECTION="local_account"
```

## Password grant

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

```bash
export CM_JWT="<jwt>"
```

or

```bash
export CM_REFRESH_TOKEN="<refresh_token>"
```

## Refresh grant

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
