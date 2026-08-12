# Key list notes

## `fields=meta`

List responses omit `meta` unless you pass `fields=meta`. The inventory always requests `fields=meta`.

## Name filters are AND

Repeated `name=` query parameters are combined with AND, not OR. Use separate GETs, then merge by key id.

## System / internal keys

| Class | Detection |
|-------|-----------|
| citrus | Name starts with `citrus-` |
| service | Name starts with `ks-*`, `meta.service_name` is set, and there is no `ownerId` |

Do not treat every `ks-*` name as a system key.

## AKeyless Customer Fragments

In each checked domain, GET `name=cf-*` (and `name=cf-*` with `objectType=Opaque Object`), then merge by id. Classify names matching `cf-<uuid>`. Usually Opaque Object, no owner. Not system keys.

Do not treat every `cf-*` name as an AKeyless Customer Fragment.

## Versions

The catalog is one row per key name. Versions start at 0. Current version N means versions 0 through N exist (N+1 versions).

## CTE (CipherTrust Transparent Encryption)

CTE keys are DEKs. A `cte` section on metadata means the key can be used with CTE.

| `meta.cte.cte_versioned` | Policy compatibility |
|--------------------------|----------------------|
| `true` | LDT policies |
| `false` or not set | Standard policies |

Do not infer CTE from the key name.

## Material

Never print key material.
