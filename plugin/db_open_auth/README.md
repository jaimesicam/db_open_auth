# Open authentication plugins for Percona Server 8.0.45

This directory contains **design** and **user** documentation for two pluggable authentication modules intended for Percona Server 8.0.45:

| Plugin | Purpose |
|--------|---------|
| `db_open_auth_gssapi` | Kerberos (GSS-API) authentication using a service keytab |
| `db_open_auth_oidc` | OpenID Connect ID-token authentication with issuer JWKS |

## Source layout

| File | Role |
|------|------|
| `CMakeLists.txt` | Registers `db_open_auth_gssapi` and `db_open_auth_oidc` with `MYSQL_ADD_PLUGIN` |
| `db_open_auth_gssapi.cc` | GSS-API server + client (`db_open_auth_gssapi.so`) |
| `db_open_auth_oidc.cc` | JWT/OIDC server + client (`db_open_auth_oidc.so`) |

The `mysql` client gains `--db-open-auth-oidc-token-file` and `--db-open-auth-oidc-token` in `client/mysql.cc` (see `init_connection_options`).

## Documents

| File | Contents |
|------|----------|
| [DESIGN-db_open_auth_gssapi.md](DESIGN-db_open_auth_gssapi.md) | Architecture, server/client behavior, configuration model, logging |
| [DESIGN-db_open_auth_oidc.md](DESIGN-db_open_auth_oidc.md) | JWT validation, issuer configuration, security requirements, logging |
| [USER-GUIDE.md](USER-GUIDE.md) | Installation, SQL, `my.cnf`, client usage, EL9 Kerberos example, Docker Keycloak example |

## Quick reference

**GSSAPI**

```sql
INSTALL PLUGIN db_open_auth_gssapi SONAME 'db_open_auth_gssapi.so';
CREATE USER gssapi_user IDENTIFIED WITH db_open_auth_gssapi AS 'gssapi_user@EXAMPLE.NET';
```

```bash
mysql --default-auth=db_open_auth_gssapi_client --user=gssapi_user
```

**OIDC**

```sql
INSTALL PLUGIN db_open_auth_oidc SONAME 'db_open_auth_oidc.so';
CREATE USER 'mysqluser'@'%' IDENTIFIED WITH db_open_auth_oidc
  AS '{"identity_provider":"mysql_realm","user":"SUB_FOR_MYSQL"}';
```

```bash
mysql --default-auth=db_open_auth_oidc_client \
  --db-open-auth-oidc-token-file=/tmp/mysql_id_token.txt \
  --ssl-mode=REQUIRED -u mysqluser -h HOST -P PORT
```


## Client binaries

Build the Percona Server tree so these separate modules are produced under the plugin output directory:

- `db_open_auth_gssapi.so` (server plugin only)
- `db_open_auth_gssapi_client.so` (client plugin only)
- `db_open_auth_oidc.so` (server plugin only)
- `db_open_auth_oidc_client.so` (client plugin only)
