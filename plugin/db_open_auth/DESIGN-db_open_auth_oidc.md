# Design: `db_open_auth_oidc` (Percona Server 8.0.45)

## 1. Purpose

Allow users to authenticate with an **OpenID Connect ID token** (JWT) presented by the client. The server validates the JWT’s signature against **configured issuer keys**, enforces **issuer** (`iss`) and **subject** (`sub`) constraints, and maps the identity to a MySQL account via the plugin authentication string.

## 2. Scope

### In scope

- Server plugin `db_open_auth_oidc` (`db_open_auth_oidc.so`).
- Client plugin `db_open_auth_oidc_client`.
- Issuer configuration via `db_open_auth_oidc_issuers` pointing to a JSON file (`file://...` URI).
- Optional **IdP group → MySQL role** mapping via `db_open_auth_oidc_group_role_map` and JWT claim name `db_open_auth_oidc_groups_claim`, feeding `MYSQL_SERVER_AUTH_INFO::external_roles`.
- Option `db_open_auth_oidc_log` for verbose diagnostic logging to the **MySQL error log**.
- Secure transport requirement: **TLS** (or other channels the server treats as secure—v1 should document **TLS with `--ssl-mode=REQUIRED`** as the supported path).

### Out of scope (initial release)

- Custom MySQL error codes for each OIDC/JWT failure; use **`db_open_auth_oidc_log`** and generic authentication failure surfaces.
- Refresh tokens, access tokens as primary proof (only **ID token** as specified).
- Automatic key rotation beyond what the administrator encodes in the issuers JSON (operators update the file and restart if required by implementation).

## 3. Configuration

### 3.1 `db_open_auth_oidc_issuers`

- **Semantics**: URI to a JSON file, e.g. `file:///etc/mysql/openid_issuers.json`.
- **File format**: JSON object whose **keys** are **identity provider short names** (e.g. `mysql_realm`). Each value is a **JSON string** that itself contains a serialized JWK (or JWK subset) with at least `kty`, `n`, `e` for RSA, plus a `name` field holding the **formal issuer** string that must match JWT `iss`.


- **Lifetime**: **READ-ONLY after server start** for v1 (no hot reload). Changing issuers requires server restart (or future enhancement).

### 3.2 `db_open_auth_oidc_log`

- **Semantics**: `OFF` (default): minimal logging. `ON`: log each validation step (JWT parse, header alg, signature verify, `iss`/`sub` checks, expiry) to the **server error log**.
- **Lifetime**: **May be changed at runtime** (alongside `db_open_auth_gssapi_log`, this is the intended **dynamic** troubleshooting knob).

> **Note:** Only **`db_open_auth_gssapi_log`**, **`db_open_auth_oidc_log`**, and other explicitly documented dynamic variables are intended to change at runtime; **keytab**, **issuers file**, and **group_role_map** paths are **read-only** for the process lifetime.

### 3.3 `db_open_auth_oidc_group_role_map`

- **Semantics**: Optional URI to a JSON object. Each **top-level key** is an **`identity_provider`** short name (same as in `CREATE USER ... AS`). Each value is a JSON object whose keys are **exact IdP group strings** (as they appear in the JWT claim) and whose values are **MySQL role names** to grant via `external_roles`.
- **Lifetime**: **READ-ONLY after server start** (reload requires restart).

### 3.4 `db_open_auth_oidc_groups_claim`

- **Semantics**: JWT payload claim used for group membership. Expected as a **JSON array of strings**; a **single string** is treated as one group. Default claim name **`groups`** if the sysvar is unset or empty.
- **Lifetime**: **READ-ONLY after server start**.

## 4. Account mapping

```sql
CREATE USER 'mysqluser'@'%' IDENTIFIED WITH db_open_auth_oidc
  AS '{"identity_provider":"mysql_realm","user":"SUB_FOR_MYSQL"}';
```

- **`identity_provider`**: Must match a **top-level key** in the issuers JSON (e.g. `mysql_realm`).
- **`user`**: Must equal the JWT **`sub`** claim for successful login.
- The JWT **`iss`** claim must equal the inner JWK’s **`name`** field for that provider.

## 5. Token validation (logical)

1. Client sends ID token to server via plugin handshake (from file, inline option, or prompt).
2. Server rejects non-JWT or oversized tokens.
3. Verify signature (**RS256**) using the key resolved from `identity_provider` → JWK.
4. Verify `iss` matches configured `name` for that provider.
5. Verify `exp` (and standard time skew policy).
6. Verify `sub` matches the `user` field in the account authentication string.
7. If `db_open_auth_oidc_group_role_map` is configured and contains an entry for this `identity_provider`, read the JWT claim named by `db_open_auth_oidc_groups_claim`, map each group string to a MySQL role name, deduplicate, and fill **`external_roles`** (comma-separated, max **512** bytes including NUL). Role names must not contain commas. The server core applies external roles when non-empty (see `sql_authentication.cc`).
8. Success → continue MySQL authorization.

When `db_open_auth_oidc_log = ON`, log success/failure at each step without introducing new SQL-visible error codes in v1.

## 6. Client behavior

The client must support:

| Mechanism | Example |
|-----------|---------|
| Token file | `--db-open-auth-oidc-token-file=/tmp/mysql_id_token.txt` |
| Inline token | `--db-open-auth-oidc-token=<token>` |
| Prompt | If neither is set, prompt: `Enter OIDC token:` |

Always with TLS, e.g.:

```bash
mysql -h HOST -P PORT -u mysqluser \
  --default-auth=db_open_auth_oidc_client \
  --db-open-auth-oidc-token-file=/tmp/mysql_id_token.txt \
  --ssl-mode=REQUIRED
```

**Client code changes** are required to register `db_open_auth_oidc_client` and parse the new options.

## 7. Security considerations

- **TLS mandatory** for production: prevents token leakage on the wire.
- Protect issuer JSON and keytab files at rest (`chmod`, ownership).
- Token is bearer-secret: treat prompt/file paths as sensitive.

## 8. Installation

```sql
INSTALL PLUGIN db_open_auth_oidc SONAME 'db_open_auth_oidc.so';
```

