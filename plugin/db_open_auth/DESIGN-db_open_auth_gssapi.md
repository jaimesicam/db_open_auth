# Design: `db_open_auth_gssapi` (Percona Server 8.0.45)

## 1. Purpose

Provide **Kerberos-based authentication** to MySQL using the platform GSS-API (typically MIT Kerberos or Heimdal). The server proves its identity to clients with a **service principal** stored in a **keytab**; clients obtain initial credentials (for example via `kinit`) and perform a mutual GSS-API context establishment with the server plugin.

## 2. Scope

### In scope

- Server authentication plugin: `db_open_auth_gssapi` (shared object `db_open_auth_gssapi.so`).
- Client authentication plugin: `db_open_auth_gssapi_client` (bundled with client builds that ship these plugins).
- Configuration options `db_open_auth_gssapi_keytab`, `db_open_auth_gssapi_host`, and `db_open_auth_gssapi_log`.
- Mapping MySQL accounts to Kerberos principals via the plugin authentication string.
- Diagnostic logging controlled by `db_open_auth_gssapi_log`, written to the **MySQL server error log** (and similarly for any client-side tracing policy—client logging is out of scope for this document unless explicitly added later).

### Out of scope (initial release)

- Dedicated MySQL error codes for every failure mode; operators rely on **`db_open_auth_gssapi_log`** and generic connection errors.


## 3. Threat model and assumptions

- **Network**: GSS-API mutual authentication protects against trivial impersonation when correctly deployed; **TLS is still recommended** for confidentiality and integrity of application data and for alignment with organizational policies.
- **Keytab**: Anyone with read access to the keytab can impersonate the MySQL service principal. The file must be readable only by the OS user running `mysqld`, and managed with standard host keytab hygiene (rotation, `k5srvutil`, etc.).
- **DNS**: Kerberos service principal names are sensitive to hostname and realm. Forward and reverse DNS should be consistent with the KDC’s expectations (same class of requirement as other Kerberos-enabled services).

## 4. Artifacts

| Artifact | Role |
|----------|------|
| `db_open_auth_gssapi.so` | Server plugin |
| `db_open_auth_gssapi_client.so` (name may follow platform conventions) | Client plugin |
| Keytab file | Path from `db_open_auth_gssapi_keytab` |
| `db_open_auth_gssapi_host` | Optional hostname for `mysql/<host>@REALM`; must align with keytab |

## 5. Configuration

### 5.1 `db_open_auth_gssapi_keytab`

- **Semantics**: Absolute path to the keytab containing the **MySQL service** principal (for example `mysql/hostname@REALM`—exact form is chosen at deployment time and must match what clients request).
- **Lifetime**: **READ-ONLY after server start** (value fixed for the process lifetime; changes require restart). Implementation may read once at plugin init or at first use, but must not follow runtime edits as a hot-reload mechanism in v1.

### 5.2 `db_open_auth_gssapi_host`

- **Semantics**: Optional **hostname segment only** for the service principal `mysql/<host>@REALM` (not the full principal string). Must match the first component after `mysql/` in the keytab entry (e.g. keytab `mysql/mysql2.example.net@REALM` → set `mysql2.example.net`). If empty, the plugin derives `<host>` from the local machine: it prefers the **DNS canonical name** (FQDN) when `getaddrinfo` provides `ai_canonname`, otherwise falls back to `gethostname()`.
- **Lifetime**: **READ-ONLY after server start** (same as keytab).

### 5.3 `db_open_auth_gssapi_log`

- **Semantics**: `OFF` (default): minimal logging. `ON`: log **each decision and branch** in the authentication path (principal parsing, GSS steps, success/failure reasons) at appropriate severity to the **server error log**.
- **Lifetime**: **May be changed at runtime** (e.g. `SET GLOBAL` / `SET PERSIST` per server policy).

## 6. Account model

### 6.1 `CREATE USER` authentication string

Example:

```sql
CREATE USER gssapi_user IDENTIFIED WITH db_open_auth_gssapi AS 'gssapi_user@EXAMPLE.NET';
```

- The `AS '...'` string MUST encode the **Kerberos user principal** expected for this MySQL login (typically `primary/instance@REALM`; for users, often `user@REALM`).
- **Exact match** between successful GSS-API peer identity and this string is required (normalization rules: implementation should document whether case-folding or realm alias mapping is applied; default should be **strict string match** after canonicalization by GSS, if any).

### 6.2 MySQL user name

The MySQL user name (`gssapi_user` in the example) is the account the client selects with `-u`. The plugin validates GSS identity against the authentication string; the mapping from principal to MySQL account follows the usual MySQL rules (user name + host).

**Note on realms**: Deployment examples sometimes use different realms in snippets (e.g. `EXAMPLE.NET` vs `EXAMPLE.COM`). The realm in `kinit`, in KDC data, in the keytab’s service principal, and in `AS 'user@REALM'` must be **consistent**.

## 7. Client usage

Clients request the client plugin explicitly:

```bash
mysql --default-auth=db_open_auth_gssapi_client --user=gssapi_user
```

The client is expected to:

1. Use existing GSS-API credentials (e.g. default credential cache after `kinit`).
2. Complete the plugin’s challenge/response exchange with the server.

**Modification to `mysql` client**: the client binary must register `db_open_auth_gssapi_client`, link against GSS/Kerberos libraries as needed, and implement the wire protocol expected by the server plugin.

## 8. Server-side authentication flow (logical)

1. Client connects and negotiates use of `db_open_auth_gssapi` / `db_open_auth_gssapi_client`.
2. Server loads service credentials from `db_open_auth_gssapi_keytab` (or uses process environment only if explicitly designed that way—v1 should prefer the explicit option).
3. GSS-API security context establishment (mutual authentication if configured).
4. Extract peer principal name; compare to the authentication string on the matched MySQL account.
5. Success → MySQL continues with authorization; failure → refuse connection.

When `db_open_auth_gssapi_log = ON`, emit structured lines for: keytab path resolution, principal names (consider PII/compliance), each GSS return code, and final accept/reject.

## 9. Installation

```sql
INSTALL PLUGIN db_open_auth_gssapi SONAME 'db_open_auth_gssapi.so';
```

Uninstall behavior should release GSS resources and invalidate the plugin’s use of the keytab; document any requirement to restart if the OS leaks state.

## 10. Dependencies

- OS Kerberos libraries (MIT/Heimdal as supported by the build).
- Consistent time synchronization (NTP) between clients, KDC, and server.
