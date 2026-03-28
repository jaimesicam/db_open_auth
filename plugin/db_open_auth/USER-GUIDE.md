# User guide: `db_open_auth_gssapi` and `db_open_auth_oidc`

Target: **Percona Server 8.0.45** with the `db_open_auth` plugins built and installed. This guide describes installation, configuration, account setup, client usage, and two full examples: **Kerberos on EL9** and **Keycloak in Docker**.

For architecture and validation rules, see [DESIGN-db_open_auth_gssapi.md](DESIGN-db_open_auth_gssapi.md) and [DESIGN-db_open_auth_oidc.md](DESIGN-db_open_auth_oidc.md).

---

## 1. Runtime variables (summary)

| Variable | Default | Runtime change |
|----------|---------|----------------|
| `db_open_auth_gssapi_keytab` | (none) | **No** — read at startup / plugin init |
| `db_open_auth_gssapi_host` | (empty) | **No** — read at startup / plugin init |
| `db_open_auth_gssapi_log` | `OFF` | **Yes** |
| `db_open_auth_oidc_issuers` | (none) | **No** — read at startup / plugin init |
| `db_open_auth_oidc_group_role_map` | (none) | **No** — read at startup / plugin init |
| `db_open_auth_oidc_groups_claim` | `groups` | **No** — read at startup / plugin init |
| `db_open_auth_oidc_log` | `OFF` | **Yes** |

Use `SET PERSIST` or `SET GLOBAL` according to your Percona Server policy when changing the `*_log` options (for example `SET GLOBAL db_open_auth_gssapi_log = ON`).

### 1.1 Client plugin files on disk

You should see **four** modules under the server plugin directory (for example `/usr/lib64/mysql/plugin/`):

- `db_open_auth_gssapi.so`, `db_open_auth_gssapi_client.so`
- `db_open_auth_oidc.so`, `db_open_auth_oidc_client.so`

If only the non-`*_client*` files appear, reinstall after a fresh build: client-only targets must be installed with the same install pass as the server tree (see `plugin/db_open_auth/CMakeLists.txt`).

---

## 2. `db_open_auth_gssapi`

### 2.1 Install the server plugin

```sql
INSTALL PLUGIN db_open_auth_gssapi SONAME 'db_open_auth_gssapi.so';
```

### 2.2 Server configuration (`my.cnf`)

```ini
[mysqld]
db_open_auth_gssapi_keytab = /etc/mysql.keytab
# If empty, hostname is taken from this machine (FQDN when DNS resolves it).
# Set explicitly when the keytab uses mysql/mysql2.example.net@REALM but gethostname() is short:
db_open_auth_gssapi_host = mysql2.example.net
db_open_auth_gssapi_log = OFF
```

- **`db_open_auth_gssapi_keytab`**: Path to the keytab for the MySQL **service** principal. **READ-ONLY** for the server process lifetime (change requires restart).
- **`db_open_auth_gssapi_host`**: Hostname **segment** of the service principal `mysql/<host>@REALM`. It must match the keytab (e.g. `mysql/mysql2.example.net@REALM` → set `mysql2.example.net`). If unset, the plugin uses the local host name and tries the **DNS canonical (FQDN)** name when possible. If clients see `Server not found in Kerberos database` for `mysql/shortname@REALM` but `kvno mysql/long.example.net@REALM` works, set this to the long form or fix forward/reverse DNS for the MySQL host.
- **`db_open_auth_gssapi_log`**: `OFF` = quiet; `ON` = log each step of GSSAPI authentication to the **MySQL error log** at **WARNING** severity so it appears with **`log_error_verbosity` 2 or 3** (plugin diagnostics previously used NOTE level and required verbosity 3).

### 2.3 Create MySQL users

The `AS` clause must contain the **Kerberos principal** expected for that account (must match what GSS resolves for the client), for example:

```sql
CREATE USER gssapi_user IDENTIFIED WITH db_open_auth_gssapi AS 'gssapi_user@EXAMPLE.NET';
```

Grant privileges as usual:

```sql
GRANT SELECT ON mydb.* TO gssapi_user;
```

### 2.4 Client connection

Obtain Kerberos credentials (example):

```bash
kinit gssapi_user@EXAMPLE.NET
```

Connect with the client plugin:

```bash
mysql --default-auth=db_open_auth_gssapi_client --user=gssapi_user
```

The `mysql` binary must include **`db_open_auth_gssapi_client`**; stock clients need to be rebuilt or extended with this plugin.

---

## 3. `db_open_auth_oidc`

### 3.1 Install the server plugin

```sql
INSTALL PLUGIN db_open_auth_oidc SONAME 'db_open_auth_oidc.so';
```

### 3.2 Server configuration (`my.cnf`)

```ini
[mysqld]
db_open_auth_oidc_issuers = file:///etc/mysql/openid_issuers.json
# Optional: map IdP group strings (e.g. Keycloak group paths) to MySQL role names
# db_open_auth_oidc_group_role_map = file:///etc/mysql/openid_group_role_map.json
# JWT claim holding group membership (default: groups)
# db_open_auth_oidc_groups_claim = groups
db_open_auth_oidc_log = OFF
```

- **`db_open_auth_oidc_issuers`**: `file://` URI to the issuers JSON. **READ-ONLY** for the server process lifetime (change requires restart).
- **`db_open_auth_oidc_group_role_map`**: Optional `file://` URI to JSON mapping **`identity_provider`** → `{ "IdP group string" : "mysql_role_name" }`. Empty = no group-based roles. **READ-ONLY** until restart.
- **`db_open_auth_oidc_groups_claim`**: Name of the JWT payload claim listing groups (JSON **array of strings**, or a single string). Default **`groups`** if unset. Must match what your IdP puts in the **ID token** (Keycloak: add a mapper). **READ-ONLY** until restart.
- **`db_open_auth_oidc_log`**: `OFF` = quiet; `ON` = log each JWT validation step (structure, header `alg`/`kid`, claim checks, signature) to the **MySQL error log** at **WARNING** severity — visible with **`log_error_verbosity` 2 or 3**.

### 3.3 Build `openid_issuers.json`

After you have JWKS (e.g. `/tmp/jwks.json` from your IdP), you can build the issuers file.

**Recommended:** embed a **`keys` array** with `kid`, `n`, and `e` for each JWK (copy from JWKS). The server chooses the key whose **`kid`** matches the ID token header, so you never mix up the **encryption** (`use: enc`) and **signing** (`use: sig`) keys when both are present (Keycloak lists both).

```bash
ISSUER_NAME="http://127.0.0.1:8080/realms/mysql-realm"
curl -s "$ISSUER_NAME/protocol/openid-connect/certs" -o /tmp/jwks.json
jq -n --arg name "$ISSUER_NAME" \
  --argjson keys "$(jq '[.keys[] | {kid, n, e}]' /tmp/jwks.json)" \
  '{mysql_realm: {name: $name, keys: $keys}}' | sudo tee /etc/mysql/openid_issuers.json
sudo chmod 640 /etc/mysql/openid_issuers.json
sudo chown mysql:mysql /etc/mysql/openid_issuers.json
```

The top-level key (`mysql_realm` here) must match `identity_provider` in each MySQL account’s `authentication_string`. The file may use **nested objects** (as above) or the older form where each value is a **JSON string** containing `name`, `n`, and `e`.

- **`mysql_realm`** is the **`identity_provider`** value you will use in `CREATE USER`.
- **`name`** inside the inner JSON must match the JWT **`iss`** claim from tokens issued for that realm.

### 3.4 Group mapping to MySQL roles (Keycloak / OIDC)

After signature verification, the plugin can map **IdP group** strings from the JWT to **MySQL role** names and pass them in `MYSQL_SERVER_AUTH_INFO::external_roles` (comma-separated, **max 512 bytes**). The server then grants those roles to the logged-in user for that connection if the roles exist (same mechanism as other external-role flows).

1. **Create MySQL roles** and grant privileges to them (names must **not** contain commas):

   ```sql
   CREATE ROLE app_readonly, app_admin;
   GRANT SELECT ON mydb.* TO app_readonly;
   GRANT app_readonly TO app_admin WITH ADMIN OPTION;
   -- add further GRANTs for app_admin as needed
   ```

2. **Keycloak**: Add a **mapper** so the **ID token** includes a **`groups`** claim (or set `db_open_auth_oidc_groups_claim` to match your claim name). Group strings must match the **keys** in the mapping file exactly (often full paths like `/my-realm/mysql-admins`).

3. **Build `openid_group_role_map.json`** (top-level keys = **`identity_provider`**, same as in `CREATE USER`):

   ```json
   {
     "mysql_realm": {
       "/mysql-admins": "app_admin",
       "/mysql-readonly": "app_readonly"
     }
   }
   ```

4. **Reference it in `my.cnf`** and restart:

   ```ini
   db_open_auth_oidc_group_role_map = file:///etc/mysql/openid_group_role_map.json
   ```

If the mapping file is missing or empty, authentication still succeeds from JWT `sub` alone; no extra roles are applied. Unmapped groups are ignored. Mapped MySQL role names are deduplicated. If the comma-separated list would exceed **512 bytes**, it is truncated and a line is written to the error log when **`db_open_auth_oidc_log = ON`**.

### 3.5 Obtain `sub` for `CREATE USER`

Request a token (replace `YOUR_CLIENT_SECRET` with your confidential client secret):

```bash
curl -s -X POST "http://127.0.0.1:8080/realms/mysql-realm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=mysql-oidc-client" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=openid" \
  -d "username=mysqluser" \
  -d "password=mysqluser" > /tmp/token_response.json
```

Decode the ID token payload and read **`sub`** (and verify **`iss`**) — works on Linux and macOS:

```bash
ID_TOKEN=$(jq -r '.id_token' /tmp/token_response.json)
PAYLOAD=$(echo "$ID_TOKEN" | cut -d. -f2)
PADDED=$(echo "$PAYLOAD" | sed 's/-/+/g; s/_/\//g')
while [ $((${#PADDED} % 4)) -ne 0 ]; do PADDED="${PADDED}="; done
DECODED=$(echo "$PADDED" | base64 -d 2>/dev/null)
echo "$DECODED" | jq -r '.sub'
echo "$DECODED" | jq -r '.iss'
```

Use the printed **`sub`** as `SUB_FOR_MYSQL` below.

### 3.6 Create MySQL users

```sql
CREATE USER 'mysqluser'@'%'
  IDENTIFIED WITH db_open_auth_oidc
  AS '{"identity_provider":"mysql_realm","user":"SUB_FOR_MYSQL"}';
```

Replace `SUB_FOR_MYSQL` with the value from the previous step.

### 3.7 Client connection

**File:**

```bash
mysql -h HOST -P PORT -u mysqluser \
  --default-auth=db_open_auth_oidc_client \
  --db-open-auth-oidc-token-file=/tmp/mysql_id_token.txt \
  --ssl-mode=REQUIRED
```

**Inline token:**

```bash
mysql -h HOST -P PORT -u mysqluser \
  --default-auth=db_open_auth_oidc_client \
  --db-open-auth-oidc-token='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...' \
  --ssl-mode=REQUIRED
```

**Prompt** (if neither `--db-open-auth-oidc-token-file` nor `--db-open-auth-oidc-token` is set):

```text
Enter OIDC token: ****
mysql>
```

The `mysql` client must ship **`db_open_auth_oidc_client`** and the `--db-open-auth-oidc-*` options.

---

## 4. Example: Kerberos on RHEL / Rocky / AlmaLinux 9 (EL9)

This example sets up a minimal MIT KDC on **one** EL9 host, creates principals, exports a keytab for MySQL, and connects with `db_open_auth_gssapi`. Adjust hostnames, realms, and paths to match your environment.

### 4.1 Install Kerberos packages

```bash
sudo dnf install -y krb5-server krb5-workstation krb5-libs
```

### 4.2 Configure `/etc/krb5.conf`

Replace `EXAMPLE.NET` and `kdc.example.net` with your realm and KDC hostname:

```ini
[libdefaults]
    default_realm = EXAMPLE.NET
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    EXAMPLE.NET = {
        kdc = kdc.example.net:88
        admin_server = kdc.example.net:749
    }

[domain_realm]
    .example.net = EXAMPLE.NET
    example.net = EXAMPLE.NET
```

On a **single test machine**, you can use `localhost` as the KDC if you set `kdc = localhost:88` and `admin_server = localhost:749` and use consistent `/etc/hosts` entries.

### 4.3 Create the KDC database (first time)

```bash
sudo kdb5_util create -s -r EXAMPLE.NET
```

### 4.4 Start and enable services

```bash
sudo systemctl enable --now krb5kdc kadmin
```

### 4.5 Create principals

```bash
sudo kadmin.local -q "addprinc -pw MyUserPass gssapi_user@EXAMPLE.NET"
sudo kadmin.local -q "addprinc -randkey mysql/$(hostname -f)@EXAMPLE.NET"
```

### 4.6 Export MySQL service keytab

Adjust `mysql/$(hostname -f)@EXAMPLE.NET` if your service principal naming policy differs.

```bash
sudo kadmin.local -q "ktadd -k /etc/mysql.keytab mysql/$(hostname -f)@EXAMPLE.NET"
sudo chown mysql:mysql /etc/mysql.keytab
sudo chmod 640 /etc/mysql.keytab
```

### 4.7 Percona Server configuration

Add to `my.cnf`:

```ini
[mysqld]
db_open_auth_gssapi_keytab = /etc/mysql.keytab
db_open_auth_gssapi_log = ON
```

Install plugin and user (after server runs with keytab):

```sql
INSTALL PLUGIN db_open_auth_gssapi SONAME 'db_open_auth_gssapi.so';

CREATE USER gssapi_user IDENTIFIED WITH db_open_auth_gssapi AS 'gssapi_user@EXAMPLE.NET';
```

### 4.8 Client test on the same or a Kerberos-configured client host

```bash
kinit gssapi_user@EXAMPLE.NET
mysql --default-auth=db_open_auth_gssapi_client -u gssapi_user -h 127.0.0.1
```

If authentication fails, temporarily set `db_open_auth_gssapi_log = ON` and inspect the **MySQL error log**.

---

## 5. Example: Keycloak in Docker with `db_open_auth_oidc`

This example runs **Keycloak** in Docker, creates a realm and user, fetches JWKS, builds `openid_issuers.json`, and connects with the OIDC client plugin.

### 5.1 Run Keycloak (development-style)

```bash
docker run -d --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

Wait until Keycloak is listening on port **8080**.

### 5.2 Admin console

Open `http://127.0.0.1:8080`, sign in as `admin` / `admin`, and:

1. Create realm **`mysql-realm`**.
2. Create client **`mysql-oidc-client`**:
   - Client authentication: **On** (confidential) *or* public, matching how you configure the token request below.
   - Valid redirect URIs: `http://localhost/*` (sufficient for resource-owner password tests).
   - Note the **client secret** if confidential.
3. Create user **`mysqluser`** with password **`mysqluser`** (or your policy).
4. Under **Realm settings → Keys**, note you can use **RSA** keys; copy the **JWKS** URL, typically:

   `http://127.0.0.1:8080/realms/mysql-realm/protocol/openid-connect/certs`

### 5.3 Download JWKS

```bash
curl -s "http://127.0.0.1:8080/realms/mysql-realm/protocol/openid-connect/certs" -o /tmp/jwks.json
```

### 5.4 Build issuers file for MySQL

Prefer a full **`keys`** list (`kid` + `n` + `e`) so the server matches the token header; otherwise use a single **`sig`** key (`use == "sig"`), not `.keys[0]` (often `enc`).

```bash
ISSUER_NAME="http://127.0.0.1:8080/realms/mysql-realm"
curl -s "$ISSUER_NAME/protocol/openid-connect/certs" -o /tmp/jwks.json
jq -n --arg name "$ISSUER_NAME" \
  --argjson keys "$(jq '[.keys[] | {kid, n, e}]' /tmp/jwks.json)" \
  '{mysql_realm: {name: $name, keys: $keys}}' | sudo tee /etc/mysql/openid_issuers.json
sudo chmod 640 /etc/mysql/openid_issuers.json
sudo chown mysql:mysql /etc/mysql/openid_issuers.json
```

### 5.5 Percona Server `my.cnf`

```ini
[mysqld]
db_open_auth_oidc_issuers = file:///etc/mysql/openid_issuers.json
# Optional: db_open_auth_oidc_group_role_map = file:///etc/mysql/openid_group_role_map.json
db_open_auth_oidc_log = ON
```

### 5.6 Get `sub` and create MySQL user

```bash
curl -s -X POST "http://127.0.0.1:8080/realms/mysql-realm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=mysql-oidc-client" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=openid" \
  -d "username=mysqluser" \
  -d "password=mysqluser" > /tmp/token_response.json

ID_TOKEN=$(jq -r '.id_token' /tmp/token_response.json)
PAYLOAD=$(echo "$ID_TOKEN" | cut -d. -f2)
PADDED=$(echo "$PAYLOAD" | sed 's/-/+/g; s/_/\//g')
while [ $((${#PADDED} % 4)) -ne 0 ]; do PADDED="${PADDED}="; done
DECODED=$(echo "$PADDED" | base64 -d 2>/dev/null)
echo "$DECODED" | jq -r '.sub'
```

In `mysql` (as admin):

```sql
INSTALL PLUGIN db_open_auth_oidc SONAME 'db_open_auth_oidc.so';

CREATE USER 'mysqluser'@'%' IDENTIFIED WITH db_open_auth_oidc
  AS '{"identity_provider":"mysql_realm","user":"<paste-sub-here>"}';
```

### 5.7 Save ID token for client and connect

```bash
jq -r '.id_token' /tmp/token_response.json > /tmp/mysql_id_token.txt

mysql -h 127.0.0.1 -P 3306 -u mysqluser \
  --default-auth=db_open_auth_oidc_client \
  --db-open-auth-oidc-token-file=/tmp/mysql_id_token.txt \
  --ssl-mode=REQUIRED
```

> ID tokens **expire**; obtain a fresh token for new sessions. For production, use your organization’s OIDC login flow rather than password grant.

---

## 6. Client software requirements

Implementing these plugins requires **server and client** changes:

- Ship **`db_open_auth_gssapi`** / **`db_open_auth_gssapi_client`** and link GSS/Kerberos appropriately.
- Ship **`db_open_auth_oidc`** / **`db_open_auth_oidc_client`** with `--db-open-auth-oidc-token-file`, `--db-open-auth-oidc-token`, and interactive prompt when no token is supplied.

Dedicated MySQL error codes are **not** required for the first iteration; enable **`db_open_auth_gssapi_log`** and/or **`db_open_auth_oidc_log`** (`ON`) for troubleshooting.
