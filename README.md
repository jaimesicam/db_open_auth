# db_open_auth

Open authentication plugins for Percona Server, focused on **Kerberos (GSSAPI)** and **OpenID Connect (OIDC)**.

`db_open_auth` is an open authentication plugin project for Percona Server, providing Kerberos (GSSAPI) and OpenID Connect (OIDC) support together with client integration changes, design documentation, and usage guidance. The implementation in this repository was developed in **Cursor**.

## What this project provides

`db_open_auth` currently focuses on two authentication approaches:

- **Kerberos / GSSAPI**
  - Server plugin: `db_open_auth_gssapi`
  - Client plugin support integrated through MySQL client changes

- **OpenID Connect / OIDC**
  - Server plugin: `db_open_auth_oidc`
  - Client plugin support integrated through MySQL client changes

These plugins are intended to extend Percona Server with external authentication options commonly needed in enterprise environments.

## Why this project exists

Many environments already use centralized identity systems such as:

- Active Directory or MIT Kerberos
- Keycloak
- Other OpenID Connect identity providers

This project aims to make it easier to connect Percona Server to those systems by providing open authentication support for:

- centralized identity management
- reduced dependence on local database passwords
- better alignment with enterprise authentication standards
- easier integration for both users and applications

## Repository layout

```text
db_open_auth/
├── client/
│   ├── client_priv.h
│   └── mysql.cc
├── plugin/
│   └── db_open_auth/
│       ├── CMakeLists.txt
│       ├── README.md
│       ├── USER-GUIDE.md
│       ├── DESIGN-db_open_auth_gssapi.md
│       ├── DESIGN-db_open_auth_oidc.md
│       ├── db_open_auth_gssapi.cc
│       └── db_open_auth_oidc.cc
├── LICENSE
└── db_open_auth.patch
```

## Plugin summary

### `db_open_auth_gssapi`

Kerberos / GSSAPI authentication for Percona Server using a service keytab.

Typical use cases include:

- integration with Active Directory
- Linux environments using Kerberos principals
- centralized authentication without storing database passwords in MySQL accounts

### `db_open_auth_oidc`

OpenID Connect authentication for Percona Server using ID tokens validated against an issuer's JWKS.

Typical use cases include:

- Keycloak-based authentication
- modern identity provider integration
- token-based database login workflows for users and applications

## Client integration

This repository also includes MySQL client-side changes needed to support these authentication flows.

The `client/` directory contains:

- `client_priv.h`
- `mysql.cc`

These changes are part of the client integration required for the authentication implementation.

## Documentation

For full plugin details, see the detailed documentation under [`plugin/db_open_auth`](plugin/db_open_auth/README.md).

Additional documents:

- [Detailed plugin README](plugin/db_open_auth/README.md)
- [User Guide](plugin/db_open_auth/USER-GUIDE.md)
- [GSSAPI design document](plugin/db_open_auth/DESIGN-db_open_auth_gssapi.md)
- [OIDC design document](plugin/db_open_auth/DESIGN-db_open_auth_oidc.md)

These documents cover architecture, build integration, configuration, installation, and usage.

## Status

This repository is an open project for Percona Server authentication plugin development. It contains source code, documentation, and patching materials for integrating Kerberos and OIDC authentication into Percona Server.

## License

This project is licensed under **GPL-2.0**. See [LICENSE](LICENSE).
