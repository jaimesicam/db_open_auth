/* Copyright (c) 2025, Percona LLC and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT THE IMPLIED WARRANTY OF MERCHANTABILITY OR FITNESS FOR A
   PARTICULAR PURPOSE.  See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA */

#include <mysql/plugin_auth.h>
#include <mysql/plugin.h>
#include <mysql/service_my_plugin_log.h>
#include <mysql/client_plugin.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#include <cstdarg>
#include <cstdio>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <string>
#include <vector>

#include "my_compiler.h"
#include "my_sys.h"
#include "mysql.h"

/* Used by server (hello packet) and client (read first packet). */
static bool parse_spn_realm_packet(const unsigned char *data, int len,
                                   std::string *spn, std::string *realm) {
  int pos = 0;
  auto read_chunk = [&](std::string *out) -> bool {
    if (pos + 2 > len) return false;
    unsigned short chunk_len =
        static_cast<unsigned char>(data[pos]) |
        (static_cast<unsigned char>(data[pos + 1]) << 8);
    pos += 2;
    if (chunk_len == 0 || pos + chunk_len > len) return false;
    out->assign(reinterpret_cast<const char *>(data + pos), chunk_len);
    pos += chunk_len;
    return true;
  };
  if (!read_chunk(spn)) return false;
  if (!read_chunk(realm)) return false;
  return true;
}

#ifndef DB_OPEN_AUTH_CLIENT_ONLY
static MYSQL_PLUGIN db_open_auth_gssapi_plugin_info = nullptr;

static char *db_open_auth_gssapi_keytab_path = nullptr;
static char *db_open_auth_gssapi_host_override = nullptr;
static bool db_open_auth_gssapi_log_enabled = false;

static void update_gssapi_log(MYSQL_THD, SYS_VAR *, void *tgt, const void *save) {
  *static_cast<bool *>(tgt) = *static_cast<const bool *>(save);
}

static MYSQL_SYSVAR_STR(
    keytab, db_open_auth_gssapi_keytab_path,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC | PLUGIN_VAR_READONLY,
    "Path to Kerberos keytab for the MySQL service principal.", nullptr, nullptr,
    nullptr);

static MYSQL_SYSVAR_STR(
    host, db_open_auth_gssapi_host_override,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC | PLUGIN_VAR_READONLY,
    "Hostname part of the service principal mysql/<host>@REALM (must match the "
    "keytab, often the FQDN e.g. mysql2.example.net). If empty, derived from "
    "this host (prefers DNS canonical name over short gethostname).",
    nullptr, nullptr, nullptr);

static MYSQL_SYSVAR_BOOL(
    log, db_open_auth_gssapi_log_enabled, PLUGIN_VAR_RQCMDARG,
    "When ON, log each GSSAPI authentication step to the error log at WARNING "
    "priority (visible with log_error_verbosity>=2).",
    nullptr, &update_gssapi_log, false);

static SYS_VAR *db_open_auth_gssapi_sysvars[] = {
    MYSQL_SYSVAR(keytab),
    MYSQL_SYSVAR(host),
    MYSQL_SYSVAR(log),
    nullptr,
};

/* WARNING_LEVEL so lines appear at log_error_verbosity>=2 (INFORMATION needs 3). */
static void oa_log(const char *msg) {
  if (!db_open_auth_gssapi_log_enabled || !db_open_auth_gssapi_plugin_info) return;
  my_plugin_log_message(&db_open_auth_gssapi_plugin_info, MY_WARNING_LEVEL, "%s",
                        msg);
}

static void oa_log_fmt(const char *fmt, ...)
    MY_ATTRIBUTE((format(printf, 1, 2)));

static void oa_log_fmt(const char *fmt, ...) {
  if (!db_open_auth_gssapi_log_enabled || !db_open_auth_gssapi_plugin_info) return;
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  my_plugin_log_message(&db_open_auth_gssapi_plugin_info, MY_WARNING_LEVEL, "%s",
                        buf);
}

static void oa_log_gss(const char *ctx, OM_uint32 maj, OM_uint32 min) {
  if (!db_open_auth_gssapi_log_enabled) return;
  oa_log_fmt("db_open_auth_gssapi: %s major=%u minor=%u", ctx, (unsigned)maj,
             (unsigned)min);
}

static bool build_spn_realm_packet(const std::string &spn,
                                   const std::string &realm,
                                   std::vector<unsigned char> *out) {
  out->clear();
  auto append_chunk = [&](const std::string &s) {
    if (s.size() > 65535) return false;
    unsigned short l = static_cast<unsigned short>(s.size());
    out->push_back(static_cast<unsigned char>(l & 0xff));
    out->push_back(static_cast<unsigned char>((l >> 8) & 0xff));
    out->insert(out->end(), s.begin(), s.end());
    return true;
  };
  if (!append_chunk(spn)) return false;
  if (!append_chunk(realm)) return false;
  return true;
}

static bool realm_from_auth_string(const char *auth_string, std::string *realm) {
  if (!auth_string) return false;
  const char *at = strrchr(auth_string, '@');
  if (!at || at[1] == '\0') return false;
  realm->assign(at + 1);
  return true;
}

/** Hostname segment for mysql/<host>@REALM; prefer FQDN when not overridden. */
static std::string local_hostname_for_spn() {
  char host[256];
  if (gethostname(host, sizeof(host) - 1) != 0) return std::string("localhost");
  host[sizeof(host) - 1] = '\0';

  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;

  struct addrinfo *res = nullptr;
  int err = getaddrinfo(host, nullptr, &hints, &res);
  if (err != 0 || res == nullptr) {
    if (res) freeaddrinfo(res);
    return std::string(host);
  }

  if (res->ai_canonname != nullptr && res->ai_canonname[0] != '\0') {
    std::string canon(res->ai_canonname);
    freeaddrinfo(res);
    return canon;
  }

  char fqdn[NI_MAXHOST];
  if (getnameinfo(res->ai_addr, res->ai_addrlen, fqdn, sizeof(fqdn), nullptr, 0,
                  0) == 0) {
    std::string out(fqdn);
    freeaddrinfo(res);
    if (out.find('.') != std::string::npos) return out;
    return std::string(host);
  }
  freeaddrinfo(res);
  return std::string(host);
}

static std::string service_principal_for_realm(const std::string &realm) {
  std::string hostpart;
  if (db_open_auth_gssapi_host_override && db_open_auth_gssapi_host_override[0])
    hostpart = db_open_auth_gssapi_host_override;
  else
    hostpart = local_hostname_for_spn();

  std::string spn = "mysql/";
  spn += hostpart;
  spn += "@";
  spn += realm;
  return spn;
}

static int db_open_auth_gssapi_server(MYSQL_PLUGIN_VIO *vio,
                                   MYSQL_SERVER_AUTH_INFO *info) {
  if (db_open_auth_gssapi_log_enabled) {
    const char *un =
        info->user_name ? info->user_name : "";
    unsigned unl = info->user_name_length;
    const char *ho =
        info->host_or_ip ? info->host_or_ip : "";
    unsigned hol = info->host_or_ip_length;
    oa_log_fmt(
        "db_open_auth_gssapi: begin MySQL user=%.*s client_host=%.*s "
        "auth_string=%s",
        static_cast<int>(unl), un, static_cast<int>(hol), ho,
        info->auth_string ? info->auth_string : "(null)");
  }

  std::string realm;
  if (!realm_from_auth_string(info->auth_string, &realm)) {
    oa_log("db_open_auth_gssapi: invalid auth_string (expected user@REALM)");
    return CR_ERROR;
  }
  if (db_open_auth_gssapi_log_enabled)
    oa_log_fmt("db_open_auth_gssapi: parsed Kerberos realm from auth_string: %s",
               realm.c_str());

  std::string spn = service_principal_for_realm(realm);
  if (db_open_auth_gssapi_log_enabled) {
    oa_log_fmt("db_open_auth_gssapi: service principal for acceptor: %s",
               spn.c_str());
    if (db_open_auth_gssapi_host_override && db_open_auth_gssapi_host_override[0])
      oa_log_fmt("db_open_auth_gssapi: host override sysvar: %s",
                 db_open_auth_gssapi_host_override);
    else
      oa_log("db_open_auth_gssapi: host from local_hostname_for_spn (no override)");
  }

  std::vector<unsigned char> hello;
  if (!build_spn_realm_packet(spn, realm, &hello)) {
    oa_log("db_open_auth_gssapi: failed to build SPN/realm hello packet");
    return CR_ERROR;
  }
  if (db_open_auth_gssapi_log_enabled)
    oa_log_fmt("db_open_auth_gssapi: sending hello packet (%zu bytes)",
               hello.size());

  if (vio->write_packet(vio, hello.data(), static_cast<int>(hello.size()))) {
    oa_log("db_open_auth_gssapi: failed to write SPN/realm packet");
    return CR_ERROR;
  }
  if (db_open_auth_gssapi_log_enabled)
    oa_log("db_open_auth_gssapi: hello packet written");

  if (db_open_auth_gssapi_keytab_path && db_open_auth_gssapi_keytab_path[0]) {
    if (db_open_auth_gssapi_log_enabled)
      oa_log_fmt("db_open_auth_gssapi: setting KRB5_KTNAME=%s",
                 db_open_auth_gssapi_keytab_path);
    if (setenv("KRB5_KTNAME", db_open_auth_gssapi_keytab_path, 1) != 0) {
      oa_log("db_open_auth_gssapi: setenv KRB5_KTNAME failed");
      return CR_ERROR;
    }
  } else if (db_open_auth_gssapi_log_enabled) {
    oa_log("db_open_auth_gssapi: db_open_auth_gssapi_keytab unset; using default "
           "Kerberos keytab resolution");
  }

  OM_uint32 maj, min;
  gss_name_t svc_name = GSS_C_NO_NAME;
  gss_buffer_desc name_buf;
  name_buf.length = spn.size();
  name_buf.value = const_cast<char *>(spn.c_str());
  maj = gss_import_name(&min, &name_buf, GSS_C_NT_USER_NAME, &svc_name);
  if (GSS_ERROR(maj)) {
    oa_log_gss("gss_import_name(service)", maj, min);
    return CR_ERROR;
  }
  if (db_open_auth_gssapi_log_enabled)
    oa_log("db_open_auth_gssapi: gss_import_name(service) ok");

  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
  maj = gss_acquire_cred(&min, svc_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                         GSS_C_ACCEPT, &cred, nullptr, nullptr);
  if (GSS_ERROR(maj)) {
    oa_log_gss("gss_acquire_cred", maj, min);
    gss_release_name(&min, &svc_name);
    return CR_ERROR;
  }
  if (db_open_auth_gssapi_log_enabled)
    oa_log("db_open_auth_gssapi: gss_acquire_cred ok (acceptor credentials)");

  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_name_t client = GSS_C_NO_NAME;
  gss_buffer_desc input = {0, nullptr};
  gss_buffer_desc output = {0, nullptr};
  int accept_round = 0;

  do {
    unsigned char *pkt = nullptr;
    int plen = vio->read_packet(vio, &pkt);
    if (plen < 0) {
      oa_log("db_open_auth_gssapi: read_packet failed");
      gss_release_cred(&min, &cred);
      gss_release_name(&min, &svc_name);
      return CR_ERROR;
    }
    input.length = static_cast<size_t>(plen);
    input.value = pkt;
    ++accept_round;
    if (db_open_auth_gssapi_log_enabled)
      oa_log_fmt("db_open_auth_gssapi: gss_accept_sec_context round %d input_len=%d",
                 accept_round, plen);

    gss_OID mech_type = GSS_C_NO_OID;
    maj = gss_accept_sec_context(
        &min, &ctx, cred, &input, GSS_C_NO_CHANNEL_BINDINGS, &client, &mech_type,
        &output, nullptr, nullptr, nullptr);

    if (GSS_ERROR(maj)) {
      oa_log_gss("gss_accept_sec_context", maj, min);
      gss_release_buffer(&min, &output);
      gss_release_cred(&min, &cred);
      gss_release_name(&min, &svc_name);
      if (client != GSS_C_NO_NAME) gss_release_name(&min, &client);
      if (ctx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
      return CR_ERROR;
    }

    if (db_open_auth_gssapi_log_enabled) {
      if (maj & GSS_S_CONTINUE_NEEDED)
        oa_log("db_open_auth_gssapi: GSS_S_CONTINUE_NEEDED (more client rounds)");
      else
        oa_log("db_open_auth_gssapi: GSS context established (no continue needed "
               "from this round)");
    }

    if (output.length > 0) {
      if (db_open_auth_gssapi_log_enabled)
        oa_log_fmt("db_open_auth_gssapi: sending output_token len=%zu to client",
                   output.length);
      int w = vio->write_packet(vio, static_cast<unsigned char *>(output.value),
                                static_cast<int>(output.length));
      gss_release_buffer(&min, &output);
      if (w) {
        oa_log("db_open_auth_gssapi: write_packet failed");
        gss_release_cred(&min, &cred);
        gss_release_name(&min, &svc_name);
        if (client != GSS_C_NO_NAME) gss_release_name(&min, &client);
        if (ctx != GSS_C_NO_CONTEXT)
          gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
        return CR_ERROR;
      }
    } else {
      gss_release_buffer(&min, &output);
    }
  } while (maj & GSS_S_CONTINUE_NEEDED);

  gss_buffer_desc disp = {0, nullptr};
  gss_OID mech = GSS_C_NO_OID;
  if (db_open_auth_gssapi_log_enabled)
    oa_log("db_open_auth_gssapi: security context complete; resolving client name");

  maj = gss_display_name(&min, client, &disp, &mech);
  if (GSS_ERROR(maj)) {
    oa_log_gss("gss_display_name", maj, min);
    gss_release_cred(&min, &cred);
    gss_release_name(&min, &svc_name);
    gss_release_name(&min, &client);
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    return CR_ERROR;
  }

  std::string client_princ(static_cast<char *>(disp.value), disp.length);
  gss_release_buffer(&min, &disp);

  bool ok = (strcmp(client_princ.c_str(), info->auth_string) == 0);
  if (db_open_auth_gssapi_log_enabled) {
    oa_log_fmt(
        "db_open_auth_gssapi: gss_display_name ok; client_principal=%s "
        "expected_auth_string=%s",
        client_princ.c_str(), info->auth_string ? info->auth_string : "(null)");
    if (ok)
      oa_log("db_open_auth_gssapi: principal matches auth_string — authentication "
             "succeeded");
    else
      oa_log("db_open_auth_gssapi: principal does not match auth_string — "
             "rejecting");
  }

  gss_release_cred(&min, &cred);
  gss_release_name(&min, &svc_name);
  gss_release_name(&min, &client);
  gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);

  return ok ? CR_OK : CR_ERROR;
}

static int generate_auth_string_hash(char *outbuf, unsigned int *buflen,
                                     const char *inbuf, unsigned int inbuflen) {
  if (*buflen < inbuflen) return 1;
  strncpy(outbuf, inbuf, inbuflen);
  *buflen = strnlen(inbuf, inbuflen);
  return 0;
}

static int validate_auth_string_hash(char *const, unsigned int) { return 0; }

static int set_salt(const char *, unsigned int, unsigned char *,
                    unsigned char *salt_len) {
  *salt_len = 0;
  return 0;
}

static struct st_mysql_auth db_open_auth_gssapi_handler = {
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,
    "db_open_auth_gssapi_client",
    db_open_auth_gssapi_server,
    generate_auth_string_hash,
    validate_auth_string_hash,
    set_salt,
    0UL,
    nullptr};

static int db_open_auth_gssapi_plugin_init(MYSQL_PLUGIN p) {
  db_open_auth_gssapi_plugin_info = p;
  return 0;
}

mysql_declare_plugin(db_open_auth_gssapi){
    MYSQL_AUTHENTICATION_PLUGIN,
    &db_open_auth_gssapi_handler,
    "db_open_auth_gssapi",
    "Percona LLC",
    "Open GSSAPI Kerberos authentication",
    PLUGIN_LICENSE_GPL,
    db_open_auth_gssapi_plugin_init,
    nullptr,
    nullptr,
    0x0100,
    nullptr,
    db_open_auth_gssapi_sysvars,
    nullptr,
#if MYSQL_PLUGIN_INTERFACE_VERSION >= 0x103
    0
#endif
}
mysql_declare_plugin_end;
#endif  // DB_OPEN_AUTH_CLIENT_ONLY

/********************* CLIENT ************************************************/
#ifndef DB_OPEN_AUTH_SERVER_ONLY

static bool read_spn_realm(MYSQL_PLUGIN_VIO *vio, std::string *spn,
                           std::string *realm) {
  unsigned char *pkt = nullptr;
  int len = vio->read_packet(vio, &pkt);
  if (len < 0 || pkt == nullptr) return false;
  return parse_spn_realm_packet(pkt, len, spn, realm);
}

static bool write_gss_buffer(MYSQL_PLUGIN_VIO *vio, const unsigned char *b,
                             int blen) {
  return vio->write_packet(vio, b, blen) == 0;
}

static bool read_gss_buffer(MYSQL_PLUGIN_VIO *vio, const unsigned char **b,
                            size_t *blen) {
  unsigned char *pkt = nullptr;
  int len = vio->read_packet(vio, &pkt);
  if (len <= 0 || pkt == nullptr) return false;
  *b = pkt;
  *blen = static_cast<size_t>(len);
  return true;
}

static int db_open_auth_gssapi_client_auth(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql) {
  std::string spn;
  std::string realm;
  if (!read_spn_realm(vio, &spn, &realm)) return CR_ERROR;

  OM_uint32 maj, min;
  gss_ctx_id_t ctxt = GSS_C_NO_CONTEXT;
  gss_name_t service_name = GSS_C_NO_NAME;
  gss_buffer_desc principal_name_buf{0, nullptr};
  principal_name_buf.length = spn.size();
  principal_name_buf.value = const_cast<char *>(spn.c_str());
  maj = gss_import_name(&min, &principal_name_buf, GSS_C_NT_USER_NAME,
                        &service_name);
  if (GSS_ERROR(maj)) return CR_ERROR;

  gss_buffer_desc input{0, nullptr};
  gss_buffer_desc output{0, nullptr};
  gss_cred_id_t cred_id = GSS_C_NO_CREDENTIAL;

  do {
    output = {0, nullptr};
    maj = gss_init_sec_context(
        &min, cred_id, &ctxt, service_name, GSS_C_NO_OID, 0, 0,
        GSS_C_NO_CHANNEL_BINDINGS, &input, nullptr, &output, nullptr, nullptr);
    if (GSS_ERROR(maj)) {
      gss_release_name(&min, &service_name);
      if (ctxt != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min, &ctxt, GSS_C_NO_BUFFER);
      return CR_ERROR;
    }
    if (output.length) {
      if (!write_gss_buffer(vio, static_cast<unsigned char *>(output.value),
                            static_cast<int>(output.length))) {
        gss_release_buffer(&min, &output);
        gss_release_name(&min, &service_name);
        if (ctxt != GSS_C_NO_CONTEXT)
          gss_delete_sec_context(&min, &ctxt, GSS_C_NO_BUFFER);
        return CR_ERROR;
      }
      gss_release_buffer(&min, &output);
    }
    if (maj & GSS_S_CONTINUE_NEEDED) {
      const unsigned char *np = nullptr;
      size_t nl = 0;
      if (!read_gss_buffer(vio, &np, &nl)) {
        gss_release_name(&min, &service_name);
        if (ctxt != GSS_C_NO_CONTEXT)
          gss_delete_sec_context(&min, &ctxt, GSS_C_NO_BUFFER);
        return CR_ERROR;
      }
      input.length = nl;
      input.value = const_cast<unsigned char *>(np);
    }
  } while (maj & GSS_S_CONTINUE_NEEDED);

  gss_release_name(&min, &service_name);
  if (ctxt != GSS_C_NO_CONTEXT)
    gss_delete_sec_context(&min, &ctxt, GSS_C_NO_BUFFER);
  return CR_OK;
}

mysql_declare_client_plugin(AUTHENTICATION) "db_open_auth_gssapi_client",
    "Percona LLC", "Open GSSAPI Kerberos client authentication", {0, 1, 0},
    "GPL", nullptr, nullptr, nullptr, nullptr, nullptr,
    db_open_auth_gssapi_client_auth, nullptr, mysql_end_client_plugin;
#endif  // DB_OPEN_AUTH_SERVER_ONLY
