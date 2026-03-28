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
#include <mysql/client_plugin.h>

#ifndef DB_OPEN_AUTH_CLIENT_ONLY
#include <mysql/service_my_plugin_log.h>
#include "mysql/service_mysql_alloc.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#ifdef RAPIDJSON_NO_SIZETYPEDEFINE
#include "my_rapidjson_size_t.h"
#endif

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#include <ctime>
#endif

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "my_compiler.h"
#include "my_sys.h"
#include "mysql.h"

#ifndef DB_OPEN_AUTH_CLIENT_ONLY
static MYSQL_PLUGIN db_open_auth_oidc_plugin_info = nullptr;

static char *db_open_auth_oidc_issuers_path = nullptr;
static bool db_open_auth_oidc_log_enabled = false;

/** One JWK (RSA). `kid` may be empty for legacy single-key files. */
struct OidcJwkKey {
  std::string kid;
  std::string n_b64url;
  std::string e_b64url;
};

struct OidcIssuer {
  std::string name;
  std::vector<OidcJwkKey> keys;
};

static std::mutex oidc_mutex;
static std::map<std::string, OidcIssuer> oidc_issuers;

/** identity_provider -> (IdP group string -> MySQL role name). Loaded at init. */
static std::map<std::string, std::map<std::string, std::string>> oidc_group_role_map;

static char *db_open_auth_oidc_group_role_map_path = nullptr;
static char *db_open_auth_oidc_groups_claim = nullptr;

static void update_oidc_log(MYSQL_THD, SYS_VAR *, void *tgt, const void *save) {
  *static_cast<bool *>(tgt) = *static_cast<const bool *>(save);
}

static MYSQL_SYSVAR_STR(
    issuers, db_open_auth_oidc_issuers_path,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC | PLUGIN_VAR_READONLY,
    "file:// URI or path to JSON issuers file for db_open_auth_oidc.", nullptr,
    nullptr, nullptr);

static MYSQL_SYSVAR_STR(
    group_role_map, db_open_auth_oidc_group_role_map_path,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC | PLUGIN_VAR_READONLY,
    "file:// URI or path to JSON mapping IdP groups to MySQL role names (see "
    "user guide). Empty disables mapping.",
    nullptr, nullptr, nullptr);

static MYSQL_SYSVAR_STR(
    groups_claim, db_open_auth_oidc_groups_claim,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC | PLUGIN_VAR_READONLY,
    "JWT payload claim for group membership (JSON array of strings, or a "
    "single string). Default groups.",
    nullptr, nullptr, nullptr);

static MYSQL_SYSVAR_BOOL(
    log, db_open_auth_oidc_log_enabled, PLUGIN_VAR_RQCMDARG,
    "When ON, log each OIDC/JWT validation step to the error log at WARNING "
    "priority (visible with log_error_verbosity>=2).",
    nullptr, &update_oidc_log, false);

static SYS_VAR *db_open_auth_oidc_sysvars[] = {
    MYSQL_SYSVAR(issuers),
    MYSQL_SYSVAR(group_role_map),
    MYSQL_SYSVAR(groups_claim),
    MYSQL_SYSVAR(log),
    nullptr,
};

/* WARNING_LEVEL so lines appear at log_error_verbosity>=2 (INFORMATION needs 3). */
static void oidc_log(const char *msg) {
  if (!db_open_auth_oidc_log_enabled || !db_open_auth_oidc_plugin_info) return;
  my_plugin_log_message(&db_open_auth_oidc_plugin_info, MY_WARNING_LEVEL, "%s",
                        msg);
}

static void oidc_log_fmt(const char *fmt, ...)
    MY_ATTRIBUTE((format(printf, 1, 2)));

static void oidc_log_fmt(const char *fmt, ...) {
  if (!db_open_auth_oidc_log_enabled || !db_open_auth_oidc_plugin_info) return;
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  my_plugin_log_message(&db_open_auth_oidc_plugin_info, MY_WARNING_LEVEL, "%s",
                        buf);
}

/**
  Base64url decode (JWT segments). Uses BIO base64 (correct padding); length
  % 4 == 1 is invalid per RFC 4648.
*/
static bool base64url_decode(const std::string &in, std::vector<unsigned char> *out) {
  if (in.empty()) return false;
  std::string s = in;
  for (auto &c : s) {
    if (c == '-') c = '+';
    else if (c == '_')
      c = '/';
  }
  switch (s.size() % 4) {
    case 0:
      break;
    case 2:
      s += "==";
      break;
    case 3:
      s += "=";
      break;
    default:
      return false;
  }

  BIO *bio = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
  if (!bio) return false;
  BIO *b64 = BIO_new(BIO_f_base64());
  if (!b64) {
    BIO_free(bio);
    return false;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);
  const size_t max_out = s.size() * 3 / 4 + 8;
  std::vector<unsigned char> buf(max_out);
  int len = BIO_read(bio, buf.data(), static_cast<int>(buf.size()));
  BIO_free_all(bio);
  if (len <= 0) return false;
  buf.resize(static_cast<size_t>(len));
  *out = std::move(buf);
  return true;
}

static bool load_issuers_from_file(const char *path_uri) {
  oidc_issuers.clear();
  if (!path_uri || !path_uri[0]) return false;
  const char *path = path_uri;
  if (strncmp(path, "file://", 7) == 0) path += 7;

  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  std::string json = ss.str();

  rapidjson::Document doc;
  doc.Parse(json.c_str());
  if (doc.HasParseError() || !doc.IsObject()) return false;

  for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
    if (!it->name.IsString()) continue;
    std::string map_key = it->name.GetString();
    rapidjson::Document inner_owned;
    const rapidjson::Value *inner = nullptr;
    if (it->value.IsString()) {
      inner_owned.Parse(it->value.GetString());
      if (inner_owned.HasParseError() || !inner_owned.IsObject()) continue;
      inner = &inner_owned;
    } else if (it->value.IsObject()) {
      inner = &it->value;
    } else {
      continue;
    }
    OidcIssuer iss;
    if (inner->HasMember("name") && (*inner)["name"].IsString())
      iss.name = (*inner)["name"].GetString();

    if (inner->HasMember("keys") && (*inner)["keys"].IsArray()) {
      for (auto &kv : (*inner)["keys"].GetArray()) {
        if (!kv.IsObject()) continue;
        OidcJwkKey jk;
        if (kv.HasMember("kid") && kv["kid"].IsString())
          jk.kid = kv["kid"].GetString();
        if (kv.HasMember("n") && kv["n"].IsString())
          jk.n_b64url = kv["n"].GetString();
        if (kv.HasMember("e") && kv["e"].IsString())
          jk.e_b64url = kv["e"].GetString();
        if (!jk.n_b64url.empty() && !jk.e_b64url.empty())
          iss.keys.push_back(std::move(jk));
      }
    }
    if (iss.keys.empty()) {
      OidcJwkKey jk;
      if (inner->HasMember("n") && (*inner)["n"].IsString())
        jk.n_b64url = (*inner)["n"].GetString();
      if (inner->HasMember("e") && (*inner)["e"].IsString())
        jk.e_b64url = (*inner)["e"].GetString();
      if (!jk.n_b64url.empty() && !jk.e_b64url.empty())
        iss.keys.push_back(std::move(jk));
    }

    if (!iss.name.empty() && !iss.keys.empty())
      oidc_issuers[map_key] = std::move(iss);
  }
  return !oidc_issuers.empty();
}

static bool load_group_role_map_from_file(const char *path_uri) {
  oidc_group_role_map.clear();
  if (!path_uri || !path_uri[0]) return true;
  const char *path = path_uri;
  if (strncmp(path, "file://", 7) == 0) path += 7;

  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  std::string json = ss.str();

  rapidjson::Document doc;
  doc.Parse(json.c_str());
  if (doc.HasParseError() || !doc.IsObject()) return false;

  for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); ++it) {
    if (!it->name.IsString() || !it->value.IsObject()) continue;
    std::string idp = it->name.GetString();
    std::map<std::string, std::string> inner;
    for (auto j = it->value.MemberBegin(); j != it->value.MemberEnd(); ++j) {
      if (!j->name.IsString() || !j->value.IsString()) continue;
      inner[j->name.GetString()] = j->value.GetString();
    }
    if (!inner.empty()) oidc_group_role_map[idp] = std::move(inner);
  }
  return true;
}

static int db_open_auth_oidc_plugin_init(MYSQL_PLUGIN p) {
  db_open_auth_oidc_plugin_info = p;
  if (db_open_auth_oidc_issuers_path && db_open_auth_oidc_issuers_path[0]) {
    if (!load_issuers_from_file(db_open_auth_oidc_issuers_path)) {
      my_plugin_log_message(&db_open_auth_oidc_plugin_info, MY_WARNING_LEVEL,
                            "db_open_auth_oidc: failed to load issuers file");
    }
  }
  if (db_open_auth_oidc_group_role_map_path &&
      db_open_auth_oidc_group_role_map_path[0]) {
    if (!load_group_role_map_from_file(db_open_auth_oidc_group_role_map_path)) {
      my_plugin_log_message(&db_open_auth_oidc_plugin_info, MY_WARNING_LEVEL,
                            "db_open_auth_oidc: failed to load group_role_map file");
    }
  }
  return 0;
}

static const OidcJwkKey *select_jwk_for_token(const OidcIssuer &iss,
                                              const rapidjson::Document &header) {
  if (iss.keys.empty()) return nullptr;

  std::string tok_kid;
  if (header.HasMember("kid") && header["kid"].IsString())
    tok_kid = header["kid"].GetString();

  if (iss.keys.size() == 1) {
    const auto &k = iss.keys[0];
    if (k.kid.empty() || tok_kid.empty() || k.kid == tok_kid) return &k;
    oidc_log_fmt(
        "db_open_auth_oidc: JWT kid=%s does not match the only JWK in file "
        "(kid=%s) — use the signing key n/e or add a `keys`[] array from JWKS",
        tok_kid.c_str(), k.kid.c_str());
    return nullptr;
  }

  if (tok_kid.empty()) {
    oidc_log("db_open_auth_oidc: JWT header missing kid but issuers file lists "
             "multiple JWKs; cannot choose a key");
    return nullptr;
  }

  for (const auto &k : iss.keys) {
    if (k.kid == tok_kid) return &k;
  }
  oidc_log_fmt(
      "db_open_auth_oidc: no JWK with kid=%s in issuers file (add full JWKS "
      "`keys` array or fix kid)",
      tok_kid.c_str());
  return nullptr;
}

static bool rsa_from_jwk(const OidcJwkKey &jwk, EVP_PKEY **out_pkey) {
  std::vector<unsigned char> nb, eb;
  if (!base64url_decode(jwk.n_b64url, &nb)) return false;
  if (!base64url_decode(jwk.e_b64url, &eb)) return false;

  BIGNUM *n = BN_bin2bn(nb.data(), static_cast<int>(nb.size()), nullptr);
  BIGNUM *e = BN_bin2bn(eb.data(), static_cast<int>(eb.size()), nullptr);
  if (!n || !e) {
    if (n) BN_free(n);
    if (e) BN_free(e);
    return false;
  }

  RSA *rsa = RSA_new();
  if (!rsa || RSA_set0_key(rsa, n, e, nullptr) != 1) {
    if (rsa) RSA_free(rsa);
    else {
      BN_free(n);
      BN_free(e);
    }
    return false;
  }

  EVP_PKEY *pkey = EVP_PKEY_new();
  if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
    if (pkey) EVP_PKEY_free(pkey);
    else
      RSA_free(rsa);
    return false;
  }
  *out_pkey = pkey;
  return true;
}

static bool verify_rs256(const std::string &signing_input,
                         const std::string &sig_b64url, EVP_PKEY *pkey) {
  std::vector<unsigned char> sig;
  if (!base64url_decode(sig_b64url, &sig)) return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  ERR_clear_error();
  bool ok = false;
  if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
      EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size()) ==
          1 &&
      EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) == 1) {
    ok = true;
  }
  EVP_MD_CTX_free(ctx);
  return ok;
}

static void oidc_log_openssl_verify_error() {
  if (!db_open_auth_oidc_log_enabled) return;
  unsigned long e = ERR_get_error();
  if (e == 0) return;
  char errbuf[256];
  ERR_error_string_n(e, errbuf, sizeof(errbuf));
  oidc_log_fmt("db_open_auth_oidc: OpenSSL EVP_DigestVerify: %s", errbuf);
}

static const char *effective_groups_claim() {
  if (db_open_auth_oidc_groups_claim && db_open_auth_oidc_groups_claim[0])
    return db_open_auth_oidc_groups_claim;
  return "groups";
}

static void extract_groups_from_payload(const rapidjson::Document &payload,
                                        const char *claim_name,
                                        std::vector<std::string> *out) {
  out->clear();
  if (!payload.HasMember(claim_name)) return;
  const rapidjson::Value &v = payload[claim_name];
  if (v.IsArray()) {
    for (const auto &x : v.GetArray()) {
      if (x.IsString()) out->emplace_back(x.GetString());
    }
  } else if (v.IsString()) {
    out->emplace_back(v.GetString());
  }
}

/**
  Build comma-separated MySQL role names for MYSQL_SERVER_AUTH_INFO::external_roles
  (max 512 bytes including trailing NUL). Role names must not contain commas.
*/
static void append_mapped_roles_to_external(
    const std::map<std::string, std::string> &group_to_role,
    const std::vector<std::string> &groups, char *buf, size_t buf_len) {
  buf[0] = '\0';
  if (buf_len < 2) return;

  std::vector<std::string> mysql_roles;
  for (const auto &g : groups) {
    auto r = group_to_role.find(g);
    if (r == group_to_role.end()) continue;
    const std::string &role = r->second;
    if (role.empty()) continue;
    if (role.find(',') != std::string::npos) {
      oidc_log_fmt(
          "db_open_auth_oidc: skip mapped role containing comma (invalid for "
          "external_roles): %s",
          role.c_str());
      continue;
    }
    bool dup = false;
    for (const auto &m : mysql_roles) {
      if (m == role) {
        dup = true;
        break;
      }
    }
    if (!dup) mysql_roles.push_back(role);
  }

  size_t pos = 0;
  for (size_t i = 0; i < mysql_roles.size(); ++i) {
    const std::string &r = mysql_roles[i];
    size_t need = r.size() + (i > 0 ? 1u : 0u);
    if (pos + need >= buf_len) {
      oidc_log("db_open_auth_oidc: external_roles truncated (512 byte limit)");
      break;
    }
    if (i > 0) buf[pos++] = ',';
    memcpy(buf + pos, r.c_str(), r.size());
    pos += r.size();
    buf[pos] = '\0';
  }
}

static void apply_group_role_mapping(const std::string &idp_key,
                                     const rapidjson::Document &payload,
                                     MYSQL_SERVER_AUTH_INFO *info) {
  info->external_roles[0] = '\0';
  if (oidc_group_role_map.empty()) return;

  auto idp_it = oidc_group_role_map.find(idp_key);
  if (idp_it == oidc_group_role_map.end()) return;

  std::vector<std::string> groups;
  extract_groups_from_payload(payload, effective_groups_claim(), &groups);

  if (db_open_auth_oidc_log_enabled) {
    const char *claim = effective_groups_claim();
    if (!payload.HasMember(claim))
      oidc_log_fmt(
          "db_open_auth_oidc: JWT has no %s claim (no group-based roles)",
          claim);
    else
      oidc_log_fmt(
          "db_open_auth_oidc: groups claim %s has %zu entries before mapping to "
          "MySQL roles",
          claim, groups.size());
  }

  append_mapped_roles_to_external(idp_it->second, groups, info->external_roles,
                                  sizeof(info->external_roles));

  if (db_open_auth_oidc_log_enabled && info->external_roles[0])
    oidc_log_fmt("db_open_auth_oidc: external_roles=%s", info->external_roles);
}

static bool parse_json_mapping(const char *auth_string, std::string *idp,
                               std::string *sub_expected) {
  if (!auth_string || !auth_string[0]) return false;
  rapidjson::Document d;
  d.Parse(auth_string);
  if (d.HasParseError() || !d.IsObject()) return false;
  if (!d.HasMember("identity_provider") || !d["identity_provider"].IsString())
    return false;
  if (!d.HasMember("user") || !d["user"].IsString()) return false;
  *idp = d["identity_provider"].GetString();
  *sub_expected = d["user"].GetString();
  return true;
}

static const char password_question[] = "\5";

static int db_open_auth_oidc_server(MYSQL_PLUGIN_VIO *vio,
                                 MYSQL_SERVER_AUTH_INFO *info) {
  if (db_open_auth_oidc_log_enabled) {
    const char *un = info->user_name ? info->user_name : "";
    unsigned unl = info->user_name_length;
    const char *ho = info->host_or_ip ? info->host_or_ip : "";
    unsigned hol = info->host_or_ip_length;
    oidc_log_fmt(
        "db_open_auth_oidc: begin MySQL user=%.*s client_host=%.*s "
        "auth_string_length=%lu",
        static_cast<int>(unl), un, static_cast<int>(hol), ho,
        static_cast<unsigned long>(info->auth_string_length));
  }

  std::string idp_key, want_sub;
  if (!parse_json_mapping(info->auth_string, &idp_key, &want_sub)) {
    oidc_log("db_open_auth_oidc: invalid auth_string JSON (need identity_provider "
             "and user)");
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log_fmt(
        "db_open_auth_oidc: parsed account mapping identity_provider=%s "
        "expected_sub=%s",
        idp_key.c_str(), want_sub.c_str());

  std::lock_guard<std::mutex> lk(oidc_mutex);
  auto it = oidc_issuers.find(idp_key);
  if (it == oidc_issuers.end()) {
    oidc_log_fmt(
        "db_open_auth_oidc: unknown identity_provider=%s (no matching key in "
        "issuers file)",
        idp_key.c_str());
    return CR_ERROR;
  }
  const OidcIssuer &issuer = it->second;
  if (db_open_auth_oidc_log_enabled)
    oidc_log_fmt("db_open_auth_oidc: issuer entry found configured iss(name)=%s",
                 issuer.name.c_str());

  if (vio->write_packet(vio, reinterpret_cast<const unsigned char *>(password_question),
                        1)) {
    oidc_log("db_open_auth_oidc: write_packet failed (could not send token "
             "challenge)");
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: sent one-byte token challenge to client");

  unsigned char *pkt = nullptr;
  int plen = vio->read_packet(vio, &pkt);
  if (plen < 0 || pkt == nullptr) {
    oidc_log("db_open_auth_oidc: read token failed (no data from client)");
    return CR_ERROR;
  }
  if (plen > 65536) {
    oidc_log_fmt("db_open_auth_oidc: token too large (%d bytes, max 65536)", plen);
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log_fmt("db_open_auth_oidc: received token from client length=%d (JWT "
                 "body not logged)",
                 plen);

  std::string jwt(reinterpret_cast<char *>(pkt), static_cast<size_t>(plen));
  /* Allow null-terminated tokens from client */
  if (!jwt.empty() && jwt.back() == '\0') jwt.pop_back();

  size_t p1 = jwt.find('.');
  size_t p2 = jwt.find('.', p1 == std::string::npos ? 0 : p1 + 1);
  if (p1 == std::string::npos || p2 == std::string::npos) {
    oidc_log("db_open_auth_oidc: malformed JWT (expected three dot-separated "
             "segments)");
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: JWT structure ok (header.payload.signature)");

  std::string sheader = jwt.substr(0, p1);
  std::string spayload = jwt.substr(p1 + 1, p2 - p1 - 1);
  std::string ssig = jwt.substr(p2 + 1);

  std::vector<unsigned char> hdr_raw;
  if (!base64url_decode(sheader, &hdr_raw)) {
    oidc_log("db_open_auth_oidc: JWT header base64url decode failed");
    return CR_ERROR;
  }
  std::string hdr_str(reinterpret_cast<char *>(hdr_raw.data()), hdr_raw.size());
  rapidjson::Document header;
  header.Parse(hdr_str.c_str());
  if (header.HasParseError() || !header.IsObject()) {
    oidc_log("db_open_auth_oidc: JWT header is not valid JSON object");
    return CR_ERROR;
  }
  const char *kid_str = "";
  if (header.HasMember("kid") && header["kid"].IsString())
    kid_str = header["kid"].GetString();
  if (db_open_auth_oidc_log_enabled) {
    const char *alg_str =
        (header.HasMember("alg") && header["alg"].IsString())
            ? header["alg"].GetString()
            : "(missing)";
    oidc_log_fmt("db_open_auth_oidc: JWT header alg=%s kid=%s", alg_str, kid_str);
  }
  if (!header.HasMember("alg") || !header["alg"].IsString() ||
      strcmp(header["alg"].GetString(), "RS256") != 0) {
    oidc_log("db_open_auth_oidc: alg is not RS256 (only RS256 is supported)");
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: header alg check passed (RS256)");

  std::vector<unsigned char> pld_raw;
  if (!base64url_decode(spayload, &pld_raw)) {
    oidc_log("db_open_auth_oidc: JWT payload base64url decode failed");
    return CR_ERROR;
  }
  std::string pld_str(reinterpret_cast<char *>(pld_raw.data()), pld_raw.size());
  rapidjson::Document payload;
  payload.Parse(pld_str.c_str());
  if (payload.HasParseError() || !payload.IsObject()) {
    oidc_log("db_open_auth_oidc: JWT payload is not valid JSON object");
    return CR_ERROR;
  }

  if (!payload.HasMember("iss") || !payload["iss"].IsString()) {
    oidc_log("db_open_auth_oidc: JWT payload missing iss or wrong type");
    return CR_ERROR;
  }
  if (!payload.HasMember("sub") || !payload["sub"].IsString()) {
    oidc_log("db_open_auth_oidc: JWT payload missing sub or wrong type");
    return CR_ERROR;
  }
  if (!payload.HasMember("exp") || !payload["exp"].IsNumber()) {
    oidc_log("db_open_auth_oidc: JWT payload missing exp or wrong type");
    return CR_ERROR;
  }

  std::string iss = payload["iss"].GetString();
  std::string sub = payload["sub"].GetString();
  int64_t exp = payload["exp"].IsInt64()
                    ? payload["exp"].GetInt64()
                    : static_cast<int64_t>(payload["exp"].GetDouble());
  int64_t now = static_cast<int64_t>(time(nullptr));
  if (db_open_auth_oidc_log_enabled)
    oidc_log_fmt(
        "db_open_auth_oidc: claims iss=%s sub=%s exp=%lld unix_now=%lld", iss.c_str(),
        sub.c_str(), static_cast<long long>(exp), static_cast<long long>(now));

  if (exp < now) {
    oidc_log_fmt(
        "db_open_auth_oidc: token expired (exp=%lld now=%lld)",
        static_cast<long long>(exp), static_cast<long long>(now));
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: exp check passed (token not expired)");

  if (iss != issuer.name) {
    oidc_log_fmt(
        "db_open_auth_oidc: iss mismatch token_iss=%s configured_iss=%s",
        iss.c_str(), issuer.name.c_str());
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: iss matches configured issuer name");

  if (sub != want_sub) {
    oidc_log_fmt(
        "db_open_auth_oidc: sub mismatch token_sub=%s expected_user=%s",
        sub.c_str(), want_sub.c_str());
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: sub matches account authentication_string user");

  const OidcJwkKey *jwk = select_jwk_for_token(issuer, header);
  if (!jwk) return CR_ERROR;

  if (db_open_auth_oidc_log_enabled)
    oidc_log_fmt(
        "db_open_auth_oidc: selected JWK for signature verification kid=%s",
        jwk->kid.empty() ? "(not set in file)" : jwk->kid.c_str());

  EVP_PKEY *pkey = nullptr;
  if (!rsa_from_jwk(*jwk, &pkey)) {
    oidc_log("db_open_auth_oidc: RSA public key build from JWK n/e failed");
    return CR_ERROR;
  }
  std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> pkey_guard(pkey, EVP_PKEY_free);
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: EVP_PKEY from JWK ok; verifying RS256 signature");

  std::string signing_input = sheader + "." + spayload;
  if (!verify_rs256(signing_input, ssig, pkey)) {
    oidc_log(
        "db_open_auth_oidc: RS256 signature verify failed (wrong key, corrupt "
        "token, or alg mismatch)");
    oidc_log_openssl_verify_error();
    return CR_ERROR;
  }
  if (db_open_auth_oidc_log_enabled)
    oidc_log("db_open_auth_oidc: RS256 signature verified");

  apply_group_role_mapping(idp_key, payload, info);

  info->password_used = PASSWORD_USED_YES;
  if (db_open_auth_oidc_log_enabled)
    oidc_log_fmt(
        "db_open_auth_oidc: authentication succeeded for MySQL user account "
        "mapped to sub=%s",
        sub.c_str());
  return CR_OK;
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

static struct st_mysql_auth db_open_auth_oidc_handler = {
    MYSQL_AUTHENTICATION_INTERFACE_VERSION,
    "db_open_auth_oidc_client",
    db_open_auth_oidc_server,
    generate_auth_string_hash,
    validate_auth_string_hash,
    set_salt,
    0UL,
    nullptr};

mysql_declare_plugin(db_open_auth_oidc){
    MYSQL_AUTHENTICATION_PLUGIN,
    &db_open_auth_oidc_handler,
    "db_open_auth_oidc",
    "Percona LLC",
    "OpenID Connect ID token authentication",
    PLUGIN_LICENSE_GPL,
    db_open_auth_oidc_plugin_init,
    nullptr,
    nullptr,
    0x0100,
    nullptr,
    db_open_auth_oidc_sysvars,
    nullptr,
#if MYSQL_PLUGIN_INTERFACE_VERSION >= 0x103
    0
#endif
}
mysql_declare_plugin_end;
#endif  // DB_OPEN_AUTH_CLIENT_ONLY

/********************* CLIENT ************************************************/
#ifndef DB_OPEN_AUTH_SERVER_ONLY

static char *opt_token_file = nullptr;
static char *opt_token_inline = nullptr;

static int db_open_auth_oidc_client_option(const char *opt, const void *val) {
  if (!val) return 1;
  if (strcmp(opt, "db_open_auth_oidc_token_file") == 0) {
    free(opt_token_file);
    opt_token_file = strdup(static_cast<const char *>(val));
    return 0;
  }
  if (strcmp(opt, "db_open_auth_oidc_token") == 0) {
    free(opt_token_inline);
    opt_token_inline = strdup(static_cast<const char *>(val));
    return 0;
  }
  return 1;
}

static int read_file_trim(const char *path, std::string *out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return 1;
  std::ostringstream ss;
  ss << in.rdbuf();
  *out = ss.str();
  while (!out->empty() && (out->back() == '\n' || out->back() == '\r'))
    out->pop_back();
  return 0;
}

static int db_open_auth_oidc_client_auth(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql) {
  unsigned char *pkt = nullptr;
  int pkt_len = vio->read_packet(vio, &pkt);
  if (pkt_len < 0) return CR_ERROR;

  std::string token;
  if (opt_token_inline && opt_token_inline[0]) {
    token = opt_token_inline;
  } else if (opt_token_file && opt_token_file[0]) {
    if (read_file_trim(opt_token_file, &token)) return CR_ERROR;
  } else {
    char buf[65536];
    if (mysql->passwd && mysql->passwd[0]) {
      token = mysql->passwd;
    } else {
      fputs("Enter OIDC token: ", stdout);
      fflush(stdout);
      if (!fgets(buf, sizeof(buf), stdin)) return CR_ERROR;
      token = buf;
      while (!token.empty() &&
             (token.back() == '\n' || token.back() == '\r'))
        token.pop_back();
    }
  }

  if (token.empty()) return CR_ERROR;

  if (vio->write_packet(vio, reinterpret_cast<const unsigned char *>(token.c_str()),
                        static_cast<int>(token.size()) + 1))
    return CR_ERROR;

  return CR_OK;
}

static int db_open_auth_oidc_client_deinit(void) {
  free(opt_token_file);
  free(opt_token_inline);
  opt_token_file = nullptr;
  opt_token_inline = nullptr;
  return 0;
}

mysql_declare_client_plugin(AUTHENTICATION) "db_open_auth_oidc_client",
    "Percona LLC", "OpenID Connect client authentication", {0, 1, 0}, "GPL",
    nullptr, nullptr, db_open_auth_oidc_client_deinit,
    db_open_auth_oidc_client_option, nullptr, db_open_auth_oidc_client_auth,
    nullptr, mysql_end_client_plugin;
#endif  // DB_OPEN_AUTH_SERVER_ONLY
