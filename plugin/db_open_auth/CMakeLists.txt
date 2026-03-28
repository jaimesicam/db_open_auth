# Copyright (c) 2025, Percona LLC and/or its affiliates.
#
# Open authentication plugins: db_open_auth_gssapi (Kerberos/GSS-API), db_open_auth_oidc (JWT/OIDC).

DISABLE_MISSING_PROFILE_WARNING()

# --- GSSAPI / Kerberos (Unix) ---
IF(NOT WIN32 AND KERBEROS_FOUND AND GSSAPI_LIBRARIES AND KERBEROS_LIBRARIES)
  SET(OAUTH_GSS_LINK_LIBS ${GSSAPI_LIBRARIES} ${KERBEROS_LIBRARIES})
  IF(LIBDL)
    LIST(APPEND OAUTH_GSS_LINK_LIBS ${LIBDL})
  ENDIF()
  MYSQL_ADD_PLUGIN(
    db_open_auth_gssapi
    db_open_auth_gssapi.cc
    MODULE_ONLY
    MODULE_OUTPUT_NAME "db_open_auth_gssapi"
    LINK_LIBRARIES ${OAUTH_GSS_LINK_LIBS}
    NO_UNDEFINED)
  MYSQL_ADD_PLUGIN(
    db_open_auth_gssapi_client
    db_open_auth_gssapi.cc
    MODULE_ONLY
    CLIENT_ONLY
    SKIP_INSTALL
    MODULE_OUTPUT_NAME "db_open_auth_gssapi_client"
    LINK_LIBRARIES ${OAUTH_GSS_LINK_LIBS}
    NO_UNDEFINED)
  IF(TARGET db_open_auth_gssapi)
    IF(KERBEROS_INCLUDE_DIR)
      TARGET_INCLUDE_DIRECTORIES(db_open_auth_gssapi PRIVATE ${KERBEROS_INCLUDE_DIR})
    ENDIF()
    IF(GSSAPI_INCLUDE_DIR)
      TARGET_INCLUDE_DIRECTORIES(db_open_auth_gssapi PRIVATE ${GSSAPI_INCLUDE_DIR})
    ENDIF()
    TARGET_INCLUDE_DIRECTORIES(db_open_auth_gssapi PRIVATE ${CMAKE_SOURCE_DIR}/include)
    TARGET_COMPILE_DEFINITIONS(db_open_auth_gssapi PRIVATE DB_OPEN_AUTH_SERVER_ONLY)
  ENDIF()
  IF(TARGET db_open_auth_gssapi_client)
    IF(KERBEROS_INCLUDE_DIR)
      TARGET_INCLUDE_DIRECTORIES(db_open_auth_gssapi_client PRIVATE ${KERBEROS_INCLUDE_DIR})
    ENDIF()
    IF(GSSAPI_INCLUDE_DIR)
      TARGET_INCLUDE_DIRECTORIES(db_open_auth_gssapi_client PRIVATE ${GSSAPI_INCLUDE_DIR})
    ENDIF()
    TARGET_INCLUDE_DIRECTORIES(db_open_auth_gssapi_client PRIVATE ${CMAKE_SOURCE_DIR}/include)
    TARGET_COMPILE_DEFINITIONS(db_open_auth_gssapi_client PRIVATE DB_OPEN_AUTH_CLIENT_ONLY)
    # Default CLIENT_ONLY install uses COMPONENT Client; RPM %install often only
    # installs COMPONENT Server — reinstall as Server so *.so land in the tree.
    MYSQL_INSTALL_TARGET(db_open_auth_gssapi_client
      DESTINATION ${INSTALL_PLUGINDIR}
      COMPONENT Server)
  ENDIF()
ELSE()
  MESSAGE(STATUS "Skipping db_open_auth_gssapi (Kerberos/GSS-API libraries not found or Windows).")
ENDIF()

# --- OIDC (JWT) ---
MYSQL_ADD_PLUGIN(
  db_open_auth_oidc
  db_open_auth_oidc.cc
  MODULE_ONLY
  MODULE_OUTPUT_NAME "db_open_auth_oidc"
  LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto extra::rapidjson
  NO_UNDEFINED)
MYSQL_ADD_PLUGIN(
  db_open_auth_oidc_client
  db_open_auth_oidc.cc
  MODULE_ONLY
  CLIENT_ONLY
  SKIP_INSTALL
  MODULE_OUTPUT_NAME "db_open_auth_oidc_client"
  LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto
  NO_UNDEFINED)
IF(TARGET db_open_auth_oidc)
  TARGET_INCLUDE_DIRECTORIES(db_open_auth_oidc PRIVATE ${CMAKE_SOURCE_DIR}/include)
  TARGET_COMPILE_DEFINITIONS(db_open_auth_oidc PRIVATE DB_OPEN_AUTH_SERVER_ONLY)
ENDIF()
IF(TARGET db_open_auth_oidc_client)
  TARGET_INCLUDE_DIRECTORIES(db_open_auth_oidc_client PRIVATE ${CMAKE_SOURCE_DIR}/include)
  TARGET_COMPILE_DEFINITIONS(db_open_auth_oidc_client PRIVATE DB_OPEN_AUTH_CLIENT_ONLY)
  MYSQL_INSTALL_TARGET(db_open_auth_oidc_client
    DESTINATION ${INSTALL_PLUGINDIR}
    COMPONENT Server)
ENDIF()
