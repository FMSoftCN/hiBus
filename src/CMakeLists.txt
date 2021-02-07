FIND_PACKAGE(PkgConfig)

PKG_CHECK_MODULES(GLIB REQUIRED glib-2.0)
INCLUDE_DIRECTORIES(${GLIB_INCLUDE_DIRS})
LINK_DIRECTORIES(${GLIB_LIBRARY_DIRS})

FIND_LIBRARY(libglib NAMES glib-2.0 PATHS ${GLIB_LIBRARY_DIRS})

FIND_PACKAGE(OpenSSL)

IF(OpenSSL_FOUND)
    ADD_DEFINITIONS(-DHAVE_LIBSSL)
ENDIF(OpenSSL_FOUND)

IF(BUILD_STATIC)
  FIND_LIBRARY(libhibox NAMES hibox.a)
ELSE(BUILD_STATIC)
  FIND_LIBRARY(libhibox NAMES hibox)
ENDIF(BUILD_STATIC)

FIND_PATH(hibox_inc_dir hibox/utils.h)
INCLUDE_DIRECTORIES(${hibox_inc_dir})

ADD_LIBRARY(hibus SHARED libhibus.c helpers.c
        sign_verify_rsa_sha256.c sign_verify_hmac_sha256.c sign_verify_dummy.c)
TARGET_LINK_LIBRARIES(hibus ${libhibox} ${OPENSSL_LIBRARIES})

ADD_EXECUTABLE(hibusd websocket.c unixsocket.c server.c endpoint.c builtin_endpoint.c
        helpers.c pattern_list.c sign_verify_rsa_sha256.c sign_verify_hmac_sha256.c sign_verify_dummy.c)
TARGET_LINK_LIBRARIES(hibusd ${libhibox} ${libglib} ${OPENSSL_LIBRARIES})

INSTALL(TARGETS hibus LIBRARY DESTINATION lib)
INSTALL(TARGETS hibusd RUNTIME DESTINATION sbin)

INSTALL(FILES hibus.h DESTINATION include)

IF(BUILD_CMDLINE)
  ADD_EXECUTABLE(hibuscl cmdline.c drum_game.c libhibus.c helpers.c
        sign_verify_rsa_sha256.c sign_verify_hmac_sha256.c sign_verify_dummy.c)
  TARGET_LINK_LIBRARIES(hibuscl ${libhibox} ${OPENSSL_LIBRARIES})
  INSTALL(TARGETS hibuscl RUNTIME DESTINATION bin)
ENDIF(BUILD_CMDLINE)
