FIND_LIBRARY(hibox NAMES hibox.a)

IF(BUILD_STATIC)
  FIND_LIBRARY(libhibox NAMES hibox.a)
ELSE(BUILD_STATIC)
  FIND_LIBRARY(libhibox NAMES hibox)
ENDIF(BUILD_STATIC)

FIND_PATH(hibox_inc_dir hibox/utils.h)
INCLUDE_DIRECTORIES(${hibox_inc_dir})

ADD_LIBRARY(hibus SHARED libhibus.c)
TARGET_LINK_LIBRARIES(hibus ${libhibox})

ADD_EXECUTABLE(hibus-cl cmdline.c libhibus.c)
TARGET_LINK_LIBRARIES(hibus-cl ${libhibox})

ADD_EXECUTABLE(hibusd websocket.c unixsocket.c server.c)
TARGET_LINK_LIBRARIES(hibusd ${libhibox})

INSTALL(TARGETS hibus hibus-cl
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)
INSTALL(TARGETS hibusd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES hibus.h DESTINATION include)
