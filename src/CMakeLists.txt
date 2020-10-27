FIND_LIBRARY(glib NAMES ubox.a)
FIND_LIBRARY(glib NAMES blobmsg_json.a)

ADD_LIBRARY(hibus SHARED unixsocket.c websocket.c)

ADD_EXECUTABLE(hibusd server.c unixsocket.c websocket.c sha1.c base64.c cJSON.c)
TARGET_LINK_LIBRARIES(hibusd ${json})

ADD_EXECUTABLE(hibus-cl cmdline.c unixsocket.c cJSON.c)
TARGET_LINK_LIBRARIES(hibus-cl ${json})

INSTALL(TARGETS hibus hibus-cl
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)
INSTALL(TARGETS hibusd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES hibus.h cJSON.h DESTINATION include)
