install(FILES	tz-mapi-to-ical
		tz-ical-to-mapi
	DESTINATION ${mapidatadir}
)

set(SOURCES
	camel-mapi-settings.c
	camel-mapi-settings.h
	e-mapi-fast-transfer.h
	e-mapi-fast-transfer.c
	e-mapi-defs.h
	e-mapi-folder.c
	e-mapi-folder.h
	e-mapi-connection.c
	e-mapi-connection.h
	e-mapi-debug.c
	e-mapi-debug.h
	e-mapi-utils.c
	e-mapi-utils.h
	e-mapi-book-utils.c
	e-mapi-book-utils.h
	e-mapi-cal-utils.c
	e-mapi-cal-utils.h
	e-mapi-cal-tz-utils.c
	e-mapi-cal-tz-utils.h
	e-mapi-cal-recur-utils.c
	e-mapi-cal-recur-utils.h
	e-mapi-mail-utils.c
	e-mapi-mail-utils.h
	e-mapi-operation-queue.c
	e-mapi-operation-queue.h
	e-source-mapi-folder.c
	e-source-mapi-folder.h
)

add_library(evolution-mapi SHARED
	${SOURCES}
)

target_compile_definitions(evolution-mapi PRIVATE
	-DG_LOG_DOMAIN=\"evolution-mapi\"
	-DMAPI_DATADIR=\"${mapidatadir}\"
	-DLIBMAPI_LDIF_DIR=\"${libmapi_ldif_dir}\"
)

target_compile_options(evolution-mapi PUBLIC
	${CAMEL_CFLAGS}
	${EVOLUTION_DATA_SERVER_CFLAGS}
	${LIBEBOOK_CFLAGS}
	${LIBECAL_CFLAGS}
	${LIBEDATASERVER_CFLAGS}
	${LIBMAPI_CFLAGS}
)

target_include_directories(evolution-mapi PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}/src
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CAMEL_INCLUDE_DIRS}
	${EVOLUTION_DATA_SERVER_INCLUDE_DIRS}
	${LIBEBOOK_INCLUDE_DIRS}
	${LIBECAL_INCLUDE_DIRS}
	${LIBEDATASERVER_INCLUDE_DIRS}
	${LIBMAPI_INCLUDE_DIRS}
)

target_link_libraries(evolution-mapi
	${CAMEL_LDFLAGS}
	${EVOLUTION_DATA_SERVER_LDFLAGS}
	${LIBEBOOK_LDFLAGS}
	${LIBECAL_LDFLAGS}
	${LIBEDATASERVER_LDFLAGS}
	${LIBMAPI_LDFLAGS}
)

install(TARGETS evolution-mapi
	DESTINATION ${privsolibdir}
)
