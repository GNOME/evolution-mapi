install(FILES libcamelmapi.urls
	DESTINATION ${camel_providerdir}
)

# *************************************************
# Installed private library which can be linked to
# *************************************************

set(DEPENDENCIES
	evolution-mapi
)

set(SOURCES
	camel-mapi-folder.c
	camel-mapi-folder.h
	camel-mapi-folder-summary.c
	camel-mapi-folder-summary.h
	camel-mapi-message-info.c
	camel-mapi-message-info.h
	camel-mapi-sasl-krb.c
	camel-mapi-sasl-krb.h
        camel-mapi-store.c
        camel-mapi-store.h
	camel-mapi-store-summary.c
	camel-mapi-store-summary.h
	camel-mapi-transport.c
	camel-mapi-transport.h
)

add_library(camelmapi-priv SHARED
	${SOURCES}
)

add_dependencies(camelmapi-priv
	${DEPENDENCIES}
)

target_compile_definitions(camelmapi-priv PRIVATE
	-DG_LOG_DOMAIN=\"camel-mapi-provider\"
	-DEXCHANGE_MAPI_LOCALEDIR=\"${LOCALE_INSTALL_DIR}\"
)

target_compile_options(camelmapi-priv PUBLIC
	${CAMEL_CFLAGS}
	${LIBEDATASERVER_CFLAGS}
	${LIBECAL_CFLAGS}
	${LIBMAPI_CFLAGS}
)

target_include_directories(camelmapi-priv PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}/src
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}
	${CAMEL_INCLUDE_DIRS}
	${LIBEDATASERVER_INCLUDE_DIRS}
	${LIBECAL_INCLUDE_DIRS}
	${LIBMAPI_INCLUDE_DIRS}
)

target_link_libraries(camelmapi-priv
	${DEPENDENCIES}
	${CAMEL_LDFLAGS}
	${LIBEDATASERVER_LDFLAGS}
	${LIBECAL_LDFLAGS}
	${LIBMAPI_LDFLAGS}
)

install(TARGETS camelmapi-priv
	DESTINATION ${privsolibdir}
)

# *************************************************
# Provider module
# *************************************************

set(DEPENDENCIES
	camelmapi-priv
	evolution-mapi
)

set(SOURCES
	camel-mapi-provider.c
)

add_library(camelmapi MODULE
	${SOURCES}
)

add_dependencies(camelmapi
	${DEPENDENCIES}
)

target_compile_definitions(camelmapi PRIVATE
	-DG_LOG_DOMAIN=\"camel-mapi-provider\"
	-DEXCHANGE_MAPI_LOCALEDIR=\"${LOCALE_INSTALL_DIR}\"
)

target_compile_options(camelmapi PUBLIC
	${CAMEL_CFLAGS}
	${LIBEDATASERVER_CFLAGS}
	${LIBECAL_CFLAGS}
	${LIBMAPI_CFLAGS}
)

target_include_directories(camelmapi PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}/src
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}
	${CAMEL_INCLUDE_DIRS}
	${LIBEDATASERVER_INCLUDE_DIRS}
	${LIBECAL_INCLUDE_DIRS}
	${LIBMAPI_INCLUDE_DIRS}
)

target_link_libraries(camelmapi
	${DEPENDENCIES}
	${CAMEL_LDFLAGS}
	${LIBEDATASERVER_LDFLAGS}
	${LIBECAL_LDFLAGS}
	${LIBMAPI_LDFLAGS}
)

install(TARGETS camelmapi
	DESTINATION ${camel_providerdir}
)
