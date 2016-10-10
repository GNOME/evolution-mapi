set(DEPENDENCIES
	evolution-mapi
)

set(SOURCES
	e-cal-backend-mapi-factory.c
	e-cal-backend-mapi.c
	e-cal-backend-mapi.h
)

add_library(ecalbackendmapi MODULE
	${SOURCES}
)

add_dependencies(ecalbackendmapi
	${DEPENDENCIES}
)

target_compile_definitions(ecalbackendmapi PRIVATE
	-DG_LOG_DOMAIN=\"ecalbackendmapi\"
	-DEXCHANGE_MAPI_LOCALEDIR=\"${LOCALE_INSTALL_DIR}\"
)

target_compile_options(ecalbackendmapi PUBLIC
	${CAMEL_CFLAGS}
	${LIBEBACKEND_CFLAGS}
	${LIBECAL_CFLAGS}
	${LIBEDATACAL_CFLAGS}
	${LIBMAPI_CFLAGS}
)

target_include_directories(ecalbackendmapi PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}/src
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}
	${CAMEL_INCLUDE_DIRS}
	${LIBEBACKEND_INCLUDE_DIRS}
	${LIBECAL_INCLUDE_DIRS}
	${LIBEDATACAL_INCLUDE_DIRS}
	${LIBMAPI_INCLUDE_DIRS}
)

target_link_libraries(ecalbackendmapi
	${DEPENDENCIES}
	${CAMEL_LDFLAGS}
	${LIBEBACKEND_LDFLAGS}
	${LIBECAL_LDFLAGS}
	${LIBEDATACAL_LDFLAGS}
	${LIBMAPI_LDFLAGS}
)

install(TARGETS ecalbackendmapi
	DESTINATION ${ecal_backenddir}
)
