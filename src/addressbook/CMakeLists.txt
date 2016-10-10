set(DEPENDENCIES
	evolution-mapi
)

set(SOURCES
	e-book-backend-mapi.c
	e-book-backend-mapi.h
	e-book-backend-mapi-contacts.c
	e-book-backend-mapi-contacts.h
	e-book-backend-mapi-gal.c
	e-book-backend-mapi-gal.h
	e-book-backend-mapi-factory.c
)

add_library(ebookbackendmapi MODULE
	${SOURCES}
)

add_dependencies(ebookbackendmapi
	${DEPENDENCIES}
)

target_compile_definitions(ebookbackendmapi PRIVATE
	-DG_LOG_DOMAIN=\"ebookbackendmapi\"
	-DBACKENDDIR=\"${ebook_backenddir}\"
	-DEXCHANGE_MAPI_LOCALEDIR=\"${LOCALE_INSTALL_DIR}\"
)

target_compile_options(ebookbackendmapi PUBLIC
	${LIBEBACKEND_CFLAGS}
	${LIBEBOOK_CFLAGS}
	${LIBEDATABOOK_CFLAGS}
	${LIBEDATASERVER_CFLAGS}
	${LIBMAPI_CFLAGS}
)

target_include_directories(ebookbackendmapi PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}/src
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${LIBEBACKEND_INCLUDE_DIRS}
	${LIBEBOOK_INCLUDE_DIRS}
	${LIBEDATABOOK_INCLUDE_DIRS}
	${LIBEDATASERVER_INCLUDE_DIRS}
	${LIBMAPI_INCLUDE_DIRS}
)

target_link_libraries(ebookbackendmapi
	${DEPENDENCIES}
	${LIBEBACKEND_LDFLAGS}
	${LIBEBOOK_LDFLAGS}
	${LIBEDATABOOK_LDFLAGS}
	${LIBEDATASERVER_LDFLAGS}
	${LIBMAPI_LDFLAGS}
)

install(TARGETS ebookbackendmapi
	DESTINATION ${ebook_backenddir}
)
