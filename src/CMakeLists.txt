macro(add_simple_module _name _sourcesvar _depsvar _defsvar _cflagsvar _incdirsvar _ldflagsvar _destination)
	set(DEPENDENCIES
		evolution-mapi
	)

	set(SOURCES
		${${_sourcesvar}}
	)

	add_library(${_name} MODULE
		${SOURCES}
	)

	set_target_properties(${_name} PROPERTIES
		PREFIX ""
	)

	add_dependencies(${_name}
		${DEPENDENCIES}
		${${_depsvar}}
	)

	target_compile_definitions(${_name} PRIVATE
		-DG_LOG_DOMAIN=\"${_name}\"
		-DEXCHANGE_MAPI_LOCALEDIR=\"${LOCALE_INSTALL_DIR}\"
		${${_defsvar}}
	)

	target_compile_options(${_name} PUBLIC
		${CAMEL_CFLAGS}
		${LIBEBACKEND_CFLAGS}
		${LIBEDATASERVER_CFLAGS}
		${LIBMAPI_CFLAGS}
		${${_cflagsvar}}
	)

	target_include_directories(${_name} PUBLIC
		${CMAKE_BINARY_DIR}
		${CMAKE_SOURCE_DIR}
		${CAMEL_INCLUDE_DIRS}
		${LIBEBACKEND_INCLUDE_DIRS}
		${LIBEDATASERVER_INCLUDE_DIRS}
		${LIBMAPI_INCLUDE_DIRS}
		${${_incdirsvar}}
	)

	target_link_libraries(${_name}
		${DEPENDENCIES}
		${${_depsvar}}
		${CAMEL_LDFLAGS}
		${LIBEBACKEND_LDFLAGS}
		${LIBEDATASERVER_LDFLAGS}
		${LIBMAPI_LDFLAGS}
		${${_ldflagsvar}}
	)

	install(TARGETS ${_name}
		DESTINATION ${_destination}
	)
endmacro(add_simple_module)

add_subdirectory(addressbook)
add_subdirectory(calendar)
add_subdirectory(camel)
add_subdirectory(collection)
add_subdirectory(configuration)
add_subdirectory(libexchangemapi)
