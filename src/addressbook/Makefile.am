INCLUDES =					\
	-DG_LOG_DOMAIN=\"libebookbackend\"	\
	-I$(top_srcdir)/src/addressbook		\
	-I$(top_builddir)/src/addressbook	\
	-I$(top_srcdir)/src/libexchangemapi	\
	$(LIBMAPI_CFLAGS)			\
	$(LIBEDATABOOK_CFLAGS)			\
	$(LIBEDATASERVER_CFLAGS)		\
	$(LIBEBACKEND_CFLAGS)			\
	$(EVOLUTION_DATA_SERVER_CFLAGS)		\
        $(EVOLUTION_ADDRESSBOOK_CFLAGS)

extension_LTLIBRARIES = libebookbackendmapi.la

libebookbackendmapi_la_SOURCES =		\
	e-book-backend-mapi.c			\
	e-book-backend-mapi.h			\
	e-book-backend-mapi-factory.c

libebookbackendmapi_la_LIBADD =			\
	$(top_builddir)/src/libexchangemapi/libexchangemapi-1.0.la \
	$(LIBEDATABOOK_LIBS)			\
	$(LIBEBACKEND_CFLAGS)			\
	$(LIBEDATASERVER_LIBS)			\
	$(EVOLUTION_DATA_SERVER_LIBS)		\
	$(EVOLUTION_ADDRESSBOOK_LIBS)		\
	$(LIBMAPI_LIBS)

libebookbackendmapi_la_LDFLAGS =		\
	-module -avoid-version $(NO_UNDEFINED)

#LDAP_SCHEMA =			\
#	evolutionperson.schema

#ldapschemadir = $(privdatadir)
#ldapschema_DATA= $(LDAP_SCHEMA)

#EXTRA_DIST = $(LDAP_SCHEMA) openldap-extract.h
