AM_CPPFLAGS =						\
	-DG_LOG_DOMAIN=\"libexchangemapi\"		\
	-DMAPI_DATADIR=\""$(mapidatadir)"\"		\
	-DLIBMAPI_LDIF_DIR=\""$(libmapi_ldif_dir)"\"	\
	-I$(top_srcdir)					\
	$(EVOLUTION_DATA_SERVER_CFLAGS)			\
	$(LIBEDATASERVER_CFLAGS)			\
	$(LIBEBOOK_CFLAGS)				\
	$(LIBECAL_CFLAGS)				\
	$(LIBMAPI_CFLAGS)				\
	$(CAMEL_CFLAGS)					\
	$(CODE_COVERAGE_CFLAGS)


lib_LTLIBRARIES = libexchangemapi-1.0.la

mapidata_DATA = 				\
	tz-mapi-to-ical 			\
	tz-ical-to-mapi 

libexchangemapi_1_0_la_SOURCES =	\
	camel-mapi-settings.c		\
	camel-mapi-settings.h		\
	e-mapi-fast-transfer.h		\
	e-mapi-fast-transfer.c		\
	e-mapi-defs.h			\
	e-mapi-folder.c			\
	e-mapi-folder.h			\
	e-mapi-connection.c		\
	e-mapi-connection.h		\
	e-mapi-debug.c			\
	e-mapi-debug.h			\
	e-mapi-utils.c			\
	e-mapi-utils.h			\
	e-mapi-book-utils.c		\
	e-mapi-book-utils.h		\
	e-mapi-cal-utils.c		\
	e-mapi-cal-utils.h		\
	e-mapi-cal-tz-utils.c		\
	e-mapi-cal-tz-utils.h		\
	e-mapi-cal-recur-utils.c	\
	e-mapi-cal-recur-utils.h	\
	e-mapi-mail-utils.c		\
	e-mapi-mail-utils.h		\
	e-mapi-operation-queue.c	\
	e-mapi-operation-queue.h	\
	e-source-mapi-folder.c		\
	e-source-mapi-folder.h


libexchangemapi_1_0_la_LIBADD =			\
	$(EVOLUTION_DATA_SERVER_LIBS)		\
	$(LIBEDATASERVER_LIBS)			\
	$(LIBEBOOK_LIBS)			\
	$(LIBECAL_LIBS)				\
	$(LIBMAPI_LIBS)				\
	$(CAMEL_LIBS)

libexchangemapi_1_0_la_LDFLAGS = $(NO_UNDEFINED) $(CODE_COVERAGE_LDFLAGS)

libexchangemapiincludedir = $(edataserver_privincludedir)/mapi

libexchangemapiinclude_HEADERS = 	\
	e-mapi-defs.h			\
	e-mapi-folder.h			\
	e-mapi-connection.h		\
	e-mapi-debug.h			\
	e-mapi-fast-transfer.h		\
	e-mapi-utils.h			\
	e-mapi-book-utils.h		\
	e-mapi-cal-utils.h		\
	e-mapi-cal-tz-utils.h		\
	e-mapi-cal-recur-utils.h	\
	e-mapi-mail-utils.h		\
	e-mapi-operation-queue.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libexchangemapi-$(EVO_MAPI_API_VERSION).pc

EXTRA_DIST = 					\
	$(mapidata_DATA)


-include $(top_srcdir)/git.mk
