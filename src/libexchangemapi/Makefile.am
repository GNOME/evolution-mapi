INCLUDES =					\
	-DG_LOG_DOMAIN=\"libexchangemapi\"	\
	-DMAPI_DATADIR=\""$(mapidatadir)"\"	\
	-I$(top_srcdir)				\
	$(EVOLUTION_DATA_SERVER_CFLAGS)		\
	$(LIBEDATASERVER_CFLAGS)		\
	$(EVOLUTION_CALENDAR_CFLAGS)		\
	$(LIBMAPI_CFLAGS)


lib_LTLIBRARIES = libexchangemapi-1.0.la

mapidata_DATA = 				\
	tz-mapi-to-ical 			\
	tz-ical-to-mapi 

libexchangemapi_1_0_la_SOURCES =		\
	exchange-mapi-defs.h			\
	exchange-mapi-folder.c			\
	exchange-mapi-folder.h			\
	exchange-mapi-connection.c		\
	exchange-mapi-connection.h		\
	exchange-mapi-utils.c			\
	exchange-mapi-utils.h			\
	exchange-mapi-cal-utils.c		\
	exchange-mapi-cal-utils.h		\
	exchange-mapi-cal-tz-utils.c		\
	exchange-mapi-cal-tz-utils.h		\
	exchange-mapi-cal-recur-utils.c		\
	exchange-mapi-cal-recur-utils.h


libexchangemapi_1_0_la_LIBADD =			\
	$(EVOLUTION_DATA_SERVER_LIBS)		\
	$(EVOLUTION_CALENDAR_LIBS)		\
	$(LIBMAPI_LIBS)

libexchangemapi_1_0_la_LDFLAGS = $(NO_UNDEFINED)

libexchangemapiincludedir = $(edataserver_privincludedir)/mapi

libexchangemapiinclude_HEADERS = 		\
	exchange-mapi-defs.h			\
	exchange-mapi-folder.h			\
	exchange-mapi-connection.h		\
	exchange-mapi-utils.h			\
	exchange-mapi-cal-utils.h		\
	exchange-mapi-cal-tz-utils.h		\
	exchange-mapi-cal-recur-utils.h

%-1.0.pc: %.pc
	 cp $< $@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libexchangemapi-1.0.pc

EXTRA_DIST = 					\
	$(pkgconfig_DATA:-1.0.pc=.pc.in) 	\
	$(mapidata_DATA)

DISTCLEANFILES = $(pkgconfig_DATA)

