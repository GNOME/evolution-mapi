INCLUDES =					\
	-DG_LOG_DOMAIN=\"libecalbackendmapi\"	\
	-I$(top_srcdir)/src/calendar		\
	-I$(top_srcdir)/src/libexchangemapi	\
	$(LIBEBACKEND_CFLAGS)			\
	$(LIBECAL_CFLAGS)			\
	$(LIBEDATACAL_CFLAGS)			\
	$(LIBMAPI_CFLAGS)

extension_LTLIBRARIES = libecalbackendmapi.la

libecalbackendmapi_la_SOURCES =			\
	e-cal-backend-mapi-factory.c		\
	e-cal-backend-mapi-factory.h		\
	e-cal-backend-mapi.c			\
	e-cal-backend-mapi.h

libecalbackendmapi_la_LIBADD =			\
	$(top_builddir)/src/libexchangemapi/libexchangemapi-1.0.la \
	$(LIBEBACKEND_LIBS)			\
	$(LIBECAL_LIBS)				\
	$(LIBEDATACAL_LIBS)			\
	$(LIBMAPI_LIBS)

libecalbackendmapi_la_LDFLAGS =			\
	-module -avoid-version $(NO_UNDEFINED)

