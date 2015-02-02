NULL =

eds_module_LTLIBRARIES = module-mapi-backend.la

module_mapi_backend_la_CPPFLAGS =		\
	$(AM_CPPFLAGS)				\
	-DG_LOG_DOMAIN=\"module-mapi-backend\"	\
	-DEXCHANGE_MAPI_LOCALEDIR=\"$(localedir)\" \
	-I$(top_srcdir)/src/libexchangemapi	\
	$(LIBEDATASERVER_CFLAGS)		\
	$(LIBEBACKEND_CFLAGS)			\
	$(LIBMAPI_CFLAGS)			\
	$(CAMEL_CFLAGS)				\
	$(CODE_COVERAGE_CFLAGS)			\
	$(NULL)

module_mapi_backend_la_SOURCES =	\
	module-mapi-backend.c		\
	e-mapi-backend.c		\
	e-mapi-backend.h		\
	e-mapi-backend-factory.c	\
	e-mapi-backend-factory.h	\
	$(NULL)

module_mapi_backend_la_LIBADD =		\
	$(top_builddir)/src/libexchangemapi/libexchangemapi-1.0.la \
	$(LIBEDATASERVER_LIBS)		\
	$(LIBEBACKEND_LIBS)		\
	$(LIBMAPI_LIBS)			\
	$(CAMEL_LIBS)			\
	$(NULL)

module_mapi_backend_la_LDFLAGS = \
	-module -avoid-version $(NO_UNDEFINED) $(CODE_COVERAGE_LDFLAGS) \
	$(NULL)

-include $(top_srcdir)/git.mk
