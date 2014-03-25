NULL =

evo_module_LTLIBRARIES = module-mapi-configuration.la

module_mapi_configuration_la_CPPFLAGS =			\
	$(AM_CPPFLAGS)					\
	-DG_LOG_DOMAIN=\"module-mapi-configuration\"	\
	-DEXCHANGE_MAPI_LOCALEDIR=\"$(localedir)\"	\
	-I$(top_srcdir)/src				\
	-I$(top_srcdir)/src/libexchangemapi		\
	$(LIBECAL_CFLAGS)				\
	$(LIBEDATASERVER_CFLAGS)			\
	$(CAMEL_CFLAGS)					\
	$(EVOLUTION_MAIL_CFLAGS)			\
	$(EVOLUTION_SHELL_CFLAGS)			\
	$(LIBMAPI_CFLAGS)				\
	$(CODE_COVERAGE_CFLAGS)				\
	$(NULL)

module_mapi_configuration_la_SOURCES =		\
	module-mapi-configuration.c		\
	e-book-config-mapi.c			\
	e-book-config-mapi.h			\
	e-book-config-mapigal.c			\
	e-book-config-mapigal.h			\
	e-cal-config-mapi.c			\
	e-cal-config-mapi.h			\
	e-mail-config-mapi-backend.c		\
	e-mail-config-mapi-backend.h		\
	e-mail-config-mapi-page.c		\
	e-mail-config-mapi-page.h		\
	e-mail-config-mapi-extension.c		\
	e-mail-config-mapi-extension.h		\
	e-mapi-config-ui-extension.c		\
	e-mapi-config-ui-extension.h		\
	e-mapi-config-utils.c			\
	e-mapi-config-utils.h			\
	e-mapi-edit-folder-permissions.c	\
	e-mapi-edit-folder-permissions.h	\
	e-mapi-search-gal-user.c		\
	e-mapi-search-gal-user.h		\
	e-mapi-subscribe-foreign-folder.c	\
	e-mapi-subscribe-foreign-folder.h	\
	$(NULL)

module_mapi_configuration_la_LIBADD =		\
	$(top_builddir)/src/libexchangemapi/libexchangemapi-1.0.la \
	$(LIBECAL_LIBS)				\
	$(LIBEDATASERVER_LIBS)			\
	$(CAMEL_LIBS)				\
	$(EVOLUTION_MAIL_LIBS)			\
	$(EVOLUTION_SHELL_LIBS)			\
	$(LIBMAPI_LIBS)				\
	$(NULL)

module_mapi_configuration_la_LDFLAGS = \
	-module -avoid-version $(NO_UNDEFINED) $(CODE_COVERAGE_LDFLAGS)

-include $(top_srcdir)/git.mk
