AM_CPPFLAGS = -I .					\
	-DEVOLUTION_GLADEDIR=\""$(gladedir)"\" 		\
	-DCONNECTOR_GLADEDIR=\""$(gladedir)"\" 		\
	-I$(top_srcdir)/src/				\
	-I$(top_srcdir)/src/libexchangemapi/		\
	$(EVOLUTION_PLUGIN_CFLAGS)			\
	$(LIBEDATASERVERUI_CFLAGS)			\
	$(CAMEL_CFLAGS)					\
	$(LIBECAL_CFLAGS)				\
	$(LIBMAPI_CFLAGS)


@EVO_PLUGIN_RULE@

plugin_DATA = org-gnome-exchange-mapi.eplug 	

plugin_LTLIBRARIES = liborg-gnome-exchange-mapi.la

liborg_gnome_exchange_mapi_la_SOURCES = 	\
	e-mapi-account-setup.c			\
	e-mapi-account-setup.h			\
	e-mapi-account-settings.c		\
	e-mapi-account-listener.c		\
	e-mapi-account-listener.h		\
	e-mapi-subscribe-foreign-folder.c	\
	e-mapi-subscribe-foreign-folder.h	\
	e-mapi-edit-folder-permissions.c	\
	e-mapi-edit-folder-permissions.h	\
	e-mapi-search-gal-user.c		\
	e-mapi-search-gal-user.h

liborg_gnome_exchange_mapi_la_LIBADD = 			\
	$(top_builddir)/src/libexchangemapi/libexchangemapi-1.0.la \
	$(top_builddir)/src/camel/libcamelmapi.la	\
	$(EVOLUTION_PLUGIN_LIBS)			\
	$(LIBEDATASERVERUI_LIBS)			\
	$(CAMEL_LIBS) 					\
	$(LIBECAL_LIBS)					\
	$(LIBMAPI_LIBS)

liborg_gnome_exchange_mapi_la_LDFLAGS = -module -avoid-version $(NO_UNDEFINED)
liborg_gnome_exchange_mapi_la_CFLAGS = $(LIBMAPI_CFLAGS)

EXTRA_DIST = 						\
	org-gnome-exchange-mapi.eplug.xml

BUILT_SOURCES = org-gnome-exchange-mapi.eplug	

CLEANFILES = $(BUILT_SOURCES)


-include $(top_srcdir)/git.mk
