INCLUDES = -I .						\
	-DEVOLUTION_GLADEDIR=\""$(gladedir)"\" 		\
	-DCONNECTOR_GLADEDIR=\""$(gladedir)"\" 		\
	-DLIBMAPI_LDIF_DIR=\""$(libmapi_ldif_dir)"\"	\
	-I$(top_srcdir)/src/libexchangemapi/		\
	$(CAMEL_CFLAGS)					\
	$(EVOLUTION_PLUGIN_CFLAGS)			\
	$(EVOLUTION_CALENDAR_CFLAGS) \
	$(EVOLUTION_ADDRESSBOOK_CFLAGS) \
	$(LIBMAPI_CFLAGS)


@EVO_PLUGIN_RULE@

plugin_DATA = org-gnome-exchange-mapi.eplug 	

plugin_LTLIBRARIES = liborg-gnome-exchange-mapi.la

liborg_gnome_exchange_mapi_la_SOURCES = 		\
	exchange-mapi-account-setup.c			\
	exchange-mapi-account-setup.h			\
	exchange-mapi-account-listener.c		\
	exchange-mapi-account-listener.h

liborg_gnome_exchange_mapi_la_LIBADD = 			\
	$(EVOLUTION_CALENDAR_LIBS) \
	$(EVOLUTION_ADDRESSBOOK_LIBS) \
	$(EVOLUTION_PLUGIN_LIBS)	\
	$(CAMEL_LIBS) \
	$(LIBMAPI_LIBS)

liborg_gnome_exchange_mapi_la_LDFLAGS = -module -avoid-version -lmapi $(NO_UNDEFINED)
liborg_gnome_exchange_mapi_la_CFLAGS = -I/usr/local/samba/include/

EXTRA_DIST = 							\
	org-gnome-exchange-mapi.eplug.xml

BUILT_SOURCES = org-gnome-exchange-mapi.eplug	

CLEANFILES = $(BUILT_SOURCES)
