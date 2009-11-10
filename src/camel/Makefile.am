## Process this file with automake to produce Makefile.in

camel_provider_LTLIBRARIES = libcamelmapi.la
camel_provider_DATA = libcamelmapi.urls

AM_CPPFLAGS = -I.. 				\
	-I$(top_srcdir)/src/			\
	-I$(top_srcdir)/src/camel		\
	-I$(top_srcdir)/src/libexchangemapi	\
	$(CAMEL_CFLAGS)				\
	$(LIBECAL_CFLAGS)			\
        $(LIBMAPI_CFLAGS)                       \
	-DG_LOG_DOMAIN=\"camel-mapi-provider\"

libcamelmapi_la_SOURCES = 			\
	camel-mapi-provider.c			\
	camel-mapi-folder.c                	\
        camel-mapi-store.c	                \
	camel-mapi-store-summary.c         	\
	camel-mapi-summary.c	         	\
	camel-mapi-utils.c			\
	camel-mapi-notifications.c		\
	camel-mapi-transport.c			

noinst_HEADERS =         			\
	camel-mapi-folder.h			\
	camel-mapi-store.h			\
	camel-mapi-store-summary.h         	\
	camel-mapi-summary.h	         	\
	camel-mapi-transport.h			\
	camel-mapi-utils.h			\
	camel-mapi-notifications.h		\
	camel-mapi-private.h			\
	camel-private.h				

libcamelmapi_la_LDFLAGS = -avoid-version -module $(NO_UNDEFINED)
libcamelmapi_la_LIBADD = 			\
	$(top_builddir)/src/libexchangemapi/libexchangemapi-1.0.la \
	$(CAMEL_LIBS) 				\
	$(LIBECAL_LIBS)				\
        $(LIBMAPI_LIBS)

EXTRA_DIST = libcamelmapi.urls

-include $(top_srcdir)/git.mk
