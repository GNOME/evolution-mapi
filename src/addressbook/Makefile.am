AM_CPPFLAGS =					\
	-DG_LOG_DOMAIN=\"libebookbackend\"	\
	-DEXCHANGE_MAPI_LOCALEDIR=\"$(localedir)\" \
	-I$(top_srcdir)/src/addressbook		\
	-I$(top_srcdir)/src/libexchangemapi	\
	$(LIBEBACKEND_CFLAGS)			\
	$(LIBEBOOK_CFLAGS)			\
	$(LIBEDATABOOK_CFLAGS)			\
	$(LIBMAPI_CFLAGS)			\
	$(CODE_COVERAGE_CFLAGS)

ebook_backend_LTLIBRARIES = libebookbackendmapi.la

libebookbackendmapi_la_SOURCES =		\
	e-book-backend-mapi.c			\
	e-book-backend-mapi.h			\
	e-book-backend-mapi-contacts.c		\
	e-book-backend-mapi-contacts.h		\
	e-book-backend-mapi-gal.c		\
	e-book-backend-mapi-gal.h		\
	e-book-backend-mapi-factory.c

libebookbackendmapi_la_LIBADD =			\
	$(top_builddir)/src/libexchangemapi/libexchangemapi-1.0.la \
	$(LIBEBACKEND_LIBS)			\
	$(LIBEBOOK_LIBS)			\
	$(LIBEDATABOOK_LIBS)			\
	$(LIBMAPI_LIBS)

libebookbackendmapi_la_LDFLAGS =		\
	-module -avoid-version $(NO_UNDEFINED) $(CODE_COVERAGE_LDFLAGS)

-include $(top_srcdir)/git.mk
