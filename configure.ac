dnl Simple configuration script for openchange evolution plugin
dnl Written by Julien Kerihuel <j.kerihuel@openchange.org>
dnl Modified for GNOME Evolution MAPI Provider by Johnny Jacob <jjohnny@novell.com>

m4_define([ema_version], [3.10.4])

AC_PREREQ(2.58)
AC_INIT([evolution-mapi], [ema_version], [http://bugzilla.gnome.org/browse.cgi?product=evolution-mapi])
AM_INIT_AUTOMAKE([gnu 1.9 dist-xz no-dist-gzip -Wno-portability])
AC_CONFIG_SRCDIR(README)
AC_CONFIG_HEADERS(config.h)

dnl ****************************
dnl Evolution-MAPI API version
dnl ****************************
m4_define([EVO_MAPI_API_VERSION_MACRO], [1.0])
EVO_MAPI_API_VERSION=EVO_MAPI_API_VERSION_MACRO
AC_SUBST(EVO_MAPI_API_VERSION)

dnl Some requirements have versioned package names
dnl XXX In the spirit of getting rid of versioned
dnl     files, can we please drop these suffixes?
EDS_PACKAGE=1.2

dnl *******************
dnl Required Packages
dnl *******************
m4_define([eds_minimum_version], [ema_version])
m4_define([evo_minimum_version], [ema_version])
m4_define([libmapi_minimum_version], [2.0])

dnl Keep these two definitions in agreement.
m4_define([glib_minimum_version], [2.34])
m4_define([glib_encoded_version], [GLIB_VERSION_2_34])

dnl Keep these two definitions in agreement.
m4_define([gdk_minimum_version], [3.0])
m4_define([gdk_encoded_version], [GDK_VERSION_3_0])

dnl ***********************************
dnl Automake 1.11 - Silent Build Rules
dnl ***********************************
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl ****************************
dnl Initialize maintainer mode
dnl ****************************
AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CPP
AC_C_INLINE
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

dnl ***********************
dnl Compiler Warning Flags
dnl ***********************
AS_COMPILER_FLAGS(WARNING_FLAGS,
	"-Wall -Wextra
	-Wdeprecated-declarations
	-Wno-missing-field-initializers
	-Wno-sign-compare
	-Wno-unused-parameter
	-Wdeclaration-after-statement
	-Werror-implicit-function-declaration
	-Wformat-nonliteral -Wformat-security -Winit-self
	-Wmissing-declarations -Wmissing-include-dirs
	-Wmissing-noreturn -Wnested-externs -Wpointer-arith
	-Wundef -Wwrite-strings")
AC_SUBST(WARNING_FLAGS)

dnl Other useful compiler warnings for test builds only.
dnl These may produce warnings we have no control over.
dnl
dnl	-Wmissing-format-attribute
dnl	-Wshadow
dnl	-Wredundant-decls

CFLAGS="$CFLAGS $WARNING_FLAGS"

dnl *******************************
dnl Check for --enable-strict
dnl *******************************
AC_ARG_ENABLE([strict],
	[AS_HELP_STRING([--enable-strict],
	[enable strict building, like without deprecated symbols (default=auto); auto enables strict building only if .git subdirectory exists])],
	[enable_strict=$enableval], [enable_strict=auto])

AC_MSG_CHECKING([if strict building is enabled])
if test "x$enable_strict" = xauto; then
	dnl Be strict when compiling with .git subdirectory
	if test -d .git ; then
		enable_strict=yes
	else
		enable_strict=no
	fi
fi
AC_MSG_RESULT([$enable_strict])

if test "x$enable_strict" = xyes; then
	CFLAGS="$CFLAGS -DG_DISABLE_DEPRECATED -DEDS_DISABLE_DEPRECATED"
fi

dnl Warn about GLib/GTK+ API usage that violates our minimum requirements.
CFLAGS="$CFLAGS -DGLIB_VERSION_MAX_ALLOWED=glib_encoded_version"
CFLAGS="$CFLAGS -DGDK_VERSION_MAX_ALLOWED=gdk_encoded_version"

dnl These will suppress warnings about newly-deprecated symbols.  Ideally
dnl these settings should match our minimum requirements and we will clean
dnl up any new deprecation warnings after bumping our minimum requirements.
dnl But if the warnings get to be overwhelming, use fixed versions instead.
CFLAGS="$CFLAGS -DGLIB_VERSION_MIN_REQUIRED=glib_encoded_version"
CFLAGS="$CFLAGS -DGDK_VERSION_MIN_REQUIRED=gdk_encoded_version"

dnl ************
dnl i18n stuff
dnl ************
IT_PROG_INTLTOOL([0.35.5])
AM_GLIB_GNU_GETTEXT

GETTEXT_PACKAGE=evolution-mapi
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Package name for gettext])

localedir='$(prefix)/$(DATADIRNAME)/locale'
AC_SUBST(localedir)

dnl ****************************
dnl Initialize libtool
dnl ****************************
AM_DISABLE_STATIC
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

dnl *****************************
dnl Check for GNOME Platform
dnl *****************************
PKG_CHECK_MODULES(GNOME_PLATFORM,
	[glib-2.0 >= glib_minimum_version
	gtk+-3.0 >= gdk_minimum_version])

dnl ********************************
dnl Check for evolution-data-server 
dnl ********************************
PKG_CHECK_MODULES(EVOLUTION_DATA_SERVER, evolution-data-server-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEDATASERVER, libedataserver-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEBACKEND, libebackend-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBECAL, libecal-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEDATACAL, libedata-cal-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEBOOK, libebook-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEDATABOOK, libedata-book-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(CAMEL, camel-$EDS_PACKAGE >= eds_minimum_version)

dnl ****************************
dnl Check for evolution stuff
dnl ****************************
PKG_CHECK_MODULES(EVOLUTION_SHELL, evolution-shell-3.0 >= evo_minimum_version)
PKG_CHECK_MODULES(EVOLUTION_MAIL, evolution-mail-3.0 >= evo_minimum_version)

dnl ****************************
dnl Check for LibMAPI
dnl ****************************

dnl libmapi requires SAMBA, it has got samba's cflags in it's own CFLAGS!
PKG_CHECK_MODULES(LIBMAPI, 
	libmapi >= libmapi_minimum_version,,
	[AC_MSG_ERROR([libmapi wasn't found! Please install at least libmapi-libmapi_minimum_version!])])
AC_SUBST(LIBMAPI_CFLAGS)
AC_SUBST(LIBMAPI_LIBS)

dnl ****************************
dnl Check for struct mapi_SNotRestriction availability
dnl see http://tracker.openchange.org/issues/377
dnl ****************************
AC_MSG_CHECKING([libmapi struct mapi_SNotRestriction])
save_cflags=$CFLAGS; CFLAGS=$LIBMAPI_CFLAGS
save_libs=$LIBS; LIBS="$LIBMAPI_LIBS"
AC_LINK_IFELSE([AC_LANG_PROGRAM(
	[[#include <libmapi/libmapi.h>]],
	[[struct mapi_SNotRestriction snot; snot.res->rt = RES_NOT]])],
	[AC_DEFINE(HAVE_RES_NOT_SUPPORTED, 1, [libmapi supports RES_NOT restrictions]) ac_cv_have_rns=yes],[ac_cv_have_rns=no])
CFLAGS=$save_cflags
LIBS=$save_libs
AC_MSG_RESULT([$ac_cv_have_rns])

dnl ****************************
dnl Expose version information
dnl ****************************
API_VERSION=$EDS_PACKAGE
AC_SUBST(API_VERSION)

EDS_REQUIRED=eds_minimum_version
AC_SUBST(EDS_REQUIRED)

EVO_REQUIRED=evo_minimum_version
AC_SUBST(EVO_REQUIRED)

LIBMAPI_REQUIRED=libmapi_minimum_version
AC_SUBST(LIBMAPI_REQUIRED)

dnl *******************
dnl Special directories
dnl *******************
ebook_backenddir=`$PKG_CONFIG --variable=backenddir libedata-book-1.2`
AC_SUBST(ebook_backenddir)

ecal_backenddir=`$PKG_CONFIG --variable=backenddir libedata-cal-1.2`
AC_SUBST(ecal_backenddir)

camel_providerdir=`$PKG_CONFIG --variable=camel_providerdir camel-1.2`
AC_SUBST(camel_providerdir) 

edataserver_privincludedir=`$PKG_CONFIG --variable=privincludedir libedataserver-$EDS_PACKAGE`
AC_SUBST(edataserver_privincludedir)

eds_moduledir=`$PKG_CONFIG --variable=moduledir libebackend-1.2`
AC_SUBST(eds_moduledir)

evo_moduledir=`$PKG_CONFIG --variable=moduledir evolution-shell-3.0`
AC_SUBST(evo_moduledir)

libmapi_ldif_dir=`$PKG_CONFIG --variable=datadir libmapi`/setup
AC_SUBST(libmapi_ldif_dir)

mapidatadir=`$PKG_CONFIG --variable=privdatadir evolution-data-server-$EDS_PACKAGE`/mapi
AC_SUBST(mapidatadir)

dnl **************************
dnl Makefiles, generated .pc's
dnl **************************
AC_CONFIG_FILES([
Makefile 
src/Makefile
src/addressbook/Makefile
src/calendar/Makefile
src/camel/Makefile
src/collection/Makefile
src/configuration/Makefile
src/libexchangemapi/Makefile
src/libexchangemapi/libexchangemapi-]EVO_MAPI_API_VERSION_MACRO[.pc:src/libexchangemapi/libexchangemapi.pc.in
po/Makefile.in
])
AC_OUTPUT
