dnl Simple configuration script for openchange evolution plugin
dnl Written by Julien Kerihuel <j.kerihuel@openchange.org>
dnl Modified for GNOME Evolution MAPI Provider by Johnny Jacob <jjohnny@novell.com>

m4_define([ema_version], [3.1.5])

AC_PREREQ(2.58)
AC_INIT([evolution-mapi], [ema_version], [http://bugzilla.gnome.org/browse.cgi?product=evolution-mapi])
AM_INIT_AUTOMAKE([gnu 1.9])
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
m4_define([libmapi_minimum_version], [0.11])
m4_define([glib_minimum_version], [2.16.1])
m4_define([gtk_minimum_version], [2.99.2])
m4_define([gconf_minimum_version], [2.0.0])

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
	"-DPANGO_DISABLE_DEPRECATED
	-DGDK_DISABLE_DEPRECATED
	-DGDK_PIXBUF_DISABLE_DEPRECATED
	-DGNOME_DISABLE_DEPRECATED
	-DGSEAL_ENABLE
	-DE_BOOK_DISABLE_DEPRECATED
	-DE_CAL_DISABLE_DEPRECATED
	-Wall -Wextra
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

dnl When evo will stop using GtkHBox/GtkVBox
dnl	-DGTK_DISABLE_DEPRECATED
dnl
dnl Other useful compiler warnings for test builds only.
dnl These may produce warnings we have no control over.
dnl
dnl	-Wmissing-format-attribute
dnl	-Wshadow
dnl	-Wredundant-decls

CFLAGS="$CFLAGS $WARNING_FLAGS"

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
	gtk+-3.0 >= gtk_minimum_version
	gconf-2.0 >= gconf_minimum_version])

dnl ********************************
dnl Check for evolution-data-server 
dnl ********************************
PKG_CHECK_MODULES(EVOLUTION_DATA_SERVER, evolution-data-server-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEDATASERVER, libedataserver-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEBACKEND, libebackend-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBECAL, libecal-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEDATACAL, libedata-cal-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBBOOK, libebook-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(LIBEDATABOOK, libedata-book-$EDS_PACKAGE >= eds_minimum_version)
PKG_CHECK_MODULES(CAMEL, camel-provider-$EDS_PACKAGE >= eds_minimum_version)

dnl ****************************
dnl Check for evolution plugins 
dnl ****************************
PKG_CHECK_MODULES(EVOLUTION_PLUGIN, evolution-plugin-3.0 >= evo_minimum_version)

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

dnl *******************************
dnl Add evolution plugin rules here
dnl *******************************
EVO_PLUGIN_RULE=$srcdir/eplugin-rule.mk
AC_SUBST_FILE(EVO_PLUGIN_RULE)

dnl *******************
dnl Special directories
dnl *******************
plugindir=`$PKG_CONFIG --variable=plugindir evolution-plugin-3.0`
AC_SUBST(plugindir)

ebook_backenddir=`$PKG_CONFIG --variable=backenddir libedata-book-1.2`
AC_SUBST(ebook_backenddir)

ecal_backenddir=`$PKG_CONFIG --variable=backenddir libedata-cal-1.2`
AC_SUBST(ecal_backenddir)

camel_providerdir=`$PKG_CONFIG --variable=camel_providerdir camel-provider-$EDS_PACKAGE`
AC_SUBST(camel_providerdir) 

edataserver_privincludedir=`$PKG_CONFIG --variable=privincludedir libedataserver-$EDS_PACKAGE`
AC_SUBST(edataserver_privincludedir)

libmapi_ldif_dir=`$PKG_CONFIG --variable=datadir libmapi`/setup
AC_SUBST(libmapi_ldif_dir)

mapidatadir=`$PKG_CONFIG --variable=privdatadir evolution-data-server-$EDS_PACKAGE`/mapi
AC_SUBST(mapidatadir)

dnl *************
dnl Gtk Doc stuff
dnl *************
GTK_DOC_CHECK(1.9)

dnl **************************
dnl Makefiles, generated .pc's
dnl **************************
AC_CONFIG_FILES([
Makefile 
src/Makefile
src/account-setup-eplugin/Makefile
src/addressbook/Makefile
src/calendar/Makefile
src/camel/Makefile
src/libexchangemapi/Makefile
src/libexchangemapi/libexchangemapi-]EVO_MAPI_API_VERSION_MACRO[.pc:src/libexchangemapi/libexchangemapi.pc.in
po/Makefile.in
])
AC_OUTPUT
