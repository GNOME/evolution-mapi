# Simple configuration script for openchange evolution plugin
# Written by Julien Kerihuel <j.kerihuel@openchange.org>
# Modified for GNOME Evolution MAPI Provider by Johnny Jacob <jjohnny@novell.com>

AC_PREREQ(2.57)
AC_DEFINE(_GNU_SOURCE, 1, [Use GNU extensions])
AC_INIT(evolution-mapi, 0.27.1, http://bugzilla.gnome.org/browse.cgi?product=evolution-mapi)
AC_CONFIG_SRCDIR(README)

AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)

# Some requirements have versioned package names
# XXX In the spirit of getting rid of versioned
#     files, can we please drop these suffixes?
EDS_PACKAGE=1.2

# Required Packages
m4_define([eds_minimum_version], [2.27.2])
m4_define([evo_minimum_version], [2.27.2])
m4_define([libmapi_minimum_version], [0.8])

AC_CONFIG_HEADER(config.h)

dnl ****************************
dnl Evolution-MAPI API version
dnl ****************************
m4_define([EVO_MAPI_API_VERSION_MACRO], [1.0])
EVO_MAPI_API_VERSION=EVO_MAPI_API_VERSION_MACRO
AC_SUBST(EVO_MAPI_API_VERSION)

dnl ****************************
dnl Initialize maintainer mode
dnl ****************************
AM_MAINTAINER_MODE

AC_ISC_POSIX
AC_PROG_CC
AC_PROG_CPP
AC_C_INLINE
AC_STDC_HEADERS
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_DEFINE(_GNU_SOURCE, 1, [Use GNU extensions])

# Compiler Warning Flags

AS_COMPILER_FLAGS(WARNING_FLAGS,
»·······"-DG_DISABLE_DEPRECATED
	-DPANGO_DISABLE_DEPRECATED
	-DGDK_DISABLE_DEPRECATED
	-DGDK_PIXBUF_DISABLE_DEPRECATED
	-DGTK_DISABLE_DEPRECATED
	-DGNOME_DISABLE_DEPRECATED
	-Wall -Wextra
	-Wno-missing-field-initializers
	-Wno-sign-compare
	-Wno-unused-parameter
	-Wdeclaration-after-statement
	-Werror-implicit-function-declaration
	-Wformat-nonliteral -Wformat-security -Winit-self
	-Wmissing-declarations -Wmissing-include-dirs
	-Wmissing-noreturn -Wnested-externs -Wpointer-arith
	-Wredundant-decls -Wundef -Wwrite-strings")
AC_SUBST(WARNING_FLAGS)

# Other useful compiler warnings for test builds only.
# These may produce warnings we have no control over.
#
#»······-Wmissing-format-attribute
#»······-Wshadow

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
PKG_CHECK_MODULES(EVOLUTION_PLUGIN, evolution-plugin >= evo_minimum_version)

dnl ****************************
dnl Check for LibMAPI 
dnl ****************************
PKG_CHECK_MODULES(LIBMAPI, libmapi >= libmapi_minimum_version)

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
plugindir=`$PKG_CONFIG --variable=plugindir evolution-plugin`
AC_SUBST(plugindir)

extensiondir=`$PKG_CONFIG --variable=extensiondir evolution-data-server-$EDS_PACKAGE`
AC_SUBST(extensiondir) 

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
AC_OUTPUT([
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
