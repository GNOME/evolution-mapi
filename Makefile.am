SUBDIRS = src po
DIST_SUBDIRS= src po

changelogs =			\
	ChangeLog

EXTRA_DIST = 			\
	$(changelog)		\
	eplugin-rule.mk		\
	intltool-merge.in	\
	intltool-update.in	\
	intltool-extract.in	

CLEANFILES = 	intltool-merge	\
		intltool-update	\
		intltool-extract	

DISTCHECK_CONFIGURE_FLAGS =	\
	--enable-gtk3

-include $(top_srcdir)/git.mk
