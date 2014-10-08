SUBDIRS = src po
DIST_SUBDIRS= src po

@GNOME_CODE_COVERAGE_RULES@

@INTLTOOL_XML_NOMERGE_RULE@
metainfodir = $(datadir)/appdata
metainfo_in_files = evolution-mapi.metainfo.xml.in
metainfo_files = $(metainfo_in_files:.xml.in=.xml)
dist_metainfo_DATA = $(metainfo_files)

EXTRA_DIST = 			\
	ChangeLog		\
	$(metainfo_in_files)	\
	intltool-merge.in	\
	intltool-update.in	\
	intltool-extract.in	

CLEANFILES = 	intltool-merge	\
		intltool-update	\
		intltool-extract	

DISTCLEANFILES = $(metainfo_files)

MAINTAINERCLEANFILES =					\
	$(srcdir)/aclocal.m4				\
	$(srcdir)/config.guess				\
	$(srcdir)/config.h.in				\
	$(srcdir)/config.sub				\
	$(srcdir)/depcomp				\
	$(srcdir)/gtk-doc.make				\
	$(srcdir)/install-sh				\
	$(srcdir)/ltmain.sh				\
	$(srcdir)/missing				\
	$(srcdir)/mkinstalldirs

-include $(top_srcdir)/git.mk
