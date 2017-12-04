/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the program; if not, see <http://www.gnu.org/licenses/>
 *
 *
 * Authors:
 *     Johnny Jacob <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef CAMEL_MAPI_STORE_SUMMARY_H
#define CAMEL_MAPI_STORE_SUMMARY_H

#include <camel/camel.h>

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_STORE_SUMMARY \
	(camel_mapi_store_summary_get_type ())
#define CAMEL_MAPI_STORE_SUMMARY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_STORE_SUMMARY, CamelMapiStoreSummary))
#define CAMEL_MAPI_STORE_SUMMARY_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_STORE_SUMMARY, CamelMapiStoreSummaryClass))
#define CAMEL_IS_MAPI_STORE_SUMMARY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_STORE_SUMMARY))
#define CAMEL_IS_MAPI_STORE_SUMMARY_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_STORE_SUMMARY))
#define CAMEL_MAPI_STORE_SUMMARY_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_STORE_SUMMARY, CamelMapiStoreSummaryClass))

G_BEGIN_DECLS

typedef struct _CamelMapiStoreSummary CamelMapiStoreSummary;
typedef struct _CamelMapiStoreSummaryClass CamelMapiStoreSummaryClass;
typedef struct _CamelMapiStoreSummaryPrivate CamelMapiStoreSummaryPrivate;

typedef struct _CamelMapiStoreInfo CamelMapiStoreInfo;

enum CamelMapiStoreFolderFlags {
	CAMEL_MAPI_STORE_FOLDER_FLAG_PERSONAL	 = 1 << 0,
	CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC	 = 1 << 1,
	CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN	 = 1 << 2,
	CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL	 = 1 << 3,
	CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL = 1 << 4, /* real public folder; the unreal is that under Favorites */
	CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN_WITH_SUBFOLDERS = 1 << 5
};

enum {
	CAMEL_MAPI_STORE_INFO_FOREIGN_USERNAME = CAMEL_STORE_INFO_LAST,
	CAMEL_MAPI_STORE_INFO_LAST
};

struct _CamelMapiStoreInfo {
	CamelStoreInfo info;
	mapi_id_t folder_id;
	mapi_id_t parent_id;
	guint32 camel_folder_flags; /* CamelFolderInfo::flags */
	guint32 mapi_folder_flags; /* bit-or of CamelMapiStoreFolderFlags */
	gchar *foreign_username; /* only if CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN is set */

	/* these are not saved */
	time_t latest_last_modify;
	gint last_obj_total;
};

struct _CamelMapiStoreSummary {
	CamelStoreSummary parent;
	CamelMapiStoreSummaryPrivate *priv;
};

struct _CamelMapiStoreSummaryClass {
	CamelStoreSummaryClass summary_class;
};

GType			camel_mapi_store_summary_get_type	(void);
CamelStoreSummary *	camel_mapi_store_summary_new		(void);
CamelStoreInfo *	camel_mapi_store_summary_add_from_full	(CamelStoreSummary *s,
								 const gchar *path,
								 mapi_id_t folder_id,
								 mapi_id_t parent_id,
								 guint32 camel_folder_flags, /* CamelFolderInfo::flags */
								 guint32 mapi_folder_flags, /* bit-or of CamelMapiStoreFolderFlags */
								 const gchar *foreign_username); /* only if CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN is set */
CamelStoreInfo *	camel_mapi_store_summary_get_folder_id	(CamelStoreSummary *s,
								 mapi_id_t folder_id);

G_END_DECLS

#endif /* CAMEL_MAPI_STORE_SUMMARY_H */
