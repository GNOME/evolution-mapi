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

#ifndef CAMEL_MAPI_FOLDER_H
#define CAMEL_MAPI_FOLDER_H

#include <camel/camel.h>
#include <libmapi/libmapi.h>
#include <e-mapi-connection.h>

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_FOLDER \
	(camel_mapi_folder_get_type ())
#define CAMEL_MAPI_FOLDER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_FOLDER, CamelMapiFolder))
#define CAMEL_MAPI_FOLDER_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_FOLDER, CamelMapiFolderClass))
#define CAMEL_IS_MAPI_FOLDER(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_FOLDER))
#define CAMEL_IS_MAPI_FOLDER_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_FOLDER))
#define CAMEL_MAPI_FOLDER_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_FOLDER, CamelMapiFolderClass))

/**
 * DATA STRUCTURES
 */

G_BEGIN_DECLS

typedef struct _CamelMapiFolder CamelMapiFolder;
typedef struct _CamelMapiFolderClass CamelMapiFolderClass;
typedef struct _CamelMapiFolderPrivate CamelMapiFolderPrivate;

struct _CamelMapiFolder {
	CamelOfflineFolder parent;
	CamelMapiFolderPrivate *priv;

	CamelFolderSearch *search;

	CamelOfflineJournal *journal;
	CamelDataCache *cache;

	/* copied from CamelMapiStoreInfo */
	guint32 mapi_folder_flags;
	guint32 camel_folder_flags;

	guint need_rescan:1;
	guint need_refresh:1;
	guint read_only:1;
};

struct _CamelMapiFolderClass {
	CamelOfflineFolderClass parent_class;
};

typedef struct {
	GSList *items_list;
	GTimeVal last_modification_time;
	CamelFolder *folder;
	CamelFolderChangeInfo *changes;
}fetch_items_data;

GType camel_mapi_folder_get_type (void);

/* implemented */
CamelFolder *
camel_mapi_folder_new(CamelStore *store, const gchar *folder_name, const gchar *folder_dir, guint32 flags, GError **error);

void mapi_update_summary ( CamelFolder *folder, GList *item_list,GError **error);
gboolean mapi_refresh_folder(CamelFolder *folder, GCancellable *cancellable, GError **error);
gboolean camel_mapi_folder_fetch_summary (CamelStore *store, CamelFolder *folder, const mapi_id_t fid, struct mapi_SRestriction *res,
					  struct SSortOrderSet *sort, fetch_items_data *fetch_data, guint32 options, GCancellable *cancellable, GError **mapi_error);

G_END_DECLS

#endif /* CAMEL_MAPI_FOLDER_H */
