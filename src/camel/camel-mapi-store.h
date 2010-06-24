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

#ifndef CAMEL_MAPI_STORE_H
#define CAMEL_MAPI_STORE_H

#include <glib/gi18n-lib.h>

#include <camel/camel.h>

#include <exchange-mapi-connection.h>
#include <exchange-mapi-folder.h>

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_STORE \
	(camel_mapi_store_get_type ())
#define CAMEL_MAPI_STORE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_STORE, CamelMapiStore))
#define CAMEL_MAPI_STORE_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_STORE, CamelMapiStoreClass))
#define CAMEL_IS_MAPI_STORE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_STORE))
#define CAMEL_IS_MAPI_STORE_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_STORE))
#define CAMEL_MAPI_STORE_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_STORE, CamelMapiStoreClass))

/* TODO : Move this to libcamel. Task when merging */
#define CAMEL_FOLDER_FLAGS_LAST (1<<13)

#define CAMEL_MAPI_FOLDER_PUBLIC (CAMEL_FOLDER_FLAGS_LAST << 1)
#define CAMEL_MAPI_FOLDER_PERSONAL (CAMEL_FOLDER_FLAGS_LAST << 2)
#define CAMEL_MAPI_FOLDER_FORIEGN (CAMEL_FOLDER_FLAGS_LAST << 3)
#define CAMEL_MAPI_FOLDER_MAIL (CAMEL_FOLDER_FLAGS_LAST << 4)

#define DISPLAY_NAME_FAVOURITES _("Favorites")
#define DISPLAY_NAME_ALL_PUBLIC_FOLDERS _("All Public Folders")

G_BEGIN_DECLS

/**
 * definition of CamelMAPIStore
 */
typedef struct _CamelMapiStore CamelMapiStore;
typedef struct _CamelMapiStoreClass CamelMapiStoreClass;
typedef struct _CamelMapiStorePrivate CamelMapiStorePrivate;

struct _CamelMapiStore{
	CamelOfflineStore parent_object;

	struct _CamelMapiStoreSummary *summary;
	CamelMapiStorePrivate *priv;
/*	gchar			*base_url; */
/*	CamelURL		*camel_url; */
/*	CamelFolderInfo		*fi; */
/*	GHashTable		*folders; */
/*	GMutex			*folders_lock; */
/*	GMutex			*connect_lock; */
};

struct _CamelMapiStoreClass {
	CamelOfflineStoreClass parent_class;
};

/**
 * PROTOTYPES
 */

GType camel_mapi_store_get_type(void);
gboolean camel_mapi_store_connected(CamelMapiStore *, CamelException *);

const gchar * camel_mapi_store_folder_id_lookup (CamelMapiStore *mapi_store, const gchar *folder_name);
const gchar * camel_mapi_store_folder_lookup (CamelMapiStore *mapi_store, const gchar *folder_id);
const gchar * camel_mapi_store_get_profile_name (CamelMapiStore *mapi_store);
const gchar *camel_mapi_store_system_folder_fid (CamelMapiStore *mapi_store, guint folder_type);
const gchar *camel_mapi_store_folder_id_lookup_offline (CamelMapiStore *mapi_store, const gchar *folder_name);
const gchar * mapi_folders_hash_table_name_lookup (CamelMapiStore *store, const gchar *fid, gboolean use_cache);

void camel_mapi_store_unset_notification_data (CamelMapiStore *mstore);

ExchangeMapiConnection *camel_mapi_store_get_exchange_connection (CamelMapiStore *mapi_store);

G_END_DECLS

#endif /* CAMEL_OPENCHANGE_STORE_H */
