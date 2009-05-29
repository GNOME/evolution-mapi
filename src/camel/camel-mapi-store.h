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

#ifndef __CAMEL_MAPI_STORE_H__
#define __CAMEL_MAPI_STORE_H__

#include <camel/camel-store.h>
#include <camel/camel-offline-store.h>
#include <camel-mapi-store-summary.h>
#include <camel/camel-net-utils.h>
#include <camel/camel-i18n.h>

#include <exchange-mapi-folder.h>

#define CAMEL_MAPI_STORE_TYPE     (camel_mapi_store_get_type ())
#define CAMEL_MAPI_STORE(obj)     (CAMEL_CHECK_CAST((obj), CAMEL_MAPI_STORE_TYPE, CamelMapiStore))
#define CAMEL_MAPI_STORE_CLASS(k) (CAMEL_CHECK_CLASS_CAST ((k), CAMEL_MAPI_STORE_TYPE, CamelMapiStoreClass))
#define CAMEL_IS_MAPI_STORE(o)    (CAMEL_CHECK_TYPE((o), CAMEL_MAPI_STORE_TYPE))

/* TODO : Move this to libcamel. Task when merging */
#define CAMEL_FOLDER_FLAGS_LAST (1<<13)

#define CAMEL_MAPI_FOLDER_PUBLIC (CAMEL_FOLDER_FLAGS_LAST << 1)
#define CAMEL_MAPI_FOLDER_PERSONAL (CAMEL_FOLDER_FLAGS_LAST << 2)
#define CAMEL_MAPI_FOLDER_FORIEGN (CAMEL_FOLDER_FLAGS_LAST << 3)

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
/* 	char			*base_url; */
/* 	CamelURL		*camel_url; */
/* 	CamelFolderInfo		*fi; */
/* 	GHashTable		*folders; */
/* 	GMutex			*folders_lock; */
/* 	GMutex			*connect_lock; */
};




struct _CamelMapiStoreClass {
	CamelOfflineStoreClass		parent_class;
};


/**
 * PROTOTYPES
 */

#ifndef __BEGIN_DECLS
#ifdef __cplusplus
#define __BEGIN_DECLS		extern "C" {
#define __END_DECLS		}
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

__BEGIN_DECLS
/* Standard Camel function */
CamelType camel_mapi_store_get_type(void);
gboolean camel_mapi_store_connected(CamelMapiStore *, CamelException *);

const gchar* camel_mapi_store_folder_id_lookup (CamelMapiStore *mapi_store, const char *folder_name);
const gchar* camel_mapi_store_folder_lookup (CamelMapiStore *mapi_store, const char *folder_id);
const gchar* camel_mapi_store_get_profile_name (CamelMapiStore *mapi_store);
const gchar *camel_mapi_store_system_folder_fid (CamelMapiStore *mapi_store, guint folder_type);
const gchar *camel_mapi_store_folder_id_lookup_offline (CamelMapiStore *mapi_store, const char *folder_name);

__END_DECLS

#endif /* __CAMEL_OPENCHANGE_STORE_H__ */
