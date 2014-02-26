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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>

#include <libmapi/libmapi.h>
#include <libemail-engine/libemail-engine.h>

#include <glib/gi18n-lib.h>
#include <glib/gstdio.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-sasl-krb.h"
#include "camel-mapi-settings.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-folder-summary.h"

#include <e-mapi-utils.h>
#include <e-mapi-folder.h>

#define d(x)

struct _CamelMapiStorePrivate {
	EMapiConnection *connection;
	GRecMutex connection_lock;

	GHashTable *id_hash; /*get names from ids*/
	GHashTable *name_hash;/*get ids from names*/
	GHashTable *container_hash;
	GHashTable *parent_hash;
	GHashTable *default_folders; /*Default Type : Folder ID*/

	gboolean folders_synced; /* whether were synced folder list already */

	GRecMutex updates_lock;
	GCancellable *updates_cancellable; /* cancelled on dispose or disconnect */
	GSList *update_folder_names; /* gchar *foldername */
	guint update_folder_id;
	guint update_folder_list_id;
};

/* Forward Declarations */
static void camel_subscribable_init (CamelSubscribableInterface *iface);

G_DEFINE_TYPE_WITH_CODE (
	CamelMapiStore,
	camel_mapi_store,
	CAMEL_TYPE_OFFLINE_STORE,
	G_IMPLEMENT_INTERFACE (
		CAMEL_TYPE_SUBSCRIBABLE,
		camel_subscribable_init))

/* service methods */
static void mapi_store_constructed (GObject *object);
static gchar	*mapi_get_name(CamelService *, gboolean );
static gboolean	mapi_connect_sync(CamelService *, GCancellable *cancellable, GError **);
static gboolean	mapi_disconnect_sync(CamelService *, gboolean , GCancellable *cancellable, GError **);
static CamelAuthenticationResult mapi_authenticate_sync (CamelService *, const gchar *mechanism, GCancellable *, GError **);
static GList	*mapi_query_auth_types_sync(CamelService *, GCancellable *cancellable, GError **);
static void camel_mapi_store_server_notification_cb (EMapiConnection *conn, guint event_mask, gpointer event_data, gpointer user_data);

/* store methods */
static CamelFolderInfo * mapi_build_folder_info(CamelMapiStore *mapi_store, const gchar *parent_name, const gchar *folder_name);
static gboolean mapi_fid_is_system_folder (CamelMapiStore *mapi_store, const gchar *fid);
static void mapi_update_hash_table_type (CamelMapiStore *store, const gchar *full_name, guint *folder_type);

static void mapi_update_folder_hash_tables (CamelMapiStore *store, const gchar *name, const gchar *fid, const gchar *parent_id);
guint mapi_folders_hash_table_type_lookup (CamelMapiStore *store, const gchar *name);
/* static const gchar * mapi_folders_hash_table_name_lookup (CamelMapiStore *store, const gchar *fid, gboolean use_cache); */
#if 0
static const gchar * mapi_folders_hash_table_fid_lookup (CamelMapiStore *store, const gchar *name, gboolean use_cache);
#endif

static CamelFolderInfo *
		mapi_store_create_folder_sync	(CamelStore *store,
						 const gchar *parent_name,
						 const gchar *folder_name,
						 GCancellable *cancellable,
						 GError **error);

static gboolean
cms_open_folder (CamelMapiStore *mapi_store,
		 EMapiConnection *conn,
		 mapi_id_t fid,
		 mapi_object_t *obj_folder,
		 GCancellable *cancellable,
		 GError **perror)
{
	CamelStoreInfo *si;
	CamelMapiStoreInfo *msi;
	GError *mapi_error = NULL;
	gboolean res;

	g_return_val_if_fail (mapi_store != NULL, FALSE);
	g_return_val_if_fail (mapi_store->summary != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (fid != 0, FALSE);
	g_return_val_if_fail (obj_folder != NULL, FALSE);

	si = camel_mapi_store_summary_get_folder_id (mapi_store->summary, fid);
	if (!si) {
		g_propagate_error (perror, g_error_new_literal (CAMEL_ERROR, CAMEL_ERROR_GENERIC, _("Cannot find folder in a local cache")));
		return FALSE;
	}

	msi = (CamelMapiStoreInfo *) si;

	if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0)
		res = e_mapi_connection_open_foreign_folder (conn, msi->foreign_username, fid, obj_folder, cancellable, &mapi_error);
	else if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0)
		res = e_mapi_connection_open_public_folder (conn, fid, obj_folder, cancellable, &mapi_error);
	else
		res = e_mapi_connection_open_personal_folder (conn, fid, obj_folder, cancellable, &mapi_error);

	if (mapi_error) {
		camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
		g_propagate_error (perror, mapi_error);
	}

	return res;
}

static gboolean
cms_peek_folder_store (CamelMapiStore *mapi_store,
		       EMapiConnection *conn,
		       mapi_id_t fid,
		       mapi_object_t **obj_store,
		       GCancellable *cancellable,
		       GError **perror)
{
	CamelStoreInfo *si;
	CamelMapiStoreInfo *msi;
	GError *mapi_error = NULL;
	gboolean res;

	g_return_val_if_fail (mapi_store != NULL, FALSE);
	g_return_val_if_fail (mapi_store->summary != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (fid != 0, FALSE);
	g_return_val_if_fail (obj_store != NULL, FALSE);

	si = camel_mapi_store_summary_get_folder_id (mapi_store->summary, fid);
	if (!si) {
		g_propagate_error (perror, g_error_new_literal (CAMEL_ERROR, CAMEL_ERROR_GENERIC, _("Cannot find folder in a local cache")));
		return FALSE;
	}

	msi = (CamelMapiStoreInfo *) si;

	if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0)
		res = e_mapi_connection_peek_store (conn, FALSE, msi->foreign_username, obj_store, cancellable, &mapi_error);
	else if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0)
		res = e_mapi_connection_peek_store (conn, TRUE, NULL, obj_store, cancellable, &mapi_error);
	else
		res = e_mapi_connection_peek_store (conn, FALSE, NULL, obj_store, cancellable, &mapi_error);

	if (mapi_error) {
		camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
		g_propagate_error (perror, mapi_error);
	}

	return res;
}

static gboolean
check_for_connection (CamelService *service, GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (service);
	gboolean connected;

	if (!mapi_store)
		return FALSE;

	g_rec_mutex_lock (&mapi_store->priv->connection_lock);
	connected = mapi_store->priv->connection && e_mapi_connection_connected (mapi_store->priv->connection);
	g_rec_mutex_unlock (&mapi_store->priv->connection_lock);

	return connected;
}

/* escapes backslashes with \5C and forward slashes with \2F */
static gchar *
escape_slash (const gchar *str)
{
	gint ii, jj, count = 0;
	gchar *res;

	if (!str)
		return NULL;

	for (ii = 0; str[ii]; ii++) {
		if (str[ii] == '\\' || str[ii] == '/')
			count++;
	}

	if (!count)
		return g_strdup (str);

	res = g_malloc0 (sizeof (gchar) * (1 + ii + (2 * count)));
	for (ii = 0, jj = 0; str[ii]; ii++, jj++) {
		if (str[ii] == '\\') {
			res[jj] = '\\';
			res[jj + 1] = '5';
			res[jj + 2] = 'C';
			jj += 2;
		} else if (str[ii] == '/') {
			res[jj] = '\\';
			res[jj + 1] = '2';
			res[jj + 2] = 'F';
			jj += 2;
		} else {
			res[jj] = str[ii];
		}
	}

	res[jj] = '\0';

	return res;
}

/* reverses escape_slash processing */
static gchar *
unescape_slash (const gchar *str)
{
	gchar *res = g_strdup (str);
	gint ii, jj;

	for (ii = 0, jj = 0; res[ii]; ii++, jj++) {
		if (res[ii] == '\\' && g_ascii_isxdigit (res[ii + 1]) && g_ascii_isxdigit (res[ii + 2])) {
			res[jj] = ((g_ascii_xdigit_value (res[ii + 1]) & 0xF) << 4) | (g_ascii_xdigit_value (res[ii + 2]) & 0xF);
			ii += 2;
		} else if (ii != jj) {
			res[jj] = res[ii];
		}
	}

	res[jj] = '\0';

	return res;
}

static CamelFolder *
mapi_get_folder_with_type (CamelStore *store, guint folder_type, GCancellable *cancellable, GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelFolderInfo *all_fi, *fi;
	CamelFolder *folder = NULL;

	g_return_val_if_fail (mapi_store != NULL, NULL);
	g_return_val_if_fail (mapi_store->priv != NULL, NULL);

	all_fi = camel_store_get_folder_info_sync (
		store, NULL, CAMEL_STORE_FOLDER_INFO_RECURSIVE,
		cancellable, error);
	if (all_fi == NULL)
		return NULL;

	fi = all_fi;
	while (fi) {
		CamelFolderInfo *next;

		if ((fi->flags & CAMEL_FOLDER_TYPE_MASK) == folder_type) {
			folder = camel_store_get_folder_sync (
				store, fi->full_name, 0, cancellable, error);
			break;
		}

		/* move to the next, depth-first search */
		next = fi->child;
		if (!next)
			next = fi->next;
		if (!next) {
			next = fi->parent;
			while (next) {
				CamelFolderInfo *sibl = next->next;
				if (sibl) {
					next = sibl;
					break;
				} else {
					next = next->parent;
				}
			}
		}

		fi = next;
	}

	camel_folder_info_free (all_fi);

	return folder;
}

static CamelFolderInfo *
mapi_convert_to_folder_info (CamelMapiStore *store,
                             EMapiFolder *folder,
                             GError **error)
{
	gchar *name;
	gchar *parent, *id = NULL;
	mapi_id_t mapi_id_folder;

	const gchar *par_name = NULL;
	CamelFolderInfo *fi;

	name = escape_slash (e_mapi_folder_get_name (folder));

	id = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", e_mapi_folder_get_id (folder));

	fi = camel_folder_info_new ();

	if (folder->is_default) {
		switch (folder->default_type) {
		case olFolderTopInformationStore:
			fi->flags |= CAMEL_FOLDER_NOSELECT;
			break;
		case olFolderInbox:
			fi->flags |= CAMEL_FOLDER_TYPE_INBOX;
			break;
		case olFolderSentMail:
			fi->flags |= CAMEL_FOLDER_TYPE_SENT;
			break;
		case olFolderDeletedItems:
			fi->flags |= CAMEL_FOLDER_TYPE_TRASH;
			break;
		case olFolderOutbox:
			fi->flags |= CAMEL_FOLDER_TYPE_OUTBOX;
			break;
		case olFolderJunk:
			fi->flags |= CAMEL_FOLDER_TYPE_JUNK;
			break;
		}

		fi->flags |= CAMEL_FOLDER_SYSTEM;
	} else {
		switch (e_mapi_folder_get_type (folder)) {
		case E_MAPI_FOLDER_TYPE_CONTACT:
			fi->flags |= CAMEL_FOLDER_TYPE_CONTACTS;
			break;
		case E_MAPI_FOLDER_TYPE_APPOINTMENT:
			fi->flags |= CAMEL_FOLDER_TYPE_EVENTS;
			break;
		case E_MAPI_FOLDER_TYPE_MEMO:
			fi->flags |= CAMEL_FOLDER_TYPE_MEMOS;
			break;
		case E_MAPI_FOLDER_TYPE_TASK:
			fi->flags |= CAMEL_FOLDER_TYPE_TASKS;
			break;
		default:
			break;
		}
	}

	if (folder->child_count <= 0)
		fi->flags |= CAMEL_FOLDER_NOCHILDREN;
	/*
	   parent_hash contains the "parent id <-> folder id" combination. So we form
	   the path for the full name in camelfolder info by looking up the hash table until
	   NULL is found
	 */

	mapi_id_folder = e_mapi_folder_get_parent_id (folder);
	parent = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", mapi_id_folder);

	fi->display_name = name;

	par_name = mapi_folders_hash_table_name_lookup (store, parent, TRUE);
	if (par_name != NULL) {
		gchar *str = g_strconcat (par_name, "/", name, NULL);

		fi->full_name = str; /* takes ownership of the string */
	} else {
		fi->full_name = g_strdup (name);
	}

	/*name_hash returns the container id given the name */
	mapi_update_folder_hash_tables (store, fi->full_name, id, parent);

	g_free (parent);
	g_free (id);

	fi->total = folder->total;
	fi->unread = folder->unread_count;

	return fi;
}

static void
remove_path_from_store_summary (const gchar *path, gpointer value, CamelMapiStore *mstore)
{
	const gchar *folder_id;
	CamelStoreInfo *si;

	g_return_if_fail (path != NULL);
	g_return_if_fail (mstore != NULL);

	folder_id = g_hash_table_lookup (mstore->priv->name_hash, path);
	if (folder_id) {
		/* name_hash as the second, because folder_id is from there */
		g_hash_table_remove (mstore->priv->id_hash, folder_id);
		g_hash_table_remove (mstore->priv->name_hash, path);
	}

	si = camel_store_summary_path (mstore->summary, path);
	if (si) {
		CamelFolderInfo *fi;

		fi = camel_folder_info_new ();
		fi->unread = -1;
		fi->total = -1;
		fi->display_name = g_strdup (camel_store_info_name (mstore->summary, si));
		fi->full_name = g_strdup (camel_store_info_path (mstore->summary, si));
		if (!fi->display_name && fi->full_name) {
			fi->display_name = strrchr (fi->full_name, '/');
			if (fi->display_name)
				fi->display_name = g_strdup (fi->display_name + 1);
		}

		camel_subscribable_folder_unsubscribed (CAMEL_SUBSCRIBABLE (mstore), fi);
		camel_store_folder_deleted (CAMEL_STORE (mstore), fi);
		camel_folder_info_free (fi);

		camel_store_summary_info_unref (mstore->summary, si);
	}

	camel_store_summary_remove_path (mstore->summary, path);
}

static gboolean
camel_mapi_update_operation_progress_cb (EMapiConnection *conn,
					 guint32 item_index,
					 guint32 items_total,
					 gpointer user_data,
					 GCancellable *cancellable,
					 GError **perror)
{
	if (items_total > 0)
		camel_operation_progress (cancellable, 100 * item_index / items_total);

	return TRUE;
}

static gboolean
mapi_folders_sync (CamelMapiStore *store, guint32 flags, GCancellable *cancellable, GError **error)
{
	CamelMapiStorePrivate  *priv = store->priv;
	gboolean status;
	GSList *folder_list = NULL, *temp_list = NULL, *list = NULL;
	gboolean subscription_list = FALSE;
	CamelFolderInfo *info = NULL;
	CamelMapiStoreInfo *msi = NULL;
	GHashTable *old_cache_folders;
	GError *err = NULL;
	EMapiConnection *conn;
	GPtrArray *array;
	gint ii;

	if (!camel_mapi_store_connected (store, cancellable, NULL)) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Folder list is not available in offline mode"));
		return FALSE;
	}

	conn = camel_mapi_store_ref_connection (store, cancellable, error);
	if (!conn)
		return FALSE;

	status = e_mapi_connection_get_folders_list (conn, &folder_list, camel_mapi_update_operation_progress_cb, NULL, cancellable, &err);
	if (!status) {
		camel_mapi_store_maybe_disconnect (store, err);

		g_warning ("Could not get folder list (%s)\n", err ? err->message : "Unknown error");
		g_clear_error (&err);
		g_object_unref (conn);
		return TRUE;
	}

	/* remember all folders in cache before update */
	old_cache_folders = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	array = camel_store_summary_array (store->summary);
	for (ii = 0; ii < array->len; ii++) {
		msi = g_ptr_array_index (array, ii);

		/* those whose left in old_cache_folders are removed at the end,
		   which is not good for public and foreign folders, thus preserve
		   them from an automatic removal */
		if (((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) == 0 &&
		    (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) == 0) ||
		    ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL) != 0 &&
		    (msi->mapi_folder_flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) == 0))
			g_hash_table_insert (old_cache_folders, g_strdup (camel_store_info_path (store->summary, (CamelStoreInfo *) msi)), GINT_TO_POINTER (1));
	}
	camel_store_summary_array_free (store->summary, array);

	subscription_list = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST);
	if (subscription_list) {
		GError *err = NULL;

		/*Consult the name <-> fid hash table for a FID.*/
		status = e_mapi_connection_get_pf_folders_list (conn, &folder_list, camel_mapi_update_operation_progress_cb, NULL, cancellable, &err);
		if (!status)
			g_warning ("Could not get Public folder list (%s)\n", err ? err->message : "Unknown error");

		camel_mapi_store_maybe_disconnect (store, err);
		g_clear_error (&err);
	}

	temp_list = folder_list;
	list = folder_list;

	/*populate the hash table for finding the mapping from container id <-> folder name*/
	for (;temp_list != NULL; temp_list = g_slist_next (temp_list) ) {
		const gchar *full_name = NULL;
		gchar *fid = NULL, *parent_id = NULL, *tmp = NULL;
		guint *folder_type = g_new0 (guint, 1);

		fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", e_mapi_folder_get_id ((EMapiFolder *)(temp_list->data)));
		parent_id = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", e_mapi_folder_get_parent_id ((EMapiFolder *)(temp_list->data)));
		full_name = g_hash_table_lookup (priv->id_hash, fid);
		if (!full_name) {
			const gchar *par_full_name;

			par_full_name = g_hash_table_lookup (priv->id_hash, parent_id);
			if (par_full_name) {
				gchar *escaped = escape_slash (e_mapi_folder_get_name (temp_list->data));
				tmp = g_strconcat (par_full_name, "/", escaped, NULL);
				full_name = tmp;
				g_free (escaped);
			} else {
				tmp = escape_slash (e_mapi_folder_get_name (temp_list->data));
				full_name = tmp;
			}
		} else {
			/* known full_name - everything is escaped already */
			tmp = g_strdup (full_name);
			full_name = tmp;
		}

		/* remove from here; what lefts is not on the server any more */
		g_hash_table_remove (old_cache_folders, full_name);
		*folder_type = ((EMapiFolder *)(temp_list->data))->container_class;
		mapi_update_folder_hash_tables (store, full_name, fid, parent_id);
		mapi_update_hash_table_type (store, full_name, folder_type);
		if (((EMapiFolder *)(temp_list->data))->is_default) {
			guint *type = g_new0 (guint, 1);
			*type = ((EMapiFolder *)(temp_list->data))->default_type;
			g_hash_table_insert (priv->default_folders, type,
					     g_strdup(fid));
		}
		g_free (fid);
		g_free (parent_id);
		g_free (tmp);
	}

	for (;folder_list != NULL; folder_list = g_slist_next (folder_list)) {
		EMapiFolder *folder = (EMapiFolder *) folder_list->data;

		if (folder->default_type == olPublicFoldersAllPublicFolders)
			continue;

		if (folder->container_class == E_MAPI_FOLDER_TYPE_MAIL) {
			info = mapi_convert_to_folder_info (store, folder, NULL);
			msi = (CamelMapiStoreInfo *) camel_store_summary_path (store->summary, info->full_name);

			if (!msi) {
				msi = (CamelMapiStoreInfo *) camel_mapi_store_summary_add_from_full (store->summary,
						info->full_name,
						e_mapi_folder_get_id (folder),
						e_mapi_folder_get_parent_id (folder),
						info->flags,
						folder->category == E_MAPI_FOLDER_CATEGORY_PERSONAL ? CAMEL_MAPI_STORE_FOLDER_FLAG_PERSONAL :
						(CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC | CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL),
						NULL);
				if (msi == NULL)
					continue;

				camel_store_summary_info_ref (store->summary, (CamelStoreInfo *) msi);

				if (!subscription_list) {
					camel_store_folder_created (CAMEL_STORE (store), info);
					camel_subscribable_folder_subscribed (CAMEL_SUBSCRIBABLE (store), info);
				}
			}

			msi->info.flags = info->flags;
			msi->info.total = info->total;
			msi->info.unread = info->unread;
			msi->mapi_folder_flags |= CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL;

			camel_store_summary_info_unref (store->summary, (CamelStoreInfo *) msi);
			camel_folder_info_free (info);
		} else if (folder->category == E_MAPI_FOLDER_CATEGORY_PUBLIC) {
			info = mapi_convert_to_folder_info (store, folder, NULL);
			msi = (CamelMapiStoreInfo *) camel_store_summary_path (store->summary, info->full_name);

			if (!msi) {
				msi = (CamelMapiStoreInfo *) camel_mapi_store_summary_add_from_full (store->summary,
						info->full_name,
						e_mapi_folder_get_id (folder),
						e_mapi_folder_get_parent_id (folder),
						info->flags,
						CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC | CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL,
						NULL);

				if (msi)
					camel_store_summary_info_ref (store->summary, (CamelStoreInfo *) msi);
			}

			if (msi == NULL)
				continue;

			msi->info.flags = info->flags;

			camel_store_summary_info_unref (store->summary, (CamelStoreInfo *) msi);
			camel_folder_info_free (info);
		}
	}

	/* Weed out deleted folders */
	g_hash_table_foreach (old_cache_folders, (GHFunc) remove_path_from_store_summary, store);
	g_hash_table_destroy (old_cache_folders);

	camel_store_summary_touch (store->summary);
	camel_store_summary_save (store->summary);

	g_slist_foreach (list, (GFunc) e_mapi_folder_free, NULL);
	g_slist_free (list);

	priv->folders_synced = TRUE;
	g_object_unref (conn);

	return TRUE;
}

static gchar *
mapi_concat (const gchar *prefix, const gchar *suffix)
{
	gsize len;

	len = strlen (prefix);
	if (len == 0 || prefix[len - 1] == '/')
		return g_strdup_printf ("%s%s", prefix, suffix);
	else
		return g_strdup_printf ("%s%c%s", prefix, '/', suffix);
}

static gint
match_path (const gchar *path, const gchar *name)
{
	gchar p, n;

	p = *path++;
	n = *name++;
	while (n && p) {
		if (n == p) {
			p = *path++;
			n = *name++;
		} else if (p == '%') {
			if (n != '/') {
				n = *name++;
			} else {
				p = *path++;
			}
		} else if (p == '*') {
			return TRUE;
		} else
			return FALSE;
	}

	return n == 0 && (p == '%' || p == 0);
}

static void
unescape_folder_names (CamelFolderInfo *fi)
{
	while (fi) {
		if (fi->display_name && strchr (fi->display_name, '\\')) {
			gchar *unescaped;

			unescaped = unescape_slash (fi->display_name);
			g_free (fi->display_name);
			fi->display_name = unescaped;
		}

		if (fi->child)
			unescape_folder_names (fi->child);

		fi = fi->next;
	}
}

static CamelFolderInfo *
mapi_get_folder_info_offline (CamelStore *store,
			      const gchar *top,
			      guint32 flags,
			      GCancellable *cancellable,
			      GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	CamelFolderInfo *fi;
	ESourceRegistry *registry = NULL;
	GList *my_sources = NULL;
	GPtrArray *folders;
	GPtrArray *array;
	gchar *path;
	gboolean subscribed, subscription_list = FALSE;
	gboolean has_public_folders = FALSE, has_foreign_folders = FALSE;
	gchar *profile;
	guint ii;

	subscription_list = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST);
	subscribed = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIBED);

	settings = camel_service_ref_settings (CAMEL_SERVICE (store));

	mapi_settings = CAMEL_MAPI_SETTINGS (settings);
	profile = camel_mapi_settings_dup_profile (mapi_settings);

	g_object_unref (settings);

	folders = g_ptr_array_new ();

	if (subscription_list) {
		GError *local_error = NULL;

		registry = e_source_registry_new_sync (cancellable, &local_error);
		if (registry) {
			GList *all_sources = e_source_registry_list_sources (registry, NULL);

			my_sources = e_mapi_utils_filter_sources_for_profile (all_sources, profile);

			g_list_free_full (all_sources, g_object_unref);
		}
	}

	if (!top || !*top)
		top = "";

	path = mapi_concat (top, "*");

	array = camel_store_summary_array (mapi_store->summary);

	for (ii = 0; ii < array->len; ii++) {
		CamelStoreInfo *si;
		CamelMapiStoreInfo *msi;

		si = g_ptr_array_index (array, ii);
		msi = (CamelMapiStoreInfo *) si;

		/* Allow only All Public Folders hierarchy;
		   Subscribed public folders are those in Favorites/... - skip them too */
		if (subscription_list &&
		    ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) == 0 ||
		    (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL) == 0 ||
		    (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0)) {
			continue;
		}

		/* Allow Mailbox and Favourites (Subscribed public folders) */
		if (subscribed &&
		    (((si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) == 0 &&
		     (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PERSONAL) == 0) ||
		    (!subscription_list && (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL) != 0))) {
			continue;
		}

		if (!subscription_list &&
		    (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL) == 0 &&
		    (si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) != 0 &&
		    ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ||
		     (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0)) {
			continue;
		}

		if (strcmp (top, camel_store_info_path (mapi_store->summary, si)) == 0
		     || match_path (path, camel_store_info_path (mapi_store->summary, si))) {
			const gchar *store_info_path = camel_store_info_path (mapi_store->summary, si);

			has_public_folders = has_public_folders || (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0;
			has_foreign_folders = has_foreign_folders || (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0;

			fi = mapi_build_folder_info (mapi_store, NULL, store_info_path);
			fi->unread = si->unread;
			fi->total = si->total;
			fi->flags = si->flags;

			if (subscription_list) {
				guint folder_type;
				CamelStoreInfo *si2;

				si2 = camel_mapi_store_summary_get_folder_id (mapi_store->summary, msi->folder_id);
				if (si2) {
					if (si != si2)
						fi->flags = si2->flags;

					camel_store_summary_info_unref (mapi_store->summary, si2);
				}

				folder_type = mapi_folders_hash_table_type_lookup (mapi_store, camel_store_info_path (mapi_store->summary, si));
				if (folder_type != E_MAPI_FOLDER_TYPE_UNKNOWN && folder_type != E_MAPI_FOLDER_TYPE_MAIL) {
					if (e_mapi_folder_is_subscribed_as_esource (my_sources, profile, msi->folder_id))
						fi->flags |= CAMEL_FOLDER_SUBSCRIBED;
				}
			}

			g_ptr_array_add (folders, fi);
		}
	}

	camel_store_summary_array_free (mapi_store->summary, array);

	if (!subscription_list && !*top) {
		if (has_public_folders) {
			fi = mapi_build_folder_info (mapi_store, NULL, DISPLAY_NAME_FAVORITES);
			fi->flags |= CAMEL_FOLDER_NOSELECT | CAMEL_FOLDER_SYSTEM;

			g_ptr_array_add (folders, fi);
		}

		if (has_foreign_folders) {
			fi = mapi_build_folder_info (mapi_store, NULL, DISPLAY_NAME_FOREIGN_FOLDERS);
			fi->flags |= CAMEL_FOLDER_NOSELECT | CAMEL_FOLDER_SYSTEM;

			g_ptr_array_add (folders, fi);
		}
	}

	g_free (path);
	/* this adds also fake folders, if missing */
	fi = camel_folder_info_build (folders, top, '/', TRUE);
	g_ptr_array_free (folders, TRUE);

	unescape_folder_names (fi);

	if (!fi && error && !*error)
		g_set_error_literal (error, CAMEL_STORE_ERROR, CAMEL_STORE_ERROR_NO_FOLDER,
			(flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST) != 0 ?
			_("No public folder found") : _("No folder found"));

	g_list_free_full (my_sources, g_object_unref);
	if (registry)
		g_object_unref (registry);

	g_free (profile);

	return fi;
}

static gboolean
mapi_forget_folder (CamelMapiStore *mapi_store, const gchar *folder_name, GError **error)
{
	CamelService *service;
	const gchar *user_cache_dir;
	gchar *state_file;
	gchar *folder_dir, *storage_path;
	CamelFolderInfo *fi;

	service = CAMEL_SERVICE (mapi_store);
	user_cache_dir = camel_service_get_user_cache_dir (service);

	storage_path = g_build_filename (user_cache_dir, "folders", NULL);

	folder_dir = g_build_filename (storage_path, folder_name, NULL);
	g_free (storage_path);

	if (g_access(folder_dir, F_OK) != 0) {
		g_free(folder_dir);
		return TRUE;
	}

	state_file = g_build_filename (folder_dir, "cmeta", NULL);
	g_unlink (state_file);
	g_free (state_file);

	g_rmdir (folder_dir);
	g_free (folder_dir);

	camel_store_summary_remove_path (mapi_store->summary, folder_name);
	camel_store_summary_save (mapi_store->summary);

	fi = mapi_build_folder_info (mapi_store, NULL, folder_name);
	camel_store_folder_deleted (CAMEL_STORE (mapi_store), fi);
	camel_folder_info_free (fi);

	return TRUE;
}

static void
mapi_rename_folder_infos (CamelMapiStore *mapi_store, const gchar *old_name, const gchar *new_name)
{
	gint olen;
	CamelStoreInfo *si = NULL;
	GPtrArray *array;
	guint ii;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (old_name != NULL);
	g_return_if_fail (new_name != NULL);

	olen = strlen (old_name);

	array = camel_store_summary_array (mapi_store->summary);

	for (ii = 0; ii < array->len; ii++) {
		const gchar *full_name;

		si = g_ptr_array_index (array, ii);

		full_name = camel_store_info_path (mapi_store->summary, si);
		if (full_name && g_str_has_prefix (full_name, old_name) && !g_str_equal (full_name, old_name) &&
		    full_name [olen] == '/' && full_name [olen + 1] != '\0') {
			/* it's a subfolder of old_name */
			mapi_id_t fid = ((CamelMapiStoreInfo *)si)->folder_id;

			if (fid) {
				gchar *new_full_name;
				gchar *fid_str = e_mapi_util_mapi_id_to_string (fid);

				/* do not remove it from name_hash yet, because this function
				   will be called for it again */
				/* g_hash_table_remove (mapi_store->priv->name_hash, full_name); */
				g_hash_table_remove (mapi_store->priv->id_hash, fid_str);

				/* parent is still the same, only the path changed */
				new_full_name = g_strconcat (new_name, full_name + olen + (g_str_has_suffix (new_name, "/") ? 1 : 0), NULL);

				mapi_update_folder_hash_tables (mapi_store, new_full_name, fid_str, NULL);

				camel_store_info_set_string (mapi_store->summary, si, CAMEL_STORE_INFO_PATH, new_full_name);
				camel_store_summary_touch (mapi_store->summary);

				g_free (new_full_name);
				g_free (fid_str);
			}
		}
	}

	camel_store_summary_array_free (mapi_store->summary, array);
}

static void
stop_pending_updates (CamelMapiStore *mapi_store)
{
	CamelMapiStorePrivate *priv;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (mapi_store->priv != NULL);

	priv = mapi_store->priv;

	g_rec_mutex_lock (&priv->updates_lock);
	if (priv->updates_cancellable) {
		g_cancellable_cancel (priv->updates_cancellable);
		g_object_unref (priv->updates_cancellable);
		priv->updates_cancellable = NULL;
	}

	if (priv->update_folder_names) {
		g_slist_free_full (priv->update_folder_names, g_free);
		priv->update_folder_names = NULL;
	}

	if (priv->update_folder_id) {
		g_source_remove (priv->update_folder_id);
		priv->update_folder_id = 0;
	}

	if (priv->update_folder_list_id) {
		g_source_remove (priv->update_folder_list_id);
		priv->update_folder_list_id = 0;
	}

	g_rec_mutex_unlock (&priv->updates_lock);
}

static void
mapi_store_dispose (GObject *object)
{
	CamelMapiStore *mapi_store;
	CamelMapiStorePrivate *priv;

	mapi_store = CAMEL_MAPI_STORE (object);
	priv = mapi_store->priv;

	stop_pending_updates (CAMEL_MAPI_STORE (object));

	if (mapi_store->summary) {
		camel_store_summary_save (mapi_store->summary);
		g_object_unref (mapi_store->summary);
		mapi_store->summary = NULL;
	}

	g_rec_mutex_lock (&mapi_store->priv->connection_lock);
	if (priv->connection != NULL) {
		g_signal_handlers_disconnect_by_func (priv->connection, camel_mapi_store_server_notification_cb, object);

		g_object_unref (priv->connection);
		priv->connection = NULL;
	}
	g_rec_mutex_unlock (&mapi_store->priv->connection_lock);

	/* Chain up to parent's dispose() method. */
	G_OBJECT_CLASS (camel_mapi_store_parent_class)->dispose (object);
}

static void
mapi_store_finalize (GObject *object)
{
	CamelMapiStorePrivate *priv;

	priv = CAMEL_MAPI_STORE (object)->priv;

	if (priv->id_hash != NULL)
		g_hash_table_destroy (priv->id_hash);

	if (priv->name_hash != NULL)
		g_hash_table_destroy (priv->name_hash);

	if (priv->parent_hash != NULL)
		g_hash_table_destroy (priv->parent_hash);

	if (priv->default_folders != NULL)
		g_hash_table_destroy (priv->default_folders);
	if (priv->container_hash != NULL)
		g_hash_table_destroy (priv->container_hash);

	g_rec_mutex_clear (&priv->connection_lock);
	g_rec_mutex_clear (&priv->updates_lock);

	/* Chain up to parent's finalize() method. */
	G_OBJECT_CLASS (camel_mapi_store_parent_class)->finalize (object);
}

static gboolean
mapi_store_can_refresh_folder (CamelStore *store,
                               CamelFolderInfo *info,
                               GError **error)
{
	CamelService *service;
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	gboolean check_all;

	/* skip unselectable folders from automatic refresh */
	if (info && (info->flags & CAMEL_FOLDER_NOSELECT) != 0)
		return FALSE;

	service = CAMEL_SERVICE (store);

	settings = camel_service_ref_settings (service);

	mapi_settings = CAMEL_MAPI_SETTINGS (settings);
	check_all = camel_mapi_settings_get_check_all (mapi_settings);

	g_object_unref (settings);

	if (check_all)
		return TRUE;

	return CAMEL_STORE_CLASS(camel_mapi_store_parent_class)->can_refresh_folder (store, info, error);
}

static gchar *
mapi_build_folder_dir (const gchar *user_cache_dir,
		       const gchar *folder_name)
{
	GString *path;
	gchar **elems;
	gint ii;

	g_return_val_if_fail (user_cache_dir != NULL, NULL);
	g_return_val_if_fail (*user_cache_dir != 0, NULL);
	g_return_val_if_fail (folder_name != NULL, NULL);

	elems = g_strsplit (folder_name, "/", -1);
	g_return_val_if_fail (elems != NULL, NULL);

	path = g_string_new (user_cache_dir);
	if (path->str[path->len - 1] != G_DIR_SEPARATOR)
		g_string_append_c (path, G_DIR_SEPARATOR);
	g_string_append (path, "folders");

	for (ii = 0; elems[ii]; ii++) {
		if (path->str[path->len - 1] != G_DIR_SEPARATOR)
			g_string_append_c (path, G_DIR_SEPARATOR);

		if (ii != 0) {
			g_string_append (path, "sub");
			g_string_append_c (path, G_DIR_SEPARATOR);
		}

		if (elems[ii + 1])
			g_string_append (path, elems[ii]);
	}

	g_strfreev (elems);

	return g_string_free (path, FALSE);
}

static CamelFolder *
mapi_store_get_folder_sync (CamelStore *store,
                            const gchar *folder_name,
                            guint32 flags,
                            GCancellable *cancellable,
                            GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelService *service;
	CamelStoreInfo *si;
	CamelFolder *folder;
	const gchar *user_cache_dir;
	gchar *folder_dir;

	si = camel_store_summary_path (mapi_store->summary, folder_name);
	if (!si && (flags & CAMEL_STORE_FOLDER_CREATE) == CAMEL_STORE_FOLDER_CREATE) {
		gchar *name, *tmp;
		const gchar *parent;
		CamelFolderInfo *folder_info;

		tmp = g_strdup (folder_name);
		if (!(name = strrchr (tmp, '/'))) {
			name = tmp;
			parent = "";
		} else {
			*name++ = '\0';
			parent = tmp;
		}

		folder_info = mapi_store_create_folder_sync (
			store, parent, name, cancellable, error);
		g_free (tmp);

		if (!folder_info)
			return NULL;

		camel_folder_info_free (folder_info);
	}

	if (si)
		camel_store_summary_info_unref (mapi_store->summary, si);

	service = CAMEL_SERVICE (store);
	user_cache_dir = camel_service_get_user_cache_dir (service);

	folder_dir = mapi_build_folder_dir (user_cache_dir, folder_name);
	g_return_val_if_fail (folder_dir != NULL, NULL);

	folder = camel_mapi_folder_new (store, folder_name, folder_dir, flags, error);
	g_free (folder_dir);

	return folder;
}

static CamelFolderInfo*
mapi_store_get_folder_info_sync (CamelStore *store,
                                 const gchar *top,
                                 guint32 flags,
                                 GCancellable *cancellable,
                                 GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelService *service;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store)) &&
	    (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST) != 0) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Folder list is not available in offline mode"));
		return NULL;
	}

	service = CAMEL_SERVICE (store);

	if (camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))) {
		CamelServiceConnectionStatus status;

		status = camel_service_get_connection_status (service);

		/* update folders from the server only when asking for the top most or the 'top' is not known;
		   otherwise believe the local cache, because folders sync is pretty slow operation to be done
		   one every single question on the folder info */
		if ((flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST) != 0 ||
		    (!(flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIBED)) ||
		    (top && *top && !camel_mapi_store_folder_id_lookup (mapi_store, top)) ||
		    camel_store_summary_count (mapi_store->summary) <= 1 ||
		    !mapi_store->priv->folders_synced) {
			if (status == CAMEL_SERVICE_DISCONNECTED) {
				gchar *name = camel_service_get_name (service, TRUE);

				camel_operation_push_message (cancellable, _("Connecting to '%s'"), name);
				camel_service_connect_sync (service, cancellable, NULL);
				camel_operation_pop_message (cancellable);

				g_free (name);
			}

			if (check_for_connection (service, NULL) || status == CAMEL_SERVICE_CONNECTING) {
				gboolean first_check = !mapi_store->priv->folders_synced;

				if (!mapi_folders_sync (mapi_store, flags, cancellable, error))
					return NULL;

				if (first_check) {
					camel_store_summary_touch (mapi_store->summary);
					camel_store_summary_save (mapi_store->summary);
				}
			}
		}
	}

	return mapi_get_folder_info_offline (store, top, flags, cancellable, error);
}

static CamelFolder *
mapi_store_get_junk_folder_sync (CamelStore *store,
                                 GCancellable *cancellable,
                                 GError **error)
{
	return mapi_get_folder_with_type (store, CAMEL_FOLDER_TYPE_JUNK, cancellable, error);
}

static CamelFolder *
mapi_store_get_trash_folder_sync (CamelStore *store,
                                  GCancellable *cancellable,
                                  GError **error)
{
	return mapi_get_folder_with_type (store, CAMEL_FOLDER_TYPE_TRASH, cancellable, error);
}

static CamelFolderInfo *
mapi_store_create_folder_sync (CamelStore *store,
                               const gchar *parent_name,
                               const gchar *folder_name,
                               GCancellable *cancellable,
                               GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate  *priv = mapi_store->priv;
	CamelFolderInfo *root = NULL;
	gchar *parent_id;
	mapi_id_t parent_fid, new_folder_id;
	mapi_object_t obj_folder;
	EMapiConnection *conn;
	GError *mapi_error = NULL;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot create MAPI folders in offline mode"));
		return NULL;
	}

	if (mapi_fid_is_system_folder (mapi_store, camel_mapi_store_folder_id_lookup (mapi_store, folder_name))) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot create new folder '%s'"),
			folder_name);
		return NULL;
	}

	if (!mapi_connect_sync (CAMEL_SERVICE(store), cancellable, NULL)) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_CANT_AUTHENTICATE,
			_("Authentication failed"));
		return NULL;
	}

	if (parent_name && (!*parent_name ||
	    g_str_equal (parent_name, DISPLAY_NAME_FAVORITES) ||
	    g_str_equal (parent_name, DISPLAY_NAME_FOREIGN_FOLDERS))) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("MAPI folders can be created only within mailbox of the logged user"));
		return NULL;
	}

	if (parent_name && *parent_name)
		parent_id = g_strdup (g_hash_table_lookup (priv->name_hash, parent_name));
	else
		parent_id = NULL;

	if (!parent_id) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot find folder '%s'"), parent_name ? parent_name : "");
		return NULL;
	}
	e_mapi_util_mapi_id_from_string (parent_id, &parent_fid);
	new_folder_id = 0;

	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);
	if (!conn)
		return NULL;

	if (!cms_open_folder (mapi_store, conn, parent_fid, &obj_folder, cancellable, error)) {
		g_object_unref (conn);
		return NULL;
	}

	if (!e_mapi_connection_create_folder (conn, &obj_folder, folder_name, IPF_NOTE, &new_folder_id, cancellable, &mapi_error))
		new_folder_id = 0;
	e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

	if (new_folder_id != 0) {
		gchar *folder_id_str;
		CamelMapiStoreInfo *parent_msi;
		gboolean is_public, is_foreign;

		parent_msi = (CamelMapiStoreInfo *) camel_mapi_store_summary_get_folder_id (mapi_store->summary, parent_fid);
		is_public = parent_msi && (parent_msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0;
		is_foreign = parent_msi && (parent_msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0;

		root = mapi_build_folder_info (mapi_store, parent_name, folder_name);
		camel_mapi_store_summary_add_from_full (mapi_store->summary,
			root->full_name,
			new_folder_id,
			parent_fid,
			root->flags | ((is_public || is_foreign) ? CAMEL_FOLDER_SUBSCRIBED | CAMEL_STORE_INFO_FOLDER_SUBSCRIBED : 0),
			(is_public ? CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC :
			is_foreign ? CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN :
			CAMEL_MAPI_STORE_FOLDER_FLAG_PERSONAL) | CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL,
			is_foreign ? parent_msi->foreign_username : NULL);

		if (parent_msi)
			camel_store_summary_info_unref (mapi_store->summary, (CamelStoreInfo *) parent_msi);

		camel_store_summary_save (mapi_store->summary);

		folder_id_str = e_mapi_util_mapi_id_to_string (new_folder_id);
		mapi_update_folder_hash_tables (mapi_store, root->full_name, folder_id_str, parent_id);
		g_free (folder_id_str);

		camel_store_folder_created (store, root);
		camel_subscribable_folder_subscribed (CAMEL_SUBSCRIBABLE (store), root);
	} else {
		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					_("Cannot create folder '%s': %s"), folder_name, mapi_error->message);
			camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
			g_error_free (mapi_error);
		} else {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Cannot create folder '%s'"), folder_name);
		}
	}

	g_object_unref (conn);

	return root;

}

static gboolean
mapi_store_delete_folder_sync (CamelStore *store,
                               const gchar *folder_name,
                               GCancellable *cancellable,
                               GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate  *priv = mapi_store->priv;
	CamelMapiStoreInfo *msi;
	EMapiConnection *conn;
	mapi_object_t *obj_store = NULL;
	const gchar *folder_id;
	mapi_id_t folder_fid;
	gboolean status = FALSE;
	gboolean success = TRUE;
	GError *local_error = NULL;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot delete MAPI folders in offline mode"));
		return FALSE;
	}

	if (!camel_mapi_store_connected ((CamelMapiStore *)store, cancellable, &local_error)) {
		if (local_error != NULL) {
			g_propagate_error (error, local_error);
			return FALSE;
		}

		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot delete MAPI folders in offline mode"));

		return FALSE;
	}

	folder_id = g_hash_table_lookup (priv->name_hash, folder_name);
	if (!folder_id) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot find folder '%s'"), folder_name);
		return FALSE;
	}

	e_mapi_util_mapi_id_from_string (folder_id, &folder_fid);

	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);
	if (!conn)
		return FALSE;

	msi = (CamelMapiStoreInfo *) camel_mapi_store_summary_get_folder_id (mapi_store->summary, folder_fid);
	if (!msi ||
	    (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ||
	    (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0) {
		/* do nore remove foreign or public folders, just unsubscribe from them,
		   even when there are folder delete permissons on the folder
		*/
		status = TRUE;
	} else if (cms_peek_folder_store (mapi_store, conn, folder_fid, &obj_store, cancellable, &local_error))
		status = e_mapi_connection_remove_folder (conn, obj_store, folder_fid, cancellable, &local_error);
	else
		status = FALSE;

	g_object_unref (conn);

	if (status) {
		success = mapi_forget_folder (mapi_store, folder_name, &local_error);

		if (success) {
			/* remove from name_cache at the end, because the folder_id is from there */
			/*g_hash_table_remove (priv->parent_hash, folder_id);*/
			g_hash_table_remove (priv->id_hash, folder_id);
			g_hash_table_remove (priv->name_hash, folder_name);
		}

		if (local_error) {
			camel_mapi_store_maybe_disconnect (mapi_store, local_error);
			g_propagate_error (error, local_error);
		}
	} else {
		success = FALSE;

		if (local_error) {
			if (!e_mapi_utils_propagate_cancelled_error (local_error, error))
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					_("Cannot remove folder '%s': %s"),
					folder_name, local_error->message);

			camel_mapi_store_maybe_disconnect (mapi_store, local_error);
			g_error_free (local_error);
		} else {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Cannot remove folder '%s'"),
				folder_name);
		}
	}

	return success;
}

static gboolean
mapi_store_rename_folder_sync (CamelStore *store,
                               const gchar *old_name,
                               const gchar *new_name,
                               GCancellable *cancellable,
                               GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate  *priv = mapi_store->priv;
	EMapiConnection *conn;
	CamelStoreInfo *si = NULL;
	CamelService *service;
	const gchar *user_cache_dir;
	gchar *old_parent, *new_parent, *tmp;
	gboolean move_cache = TRUE;
	const gchar *old_fid_str, *new_parent_fid_str = NULL;
	mapi_id_t old_fid;
	GError *local_error = NULL;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot rename MAPI folders in offline mode"));
		return FALSE;
	}

	service = CAMEL_SERVICE (store);
	user_cache_dir = camel_service_get_user_cache_dir (service);

	if (!camel_mapi_store_connected ((CamelMapiStore *)store, cancellable, &local_error)) {
		if (local_error != NULL) {
			g_propagate_error (error, local_error);
			return FALSE;
		}

		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot rename MAPI folders in offline mode"));

		return FALSE;
	}

	/* Need a full name of a folder */
	old_fid_str = camel_mapi_store_folder_id_lookup (mapi_store, old_name);
	if (!old_fid_str) {
		/*To translators : '%s' is current name of the folder */
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot rename MAPI folder '%s'. Folder does not exist"),
			old_name);
		return FALSE;
	}

	/*Do not allow rename for system folders.*/
	if (mapi_fid_is_system_folder (mapi_store, old_fid_str)) {
		/*To translators : '%s to %s' is current name of the folder  and
		 new name of the folder.*/
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot rename MAPI default folder '%s' to '%s'"),
			old_name, new_name);
		return FALSE;
	}

	old_parent = g_strdup (old_name);
	tmp = strrchr (old_parent, '/');
	if (tmp) {
		*tmp = '\0';
	} else {
		strcpy (old_parent, "");
	}

	new_parent = g_strdup (new_name);
	tmp = strrchr (new_parent, '/');
	if (tmp) {
		*tmp = '\0';
		tmp++; /* here's a new folder name now */
	} else {
		strcpy (new_parent, "");
		tmp = NULL;
	}

	if (!e_mapi_util_mapi_id_from_string (old_fid_str, &old_fid)) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot rename MAPI folder '%s' to '%s'"),
			old_name, new_name);
		g_free (old_parent);
		g_free (new_parent);
		return FALSE;
	}

	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);
	if (!conn) {
		g_free (old_parent);
		g_free (new_parent);

		return FALSE;
	}

	if (tmp == NULL || g_str_equal (old_parent, new_parent)) {
		gchar *folder_id;
		gboolean status = FALSE;
		mapi_object_t obj_folder;

		if (cms_open_folder (mapi_store, conn, old_fid, &obj_folder, cancellable, &local_error)) {
			status = e_mapi_connection_rename_folder (conn, &obj_folder, tmp ? tmp : new_name, cancellable, &local_error);
			e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &local_error);
		}

		/* renaming in the same folder, thus no MoveFolder necessary */
		if (!status) {
			g_object_unref (conn);

			if (local_error) {
				if (!e_mapi_utils_propagate_cancelled_error (local_error, error))
					g_set_error (
						error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
						/* Translators: '%s to %s' is current name of the folder and new name of the folder.
						   The last '%s' is a detailed error message. */
						_("Cannot rename MAPI folder '%s' to '%s': %s"),
						old_name, new_name, local_error->message);
				camel_mapi_store_maybe_disconnect (mapi_store, local_error);
				g_error_free (local_error);
			} else {
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					/* Translators: '%s to %s' is current name of the folder and new name of the folder. */
					_("Cannot rename MAPI folder '%s' to '%s'"),
					old_name, new_name);
			}

			g_free (old_parent);
			g_free (new_parent);
			return FALSE;
		}

		mapi_rename_folder_infos (mapi_store, old_name, new_name);

		folder_id = g_strdup (old_fid_str);

		/* this frees old_fid_str */
		g_hash_table_remove (priv->name_hash, old_name);
		g_hash_table_remove (priv->id_hash, folder_id);

		mapi_update_folder_hash_tables (mapi_store, new_name, folder_id, NULL);

		g_free (folder_id);
	} else {
		const gchar *old_parent_fid_str;
		mapi_id_t old_parent_fid, new_parent_fid;
		gchar *folder_id;

		old_parent_fid_str = camel_mapi_store_folder_id_lookup (mapi_store, old_parent);
		new_parent_fid_str = camel_mapi_store_folder_id_lookup (mapi_store, new_parent);
		if (!old_parent_fid_str && new_parent_fid_str) {
			CamelStoreInfo *new_si;

			/* Folder was in a store-summary, and is known, but the parent gone.
			   The reason might be that this is a subfolder whose parent got moved
			   a second ago. Thus just update local summary with proper paths. */
			move_cache = FALSE;

			new_si = camel_store_summary_path (mapi_store->summary, new_name);
			if (new_si) {
				si = camel_store_summary_path (mapi_store->summary, old_name);
				if (si) {
					/* for cases where folder sync realized new folders before this got updated;
					   this shouldn't duplicate the info in summary, but remove the old one */
					camel_store_summary_remove (mapi_store->summary, si);
					si = NULL;
				}
				camel_store_summary_info_unref (mapi_store->summary, new_si);
			}
		} else {
			gboolean status = FALSE;

			if (old_parent_fid_str && new_parent_fid_str &&
			   e_mapi_util_mapi_id_from_string (old_parent_fid_str, &old_parent_fid) &&
			   e_mapi_util_mapi_id_from_string (new_parent_fid_str, &new_parent_fid)) {
				mapi_object_t src_obj_folder, src_parent_obj_folder, des_obj_folder;

				if (cms_open_folder (mapi_store, conn, old_fid, &src_obj_folder, cancellable, &local_error)) {
					if (cms_open_folder (mapi_store, conn, old_parent_fid, &src_parent_obj_folder, cancellable, &local_error)) {
						if (cms_open_folder (mapi_store, conn, new_parent_fid, &des_obj_folder, cancellable, &local_error)) {
							status = e_mapi_connection_move_folder (conn, &src_obj_folder, &src_parent_obj_folder, &des_obj_folder, tmp, cancellable, &local_error);
							e_mapi_connection_close_folder (conn, &des_obj_folder, cancellable, &local_error);
						}
						e_mapi_connection_close_folder (conn, &src_parent_obj_folder, cancellable, &local_error);
					}
					e_mapi_connection_close_folder (conn, &src_obj_folder, cancellable, &local_error);
				}
			}

			if (!status) {
				g_object_unref (conn);

				if (local_error) {
					if (!e_mapi_utils_propagate_cancelled_error (local_error, error))
						g_set_error (
							error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
							_("Cannot rename MAPI folder '%s' to '%s': %s"),
							old_name, new_name, local_error->message);
					camel_mapi_store_maybe_disconnect (mapi_store, local_error);
					g_error_free (local_error);
				} else {
					g_set_error (
						error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
						_("Cannot rename MAPI folder '%s' to '%s'"),
						old_name, new_name);
				}
				g_free (old_parent);
				g_free (new_parent);
				return FALSE;
			} else {
				/* folder was moved, update all subfolders immediately, thus
				   the next get_folder_info call will know about them */
				mapi_rename_folder_infos (mapi_store, old_name, new_name);
			}
		}

		folder_id = g_strdup (old_fid_str);

		/* this frees old_fid_str */
		g_hash_table_remove (priv->name_hash, old_name);
		g_hash_table_remove (priv->id_hash, folder_id);
		/*g_hash_table_remove (priv->parent_hash, folder_id);*/

		mapi_update_folder_hash_tables (mapi_store, new_name, folder_id, new_parent_fid_str);

		g_free (folder_id);
	}

	g_object_unref (conn);

	si = camel_store_summary_path (mapi_store->summary, old_name);
	if (si) {
		mapi_id_t new_parent_fid;

		camel_store_info_set_string (mapi_store->summary, si, CAMEL_STORE_INFO_PATH, new_name);
		if (new_parent_fid_str && e_mapi_util_mapi_id_from_string (new_parent_fid_str, &new_parent_fid))
			((CamelMapiStoreInfo *) si)->parent_id = new_parent_fid;
		camel_store_summary_info_unref (mapi_store->summary, si);
		camel_store_summary_touch (mapi_store->summary);
	}

	if (move_cache) {
		gchar *oldpath, *newpath;

		oldpath = g_build_filename (user_cache_dir, "folders", old_name, NULL);
		newpath = g_build_filename (user_cache_dir, "folders", new_name, NULL);

		if (g_file_test (oldpath, G_FILE_TEST_IS_DIR) && g_rename (oldpath, newpath) == -1 && errno != ENOENT) {
			g_warning ("Could not rename message cache '%s' to '%s': %s: cache reset", oldpath, newpath, g_strerror (errno));
		}

		g_free (oldpath);
		g_free (newpath);
	}

	g_free (old_parent);
	g_free (new_parent);

	return TRUE;
}

static gboolean
mapi_store_folder_is_subscribed (CamelSubscribable *subscribable,
                                 const gchar *folder_name)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (subscribable);
	CamelStoreInfo *si;
	gint truth = FALSE;

	if ((si = camel_store_summary_path (mapi_store->summary, folder_name))) {
		truth = (si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) != 0;
		camel_store_summary_info_unref (mapi_store->summary, si);
	}

	return truth;
}

static gboolean
mapi_store_subscribe_folder_sync (CamelSubscribable *subscribable,
                                  const gchar *folder_name,
                                  GCancellable *cancellable,
                                  GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (subscribable);
	CamelFolderInfo *fi;
	CamelStoreInfo *si, *si2;
	CamelMapiStoreInfo *msi;
	const gchar *use_folder_name = folder_name, *f_name;
	gchar *path;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store))) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot subscribe MAPI folders in offline mode"));
		return FALSE;
	}

	/* subscribe is done only with public folders, which are added to Favorites */
	f_name = strrchr (folder_name, '/');
	if (!f_name) {
		/* Don't process All Public Folder. */
		return TRUE;
	}

	use_folder_name = f_name + 1;

	si = camel_store_summary_path (mapi_store->summary, folder_name);
	if (!si) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Folder '%s' not found"), folder_name);

		return FALSE;
	}

	msi = (CamelMapiStoreInfo *) si;
	if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) == 0) {
		/* this is not a public folder, but MAPI supports subscribtions
		   only on public folders, thus report success
		*/

		camel_store_summary_info_unref (mapi_store->summary, si);

		return TRUE;
	}

	path = g_strconcat (DISPLAY_NAME_FAVORITES, "/", use_folder_name, NULL);
	si2 = camel_store_summary_path (mapi_store->summary, path);
	if (si2 && ((CamelMapiStoreInfo *) si2)->folder_id == msi->folder_id && (si2->flags & CAMEL_FOLDER_SUBSCRIBED) != 0) {
		/* already subscribed */
		camel_store_summary_info_unref (mapi_store->summary, si);
		camel_store_summary_info_unref (mapi_store->summary, si2);

		return TRUE;
	} else if (si2) {
		camel_store_summary_info_unref (mapi_store->summary, si2);
		si2 = NULL;
	}

	if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL) != 0) {
		/* make sure parent folder is known */
		fi = mapi_build_folder_info (mapi_store, NULL, DISPLAY_NAME_FAVORITES);
		fi->flags |= CAMEL_FOLDER_NOSELECT | CAMEL_FOLDER_SYSTEM;

		camel_subscribable_folder_subscribed (CAMEL_SUBSCRIBABLE (mapi_store), fi);

		camel_folder_info_free (fi);

		camel_mapi_store_ensure_unique_path (mapi_store, &path);

		/* then add copy with Favorites/xxx */
		si2 = camel_mapi_store_summary_add_from_full (mapi_store->summary,
			path,
			msi->folder_id,
			msi->parent_id,
			msi->camel_folder_flags | CAMEL_FOLDER_SUBSCRIBED | CAMEL_STORE_INFO_FOLDER_SUBSCRIBED | CAMEL_FOLDER_NOCHILDREN,
			msi->mapi_folder_flags & ~(CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL),
			msi->foreign_username);

		if (si2) {
			camel_store_summary_touch (mapi_store->summary);

			fi = mapi_build_folder_info (mapi_store, NULL, path);
			fi->unread = si2->unread;
			fi->total = si2->total;
			fi->flags = si2->flags;
			camel_subscribable_folder_subscribed (subscribable, fi);
			camel_folder_info_free (fi);
		} else {
			g_debug ("%s: Failed to add '%s' to store's summary", G_STRFUNC, path);
		}
	} else {
		CamelSettings *settings;
		CamelMapiSettings *mapi_settings;
		guint folder_type = mapi_folders_hash_table_type_lookup (mapi_store, folder_name);
		gchar *profile;

		/* remember the folder, thus it can be removed and checked in Subscriptions dialog */
		msi->camel_folder_flags = msi->camel_folder_flags | CAMEL_FOLDER_SUBSCRIBED | CAMEL_STORE_INFO_FOLDER_SUBSCRIBED | CAMEL_FOLDER_NOCHILDREN;
		camel_store_summary_touch (mapi_store->summary);

		settings = camel_service_ref_settings (CAMEL_SERVICE (mapi_store));
		mapi_settings = CAMEL_MAPI_SETTINGS (settings);
		profile = camel_mapi_settings_dup_profile (mapi_settings);

		g_object_unref (settings);

		if (!e_mapi_folder_add_as_esource (NULL, folder_type, profile,
			TRUE /* camel_offline_settings_get_stay_synchronized (CAMEL_OFFLINE_SETTINGS (mapi_settings)) */,
			E_MAPI_FOLDER_CATEGORY_PUBLIC,
			NULL,
			use_folder_name,
			msi->folder_id,
			(gint) msi->folder_id,
			cancellable,
			error)) {
			camel_store_summary_info_unref (mapi_store->summary, si);
			g_free (profile);
			g_free (path);

			return FALSE;
		}

		g_free (profile);
	}
	camel_store_summary_info_unref (mapi_store->summary, si);
	camel_store_summary_save (mapi_store->summary);

	g_free (path);

	return TRUE;
}

static gboolean
mapi_store_unsubscribe_folder_sync (CamelSubscribable *subscribable,
                                    const gchar *folder_name,
                                    GCancellable *cancellable,
                                    GError **error)
{
	gboolean res = TRUE;
	CamelFolderInfo *fi;
	CamelStoreInfo *si;
	CamelMapiStoreInfo *msi;
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (subscribable);

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store))) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot unsubscribe MAPI folders in offline mode"));
		return FALSE;
	}

	si = camel_store_summary_path (mapi_store->summary, folder_name);
	if (!si) {
		/* no such folder in the cache, might be unsubscribed already */
		return TRUE;
	}

	msi = (CamelMapiStoreInfo *) si;
	if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL) != 0) {
		CamelStoreInfo *si2 = camel_mapi_store_summary_get_folder_id (mapi_store->summary, msi->folder_id);

		if (si2) {
			CamelMapiStoreInfo *msi2 = (CamelMapiStoreInfo *) si2;

			fi = mapi_build_folder_info (mapi_store, NULL, camel_store_info_path (mapi_store->summary, si2));
			camel_subscribable_folder_unsubscribed (subscribable, fi);
			camel_folder_info_free (fi);

			if ((msi2->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 &&
			    (msi2->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL) == 0) {
				/* remove calls also free on 'si2' */
				camel_store_summary_remove (mapi_store->summary, si2);
				camel_store_summary_touch (mapi_store->summary);
			} else {
				camel_store_summary_info_unref (mapi_store->summary, si2);
			}
		} else {
			g_debug ("%s: Failed to find subscribed by folder ID", G_STRFUNC);
		}
	} else {
		CamelSettings *settings;
		const gchar *profile;

		settings = camel_service_ref_settings (CAMEL_SERVICE (mapi_store));
		profile = camel_mapi_settings_get_profile (CAMEL_MAPI_SETTINGS (settings));

		res = e_mapi_folder_remove_as_esource (NULL,
			profile,
			msi->folder_id,
			cancellable,
			error);

		g_object_unref (settings);
	}

	if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 &&
	    (msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL) == 0) {
		/* remove calls also free on 'si' */
		camel_store_summary_remove (mapi_store->summary, si);
		camel_store_summary_touch (mapi_store->summary);
	} else {
		camel_store_summary_info_unref (mapi_store->summary, si);
	}

	camel_store_summary_save (mapi_store->summary);

	return res;
}

static void
mapi_migrate_to_user_cache_dir (CamelService *service)
{
	const gchar *user_data_dir, *user_cache_dir;

	g_return_if_fail (service != NULL);
	g_return_if_fail (CAMEL_IS_SERVICE (service));

	user_data_dir = camel_service_get_user_data_dir (service);
	user_cache_dir = camel_service_get_user_cache_dir (service);

	g_return_if_fail (user_data_dir != NULL);
	g_return_if_fail (user_cache_dir != NULL);

	/* migrate only if the source directory exists and the destination doesn't */
	if (g_file_test (user_data_dir, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR) &&
	    !g_file_test (user_cache_dir, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)) {
		gchar *parent_dir;

		parent_dir = g_path_get_dirname (user_cache_dir);
		g_mkdir_with_parents (parent_dir, S_IRWXU);
		g_free (parent_dir);

		if (g_rename (user_data_dir, user_cache_dir) == -1)
			g_debug ("%s: Failed to migrate '%s' to '%s': %s", G_STRFUNC, user_data_dir, user_cache_dir, g_strerror (errno));
	}
}

static void
camel_mapi_store_class_init (CamelMapiStoreClass *class)
{
	GObjectClass *object_class;
	CamelServiceClass *service_class;
	CamelStoreClass *store_class;

	/* register MAPIKRB auth type */
	CAMEL_TYPE_MAPI_SASL_KRB;

	g_type_class_add_private (class, sizeof (CamelMapiStorePrivate));

	object_class = G_OBJECT_CLASS (class);
	object_class->dispose = mapi_store_dispose;
	object_class->finalize = mapi_store_finalize;
	object_class->constructed = mapi_store_constructed;

	service_class = CAMEL_SERVICE_CLASS (class);
	service_class->settings_type = CAMEL_TYPE_MAPI_SETTINGS;
	service_class->get_name = mapi_get_name;
	service_class->connect_sync = mapi_connect_sync;
	service_class->disconnect_sync = mapi_disconnect_sync;
	service_class->authenticate_sync = mapi_authenticate_sync;
	service_class->query_auth_types_sync = mapi_query_auth_types_sync;

	store_class = CAMEL_STORE_CLASS (class);
	store_class->can_refresh_folder = mapi_store_can_refresh_folder;
	store_class->get_folder_sync = mapi_store_get_folder_sync;
	store_class->get_folder_info_sync = mapi_store_get_folder_info_sync;
	store_class->get_junk_folder_sync = mapi_store_get_junk_folder_sync;
	store_class->get_trash_folder_sync = mapi_store_get_trash_folder_sync;
	store_class->create_folder_sync = mapi_store_create_folder_sync;
	store_class->delete_folder_sync = mapi_store_delete_folder_sync;
	store_class->rename_folder_sync = mapi_store_rename_folder_sync;
}

static void
camel_subscribable_init (CamelSubscribableInterface *iface)
{
	iface->folder_is_subscribed = mapi_store_folder_is_subscribed;
	iface->subscribe_folder_sync = mapi_store_subscribe_folder_sync;
	iface->unsubscribe_folder_sync = mapi_store_unsubscribe_folder_sync;
}

/*
** store is already initilyse to NULL or 0 value
** class already have a parent_class
** nothing must be doing here
*/
static void
camel_mapi_store_init (CamelMapiStore *mapi_store)
{
	mapi_store->priv = G_TYPE_INSTANCE_GET_PRIVATE (mapi_store, CAMEL_TYPE_MAPI_STORE, CamelMapiStorePrivate);

	g_rec_mutex_init (&mapi_store->priv->connection_lock);
	g_rec_mutex_init (&mapi_store->priv->updates_lock);
	mapi_store->priv->updates_cancellable = NULL;
	mapi_store->priv->update_folder_names = NULL;
	mapi_store->priv->update_folder_id = 0;
	mapi_store->priv->update_folder_list_id = 0;
}

/* service methods */
static void
mapi_store_constructed (GObject *object)
{
	CamelMapiStore	*mapi_store = CAMEL_MAPI_STORE (object);
	CamelStore *store = CAMEL_STORE (object);
	CamelMapiStorePrivate *priv = mapi_store->priv;
	CamelService *service;
	const gchar *user_cache_dir;
	gchar *path = NULL;

	/* Chain up to parent's constructed() method. */
	G_OBJECT_CLASS (camel_mapi_store_parent_class)->constructed (object);

	service = CAMEL_SERVICE (object);
	mapi_migrate_to_user_cache_dir (service);

	user_cache_dir = camel_service_get_user_cache_dir (service);

	/*store summary*/
	path = g_build_filename (user_cache_dir, ".summary", NULL);

	mapi_store->summary = camel_mapi_store_summary_new ();
	camel_store_summary_set_filename (mapi_store->summary, path);

	camel_store_summary_load (mapi_store->summary);

	/*Hash Table*/
	priv->id_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free); /* folder ID to folder Full name */
	priv->name_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free); /* folder Full name to folder ID */
	/*priv->parent_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free); / * folder ID to its parent folder ID */
	priv->default_folders = g_hash_table_new_full (g_int_hash, g_int_equal, g_free, g_free); /* default folder type to folder ID */
	priv->container_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	store->flags &= ~CAMEL_STORE_VJUNK;
	store->flags &= ~CAMEL_STORE_VTRASH;

	store->flags |= CAMEL_STORE_REAL_JUNK_FOLDER | CAMEL_STORE_USE_CACHE_DIR;

	g_free (path);
}

static char *
mapi_get_name(CamelService *service, gboolean brief)
{
	CamelNetworkSettings *network_settings;
	CamelSettings *settings;
	gchar *host;
	gchar *name;
	gchar *user;

	settings = camel_service_ref_settings (service);

	network_settings = CAMEL_NETWORK_SETTINGS (settings);
	host = camel_network_settings_dup_host (network_settings);
	user = camel_network_settings_dup_user (network_settings);

	g_object_unref (settings);

	if (brief) {
		/* Translators: The %s is replaced with a server's host name */
		name = g_strdup_printf(_("Exchange MAPI server %s"), host);
	} else {
		/*To translators : Example string : Exchange MAPI service for
		  _username_ on _server host name__*/
		name = g_strdup_printf(_("Exchange MAPI service for %s on %s"),
				       user, host);
	}

	g_free (host);
	g_free (user);

	return name;
}

static gboolean
mapi_connect_sync (CamelService *service,
                   GCancellable *cancellable,
                   GError **error)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);
	EMapiConnection *conn;
	CamelServiceConnectionStatus status;
	CamelSession *session;
	CamelSettings *settings;
	EMapiProfileData empd = { 0 };
	uint64_t current_size = -1, receive_quota = -1, send_quota = -1;
	gchar *name;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))) {
		g_set_error_literal (
			error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Cannot connect MAPI store in offline mode"));
		return FALSE;
	}

	session = camel_service_ref_session (service);

	status = camel_service_get_connection_status (service);
	if (status == CAMEL_SERVICE_DISCONNECTED) {
		g_object_unref (session);
		return FALSE;
	}

	if (check_for_connection (service, NULL)) {
		g_object_unref (session);
		return TRUE;
	}

	name = camel_service_get_name (service, TRUE);
	camel_operation_push_message (cancellable, _("Connecting to '%s'"), name);

	settings = camel_service_ref_settings (service);
	e_mapi_util_profiledata_from_settings (&empd, CAMEL_MAPI_SETTINGS (settings));
	g_object_unref (settings);

	if (!camel_session_authenticate_sync (session, service, empd.krb_sso ? "MAPIKRB" : NULL, cancellable, error)) {
		camel_operation_pop_message (cancellable);
		g_object_unref (session);
		g_free (name);
		return FALSE;
	}

	camel_operation_pop_message (cancellable);

	camel_offline_store_set_online_sync (
		CAMEL_OFFLINE_STORE (store), TRUE, cancellable, NULL);

	camel_store_summary_save (store->summary);

	conn = camel_mapi_store_ref_connection (store, cancellable, error);
	if (!conn) {
		g_object_unref (session);
		g_free (name);

		return FALSE;
	}

	if (e_mapi_connection_get_store_quotas (conn, NULL, &current_size, &receive_quota, &send_quota, cancellable, NULL)) {
		if (current_size != -1) {
			gchar *msg = NULL;

			/* warn/alert when the last 1% lefts from the size quota */
			if (send_quota != -1 && current_size * 0.95 >= send_quota) {
				if (send_quota != -1 && current_size >= send_quota) {
					msg = g_strdup_printf (_("Mailbox '%s' is full, no new messages will be received or sent."), name);
				} else {
					msg = g_strdup_printf (_("Mailbox '%s' is near its size limit, message send will be disabled soon."), name);
				}
			} else if (receive_quota != -1 && current_size * 0.95 >= receive_quota) {
				if (current_size >= receive_quota) {
					msg = g_strdup_printf (_("Mailbox '%s' is full, no new messages will be received."), name);
				} else {
					msg = g_strdup_printf (_("Mailbox '%s' is near its size limit."), name);
				}
			}

			if (msg) {
				camel_session_user_alert (session, service, CAMEL_SESSION_ALERT_WARNING, msg);
				g_free (msg);
			}
		}
	}

	g_object_unref (conn);
	g_free (name);

	g_object_unref (session);

	return TRUE;
}

static gboolean
mapi_disconnect_sync (CamelService *service,
                      gboolean clean,
                      GCancellable *cancellable,
                      GError **error)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);

	stop_pending_updates (store);

	g_rec_mutex_lock (&store->priv->connection_lock);
	if (store->priv->connection) {
		g_signal_handlers_disconnect_by_func (store->priv->connection, camel_mapi_store_server_notification_cb, store);
		e_mapi_connection_disable_notifications (store->priv->connection, NULL, cancellable, error);

		/* Close the mapi subsystem */
		e_mapi_connection_disconnect (store->priv->connection, clean, clean ? cancellable : NULL, error);

		g_object_unref (store->priv->connection);
		store->priv->connection = NULL;
	}
	g_rec_mutex_unlock (&store->priv->connection_lock);

	store->priv->folders_synced = FALSE;

	return TRUE;
}

struct ScheduleUpdateData
{
	GCancellable *cancellable;
	CamelMapiStore *mapi_store;
	GSList *foldernames;
	guint expected_id;
};

static void
free_schedule_update_data (gpointer ptr)
{
	struct ScheduleUpdateData *sud = ptr;

	if (!sud)
		return;

	if (sud->cancellable)
		g_object_unref (sud->cancellable);
	g_slist_free_full (sud->foldernames, g_free);
	g_free (sud);
}

static gpointer
camel_mapi_folder_update_thread (gpointer user_data)
{
	struct ScheduleUpdateData *sud = user_data;
	CamelMapiStore *mapi_store;
	GSList *fn;

	g_return_val_if_fail (sud != NULL, NULL);

	mapi_store = g_object_ref (sud->mapi_store);

	for (fn = sud->foldernames; fn && !g_cancellable_is_cancelled (sud->cancellable); fn = fn->next) {
		const gchar *foldername = fn->data;
		CamelFolder *folder;

		if (!foldername)
			continue;

		folder = camel_store_get_folder_sync (CAMEL_STORE (mapi_store), foldername, 0, sud->cancellable, NULL);
		if (folder) {
			camel_folder_refresh_info_sync (folder, sud->cancellable, NULL);
			g_object_unref (folder);
		}
	}

	if (!g_cancellable_is_cancelled (sud->cancellable) &&
	    !mapi_store->priv->folders_synced)
		mapi_folders_sync (sud->mapi_store, CAMEL_STORE_FOLDER_INFO_RECURSIVE | CAMEL_STORE_FOLDER_INFO_SUBSCRIBED, sud->cancellable, NULL);

	g_object_unref (mapi_store);

	free_schedule_update_data (sud);

	return NULL;
}

static void
run_update_thread (CamelMapiStore *mapi_store,
		   GCancellable *cancellable,
		   GSList *foldernames)
{
	struct ScheduleUpdateData *sud;
	GThread *thread;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (cancellable != NULL);

	sud = g_new0 (struct ScheduleUpdateData, 1);
	sud->mapi_store = mapi_store;
	sud->cancellable = g_object_ref (cancellable);
	sud->foldernames = foldernames;

	thread = g_thread_new (NULL, camel_mapi_folder_update_thread, sud);
	g_thread_unref (thread);
}

static gboolean
folder_update_cb (gpointer user_data)
{
	struct ScheduleUpdateData *sud = user_data;
	GSList *foldernames;

	g_return_val_if_fail (sud != NULL, FALSE);

	if (g_cancellable_is_cancelled (sud->cancellable))
		return FALSE;

	g_return_val_if_fail (sud->mapi_store != NULL, FALSE);
	g_return_val_if_fail (sud->mapi_store->priv != NULL, FALSE);

	g_rec_mutex_lock (&sud->mapi_store->priv->updates_lock);
	if (sud->expected_id != sud->mapi_store->priv->update_folder_id) {
		g_rec_mutex_unlock (&sud->mapi_store->priv->updates_lock);
		return FALSE;
	}

	foldernames = sud->mapi_store->priv->update_folder_names;
	sud->mapi_store->priv->update_folder_names = NULL;
	sud->mapi_store->priv->update_folder_id = 0;

	if (!g_cancellable_is_cancelled (sud->cancellable))
		run_update_thread (sud->mapi_store, sud->cancellable, foldernames);
	else
		g_slist_free_full (foldernames, g_free);

	g_rec_mutex_unlock (&sud->mapi_store->priv->updates_lock);

	return FALSE;
}

static void
schedule_folder_update (CamelMapiStore *mapi_store, mapi_id_t fid)
{
	gchar *fidstr;
	const gchar *foldername;
	struct ScheduleUpdateData *sud;
	CamelStoreInfo *si;
	CamelMapiStoreInfo *msi;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (mapi_store->priv != NULL);

	si = camel_mapi_store_summary_get_folder_id (mapi_store->summary, fid);
	if (!si)
		return;

	msi = (CamelMapiStoreInfo *) si;
	if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL) == 0) {
		camel_store_summary_info_unref (mapi_store->summary, si);
		return;
	}

	camel_store_summary_info_unref (mapi_store->summary, si);

	fidstr = e_mapi_util_mapi_id_to_string (fid);
	if (!fidstr)
		return;

	foldername = camel_mapi_store_folder_lookup (mapi_store, fidstr);
	g_free (fidstr);

	if (!foldername)
		return;

	g_rec_mutex_lock (&mapi_store->priv->updates_lock);
	if (!mapi_store->priv->updates_cancellable ||
	    g_slist_find_custom (mapi_store->priv->update_folder_names, foldername, (GCompareFunc) g_ascii_strcasecmp) != 0) {
		g_rec_mutex_unlock (&mapi_store->priv->updates_lock);
		return;
	}

	sud = g_new0 (struct ScheduleUpdateData, 1);
	sud->cancellable = g_object_ref (mapi_store->priv->updates_cancellable);
	sud->mapi_store = mapi_store;

	mapi_store->priv->update_folder_names = g_slist_prepend (mapi_store->priv->update_folder_names, g_strdup (foldername));
	if (mapi_store->priv->update_folder_id)
		g_source_remove (mapi_store->priv->update_folder_id);
	mapi_store->priv->update_folder_id = g_timeout_add_seconds_full (G_PRIORITY_LOW, 5, folder_update_cb, sud, free_schedule_update_data);
	sud->expected_id = mapi_store->priv->update_folder_id;

	g_rec_mutex_unlock (&mapi_store->priv->updates_lock);
}

static gboolean
folder_list_update_cb (gpointer user_data)
{
	struct ScheduleUpdateData *sud = user_data;

	g_return_val_if_fail (sud != NULL, FALSE);

	if (g_cancellable_is_cancelled (sud->cancellable))
		return FALSE;

	g_return_val_if_fail (sud->mapi_store != NULL, FALSE);
	g_return_val_if_fail (sud->mapi_store->priv != NULL, FALSE);

	g_rec_mutex_lock (&sud->mapi_store->priv->updates_lock);
	if (sud->expected_id != sud->mapi_store->priv->update_folder_list_id) {
		g_rec_mutex_unlock (&sud->mapi_store->priv->updates_lock);
		return FALSE;
	}

	sud->mapi_store->priv->folders_synced = FALSE;
	sud->mapi_store->priv->update_folder_list_id = 0;

	if (!g_cancellable_is_cancelled (sud->cancellable))
		run_update_thread (sud->mapi_store, sud->cancellable, NULL);

	g_rec_mutex_unlock (&sud->mapi_store->priv->updates_lock);

	return FALSE;
}

static void
schedule_folder_list_update (CamelMapiStore *mapi_store)
{
	struct ScheduleUpdateData *sud;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (mapi_store->priv != NULL);

	g_rec_mutex_lock (&mapi_store->priv->updates_lock);
	if (!mapi_store->priv->updates_cancellable) {
		g_rec_mutex_unlock (&mapi_store->priv->updates_lock);
		return;
	}

	sud = g_new0 (struct ScheduleUpdateData, 1);
	sud->cancellable = g_object_ref (mapi_store->priv->updates_cancellable);
	sud->mapi_store = mapi_store;

	if (mapi_store->priv->update_folder_list_id)
		g_source_remove (mapi_store->priv->update_folder_list_id);
	mapi_store->priv->update_folder_list_id = g_timeout_add_seconds_full (G_PRIORITY_LOW, 5, folder_list_update_cb, sud, free_schedule_update_data);
	sud->expected_id = mapi_store->priv->update_folder_list_id;

	g_rec_mutex_unlock (&mapi_store->priv->updates_lock);
}

static void
camel_mapi_store_server_notification_cb (EMapiConnection *conn,
					 guint event_mask,
					 gpointer event_data,
					 gpointer user_data)
{
	CamelMapiStore *mapi_store = user_data;
	mapi_id_t update_folder1 = 0, update_folder2 = 0;
	gboolean update_folder_list = FALSE;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (mapi_store->priv != NULL);

	switch (event_mask) {
	/* -- Folder Events -- */
	case fnevObjectCreated:
		d (printf ("Event : Folder Created\n"));
		d (mapidump_foldercreated (event_data, "\t"));
		update_folder_list = TRUE;
		break;
	case fnevObjectDeleted:
		d (printf ("Event : Folder Deleted\n"));
		d (mapidump_folderdeleted (event_data, "\t"));
		update_folder_list = TRUE;
		break;
	case fnevObjectMoved:
		d (printf ("Event : Folder Moved\n"));
		d (mapidump_foldermoved (event_data, "\t"));
		update_folder_list = TRUE;
		break;
	case fnevObjectCopied:
		d (printf ("Event : Folder Copied\n"));
		d (mapidump_foldercopied (event_data, "\t"));
		update_folder_list = TRUE;
		break;

	/* -- Message Events -- */
	case fnevNewMail:
	case fnevNewMail | fnevMbit: {
		struct NewMailNotification *newmail = event_data;

		d (printf ("Event : New mail\n"));
		d (mapidump_newmail (event_data, "\t"));

		if (newmail)
			update_folder1 = newmail->FID;
		} break;
	case fnevMbit | fnevObjectCreated: {
		struct MessageCreatedNotification *msgcreated = event_data;

		d (printf ("Event : Message created\n"));
		d (mapidump_messagecreated (event_data, "\t"));

		if (msgcreated)
			update_folder1 = msgcreated->FID;
		} break;
	case fnevMbit | fnevObjectModified: {
		struct MessageModifiedNotification *msgmodified = event_data;

		d (printf ("Event : Message modified\n"));
		d (mapidump_messagemodified (event_data, "\t"));

		if (msgmodified)
			update_folder1 = msgmodified->FID;
		} break;
	case fnevMbit | fnevObjectDeleted: {
		struct MessageDeletedNotification *msgdeleted = event_data;

		d (printf ("Event : Message deleted\n"));
		d (mapidump_messagedeleted (event_data, "\t"));

		if (msgdeleted)
			update_folder1 = msgdeleted->FID;
		} break;
	case fnevMbit | fnevObjectMoved: {
		struct MessageMoveCopyNotification *msgmoved = event_data;

		d (printf ("Event : Message moved\n"));
		d (mapidump_messagemoved (event_data, "\t"));

		if (msgmoved) {
			update_folder1 = msgmoved->OldFID;
			update_folder2 = msgmoved->FID;
		}
		} break;
	case fnevMbit | fnevObjectCopied: {
		struct MessageMoveCopyNotification *msgcopied = event_data;

		d (printf ("Event : Message copied\n"));
		d (mapidump_messagecopied (event_data, "\t"));

		if (msgcopied) {
			update_folder1 = msgcopied->OldFID;
			update_folder2 = msgcopied->FID;
		}
		} break;
	default:
		/* Unsupported  */
		break;
	}

	if (update_folder1 > 0)
		schedule_folder_update (mapi_store, update_folder1);
	if (update_folder2 > 0)
		schedule_folder_update (mapi_store, update_folder2);
	if (update_folder_list)
		schedule_folder_list_update (mapi_store);
}

static CamelAuthenticationResult
mapi_authenticate_sync (CamelService *service,
                        const gchar *mechanism,
                        GCancellable *cancellable,
                        GError **error)
{
	CamelAuthenticationResult result;
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);
	CamelSession *session;
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	CamelNetworkSettings *network_settings;
	EMapiProfileData empd = { 0 };
	const gchar *profile;
	const gchar *password;
	GError *mapi_error = NULL;
	GString *password_str;

	settings = camel_service_ref_settings (service);
	mapi_settings = CAMEL_MAPI_SETTINGS (settings);
	network_settings = CAMEL_NETWORK_SETTINGS (settings);

	empd.server = camel_network_settings_get_host (network_settings);
	empd.username = camel_network_settings_get_user (network_settings);
	e_mapi_util_profiledata_from_settings (&empd, mapi_settings);

	profile = camel_mapi_settings_get_profile (mapi_settings);

	if (empd.krb_sso) {
		if (!e_mapi_util_trigger_krb_auth (&empd, error)) {
			g_object_unref (settings);
			return CAMEL_AUTHENTICATION_ERROR;
		}

		password = NULL;
	} else {
		password = camel_service_get_password (service);

		if (password == NULL) {
			g_set_error_literal (
				error, CAMEL_SERVICE_ERROR,
				CAMEL_SERVICE_ERROR_CANT_AUTHENTICATE,
				_("Authentication password not available"));
			g_object_unref (settings);
			return CAMEL_AUTHENTICATION_ERROR;
		}
	}

	password_str = g_string_new (password);
	g_rec_mutex_lock (&store->priv->connection_lock);
	session = camel_service_ref_session (service);
	store->priv->connection = e_mapi_connection_new (
		e_mail_session_get_registry (E_MAIL_SESSION (session)),
		profile, password_str, cancellable, &mapi_error);
	g_object_unref (session);
	g_string_free (password_str, TRUE);
	if (store->priv->connection && e_mapi_connection_connected (store->priv->connection)) {
		result = CAMEL_AUTHENTICATION_ACCEPTED;

		if (!store->priv->updates_cancellable)
			store->priv->updates_cancellable = g_cancellable_new ();

		g_signal_connect (store->priv->connection, "server-notification", G_CALLBACK (camel_mapi_store_server_notification_cb), store);

		if (camel_mapi_settings_get_listen_notifications (mapi_settings))
			e_mapi_connection_enable_notifications (store->priv->connection, NULL, 0, NULL, NULL);
	} else if (g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_LOGON_FAILED) ||
		   g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NETWORK_ERROR)) {
		g_clear_error (&mapi_error);
		result = CAMEL_AUTHENTICATION_REJECTED;
	} else {
		/* mapi_error should be set */
		g_return_val_if_fail (
			mapi_error != NULL,
			CAMEL_AUTHENTICATION_ERROR);
		if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
			g_propagate_error (error, mapi_error);
		else
			g_clear_error (&mapi_error);
		result = CAMEL_AUTHENTICATION_ERROR;
	}

	g_rec_mutex_unlock (&store->priv->connection_lock);
	g_object_unref (settings);

	return result;
}

static GList *
mapi_query_auth_types_sync (CamelService *service,
                            GCancellable *cancellable,
                            GError **error)
{
	return NULL;
}

static gboolean
hash_check_fid_presence (gpointer key, gpointer value, gpointer folder_id)
{
	return (g_ascii_strcasecmp (value, folder_id) == 0);
}

static gboolean
mapi_fid_is_system_folder (CamelMapiStore *mapi_store, const gchar *fid)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;

	if (!(fid && *fid))
		return FALSE;

	return (g_hash_table_find (priv->default_folders, hash_check_fid_presence, (gpointer) fid) != NULL);
}

static const gchar *
mapi_system_folder_fid (CamelMapiStore *mapi_store, gint folder_type)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;

	return g_hash_table_lookup (priv->default_folders, &folder_type);
}

static CamelFolderInfo *
mapi_build_folder_info (CamelMapiStore *mapi_store, const gchar *parent_name, const gchar *folder_name)
{
	const gchar *name;
	CamelFolderInfo *fi;

	fi = camel_folder_info_new ();

	fi->unread = -1;
	fi->total = -1;

	if (parent_name && *parent_name)
		fi->full_name = g_strconcat (parent_name, "/", folder_name, NULL);
	else
		fi->full_name = g_strdup (folder_name);

	name = strrchr(fi->full_name,'/');
	if (name == NULL)
		name = fi->full_name;
	else
		name++;

	fi->display_name = g_strdup (name);

	return fi;
}

gboolean
camel_mapi_store_connected (CamelMapiStore *mapi_store,
			    GCancellable *cancellable,
			    GError **error)
{
	return camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store))
	    && camel_service_connect_sync (CAMEL_SERVICE (mapi_store), cancellable, error);
}

void
camel_mapi_store_maybe_disconnect (CamelMapiStore *mapi_store,
				   const GError *mapi_error)
{
	g_return_if_fail (CAMEL_IS_MAPI_STORE (mapi_store));

	/* no error or already disconnected */
	g_rec_mutex_lock (&mapi_store->priv->connection_lock);
	if (!mapi_error || !mapi_store->priv->connection) {
		g_rec_mutex_unlock (&mapi_store->priv->connection_lock);
		return;
	}
	g_rec_mutex_unlock (&mapi_store->priv->connection_lock);

	if (g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NETWORK_ERROR) ||
	    g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_CALL_FAILED))
		camel_service_disconnect_sync (CAMEL_SERVICE (mapi_store),
			!g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NETWORK_ERROR),
			NULL, NULL);
}

static void
mapi_update_hash_table_type (CamelMapiStore *store, const gchar *full_name, guint *folder_type)
{
	CamelMapiStorePrivate  *priv = store->priv;
	if (full_name && folder_type) {
		if (!g_hash_table_lookup (priv->container_hash, full_name))
			g_hash_table_insert (priv->container_hash, g_strdup (full_name), folder_type);
		else
			g_free (folder_type);
	} else {
		g_free (folder_type);
	}
}

static void
mapi_update_folder_hash_tables (CamelMapiStore *store, const gchar *full_name, const gchar *fid, const gchar *parent_id)
{
	CamelMapiStorePrivate  *priv = store->priv;

	if (fid && full_name) {
		/*id_hash returns the name for a given container id*/
		if (!g_hash_table_lookup (priv->id_hash, fid))
			g_hash_table_insert (priv->id_hash, g_strdup (fid), g_strdup (full_name));

		/* name_hash : name <-> fid mapping */
		if (!g_hash_table_lookup (priv->name_hash, full_name))
			g_hash_table_insert (priv->name_hash, g_strdup (full_name), g_strdup (fid));
	}

	/*parent_hash returns the parent container id, given an id*/
	/*if (fid && parent_id && !g_hash_table_lookup (priv->parent_hash, fid))
		g_hash_table_insert (priv->parent_hash, g_strdup (fid), g_strdup (parent_id));*/

}

static void
mapi_folders_update_hash_tables_from_cache (CamelMapiStore *store)
{
	GPtrArray *array;
	guint ii;

	array = camel_store_summary_array (store->summary);

	for (ii = 0; ii < array->len; ii++) {
		CamelMapiStoreInfo *msi;
		gchar *fid, *pid;

		msi = g_ptr_array_index (array, ii);

		fid = e_mapi_util_mapi_id_to_string (msi->folder_id);
		pid = e_mapi_util_mapi_id_to_string (msi->parent_id);

		mapi_update_folder_hash_tables (store, camel_store_info_path (store->summary, (CamelStoreInfo *) msi), fid, pid);

		g_free (fid);
		g_free (pid);
	}

	camel_store_summary_array_free (store->summary, array);
}

/* static const gchar * */

guint
mapi_folders_hash_table_type_lookup (CamelMapiStore *store, const gchar *name)
{
	CamelMapiStorePrivate  *priv = store->priv;
	guint *folder_type = g_hash_table_lookup (priv->container_hash, name);

	g_return_val_if_fail (folder_type != NULL, 0);

	return *folder_type;
}

const gchar *
mapi_folders_hash_table_name_lookup (CamelMapiStore *store, const gchar *fid, gboolean use_cache)
{
	CamelMapiStorePrivate  *priv = store->priv;
	const gchar *name = g_hash_table_lookup (priv->id_hash, fid);

	if (!name && use_cache) {
		mapi_folders_update_hash_tables_from_cache (store);

		name = g_hash_table_lookup (priv->id_hash, fid);
	}

	return name;
}

#if 0
static const gchar *
mapi_folders_hash_table_fid_lookup (CamelMapiStore *store, const gchar *name,
				    gboolean use_cache)
{
	CamelMapiStorePrivate  *priv = store->priv;

	const gchar *fid = g_hash_table_lookup (priv->name_hash, name);

	if (!fid && use_cache)
		mapi_folders_update_hash_tables_from_cache (store);

	fid = g_hash_table_lookup (priv->name_hash, name);

	return fid;
}
#endif

const gchar *
camel_mapi_store_folder_id_lookup (CamelMapiStore *mapi_store, const gchar *folder_name)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;

	return g_hash_table_lookup (priv->name_hash, folder_name);
}

const gchar *
camel_mapi_store_system_folder_fid (CamelMapiStore *mapi_store, guint folder_type)
{
	return mapi_system_folder_fid (mapi_store, folder_type);
}

const gchar *
camel_mapi_store_folder_lookup (CamelMapiStore *mapi_store, const gchar *folder_id)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;

	return g_hash_table_lookup (priv->id_hash, folder_id);
}

EMapiConnection *
camel_mapi_store_ref_connection (CamelMapiStore *mapi_store,
				 GCancellable *cancellable,
				 GError **error)
{
	EMapiConnection *conn;

	g_return_val_if_fail (mapi_store != NULL, NULL);
	g_return_val_if_fail (CAMEL_IS_MAPI_STORE (mapi_store), NULL);
	g_return_val_if_fail (mapi_store->priv != NULL, NULL);

	g_rec_mutex_lock (&mapi_store->priv->connection_lock);
	if (!mapi_store->priv->connection) {
		g_rec_mutex_unlock (&mapi_store->priv->connection_lock);

		if (!camel_mapi_store_connected (mapi_store, cancellable, error))
			return NULL;

		g_rec_mutex_lock (&mapi_store->priv->connection_lock);
	}

	conn = mapi_store->priv->connection;
	if (conn)
		g_object_ref (conn);
	g_rec_mutex_unlock (&mapi_store->priv->connection_lock);

	return conn;
}

/* ppath contains proposed path, this only makes sure that it's a unique path */
void
camel_mapi_store_ensure_unique_path (CamelMapiStore *mapi_store,
				     gchar **ppath)
{
	gboolean done;
	guint counter = 0;
	gchar *base_path = NULL;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (mapi_store->summary != NULL);
	g_return_if_fail (ppath != NULL);
	g_return_if_fail (*ppath != NULL);

	done = FALSE;
	while (!done) {
		CamelStoreInfo *si;

		done = TRUE;

		si = camel_store_summary_path (mapi_store->summary, *ppath);
		if (si) {
			camel_store_summary_info_unref (mapi_store->summary, si);

			done = FALSE;
			counter++;
			if (!counter) {
				g_debug ("%s: Counter overflow", G_STRFUNC);
				break;
			}

			if (!base_path)
				base_path = *ppath;
			else
				g_free (*ppath);

			*ppath = g_strdup_printf ("%s_%u", base_path, counter);
		}
	}

	g_free (base_path);
}

void
camel_mapi_store_announce_subscribed_folder (CamelMapiStore *mapi_store,
					     const gchar *path)
{
	CamelStoreInfo *si;
	CamelFolderInfo *fi;
	CamelMapiStoreInfo *msi;
	gchar **parts, *folder_id_str, *parent_id_str;
	GString *partial_path;
	gint ii;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (mapi_store->summary != NULL);
	g_return_if_fail (path != NULL);

	si = camel_store_summary_path (mapi_store->summary, path);
	g_return_if_fail (si != NULL);

	camel_store_summary_info_unref (mapi_store->summary, si);

	parts = g_strsplit (path, "/", -1);
	g_return_if_fail (parts != NULL);

	partial_path = g_string_new ("");

	/* first announce about virtual parents */
	for (ii = 0; parts[ii]; ii++) {
		if (ii > 0)
			g_string_append (partial_path, "/");
		g_string_append (partial_path, parts[ii]);

		si = camel_store_summary_path (mapi_store->summary, partial_path->str);
		if (si) {
			/* it's a known path, no need to announce it */
			camel_store_summary_info_unref (mapi_store->summary, si);
		} else {
			/* it's an unknown path, not a real path, thus announce it too,
			   to ensure the folder path for this new path will exist
			*/
			fi = mapi_build_folder_info (mapi_store, NULL, partial_path->str);
			fi->flags |= CAMEL_FOLDER_NOSELECT | CAMEL_FOLDER_SYSTEM;

			camel_store_folder_created (CAMEL_STORE (mapi_store), fi);
			camel_subscribable_folder_subscribed (CAMEL_SUBSCRIBABLE (mapi_store), fi);

			camel_folder_info_free (fi);
		}
	}

	g_string_free (partial_path, TRUE);
	g_strfreev (parts);

	/* finally announce about the path itself */
	si = camel_store_summary_path (mapi_store->summary, path);
	g_return_if_fail (si != NULL);

	msi = (CamelMapiStoreInfo *) si;
	folder_id_str = e_mapi_util_mapi_id_to_string (msi->folder_id);
	parent_id_str = e_mapi_util_mapi_id_to_string (msi->parent_id);

	fi = mapi_build_folder_info (mapi_store, NULL, camel_store_info_path (mapi_store->summary, si));
	fi->flags = msi->camel_folder_flags;

	mapi_update_folder_hash_tables (mapi_store, fi->full_name, folder_id_str, parent_id_str);

	camel_store_folder_created (CAMEL_STORE (mapi_store), fi);
	camel_subscribable_folder_subscribed (CAMEL_SUBSCRIBABLE (mapi_store), fi);

	camel_folder_info_free (fi);
	camel_store_summary_info_unref (mapi_store->summary, si);
	g_free (folder_id_str);
	g_free (parent_id_str);
}
