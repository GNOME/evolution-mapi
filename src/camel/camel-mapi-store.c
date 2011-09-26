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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib/gi18n-lib.h>
#include <glib/gstdio.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-settings.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-summary.h"
#include "camel-mapi-notifications.h"
#include "account-setup-eplugin/exchange-mapi-account-listener.h"
#include <exchange-mapi-utils.h>
//#define d(x) x

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <libmapi/libmapi.h>
#include <param.h>

#define d(x) printf("%s:%s:%s \n", G_STRLOC, G_STRFUNC, x)

struct _CamelMapiStorePrivate {
	ExchangeMapiConnection *conn;

	GHashTable *id_hash; /*get names from ids*/
	GHashTable *name_hash;/*get ids from names*/
	GHashTable *container_hash;
	GHashTable *parent_hash;
	GHashTable *default_folders; /*Default Type : Folder ID*/

	gboolean folders_synced; /* whether were synced folder list already */
	gpointer notification_data; /* pointer to a notification data; can be only one */
};

/* Forward Declarations */
static void camel_subscribable_init (CamelSubscribableInterface *interface);

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
static GList	*mapi_query_auth_types_sync(CamelService *, GCancellable *cancellable, GError **);

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
#if 0
static void
dump_summary (CamelMapiStore *mstore)
{
	CamelStoreSummary *summary = (CamelStoreSummary *) mstore->summary;
	gint summary_count = camel_store_summary_count (summary);
	guint i = 0;

	printf ("%s: dumping %d items:\n", G_STRFUNC, summary_count);
	for (i = 0; i < summary_count; i++) {
		CamelStoreInfo *csi = camel_store_summary_index(summary, i);
		CamelMapiStoreInfo *si = (CamelMapiStoreInfo *) csi;

		printf ("[%2d] ", i);
		if (si == NULL) {
			printf ("NULL\n");
			continue;
		} /*else if (strstr (si->full_name, "/s3/") == NULL) {
			printf ("   '%s'\n", si->full_name);
			camel_store_summary_info_free ((CamelStoreSummary *)mstore->summary, csi);
			continue;
		}*/

		printf ("   full name: '%s'\n", si->full_name);
		printf ("   folder id: '%s'\n", si->folder_id);
		printf ("   parent id: '%s'\n", si->parent_id);
		printf ("   path: '%s'\n", csi->path);
		printf ("   uri: '%s'\n", csi->uri?csi->uri:"[null]");
		printf ("   flags:%x unread:%d total:%d\n", csi->flags, csi->unread, csi->total);
		camel_store_summary_info_free ((CamelStoreSummary *)mstore->summary, csi);
	}
	printf ("\n");
}
#endif

static gboolean
check_for_connection (CamelService *service, GError **error)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);

	return store && store->priv->conn && exchange_mapi_connection_connected (store->priv->conn);
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

	res = g_malloc0 (sizeof (gchar *) * (1 + ii + (2 * count)));
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

	camel_store_free_folder_info (store, all_fi);

	return folder;
}

static CamelFolderInfo *
mapi_convert_to_folder_info (CamelMapiStore *store,
                             ExchangeMAPIFolder *folder,
                             GError **error)
{
	gchar *name;
	gchar *parent, *id = NULL;
	mapi_id_t mapi_id_folder;

	const gchar *par_name = NULL;
	CamelFolderInfo *fi;

	name = escape_slash (exchange_mapi_folder_get_name (folder));

	id = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", exchange_mapi_folder_get_fid (folder));

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
	}

	if (folder->category == MAPI_PERSONAL_FOLDER) {
		fi->flags |= CAMEL_MAPI_FOLDER_PERSONAL;
		fi->flags |= CAMEL_STORE_INFO_FOLDER_SUBSCRIBED; /*Set this default for mailbox.*/
	} else if (folder->category == MAPI_FAVOURITE_FOLDER)
		fi->flags |= CAMEL_MAPI_FOLDER_PUBLIC;

	if (folder->child_count <=0)
		fi->flags |= CAMEL_FOLDER_NOCHILDREN;
	/*
	   parent_hash contains the "parent id <-> folder id" combination. So we form
	   the path for the full name in camelfolder info by looking up the hash table until
	   NULL is found
	 */

	mapi_id_folder = exchange_mapi_folder_get_parent_id (folder);
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

	si = camel_store_summary_path ((CamelStoreSummary *)mstore->summary, path);
	if (si) {
		CamelFolderInfo *fi;

		fi = camel_folder_info_new ();
		fi->unread = -1;
		fi->total = -1;
		fi->display_name = g_strdup (camel_store_info_name (mstore->summary, si));
		fi->full_name = g_strdup (camel_mapi_store_info_full_name (mstore->summary, si));
		if (!fi->display_name && fi->full_name) {
			fi->display_name = strrchr (fi->full_name, '/');
			if (fi->display_name)
				fi->display_name = g_strdup (fi->display_name + 1);
		}

		camel_subscribable_folder_unsubscribed (CAMEL_SUBSCRIBABLE (mstore), fi);
		camel_store_folder_deleted (CAMEL_STORE (mstore), fi);
		camel_folder_info_free (fi);

		camel_store_summary_info_free ((CamelStoreSummary *)mstore->summary, si);
	}

	camel_store_summary_remove_path ((CamelStoreSummary *)mstore->summary, path);
}

static gboolean
mapi_folders_sync (CamelMapiStore *store, guint32 flags, GError **error)
{
	CamelMapiStorePrivate  *priv = store->priv;
	gboolean status;
	GSList *folder_list = NULL, *temp_list = NULL, *list = NULL;
	gboolean subscription_list = FALSE;
	CamelFolderInfo *info = NULL;
	CamelMapiStoreInfo *mapi_si = NULL;
	guint32 count, i;
	CamelStoreInfo *si = NULL;
	GHashTable *old_cache_folders;
	GError *err = NULL;

	if (!camel_mapi_store_connected (store, NULL)) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Folder list not available in offline mode."));
		return FALSE;
	}

	status = exchange_mapi_connection_get_folders_list (priv->conn, &folder_list, &err);

	if (!status) {
		g_warning ("Could not get folder list (%s)\n", err ? err->message : "Unknown error");
		if (err)
			g_error_free (err);
		return TRUE;
	}

	/* remember all folders in cache before update */
	old_cache_folders = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	count = camel_store_summary_count ((CamelStoreSummary *)store->summary);
	for (i = 0; i < count; i++) {
		si = camel_store_summary_index ((CamelStoreSummary *)store->summary, i);
		if (si == NULL)
			continue;

		/* those whose left in old_cache_folders are removed at the end,
		   which is not good for public folders, thus preserve them from
		   an automatic removal */
		if ((si->flags & CAMEL_MAPI_FOLDER_PUBLIC) == 0 || (si->flags & CAMEL_FOLDER_SUBSCRIBED) == 0)
			g_hash_table_insert (old_cache_folders, g_strdup (camel_store_info_path (store->summary, si)), GINT_TO_POINTER (1));

		camel_store_summary_info_free ((CamelStoreSummary *)store->summary, si);
	}

	subscription_list = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST);
	if (subscription_list) {
		GError *err = NULL;

		/*Consult the name <-> fid hash table for a FID.*/
		status = exchange_mapi_connection_get_pf_folders_list (priv->conn, &folder_list, &err);
		if (!status)
			g_warning ("Could not get Public folder list (%s)\n", err ? err->message : "Unknown error");

		if (err)
			g_error_free (err);
	}

	temp_list = folder_list;
	list = folder_list;

	/*populate the hash table for finding the mapping from container id <-> folder name*/
	for (;temp_list != NULL; temp_list = g_slist_next (temp_list) ) {
		const gchar *full_name = NULL;
		gchar *fid = NULL, *parent_id = NULL, *tmp = NULL;
		guint *folder_type = g_new0 (guint, 1);

		fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", exchange_mapi_folder_get_fid((ExchangeMAPIFolder *)(temp_list->data)));
		parent_id = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", exchange_mapi_folder_get_parent_id ((ExchangeMAPIFolder *)(temp_list->data)));
		full_name = g_hash_table_lookup (priv->id_hash, fid);
		if (!full_name) {
			const gchar *par_full_name;

			par_full_name = g_hash_table_lookup (priv->id_hash, parent_id);
			if (par_full_name) {
				gchar *escaped = escape_slash (exchange_mapi_folder_get_name (temp_list->data));
				tmp = g_strconcat (par_full_name, "/", escaped, NULL);
				full_name = tmp;
				g_free (escaped);
			} else {
				tmp = escape_slash (exchange_mapi_folder_get_name (temp_list->data));
				full_name = tmp;
			}
		} else {
			/* known full_name - everything is escaped already */
			tmp = g_strdup (full_name);
			full_name = tmp;
		}

		/* remove from here; what lefts is not on the server any more */
		g_hash_table_remove (old_cache_folders, full_name);
		*folder_type = ((ExchangeMAPIFolder *)(temp_list->data))->container_class;
		mapi_update_folder_hash_tables (store, full_name, fid, parent_id);
		mapi_update_hash_table_type (store, full_name, folder_type);
		if (((ExchangeMAPIFolder *)(temp_list->data))->is_default) {
			guint *type = g_new0 (guint, 1);
			*type = ((ExchangeMAPIFolder *)(temp_list->data))->default_type;
			g_hash_table_insert (priv->default_folders, type,
					     g_strdup(fid));
		}
		g_free (fid);
		g_free (parent_id);
		g_free (tmp);
	}

	for (;folder_list != NULL; folder_list = g_slist_next (folder_list)) {
		ExchangeMAPIFolder *folder = (ExchangeMAPIFolder *) folder_list->data;

		if (folder->default_type == olPublicFoldersAllPublicFolders)
			continue;

		if ( folder->container_class == MAPI_FOLDER_TYPE_MAIL) {
			info = mapi_convert_to_folder_info (store, folder, NULL);
			info->flags |= CAMEL_MAPI_FOLDER_MAIL;
			mapi_si = (CamelMapiStoreInfo *) camel_store_summary_path ((CamelStoreSummary *)store->summary, info->full_name);

			if (!mapi_si) {
				gchar *fid, *pfid = NULL;

				fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X",
						       exchange_mapi_folder_get_fid((ExchangeMAPIFolder *)(folder_list->data)));
				pfid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X",
							exchange_mapi_folder_get_parent_id((ExchangeMAPIFolder *)(folder_list->data)));

				mapi_si = camel_mapi_store_summary_add_from_full (store->summary, info->full_name, '/', fid, pfid);
				g_free (fid);
				g_free (pfid);
				if (mapi_si == NULL)
					continue;

				camel_store_summary_info_ref ((CamelStoreSummary *)store->summary, (CamelStoreInfo *)mapi_si);

				if (!subscription_list) {
					camel_store_folder_created (CAMEL_STORE (store), info);
					camel_subscribable_folder_subscribed (CAMEL_SUBSCRIBABLE (store), info);
				}
			}

			mapi_si->info.flags |= info->flags;
			mapi_si->info.total = info->total;
			mapi_si->info.unread = info->unread;

			camel_store_summary_info_free ((CamelStoreSummary *)store->summary, (CamelStoreInfo *)mapi_si);
			camel_folder_info_free (info);
		} else if (folder->category == MAPI_FAVOURITE_FOLDER) {
			gchar *fid, *pfid = NULL;
			info = mapi_convert_to_folder_info (store, folder, NULL);
			mapi_si = (CamelMapiStoreInfo *) camel_store_summary_path ((CamelStoreSummary *)store->summary, info->full_name);
			fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X",
						exchange_mapi_folder_get_fid((ExchangeMAPIFolder *)(folder_list->data)));
			pfid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X",
						exchange_mapi_folder_get_parent_id((ExchangeMAPIFolder *)(folder_list->data)));
			mapi_si = camel_mapi_store_summary_add_from_full (store->summary, info->full_name, '/', fid, pfid);
			g_free (fid);
			g_free (pfid);

			if (mapi_si == NULL)
				continue;

			camel_store_summary_info_ref ((CamelStoreSummary *)store->summary, (CamelStoreInfo *)mapi_si);
			mapi_si->info.flags |= info->flags;
			camel_store_summary_info_free ((CamelStoreSummary *)store->summary, (CamelStoreInfo *)mapi_si);
			camel_folder_info_free (info);
		}
	}

	/* Weed out deleted folders */
	g_hash_table_foreach (old_cache_folders, (GHFunc) remove_path_from_store_summary, store);
	g_hash_table_destroy (old_cache_folders);

	camel_store_summary_touch ((CamelStoreSummary *)store->summary);
	camel_store_summary_save ((CamelStoreSummary *)store->summary);

	g_slist_foreach (list, (GFunc) exchange_mapi_folder_free, NULL);
	g_slist_free (list);

	priv->folders_synced = TRUE;

	//	g_hash_table_foreach (present, get_folders_free, NULL);
	//	g_hash_table_destroy (present);

	/* FIXME : This place is not right! */
	/* Start Push Notification listener */
	/* event_mask = fnevNewMail | fnevObjectCreated | fnevObjectDeleted | */
	/*	fnevObjectModified | fnevObjectMoved | fnevObjectCopied; */

	/* camel_mapi_notfication_listener_start (store, event_mask, MAPI_EVENTS_USE_STORE); */

	return TRUE;
}

static gchar *
mapi_concat ( const gchar *prefix, const gchar *suffix)
{
	gsize len;

	len = strlen (prefix);
	if (len == 0 || prefix[len - 1] == '/')
		return g_strdup_printf ("%s%s", prefix, suffix);
	else
		return g_strdup_printf ("%s%c%s", prefix, '/', suffix);
}

//do we realy need this. move to utils then !
static gint
match_path(const gchar *path, const gchar *name)
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
fix_folder_names (CamelFolderInfo *fi)
{
	while (fi) {
		if (fi->display_name && strchr (fi->display_name, '\\')) {
			gchar *unescaped;

			unescaped = unescape_slash (fi->display_name);
			g_free (fi->display_name);
			fi->display_name = unescaped;
		}

		if (fi->child)
			fix_folder_names (fi->child);

		fi = fi->next;
	}
}

static CamelFolderInfo *
mapi_get_folder_info_offline (CamelStore *store, const gchar *top,
			 guint32 flags, GError **error)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelFolderInfo *fi;
	GPtrArray *folders;
	gchar *path, *name;
	gint i;
	gboolean subscribed, subscription_list = FALSE;

	subscription_list = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST);
	subscribed = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIBED);

	folders = g_ptr_array_new ();

	if (top == NULL)
		top = "";

	/* get starting point */
	if (top[0] == 0) {
			name = g_strdup("");
	} else {
		name = camel_mapi_store_summary_full_from_path(mapi_store->summary, top);
		if (name == NULL)
			name = camel_mapi_store_summary_path_to_full(mapi_store->summary, top, '/');
	}

	path = mapi_concat (name, "*");

	for (i=0;i<camel_store_summary_count((CamelStoreSummary *)mapi_store->summary);i++) {
		CamelStoreInfo *si = camel_store_summary_index((CamelStoreSummary *)mapi_store->summary, i);

		if (si == NULL)
			continue;

		/* Allow only All Public Folders heirarchy */
		if (subscription_list && (!(si->flags & CAMEL_MAPI_FOLDER_PUBLIC))) {
			camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
			continue;
		}

		/*Allow Mailbox and Favourites (Subscribed public folders)*/
		if (subscribed && (!(si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED))) {
			camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
			continue;
		}

		if (!subscription_list && !(si->flags & CAMEL_MAPI_FOLDER_MAIL) && si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED &&
												si->flags & CAMEL_MAPI_FOLDER_PUBLIC) {
			camel_store_summary_info_free ((CamelStoreSummary *) mapi_store->summary, si);
			continue;
		}

		if (!strcmp(name, camel_mapi_store_info_full_name (mapi_store->summary, si))
		     || match_path (path, camel_mapi_store_info_full_name (mapi_store->summary, si))) {

			const gchar *store_info_path = camel_store_info_path((CamelStoreSummary *)mapi_store->summary, si);
			gchar *parent_name = NULL;
			const gchar *folder_name = NULL;

			/* TODO : UTF8 / i18n*/
			if (g_str_has_prefix (store_info_path, DISPLAY_NAME_ALL_PUBLIC_FOLDERS) && subscribed) {
				parent_name = DISPLAY_NAME_FAVOURITES;

				folder_name = strrchr(store_info_path,'/');
				if (folder_name != NULL)
					store_info_path = ++folder_name;
			}

			fi = mapi_build_folder_info(mapi_store, parent_name, store_info_path);
			fi->unread = si->unread;
			fi->total = si->total;
			fi->flags = si->flags;

			if ((fi->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_NORMAL) {
				guint folder_type = mapi_folders_hash_table_type_lookup (mapi_store, fi->full_name);
				switch (folder_type) {
				case MAPI_FOLDER_TYPE_CONTACT:
					fi->flags |= CAMEL_FOLDER_TYPE_CONTACTS;
					break;
				case MAPI_FOLDER_TYPE_APPOINTMENT:
					fi->flags |= CAMEL_FOLDER_TYPE_EVENTS;
					break;
				case MAPI_FOLDER_TYPE_MEMO:
					fi->flags |= CAMEL_FOLDER_TYPE_MEMOS;
					break;
				case MAPI_FOLDER_TYPE_TASK:
					fi->flags |= CAMEL_FOLDER_TYPE_TASKS;
					break;
				}
			}

			g_ptr_array_add (folders, fi);
		}
		camel_store_summary_info_free((CamelStoreSummary *)mapi_store->summary, si);
	}

	if (!(subscription_list) && top[0] == '\0') {
		fi = mapi_build_folder_info(mapi_store, NULL, DISPLAY_NAME_FAVOURITES);
		fi->flags |= CAMEL_FOLDER_NOSELECT;
		fi->flags |= CAMEL_FOLDER_SYSTEM;

		g_ptr_array_add (folders, fi);
	}

	g_free(name);
	g_free (path);
	fi = camel_folder_info_build (folders, top, '/', TRUE);
	g_ptr_array_free (folders, TRUE);

	fix_folder_names (fi);

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

	camel_store_summary_remove_path ((CamelStoreSummary *)mapi_store->summary, folder_name);
	camel_store_summary_save ((CamelStoreSummary *)mapi_store->summary);

	fi = mapi_build_folder_info (mapi_store, NULL, folder_name);
	camel_store_folder_deleted (CAMEL_STORE (mapi_store), fi);
	camel_folder_info_free (fi);

	return TRUE;
}

static void
mapi_rename_folder_infos (CamelMapiStore *mapi_store, const gchar *old_name, const gchar *new_name)
{
	gint sz, i, olen;
	CamelStoreInfo *si = NULL;

	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (old_name != NULL);
	g_return_if_fail (new_name != NULL);

	olen = strlen (old_name);
	sz = camel_store_summary_count ((CamelStoreSummary*) mapi_store->summary);
	for (i = 0; i < sz; i++) {
		const gchar *full_name;

		si = camel_store_summary_index ((CamelStoreSummary *) mapi_store->summary, i);
		if (!si)
			continue;

		full_name = camel_mapi_store_info_full_name (mapi_store->summary, si);
		if (full_name && g_str_has_prefix (full_name, old_name) && !g_str_equal (full_name, old_name) &&
		    full_name [olen] == '/' && full_name [olen + 1] != '\0') {
			/* it's a subfolder of old_name */
			const gchar *fid = camel_mapi_store_info_folder_id (mapi_store->summary, si);

			if (fid) {
				gchar *new_full_name;

				/* do not remove it from name_hash yet, because this function
				   will be called for it again */
				/* g_hash_table_remove (mapi_store->priv->name_hash, full_name); */
				g_hash_table_remove (mapi_store->priv->id_hash, fid);

				/* parent is still the same, only the path changed */
				new_full_name = g_strconcat (new_name, full_name + olen + (g_str_has_suffix (new_name, "/") ? 1 : 0), NULL);

				mapi_update_folder_hash_tables (mapi_store, new_full_name, fid, NULL);

				camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_STORE_INFO_PATH, new_full_name);
				camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_MAPI_STORE_INFO_FULL_NAME, new_full_name);
				camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);

				g_free (new_full_name);
			}
		}
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
	}
}

static void
mapi_store_dispose (GObject *object)
{
	CamelMapiStorePrivate *priv;

	priv = CAMEL_MAPI_STORE (object)->priv;

	if (priv->conn != NULL) {
		g_object_unref (priv->conn);
		priv->conn = NULL;
	}

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

	/* Chain up to parent's finalize() method. */
	G_OBJECT_CLASS (camel_mapi_store_parent_class)->finalize (object);
}

static guint
mapi_store_hash_folder_name (gconstpointer key)
{
	return g_str_hash(key);
}

static gint
mapi_store_compare_folder_name (gconstpointer a,
                          gconstpointer b)
{
	gconstpointer	aname = a;
	gconstpointer	bname = b;

	return g_str_equal(aname, bname);
}

static gboolean
mapi_store_can_refresh_folder (CamelStore *store,
                               CamelFolderInfo *info,
                               GError **error)
{
	CamelService *service;
	CamelSettings *settings;
	gboolean check_all;

	/* skip unselectable folders from automatic refresh */
	if (info && (info->flags & CAMEL_FOLDER_NOSELECT) != 0)
		return FALSE;

	service = CAMEL_SERVICE (store);
	settings = camel_service_get_settings (service);

	check_all = camel_mapi_settings_get_check_all (CAMEL_MAPI_SETTINGS (settings));

	return CAMEL_STORE_CLASS(camel_mapi_store_parent_class)->can_refresh_folder (store, info, error) || check_all;
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
	gchar *storage_path;

	si = camel_mapi_store_summary_full_name (mapi_store->summary, folder_name);
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
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);

	service = CAMEL_SERVICE (store);
	user_cache_dir = camel_service_get_user_cache_dir (service);

	storage_path = g_build_filename (user_cache_dir, "folders", NULL);
	folder = camel_mapi_folder_new (store, folder_name, storage_path, flags, error);
	g_free (storage_path);

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
	CamelServiceConnectionStatus status;
	CamelService *service;

	/*
	 * Thanks to Michael, for his cached folders implementation in IMAP
	 * is used as is here.
	 */

	service = CAMEL_SERVICE (store);
	status = camel_service_get_connection_status (service);

	camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

	if (camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))) {
		if (status == CAMEL_SERVICE_DISCONNECTED)
			camel_service_connect_sync (service, NULL);

		/* update folders from the server only when asking for the top most or the 'top' is not known;
		   otherwise believe the local cache, because folders sync is pretty slow operation to be done
		   one every single question on the folder info */
		status = camel_service_get_connection_status (service);
		if (((flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST) != 0 ||
		    (!(flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIBED)) ||
		    (!mapi_store->priv->folders_synced) ||
		    (top && *top && !camel_mapi_store_folder_id_lookup (mapi_store, top))) &&
		    (check_for_connection (service, NULL) || status == CAMEL_SERVICE_CONNECTING)) {
			if (!mapi_folders_sync (mapi_store, flags, error)) {
				camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
				return NULL;
			}
			camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);
			camel_store_summary_save ((CamelStoreSummary *)mapi_store->summary);
		}
	}

	camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

	return mapi_get_folder_info_offline (store, top, flags, error);
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
	GError *mapi_error = NULL;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot create MAPI folders in offline mode."));
		return NULL;
	}

	if (mapi_fid_is_system_folder (mapi_store, camel_mapi_store_folder_id_lookup (mapi_store, folder_name))) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot create new folder '%s'"),
			folder_name);
		return NULL;
	}

	if (parent_name && (strlen(parent_name) > 0) )
		parent_id = g_strdup (g_hash_table_lookup (priv->name_hash, parent_name));
	else
		parent_id = g_strdup ("");

	if (!mapi_connect_sync (CAMEL_SERVICE(store), cancellable, NULL)) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_CANT_AUTHENTICATE,
			_("Authentication failed"));
		return NULL;
	}

	camel_service_lock (CAMEL_SERVICE (store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	exchange_mapi_util_mapi_id_from_string (parent_id, &parent_fid);
	new_folder_id = exchange_mapi_connection_create_folder (priv->conn, olFolderInbox, parent_fid, 0, folder_name, &mapi_error);
	if (new_folder_id != 0) {
		CamelMapiStoreInfo *si;
		gchar *fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", new_folder_id);

		root = mapi_build_folder_info(mapi_store, parent_name, folder_name);

		si = camel_mapi_store_summary_add_from_full(mapi_store->summary, root->full_name, '/', fid, parent_id);
		si->info.flags |= CAMEL_MAPI_FOLDER_MAIL;
		camel_store_summary_save((CamelStoreSummary *)mapi_store->summary);

		mapi_update_folder_hash_tables (mapi_store, root->full_name, fid, parent_id);

		camel_store_folder_created (store, root);
		camel_subscribable_folder_subscribed (CAMEL_SUBSCRIBABLE (store), root);
	} else {
		if (mapi_error) {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Cannot create folder '%s': %s"), folder_name, mapi_error->message);
			g_error_free (mapi_error);
		} else {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Cannot create folder '%s'"), folder_name);
		}
	}

	camel_service_unlock (CAMEL_SERVICE (store), CAMEL_SERVICE_REC_CONNECT_LOCK);
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

	const gchar *folder_id;
	mapi_id_t folder_fid;
	gboolean status = FALSE;
	gboolean success = TRUE;
	GError *local_error = NULL;

	camel_service_lock (CAMEL_SERVICE (store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	if (!camel_mapi_store_connected ((CamelMapiStore *)store, &local_error)) {
		camel_service_unlock (CAMEL_SERVICE (store), CAMEL_SERVICE_REC_CONNECT_LOCK);

		if (local_error != NULL) {
			g_propagate_error (error, local_error);
			return FALSE;
		}

		return TRUE;
	}

	folder_id = g_hash_table_lookup (priv->name_hash, folder_name);
	exchange_mapi_util_mapi_id_from_string (folder_id, &folder_fid);
	status = exchange_mapi_connection_remove_folder (priv->conn, folder_fid, 0, &local_error);

	if (status) {
		/* Fixme ??  */
/*		if (mapi_store->current_folder) */
/*			g_object_unref (mapi_store->current_folder); */
		success = mapi_forget_folder(mapi_store,folder_name,error);

		/* remove from name_cache at the end, because the folder_id is from there */
		/*g_hash_table_remove (priv->parent_hash, folder_id);*/
		g_hash_table_remove (priv->id_hash, folder_id);
		g_hash_table_remove (priv->name_hash, folder_name);
	} else {
		success = FALSE;

		if (local_error) {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Cannot remove folder '%s': %s"),
				folder_name, local_error->message);

			g_error_free (local_error);
		} else {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Cannot remove folder '%s'"),
				folder_name);
		}
	}

	camel_service_unlock (CAMEL_SERVICE (store), CAMEL_SERVICE_REC_CONNECT_LOCK);

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
	CamelStoreInfo *si = NULL;
	CamelService *service;
	const gchar *user_cache_dir;
	gchar *old_parent, *new_parent, *tmp;
	gboolean move_cache = TRUE;
	const gchar *old_fid_str, *new_parent_fid_str = NULL;
	mapi_id_t old_fid;
	GError *local_error = NULL;

	service = CAMEL_SERVICE (store);
	user_cache_dir = camel_service_get_user_cache_dir (service);

	camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

	if (!camel_mapi_store_connected ((CamelMapiStore *)store, &local_error)) {
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

		if (local_error != NULL) {
			g_propagate_error (error, local_error);
			return FALSE;
		}

		return TRUE;
	}

	/* Need a full name of a folder */
	old_fid_str = camel_mapi_store_folder_id_lookup (mapi_store, old_name);
	if (!old_fid_str) {
		/*To translators : '%s' is current name of the folder */
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot rename MAPI folder '%s'. Folder does not exist."),
			old_name);
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		return FALSE;
	}

	/*Do not allow rename for system folders.*/
	if (mapi_fid_is_system_folder (mapi_store, old_fid_str)) {
		/*To translators : '%s to %s' is current name of the folder  and
		 new name of the folder.*/
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot rename MAPI default folder '%s' to '%s'."),
			old_name, new_name);
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
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

	if (!exchange_mapi_util_mapi_id_from_string (old_fid_str, &old_fid)) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot rename MAPI folder '%s' to '%s'"),
			old_name, new_name);
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		g_free (old_parent);
		g_free (new_parent);
		return FALSE;
	}

	if (tmp == NULL || g_str_equal (old_parent, new_parent)) {
		gchar *folder_id;

		/* renaming in the same folder, thus no MoveFolder necessary */
		if (!exchange_mapi_connection_rename_folder (priv->conn, old_fid, 0, tmp ? tmp : new_name, &local_error)) {
			if (local_error) {
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					/* Translators: '%s to %s' is current name of the folder and new name of the folder.
					   The last '%s' is a detailed error message. */
					_("Cannot rename MAPI folder '%s' to '%s': %s"),
					old_name, new_name, local_error->message);
				g_error_free (local_error);
			} else {
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					/* Translators: '%s to %s' is current name of the folder and new name of the folder. */
					_("Cannot rename MAPI folder '%s' to '%s'"),
					old_name, new_name);
			}

			camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
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

			new_si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, new_name);
			if (new_si) {
				si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, old_name);
				if (si) {
					/* for cases where folder sync realized new folders before this got updated;
					   this shouldn't duplicate the info in summary, but remove the old one */
					camel_store_summary_remove ((CamelStoreSummary *)mapi_store->summary, si);
					camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
					si = NULL;
				}
				camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, new_si);
			}
		} else if (!old_parent_fid_str || !new_parent_fid_str ||
			   !exchange_mapi_util_mapi_id_from_string (old_parent_fid_str, &old_parent_fid) ||
			   !exchange_mapi_util_mapi_id_from_string (new_parent_fid_str, &new_parent_fid) ||
			   !exchange_mapi_connection_move_folder (priv->conn, old_fid, old_parent_fid, 0, new_parent_fid, 0, tmp, &local_error)) {
			camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
			if (local_error) {
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					_("Cannot rename MAPI folder '%s' to '%s': %s"),
					old_name, new_name, local_error->message);
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

		folder_id = g_strdup (old_fid_str);

		/* this frees old_fid_str */
		g_hash_table_remove (priv->name_hash, old_name);
		g_hash_table_remove (priv->id_hash, folder_id);
		/*g_hash_table_remove (priv->parent_hash, folder_id);*/

		mapi_update_folder_hash_tables (mapi_store, new_name, folder_id, new_parent_fid_str);

		g_free (folder_id);
	}

	camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

	si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, old_name);
	if (si) {
		camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_STORE_INFO_PATH, new_name);
		camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_MAPI_STORE_INFO_FULL_NAME, new_name);
		if (new_parent_fid_str) {
			camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_MAPI_STORE_INFO_PARENT_ID, new_parent_fid_str);
		}
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
		camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);
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
mapi_store_noop_sync (CamelStore *store,
                      GCancellable *cancellable,
                      GError **error)
{
	return TRUE;
}

static gboolean
mapi_store_folder_is_subscribed (CamelSubscribable *subscribable,
                                 const gchar *folder_name)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (subscribable);
	CamelStoreInfo *si;
	gint truth = FALSE;

	if ((si = camel_store_summary_path ((CamelStoreSummary *) mapi_store->summary, folder_name))) {
		truth = (si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) != 0;
		camel_store_summary_info_free ((CamelStoreSummary *) mapi_store->summary, si);
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
	CamelStoreInfo *si = NULL;
	const gchar *parent_name = NULL, *use_folder_name = folder_name, *fid = NULL;
	/* TODO : exchange_mapi_add_to_favorites (); */

	fid = camel_mapi_store_folder_id_lookup(mapi_store, folder_name);

	if (g_str_has_prefix (folder_name, DISPLAY_NAME_ALL_PUBLIC_FOLDERS) ) {
		const gchar *f_name = NULL;

		parent_name = DISPLAY_NAME_FAVOURITES;

		f_name = strrchr (folder_name,'/');
		if (!f_name) {
			/* Don't process All Public Folder. */
			return TRUE;
		}

		use_folder_name = ++f_name;
	}

	si = camel_store_summary_path((CamelStoreSummary *)mapi_store->summary, folder_name);

	if (!si) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Folder '%s' not found"), folder_name);

		return FALSE;
	}

	if ((si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) == 0) {
		si->flags |= CAMEL_STORE_INFO_FOLDER_SUBSCRIBED;
		si->flags |= CAMEL_FOLDER_SUBSCRIBED;
		camel_store_summary_touch((CamelStoreSummary *)mapi_store->summary);
	}

	if (si->flags & CAMEL_MAPI_FOLDER_MAIL) {
		fi = mapi_build_folder_info (mapi_store, parent_name, use_folder_name);
		fi->unread = si->unread;
		fi->total = si->total;
		fi->flags = si->flags;
		fi->flags |= CAMEL_FOLDER_SUBSCRIBED;
		fi->flags |= CAMEL_FOLDER_NOCHILDREN;
		fi->flags |= CAMEL_STORE_INFO_FOLDER_SUBSCRIBED;
		camel_subscribable_folder_subscribed (subscribable, fi);
		camel_folder_info_free (fi);
	} else {
		CamelURL *url;
		guint folder_type = mapi_folders_hash_table_type_lookup (mapi_store, folder_name);

		url = camel_service_get_camel_url (CAMEL_SERVICE (mapi_store));
		exchange_mapi_add_esource (url, use_folder_name, fid, folder_type);
	}
	camel_store_summary_info_free((CamelStoreSummary *)mapi_store->summary, si);
	return TRUE;
}

static gboolean
mapi_store_unsubscribe_folder_sync (CamelSubscribable *subscribable,
                                    const gchar *folder_name,
                                    GCancellable *cancellable,
                                    GError **error)
{
	CamelFolderInfo *fi;
	CamelStoreInfo *si;
	gchar *parent_name = NULL;
	const gchar *fid = NULL, *use_folder_name = folder_name;
	gchar *f_name = NULL;

	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (subscribable);
	CamelURL *url;

	url = camel_service_get_camel_url (CAMEL_SERVICE (mapi_store));
	fid = camel_mapi_store_folder_id_lookup(mapi_store, folder_name);
	si = camel_store_summary_path((CamelStoreSummary *)mapi_store->summary, folder_name);
	if (si) {
		if (si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) {
			si->flags &= ~CAMEL_STORE_INFO_FOLDER_SUBSCRIBED;
			camel_store_summary_touch((CamelStoreSummary *)mapi_store->summary);
			camel_store_summary_save((CamelStoreSummary *)mapi_store->summary);
		}
	} else {
		/* no such folder in the cache, might be unsubscribed already */
		return TRUE;
	}

	if (g_str_has_prefix (folder_name, DISPLAY_NAME_ALL_PUBLIC_FOLDERS) ) {
		parent_name = DISPLAY_NAME_FAVOURITES;

		f_name = strrchr(folder_name,'/');
		if (f_name != NULL)
			folder_name = ++f_name;
		else //Don't process All Public Folder.
			return TRUE;
	}
	if (si->flags & CAMEL_MAPI_FOLDER_MAIL) {
		fi = mapi_build_folder_info (mapi_store, parent_name, folder_name);
		camel_subscribable_folder_unsubscribed (subscribable, fi);
		camel_folder_info_free (fi);
	} else {
		guint folder_type = mapi_folders_hash_table_type_lookup (mapi_store, use_folder_name);
		exchange_mapi_remove_esource(url, folder_name, fid, folder_type);
	}

	camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);

	return TRUE;
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
	service_class->query_auth_types_sync = mapi_query_auth_types_sync;

	store_class = CAMEL_STORE_CLASS (class);
	store_class->hash_folder_name = mapi_store_hash_folder_name;
	store_class->compare_folder_name = mapi_store_compare_folder_name;
	store_class->can_refresh_folder = mapi_store_can_refresh_folder;
	store_class->free_folder_info = camel_store_free_folder_info_full;
	store_class->get_folder_sync = mapi_store_get_folder_sync;
	store_class->get_folder_info_sync = mapi_store_get_folder_info_sync;
	store_class->get_junk_folder_sync = mapi_store_get_junk_folder_sync;
	store_class->get_trash_folder_sync = mapi_store_get_trash_folder_sync;
	store_class->create_folder_sync = mapi_store_create_folder_sync;
	store_class->delete_folder_sync = mapi_store_delete_folder_sync;
	store_class->rename_folder_sync = mapi_store_rename_folder_sync;
	store_class->noop_sync = mapi_store_noop_sync;
}

static void
camel_subscribable_init (CamelSubscribableInterface *interface)
{
	interface->folder_is_subscribed = mapi_store_folder_is_subscribed;
	interface->subscribe_folder_sync = mapi_store_subscribe_folder_sync;
	interface->unsubscribe_folder_sync = mapi_store_unsubscribe_folder_sync;
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
	camel_store_summary_set_filename ((CamelStoreSummary *)mapi_store->summary, path);

	camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);
	camel_store_summary_load ((CamelStoreSummary *) mapi_store->summary);

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
	CamelURL *url;

	url = camel_service_get_camel_url (service);

	if (brief) {
		/* Translators: The %s is replaced with a server's host name */
		return g_strdup_printf(_("Exchange MAPI server %s"), url->host);
	} else {
		/*To translators : Example string : Exchange MAPI service for
		  _username_ on _server host name__*/
		return g_strdup_printf(_("Exchange MAPI service for %s on %s"),
				       url->user, url->host);
	}
}

static gboolean
mapi_prompt_pass_creds (CamelService *service, CamelURL *url, const gchar *reason, GError **error) {
	gchar *prompt;
	gchar *new_passwd;
	const gchar *password;
	guint32 prompt_flags = CAMEL_SESSION_PASSWORD_SECRET;
	CamelSession *session = camel_service_get_session (service);

	if (reason) {
		/* We need to un-cache the password before prompting again */
		prompt_flags |= CAMEL_SESSION_PASSWORD_REPROMPT;
		camel_service_set_password (service, NULL);
	}

	/*To translators : First %s : is the error text or the reason
	  for prompting the user if it is available.
	 Second %s is : Username.
	 Third %s is : Server host name.*/
	prompt = g_strdup_printf (_("%s Please enter the MAPI password for %s@%s"), reason ? reason : "", url->user, url->host);

	/* XXX This is a tad awkward.  Maybe define a
	 *     camel_service_ask_password() that calls
	 *     camel_session_get_password() and caches
	 *     the password itself? */
	new_passwd = camel_session_get_password (session, service, prompt, "password", prompt_flags, NULL);
	camel_service_set_password (service, new_passwd);
	password = camel_service_get_password (service);
	g_free (new_passwd);

	g_free (prompt);

	if (password == NULL) {
		if (error && !*error)
			g_set_error (
				error, G_IO_ERROR,
				G_IO_ERROR_CANCELLED,
				_("You did not enter a password."));
		return FALSE;
	}

	return TRUE;
}

static gboolean
mapi_auth_loop (CamelService *service, GError **error)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);
	CamelURL *url;
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	ExchangeMapiProfileData empd = { 0 };

	gchar *errbuf = NULL;
	gboolean authenticated = FALSE, ret = TRUE, krb_requested = FALSE;
	const gchar *profile;

	url = camel_service_get_camel_url (service);
	settings = camel_service_get_settings (service);
	mapi_settings = CAMEL_MAPI_SETTINGS (settings);

	empd.server = url->host;
	empd.username = url->user;
	exchange_mapi_util_profiledata_from_settings (&empd, mapi_settings);

	profile = camel_mapi_settings_get_profile (mapi_settings);

	camel_service_set_password (service, NULL);

	while (!authenticated) {
		const gchar *password;
		GError *mapi_error = NULL;

		password = camel_service_get_password (service);

		if (password == NULL || errbuf) {
			const gchar *why = errbuf ? errbuf : NULL;

			if (empd.krb_sso) {
				if (!krb_requested) {
					ret = exchange_mapi_util_trigger_krb_auth (&empd, error);
					krb_requested = TRUE;
				} else {
					ret = FALSE;
				}
			} else {
				ret = mapi_prompt_pass_creds (service, url, why, error);
			}

			g_free (errbuf);
			errbuf = NULL;
		}

		if (!ret || (error && *error)) {
			return FALSE;
		}

		password = camel_service_get_password (service);
		store->priv->conn = exchange_mapi_connection_new (profile, password, &mapi_error);
		if (!store->priv->conn || !exchange_mapi_connection_connected (store->priv->conn)) {
			if (mapi_error) {
				errbuf = g_strdup_printf (_("Unable to authenticate to Exchange MAPI server: %s"), mapi_error->message);
				g_error_free (mapi_error);
			} else {
				errbuf = g_strdup (_("Unable to authenticate to Exchange MAPI server"));
			}
		} else
			authenticated = TRUE;

	}
	return TRUE;
}

static gboolean
mapi_connect_sync (CamelService *service,
                   GCancellable *cancellable,
                   GError **error)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);
	CamelServiceConnectionStatus status;
	guint16 event_mask = 0;

	status = camel_service_get_connection_status (service);
	if (status == CAMEL_SERVICE_DISCONNECTED) {
		return FALSE;
	}

	camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
	if (check_for_connection (service, NULL)) {
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		return TRUE;
	}

	if (!mapi_auth_loop (service, error)) {
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		camel_service_disconnect_sync (service, TRUE, NULL);
		return FALSE;
	}

	camel_offline_store_set_online_sync (
		CAMEL_OFFLINE_STORE (store), TRUE, cancellable, NULL);

	/* Start event monitor */
	event_mask = fnevNewMail | fnevObjectCreated | fnevObjectDeleted |
		fnevObjectModified | fnevObjectMoved | fnevObjectCopied;

	/* use MAPI_LISTEN_NOTIFY=1 to enable notifications */
	if (!store->priv->notification_data && g_getenv ("MAPI_LISTEN_NOTIFY") != NULL)
		store->priv->notification_data = camel_mapi_notification_listener_start (store, event_mask, MAPI_EVENTS_USE_STORE);

	camel_store_summary_save ((CamelStoreSummary *) store->summary);

	camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

	return TRUE;
}

void
camel_mapi_store_unset_notification_data (CamelMapiStore *mstore)
{
	g_return_if_fail (mstore != NULL);
	g_return_if_fail (CAMEL_IS_MAPI_STORE (mstore));

	mstore->priv->notification_data = NULL;
}

static gboolean
mapi_disconnect_sync (CamelService *service,
                      gboolean clean,
                      GCancellable *cancellable,
                      GError **error)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);

	/* Disconnect from event monitor */
	if (store->priv->notification_data) {
		camel_mapi_notification_listener_stop (store, store->priv->notification_data);
		store->priv->notification_data = NULL;
	}

	if (store->priv->conn) {
		/* Close the mapi subsystem */
		g_object_unref (store->priv->conn);
		store->priv->conn = NULL;
	}

	store->priv->folders_synced = FALSE;

	return TRUE;
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

static guint32 hexnib(guint32 c)
{
	if (c >= '0' && c <= '9')
		return c-'0';
	else if (c>='A' && c <= 'Z')
		return c-'A'+10;
	else
		return 0;
}

gchar *
camel_mapi_store_summary_path_to_full(CamelMapiStoreSummary *s, const gchar *path, gchar dir_sep)
{
	gchar *full, *f;
	guint32 c, v = 0;
	const gchar *p;
	gint state=0;
	gchar *subpath, *last = NULL;
	CamelStoreInfo *si;

	/* check to see if we have a subpath of path already defined */
	subpath = alloca(strlen(path)+1);
	strcpy(subpath, path);
	do {
		si = camel_store_summary_path((CamelStoreSummary *)s, subpath);
		if (si == NULL) {
			last = strrchr(subpath, '/');
			if (last)
				*last = 0;
		}
	} while (si == NULL && last);

	/* path is already present, use the raw version we have */
	if (si && strlen(subpath) == strlen(path)) {
		f = g_strdup(camel_mapi_store_info_full_name(s, si));
		camel_store_summary_info_free((CamelStoreSummary *)s, si);
		return f;
	}

	f = full = alloca(strlen(path)*2+1);
	if (si)
		p = path + strlen(subpath);
	else
		p = path;

	while ((c = camel_utf8_getc((const guchar **)&p))) {
		switch (state) {
			case 0:
				if (c == '%')
					state = 1;
				else {
					if (c == '/')
						c = dir_sep;
					camel_utf8_putc((guchar **)&f, c);
				}
				break;
			case 1:
				state = 2;
				v = hexnib(c)<<4;
				break;
			case 2:
				state = 0;
				v |= hexnib(c);
				camel_utf8_putc((guchar **)&f, v);
				break;
		}
	}
	camel_utf8_putc((guchar **)&f, c);

	/* merge old path part if required */
	f = g_strdup (full);
	if (si) {
		full = g_strdup_printf("%s%s", camel_mapi_store_info_full_name(s, si), f);
		g_free(f);
		camel_store_summary_info_free((CamelStoreSummary *)s, si);
		f = full;
	}

	return f;
}

static CamelFolderInfo *
mapi_build_folder_info(CamelMapiStore *mapi_store, const gchar *parent_name, const gchar *folder_name)
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
camel_mapi_store_connected (CamelMapiStore *store, GError **error)
{
	return camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store))
	    && camel_service_connect_sync ((CamelService *)store, error);
}

static void
mapi_update_hash_table_type (CamelMapiStore *store, const gchar *full_name, guint *folder_type)
{
	CamelMapiStorePrivate  *priv = store->priv;
	if (full_name && folder_type) {
		if (!g_hash_table_lookup (priv->container_hash, full_name))
			g_hash_table_insert (priv->container_hash, g_strdup (full_name), folder_type);
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
	CamelStoreSummary *summary = (CamelStoreSummary *) store->summary;
	gint summary_count = camel_store_summary_count (summary);
	guint i = 0;

	for (i = 0; i < summary_count; i++) {
		CamelMapiStoreInfo *si = (CamelMapiStoreInfo *) camel_store_summary_index(summary, i);

		if (si == NULL) continue;

		mapi_update_folder_hash_tables (store, si->full_name, si->folder_id, si->parent_id);
		camel_store_summary_info_free (summary, (CamelStoreInfo *)si);
	}
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
mapi_folders_hash_table_name_lookup (CamelMapiStore *store, const gchar *fid,
				     gboolean use_cache)
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
camel_mapi_store_folder_id_lookup_offline (CamelMapiStore *mapi_store, const gchar *folder_name)
{
	CamelMapiStoreInfo *mapi_si;
	const gchar *folder_id;

	mapi_si = (CamelMapiStoreInfo *)camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, folder_name);
	g_return_val_if_fail (mapi_si != NULL, NULL);
	folder_id = mapi_si->folder_id;

	/* shouldn't be the last reference to it, right? */
	camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, (CamelStoreInfo *) mapi_si);

	return folder_id;
}

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

ExchangeMapiConnection *
camel_mapi_store_get_exchange_connection (CamelMapiStore *mapi_store)
{
	g_return_val_if_fail (mapi_store != NULL, NULL);
	g_return_val_if_fail (CAMEL_IS_MAPI_STORE (mapi_store), NULL);
	g_return_val_if_fail (mapi_store->priv != NULL, NULL);

	return mapi_store->priv->conn;
}

