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

#include <string.h>
#include <time.h>

#include <glib.h>

#include <libmapi/libmapi.h>
#include <exchange-mapi-defs.h>
#include <exchange-mapi-utils.h>
#include <exchange-mapi-folder.h>
#include <exchange-mapi-cal-utils.h>
#include "exchange-mapi-mail-utils.h"

#include "camel-mapi-store.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-private.h"
#include "camel-mapi-summary.h"
#include "camel-mapi-utils.h"

#define DEBUG_FN( ) printf("----%p %s\n", g_thread_self(), G_STRFUNC);
#define SUMMARY_FETCH_BATCH_COUNT 150
#define d(x)

#define CAMEL_MAPI_FOLDER_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE \
	((obj), CAMEL_TYPE_MAPI_FOLDER, CamelMapiFolderPrivate))

struct _CamelMapiFolderPrivate {

//#ifdef ENABLE_THREADS
	GStaticMutex search_lock;	/* for locking the search object */
//#endif

};

/*for syncing flags back to server*/
typedef struct {
	guint32 changed;
	guint32 bits;
} flags_diff_t;

/*For collecting summary info from server*/

static void mapi_update_cache (CamelFolder *folder, GSList *list, CamelFolderChangeInfo **changeinfo,
			       GCancellable *cancellable, GError **error, gboolean uid_flag);

static gboolean		mapi_folder_synchronize_sync
						(CamelFolder *folder,
						 gboolean expunge,
						 GCancellable *cancellable,
						 GError **error);

G_DEFINE_TYPE (CamelMapiFolder, camel_mapi_folder, CAMEL_TYPE_OFFLINE_FOLDER)

static GPtrArray *
mapi_folder_search_by_expression (CamelFolder *folder, const gchar *expression, GError **error)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER(folder);
	GPtrArray *matches;

	CAMEL_MAPI_FOLDER_LOCK(mapi_folder, search_lock);
	camel_folder_search_set_folder (mapi_folder->search, folder);
	matches = camel_folder_search_search(mapi_folder->search, expression, NULL, error);
	CAMEL_MAPI_FOLDER_UNLOCK(mapi_folder, search_lock);

	return matches;
}

static GPtrArray *
mapi_folder_search_by_uids (CamelFolder *folder, const gchar *expression, GPtrArray *uids, GError **error)
{
	GPtrArray *matches;
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);

	if (uids->len == 0)
		return g_ptr_array_new ();

	CAMEL_MAPI_FOLDER_LOCK (mapi_folder, search_lock);
	camel_folder_search_set_folder (mapi_folder->search, folder);
	matches = camel_folder_search_search (mapi_folder->search, expression, uids, error);
	CAMEL_MAPI_FOLDER_UNLOCK (mapi_folder, search_lock);

	return matches;
}

static gboolean
update_store_summary (CamelFolder *folder, GError **error)
{
	CamelStore *parent_store;
	CamelStoreSummary *store_summary;
	CamelStoreInfo *si;
	const gchar *full_name;
	gint retval;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);
	store_summary = (CamelStoreSummary *)((CamelMapiStore *)parent_store)->summary;

	si = camel_store_summary_path (store_summary, full_name);

	if (si) {
		guint32 unread, total;

		unread = folder->summary->unread_count;
		total = camel_folder_summary_count (folder->summary);

		if (si->total != total || si->unread != unread) {
			si->total = total;
			si->unread = unread;
			camel_store_summary_touch (store_summary);
		}
		camel_store_summary_info_free (store_summary, si);
	}

	retval = camel_folder_summary_save_to_db (folder->summary, error);
	camel_store_summary_save (store_summary);

	return (retval == 0);
}

static gboolean
fetch_items_summary_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	fetch_items_data *fi_data = (fetch_items_data *)data;

	GSList **slist = &(fi_data->items_list);

	long *flags = NULL;
	struct FILETIME *delivery_date = NULL;
	struct FILETIME *last_modification_time = NULL;
	struct timeval item_modification_time = { 0 };
	struct timeval fi_data_mod_time = { 0 };
	guint32 j = 0;

	MailItem *item = g_new0(MailItem , 1);

	if (camel_debug_start("mapi:folder")) {
		exchange_mapi_debug_property_dump (item_data->properties);
		camel_debug_end();
	}

	item->fid = item_data->fid;
	item->mid = item_data->mid;

	/*Hold a reference to Recipient List*/
	item->recipients = item_data->recipients;

	for (j = 0; j < item_data->properties->cValues; j++) {
		gconstpointer prop_data = get_mapi_SPropValue_data(&item_data->properties->lpProps[j]);

		if (fetch_read_item_common_data (item, item_data->properties->lpProps[j].ulPropTag, prop_data))
			continue;

		switch (item_data->properties->lpProps[j].ulPropTag) {
		case PR_MESSAGE_DELIVERY_TIME:
			delivery_date = (struct FILETIME *) prop_data;
			break;
		case PR_LAST_MODIFICATION_TIME:
			last_modification_time = (struct FILETIME *) prop_data;
			break;
		case PR_MESSAGE_FLAGS:
			flags = (long *) prop_data;
			break;
		default:
			break;
		}
	}

	/* item->header.from = camel_internet_address_format_address (from_name, from_email); */

	if (delivery_date) {
		item->header.recieved_time = exchange_mapi_util_filetime_to_time_t (delivery_date);
	}

	if (last_modification_time) {
		item_modification_time.tv_sec = exchange_mapi_util_filetime_to_time_t (last_modification_time);
		item_modification_time.tv_usec = 0;
	}

	fi_data_mod_time.tv_sec = fi_data->last_modification_time.tv_sec;
	fi_data_mod_time.tv_usec = fi_data->last_modification_time.tv_usec;

	if (timeval_compare (&item_modification_time, &fi_data_mod_time) == 1) {
		fi_data->last_modification_time.tv_sec = item_modification_time.tv_sec;
		fi_data->last_modification_time.tv_usec = item_modification_time.tv_usec;
	}

	if ((*flags & MSGFLAG_READ) != 0)
		item->header.flags |= CAMEL_MESSAGE_SEEN;
	if ((*flags & MSGFLAG_HASATTACH) != 0)
		item->header.flags |= CAMEL_MESSAGE_ATTACHMENTS;

	*slist = g_slist_prepend (*slist, item);

	/*Write summary to db in batches of SUMMARY_FETCH_BATCH_COUNT items.*/
	if ((item_data->index % SUMMARY_FETCH_BATCH_COUNT == 0) ||
	     item_data->index == item_data->total-1) {
		mapi_update_cache (fi_data->folder, *slist, &fi_data->changes, NULL, NULL, false);
		g_slist_foreach (*slist, (GFunc)mail_item_free, NULL);
		g_slist_free (*slist);
		*slist = NULL;
	}

	if (item_data->total > 0)
               camel_operation_progress (NULL, (item_data->index * 100)/item_data->total);

	if (camel_operation_cancel_check(NULL))
		return FALSE;

	return TRUE;
}

static void
mapi_set_message_id (CamelMapiMessageInfo *mapi_mi, const gchar *message_id)
{
	gchar *msgid;
	guint8 *digest;
	gsize length;
	CamelMessageInfoBase *mi = &mapi_mi->info;

	msgid = camel_header_msgid_decode (message_id);
	if (msgid) {
		GChecksum *checksum;

		length = g_checksum_type_get_length (G_CHECKSUM_MD5);
		digest = g_alloca (length);

		checksum = g_checksum_new (G_CHECKSUM_MD5);
		g_checksum_update (checksum, (guchar *) msgid, -1);
		g_checksum_get_digest (checksum, digest, &length);
		g_checksum_free (checksum);

		memcpy(mi->message_id.id.hash, digest, sizeof(mi->message_id.id.hash));
		g_free(msgid);
	}

}

static void
mapi_set_message_references (CamelMapiMessageInfo *mapi_mi, const gchar *references, const gchar *in_reply_to)
{
	struct _camel_header_references *refs, *irt, *scan;
	guint8 *digest;
	gint count;
	gsize length;
	CamelMessageInfoBase *mi = &mapi_mi->info;

	refs = camel_header_references_decode (references);
	irt = camel_header_references_inreplyto_decode (in_reply_to);
	if (refs || irt) {
		if (irt) {
			/* The References field is populated from the "References" and/or "In-Reply-To"
			   headers. If both headers exist, take the first thing in the In-Reply-To header
			   that looks like a Message-ID, and append it to the References header. */

			if (refs)
				irt->next = refs;

			refs = irt;
		}

		count = camel_header_references_list_size(&refs);
		mi->references = g_malloc(sizeof(*mi->references) + ((count-1) * sizeof(mi->references->references[0])));

		length = g_checksum_type_get_length (G_CHECKSUM_MD5);
		digest = g_alloca (length);

		count = 0;
		scan = refs;
		while (scan) {
			GChecksum *checksum;

			checksum = g_checksum_new (G_CHECKSUM_MD5);
			g_checksum_update (checksum, (guchar *) scan->id, -1);
			g_checksum_get_digest (checksum, digest, &length);
			g_checksum_free (checksum);

			memcpy(mi->references->references[count].id.hash, digest, sizeof(mi->message_id.id.hash));
			count++;
			scan = scan->next;
		}
		mi->references->size = count;
		camel_header_references_list_clear(&refs);
	}
}

static void
mapi_update_cache (CamelFolder *folder, GSList *list, CamelFolderChangeInfo **changeinfo,
		   GCancellable *cancellable, GError **error, gboolean uid_flag)
{
	CamelMapiMessageInfo *mi = NULL;
	CamelMessageInfo *pmi = NULL;
	CamelMapiStore *mapi_store;
	CamelStore *parent_store;

	guint32 status_flags = 0;
	CamelFolderChangeInfo *changes = NULL;
	gboolean exists = FALSE;
	GString *str = g_string_new (NULL);
	const gchar *folder_id = NULL;
	const gchar *full_name;
	GSList *item_list = list;
	gint total_items = g_slist_length (item_list), i=0;

	changes = *changeinfo;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	mapi_store = CAMEL_MAPI_STORE (parent_store);

	folder_id = camel_mapi_store_folder_id_lookup (mapi_store, full_name);

	if (!folder_id) {
		d(printf("\nERROR - Folder id not present. Cannot refresh info\n"));
		return;
	}

	camel_operation_push_message (
		cancellable,
		_("Updating local summary cache for new messages in %s"),
		camel_folder_get_name (folder));

	for (; item_list != NULL; item_list = g_slist_next (item_list) ) {
		MailItem *temp_item;
		MailItem *item;
		gchar *msg_uid;
		guint64 id;

		exists = FALSE;
		status_flags = 0;

		if (uid_flag == FALSE) {
			temp_item = (MailItem *)item_list->data;
			id = temp_item->mid;
			item = temp_item;
		}

		camel_operation_progress (cancellable, (100*i)/total_items);

		/************************ First populate summary *************************/
		mi = NULL;
		pmi = NULL;
		msg_uid = exchange_mapi_util_mapi_ids_to_uid (item->fid, item->mid);
		pmi = camel_folder_summary_uid (folder->summary, msg_uid);

		if (pmi) {
			exists = TRUE;
			camel_message_info_ref (pmi);
			mi = (CamelMapiMessageInfo *)pmi;
		}

		if (!exists) {
			mi = (CamelMapiMessageInfo *)camel_message_info_new (folder->summary);
			if (mi->info.content == NULL) {
				mi->info.content = camel_folder_summary_content_info_new (folder->summary);
				mi->info.content->type = camel_content_type_new ("multipart", "related");
			}
		}

		mi->info.flags = item->header.flags;
		mi->server_flags = mi->info.flags;

		if (!exists) {
			GSList *l = NULL;
			guint32 count_to = 0, count_cc =0;
			gchar *to = NULL, *cc = NULL;

			mi->info.uid = exchange_mapi_util_mapi_ids_to_uid(item->fid, item->mid);
			mi->info.subject = camel_pstring_strdup(item->header.subject);
			mi->info.date_sent = mi->info.date_received = item->header.recieved_time;
			mi->info.size = (guint32) item->header.size;

			/*Threading related properties*/
			mapi_set_message_id (mi, item->header.message_id);
			if (item->header.references || item->header.in_reply_to)
				mapi_set_message_references (mi, item->header.references, item->header.in_reply_to);

			/*Recipients*/
			for (l = item->recipients; l; l=l->next) {
				gchar *formatted_id = NULL;
				const gchar *name, *display_name;
				guint32 *type = NULL;
				struct SRow *aRow;
				ExchangeMAPIRecipient *recip = (ExchangeMAPIRecipient *)(l->data);

				/*Can't continue when there is no email-id*/
				if (!recip->email_id)
					continue;

				/* Build a SRow structure */
				aRow = &recip->out_SRow;

				type = (uint32_t *) exchange_mapi_util_find_row_propval (aRow, PR_RECIPIENT_TYPE);

				if (type) {
					name = (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_DISPLAY_NAME_UNICODE);
					name = name ? name : (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
					name = name ? name : (const gchar *) exchange_mapi_util_find_row_propval (aRow,
												 PR_7BIT_DISPLAY_NAME_UNICODE);
					display_name = name ? name : recip->email_id;
					formatted_id = camel_internet_address_format_address(display_name, recip->email_id);

					switch (*type) {
					case MAPI_TO:
						if (count_to) {
							gchar *tmp = to;
							to = g_strconcat (to, ", ", formatted_id, NULL);
							g_free (formatted_id);
							g_free (tmp);
						} else
							to = formatted_id;
						count_to++;
						break;

					case MAPI_CC:
						if (count_cc) {
							gchar *tmp = cc;
							cc = g_strconcat (cc, ", ", formatted_id, NULL);
							g_free (formatted_id);
							g_free (tmp);
						} else
							cc = formatted_id;
						count_cc++;
						break;

					default:
						continue;
					}
				}
			}

			if ((item->header.from_type != NULL) && !g_utf8_collate (item->header.from_type, "EX")) {
				gchar *from_email;

				camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
				from_email = exchange_mapi_connection_ex_to_smtp (camel_mapi_store_get_exchange_connection (mapi_store), item->header.from_email, NULL);
				camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

				g_free (item->header.from_email);
				item->header.from_email = from_email;
			}

			item->header.from_email = item->header.from_email ?
				item->header.from_email : item->header.from;

			if (item->header.from_email) {
				gchar *from = camel_internet_address_format_address (item->header.from,
										     item->header.from_email);
				mi->info.from = camel_pstring_strdup (from);

				g_free (from);
			} else
				mi->info.from = NULL;

			/* Fallback */
			mi->info.to = to ? camel_pstring_strdup (to) : camel_pstring_strdup (item->header.to);
			mi->info.cc = cc ? camel_pstring_strdup (cc) : camel_pstring_strdup (item->header.cc);

			g_free (to);
			g_free (cc);
		}

		if (exists) {
			camel_folder_change_info_change_uid (changes, mi->info.uid);
			camel_message_info_free (pmi);
		} else {
			camel_folder_summary_lock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
			camel_folder_summary_add (folder->summary,(CamelMessageInfo *)mi);
			camel_folder_change_info_add_uid (changes, mi->info.uid);
			camel_folder_change_info_recent_uid (changes, mi->info.uid);
			camel_folder_summary_unlock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
		}

		/********************* Summary ends *************************/
		/* FIXME : Don't use folder names for identifying */
		if (!strcmp (camel_folder_get_full_name (folder), "Junk Mail"))
			continue;

		g_free (msg_uid);
		i++;
	}
	camel_operation_pop_message (cancellable);

	g_string_free (str, TRUE);
}

static void
mapi_utils_do_flags_diff (flags_diff_t *diff, guint32 old, guint32 _new)
{
	diff->changed = old ^ _new;
	diff->bits = _new & diff->changed;
}

struct mapi_update_deleted_msg {
	CamelSessionThreadMsg msg;

	CamelFolder *folder;
	mapi_id_t folder_id;
	gboolean need_refresh;
};

static gboolean
deleted_items_sync_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	guint32 msg_flags = CAMEL_MESSAGE_FOLDER_FLAGGED; /* to not have 0 in the hash table */
	GHashTable *uids = data;
	gchar *msg_uid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid,
							     item_data->mid);

	if ((item_data->msg_flags & MSGFLAG_READ) != 0)
		msg_flags |= CAMEL_MESSAGE_SEEN;
	if ((item_data->msg_flags & MSGFLAG_HASATTACH) != 0)
		msg_flags |= CAMEL_MESSAGE_ATTACHMENTS;

	g_hash_table_insert (uids, msg_uid, GINT_TO_POINTER (msg_flags));

	/* Progress update */
	if (item_data->total > 0)
		camel_operation_progress (NULL, (item_data->index * 100)/item_data->total);

	/* Check if we have to stop */
	if (camel_operation_cancel_check(NULL))
		return FALSE;

	return TRUE;
}

static void
mapi_sync_deleted (CamelSession *session, CamelSessionThreadMsg *msg)
{
	struct mapi_update_deleted_msg *m = (struct mapi_update_deleted_msg *)msg;

	CamelMapiStore *mapi_store;
	CamelMapiFolder *mapi_folder;
	CamelFolderChangeInfo *changes = NULL;
	CamelMessageInfo *info = NULL;
	CamelStore *parent_store;

	guint32 index, count, options = 0;
	GHashTable *server_messages = NULL;
	const gchar *uid = NULL;
	gboolean flags_changed = FALSE;

	parent_store = camel_folder_get_parent_store (m->folder);

	mapi_folder = CAMEL_MAPI_FOLDER (m->folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store)) ||
			((CamelService *)mapi_store)->status == CAMEL_SERVICE_DISCONNECTED) {

		return;
	}

	camel_operation_push_message (
		NULL, _("Retrieving message IDs from server for %s"),
		camel_folder_get_name (m->folder));

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	if (mapi_folder->type & CAMEL_MAPI_FOLDER_PUBLIC)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	server_messages = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	/*Get the UID list from server.*/
	exchange_mapi_connection_fetch_items (camel_mapi_store_get_exchange_connection (mapi_store), m->folder_id, NULL, NULL,
					       NULL, NULL,
					       deleted_items_sync_cb, server_messages,
					       options | MAPI_OPTIONS_DONT_OPEN_MESSAGE, NULL);

	camel_operation_pop_message (NULL);

	camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	/* Check if we have to stop */
	if (camel_operation_cancel_check(NULL)) {
		g_hash_table_destroy (server_messages);
		return;
	}

	changes = camel_folder_change_info_new ();

	count = camel_folder_summary_count (m->folder->summary);
	camel_operation_push_message (
		NULL, _("Removing deleted messages from cache in %s"),
		camel_folder_get_name (m->folder));

	/* Iterate over cache and check if the UID is in server*/
	for (index = 0; index < count; index++) {
		guint32 msg_flags;

		/* Iterate in a reverse order, thus removal will not hurt */
		info = camel_folder_summary_index (m->folder->summary, count - index - 1);
		if (!info) continue; /*This is bad. *Should* not happen*/

		uid = camel_message_info_uid (info);
		if (!uid) {
			camel_message_info_free (info);
			continue;
		}

		msg_flags = GPOINTER_TO_INT (g_hash_table_lookup (server_messages, uid));

		/* If it is not in server list, clean our cache */
		if (!msg_flags) {
			camel_folder_summary_lock (m->folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
			camel_folder_summary_remove_uid (m->folder->summary, uid);
			camel_data_cache_remove (mapi_folder->cache, "cache", uid, NULL);
			camel_folder_change_info_remove_uid (changes, uid);
			camel_folder_summary_unlock (m->folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
		} else {
			CamelMapiMessageInfo *mapi_info = (CamelMapiMessageInfo *) info;

			msg_flags = msg_flags & (~CAMEL_MESSAGE_FOLDER_FLAGGED);
			if (mapi_info->server_flags != msg_flags) {
				mapi_info->server_flags = msg_flags;
				camel_message_info_set_flags (info, msg_flags, CAMEL_MESSAGE_SEEN | CAMEL_MESSAGE_ATTACHMENTS);
				camel_folder_change_info_change_uid (changes, uid);
				flags_changed = TRUE;
			}
		}

		camel_message_info_free (info);

		/* Progress update */
		camel_operation_progress (NULL, (index * 100)/count); /* ;-) */

		/* Check if we have to stop */
		if (camel_operation_cancel_check(NULL)) {
			g_hash_table_destroy (server_messages);
			if (camel_folder_change_info_changed (changes))
				camel_folder_changed (m->folder, changes);
			camel_folder_change_info_free (changes);
			return;
		}
	}

	camel_operation_pop_message (NULL);

	if (camel_folder_change_info_changed (changes)) {
		if (flags_changed)
			camel_mapi_summary_update_store_info_counts (CAMEL_MAPI_SUMMARY (CAMEL_FOLDER (mapi_folder)->summary));
		camel_folder_changed (m->folder, changes);
	}
	camel_folder_change_info_free (changes);

	m->need_refresh = camel_folder_summary_count (m->folder->summary) != g_hash_table_size (server_messages);

	g_hash_table_destroy (server_messages);
}

static void
mapi_sync_deleted_free (CamelSession *session, CamelSessionThreadMsg *msg)
{
	struct mapi_update_deleted_msg *m = (struct mapi_update_deleted_msg *)msg;
	CamelStore *parent_store;

	parent_store = camel_folder_get_parent_store (m->folder);

	if (m->need_refresh) {
		CamelMapiSummary *mapi_summary = CAMEL_MAPI_SUMMARY (m->folder->summary);
		if (mapi_summary) {
			GError *local_error = NULL;

			camel_service_lock (CAMEL_SERVICE (parent_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
			g_free (mapi_summary->sync_time_stamp);
			mapi_summary->sync_time_stamp = NULL;
			camel_service_unlock (CAMEL_SERVICE (parent_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

			/* FIXME Need to pass a GCancellable here. */
			if (!mapi_refresh_folder (m->folder, NULL, &local_error)) {
				g_warning ("%s: %s", G_STRFUNC, local_error->message);
				g_error_free (local_error);
			}
		}
	}

	g_object_unref (m->folder);
}

static CamelSessionThreadOps deleted_items_sync_ops = {
	mapi_sync_deleted,
	mapi_sync_deleted_free,
};

static gboolean
mapi_camel_get_summary_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
{
	static const uint32_t summary_prop_list[] = {
		PR_INTERNET_CPID,
		PR_SUBJECT_UNICODE,
		PR_MESSAGE_SIZE,
		PR_MESSAGE_DELIVERY_TIME,
		PR_MESSAGE_FLAGS,
		PR_SENT_REPRESENTING_NAME_UNICODE,
		PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE,
		PR_SENT_REPRESENTING_ADDRTYPE_UNICODE,
		PR_LAST_MODIFICATION_TIME,
		PR_INTERNET_MESSAGE_ID,
		PR_INTERNET_REFERENCES,
		PR_IN_REPLY_TO_ID,
		PR_DISPLAY_TO_UNICODE,
		PR_DISPLAY_CC_UNICODE,
		PR_DISPLAY_BCC_UNICODE,
		PR_TRANSPORT_MESSAGE_HEADERS_UNICODE
	};

	g_return_val_if_fail (props != NULL, FALSE);

	return exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, summary_prop_list, G_N_ELEMENTS (summary_prop_list));
}

gboolean
camel_mapi_folder_fetch_summary (CamelStore *store, CamelFolder *folder, const mapi_id_t fid, struct mapi_SRestriction *res,
				 struct SSortOrderSet *sort, fetch_items_data *fetch_data, guint32 options, GCancellable *cancellable, GError **mapi_error)
{
	gboolean status;
	CamelMapiStore *mapi_store = (CamelMapiStore *) store;

	/*TODO : Check for online state*/

	camel_operation_push_message (cancellable, _("Fetching summary information for new messages in %s"), camel_folder_get_name (folder));

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	status = exchange_mapi_connection_fetch_items  (camel_mapi_store_get_exchange_connection (mapi_store), fid, res, sort,
							mapi_camel_get_summary_list, NULL,
							fetch_items_summary_cb, fetch_data,
							options, mapi_error);

	camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	camel_operation_pop_message (cancellable);

	return status;
}

gboolean
mapi_refresh_folder(CamelFolder *folder, GCancellable *cancellable, GError **error)
{

	CamelMapiStore *mapi_store;
	CamelMapiFolder *mapi_folder;
	CamelMapiSummary *mapi_summary;
	CamelSession *session;
	CamelStore *parent_store;

	gboolean is_proxy;
	gboolean is_locked = FALSE;
	gboolean status;
	gboolean success = TRUE;

	TALLOC_CTX *mem_ctx = NULL;
	struct mapi_SRestriction *res = NULL;
	struct SSortOrderSet *sort = NULL;
	struct mapi_update_deleted_msg *deleted_items_op_msg;
	fetch_items_data *fetch_data = g_new0 (fetch_items_data, 1);
	const gchar *folder_id = NULL;
	const gchar *full_name;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);
	mapi_summary = CAMEL_MAPI_SUMMARY (folder->summary);

	is_proxy = parent_store->flags & CAMEL_STORE_PROXY;
	session = CAMEL_SERVICE (parent_store)->session;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store)))
		goto end1;

	/* Sync-up the (un)read changes before getting updates,
	so that the getFolderList will reflect the most recent changes too */
	mapi_folder_synchronize_sync (folder, FALSE, cancellable, NULL);

	//creating a copy
	folder_id = camel_mapi_store_folder_id_lookup (mapi_store, full_name);
	if (!folder_id) {
		d(printf ("\nERROR - Folder id not present. Cannot refresh info for %s\n", full_name));
		goto end1;
	}

	if (camel_folder_is_frozen (folder) ) {
		mapi_folder->need_refresh = TRUE;
	}

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	is_locked = TRUE;

	if (!camel_mapi_store_connected (mapi_store, NULL))
		goto end1;

	/*Get the New Items*/
	if (!is_proxy) {
		mapi_id_t temp_folder_id;
		guint32 options = 0;
		GError *mapi_error = NULL;

		if (mapi_summary->sync_time_stamp && *mapi_summary->sync_time_stamp &&
		    g_time_val_from_iso8601 (mapi_summary->sync_time_stamp,
					     &fetch_data->last_modification_time)) {
			struct SPropValue sprop;
			struct timeval t;

			mem_ctx = talloc_init ("ExchangeMAPI_mapi_refresh_folder");
			res = g_new0 (struct mapi_SRestriction, 1);
			res->rt = RES_PROPERTY;
			/*RELOP_GE acts more like >=. Few extra items are being fetched.*/
			res->res.resProperty.relop = RELOP_GE;
			res->res.resProperty.ulPropTag = PR_LAST_MODIFICATION_TIME;

			t.tv_sec = fetch_data->last_modification_time.tv_sec;
			t.tv_usec = fetch_data->last_modification_time.tv_usec;

			//Creation time ?
			set_SPropValue_proptag_date_timeval (&sprop, PR_LAST_MODIFICATION_TIME, &t);
			cast_mapi_SPropValue (
				#ifdef HAVE_MEMCTX_ON_CAST_MAPI_SPROPVALUE
				mem_ctx,
				#endif
				&(res->res.resProperty.lpProp), &sprop);

		}

		/*Initialize other fetch_data fields*/
		fetch_data->changes = camel_folder_change_info_new ();
		fetch_data->folder = folder;

		/*Set sort order*/
		sort = g_new0 (struct SSortOrderSet, 1);
		sort->cSorts = 1;
		sort->aSort = g_new0 (struct SSortOrder, sort->cSorts);
		sort->aSort[0].ulPropTag = PR_LAST_MODIFICATION_TIME;
		sort->aSort[0].ulOrder = TABLE_SORT_ASCEND;

		exchange_mapi_util_mapi_id_from_string (folder_id, &temp_folder_id);

		if (!camel_mapi_store_connected (mapi_store, NULL)) {
			/*BUG : Fix exception string.*/
			g_set_error (
				error, CAMEL_SERVICE_ERROR,
				CAMEL_SERVICE_ERROR_UNAVAILABLE,
				_("This message is not available in offline mode."));
			success = FALSE;
			goto end1;
		}

		options |= MAPI_OPTIONS_FETCH_RECIPIENTS;

		if (((CamelMapiFolder *)folder)->type & CAMEL_MAPI_FOLDER_PUBLIC)
			options |= MAPI_OPTIONS_USE_PFSTORE;

		status = camel_mapi_folder_fetch_summary ((CamelStore *)mapi_store, folder, temp_folder_id, res, sort,
							  fetch_data, options, cancellable, &mapi_error);

		if (!status) {
			if (mapi_error) {
				g_set_error (
					error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_INVALID,
					_("Fetching items failed: %s"), mapi_error->message);
				g_error_free (mapi_error);
			} else {
				g_set_error_literal (
					error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_INVALID,
					_("Fetching items failed"));
			}
			success = FALSE;
			goto end1;
		}

		/*Preserve last_modification_time from this fetch for later use with restrictions.*/
		g_free (mapi_summary->sync_time_stamp);
		mapi_summary->sync_time_stamp = g_time_val_to_iso8601 (&fetch_data->last_modification_time);

		camel_folder_summary_touch (folder->summary);
		update_store_summary (folder, NULL);

		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		is_locked = FALSE;

		/* Downsync deleted items */
		deleted_items_op_msg = camel_session_thread_msg_new (session, &deleted_items_sync_ops,
							 sizeof (*deleted_items_op_msg));
		deleted_items_op_msg->folder = folder;
		deleted_items_op_msg->folder_id = temp_folder_id;
		deleted_items_op_msg->need_refresh = FALSE;
		g_object_ref (folder);

		camel_session_thread_queue (session, &deleted_items_op_msg->msg, 0);

		camel_folder_changed (folder, fetch_data->changes);
		camel_folder_change_info_free (fetch_data->changes);
	}

end1:
	if (is_locked)
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	g_slist_foreach (fetch_data->items_list, (GFunc) mail_item_free, NULL);
	g_slist_free (fetch_data->items_list);
	g_free (fetch_data);

	if (mem_ctx)
		talloc_free (mem_ctx);

	return success;
}

static void
mapi_folder_search_free (CamelFolder *folder, GPtrArray *uids)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER(folder);

	g_return_if_fail (mapi_folder->search);

	CAMEL_MAPI_FOLDER_LOCK(mapi_folder, search_lock);

	camel_folder_search_free_result (mapi_folder->search, uids);

	CAMEL_MAPI_FOLDER_UNLOCK(mapi_folder, search_lock);

}

#if 0
static CamelMessageInfo*
mapi_get_message_info(CamelFolder *folder, const gchar *uid)
{
	CamelMessageInfo	*msg_info = NULL;
	CamelMessageInfoBase	*mi = (CamelMessageInfoBase *)msg;
	gint			status = 0;
	oc_message_headers_t	headers;

	if (folder->summary) {
		msg_info = camel_folder_summary_uid(folder->summary, uid);
	}
	if (msg_info != NULL) {
		mi = (CamelMessageInfoBase *)msg_info;
		return (msg_info);
	}
	/* Go online and fetch message summary. */

	msg_info = camel_message_info_new(folder->summary);
	mi = (CamelMessageInfoBase *)msg_info;

	if (headers.subject) mi->subject = (gchar *)camel_pstring_strdup(headers.subject);
	if (headers.from) mi->from = (gchar *)camel_pstring_strdup(headers.from);
	if (headers.to) mi->to = (gchar *)camel_pstring_strdup(headers.to);
	if (headers.cc) mi->cc = (gchar *)camel_pstring_strdup(headers.cc);
	mi->flags = headers.flags;

	mi->user_flags = NULL;
	mi->user_tags = NULL;
	mi->date_received = 0;
	mi->date_sent = headers.send;
	mi->content = NULL;
	mi->summary = folder->summary;
	if (uid) mi->uid = g_strdup(uid);
	oc_message_headers_release(&headers);
	return (msg);
}
#endif

static void
mapi_folder_rename (CamelFolder *folder, const gchar *new)
{
	((CamelFolderClass *)camel_mapi_folder_parent_class)->rename(folder, new);
}

static gint
mapi_cmp_uids (CamelFolder *folder, const gchar *uid1, const gchar *uid2)
{
	g_return_val_if_fail (uid1 != NULL, 0);
	g_return_val_if_fail (uid2 != NULL, 0);

	return strcmp (uid1, uid2);
}

static gboolean
mapi_set_message_flags (CamelFolder *folder,
                        const gchar *uid,
                        CamelMessageFlags flags,
                        CamelMessageFlags set)
{
	CamelMessageInfo *info;
	gint res;

	g_return_val_if_fail (folder->summary != NULL, FALSE);

	info = camel_folder_summary_uid (folder->summary, uid);
	if (info == NULL)
		return FALSE;

	res = camel_message_info_set_flags (info, flags, set);

	camel_message_info_free (info);
	return res;
}

static void
mapi_folder_dispose (GObject *object)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (object);

	if (mapi_folder->cache != NULL) {
		g_object_unref (mapi_folder->cache);
		mapi_folder->cache = NULL;
	}

	/* Chain up to parent's dispose() method. */
	G_OBJECT_CLASS (camel_mapi_folder_parent_class)->dispose (object);
}

static void
mapi_folder_constructed (GObject *object)
{
	CamelFolder *folder;
	CamelStore *parent_store;
	CamelURL *url;
	const gchar *full_name;
	gchar *description;

	folder = CAMEL_FOLDER (object);
	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);
	url = CAMEL_SERVICE (parent_store)->url;

	description = g_strdup_printf (
		"%s@%s:%s", url->user, url->host, full_name);
	camel_folder_set_description (folder, description);
	g_free (description);
}

static gboolean
mapi_folder_append_message_sync (CamelFolder *folder,
                                 CamelMimeMessage *message,
                                 CamelMessageInfo *info,
                                 gchar **appended_uid,
                                 GCancellable *cancellable,
                                 GError **error)
{
	CamelMapiStore *mapi_store;
	CamelOfflineStore *offline;
	CamelAddress *from = NULL;
	CamelStoreInfo *si;
	CamelStore *parent_store;
	MailItem *item = NULL;
	mapi_id_t fid = 0, mid = 0;
	const gchar *folder_id;
	const gchar *full_name;
	guint32 folder_flags = 0;
	GError *mapi_error = NULL;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	mapi_store = CAMEL_MAPI_STORE (parent_store);
	offline = CAMEL_OFFLINE_STORE (parent_store);

	/*Reject outbox / sent & trash*/
	si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, full_name);
	if (si) {
		folder_flags = si->flags;
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
	}

	if (((folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) ||
	    ((folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_OUTBOX)) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot append message to folder '%s'"),
			full_name);
		return FALSE;
	}

	if (!camel_offline_store_get_online (offline)) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Offline."));
		return FALSE;
	}

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, full_name);

	exchange_mapi_util_mapi_id_from_string (folder_id, &fid);

	/* Convert MIME to Item */
	from = (CamelAddress *) camel_mime_message_get_from (message);

	item = camel_mapi_utils_mime_to_item (message, info ? camel_message_info_flags (info) : 0, from, cancellable, error);
	if (item == NULL)
		return FALSE;

	mid = exchange_mapi_connection_create_item (camel_mapi_store_get_exchange_connection (mapi_store), -1, fid,
					 camel_mapi_utils_create_item_build_props, item,
					 item->recipients, item->attachments,
					 item->generic_streams, MAPI_OPTIONS_DONT_SUBMIT, &mapi_error);

	if (!mid) {
		if (mapi_error) {
			g_set_error_literal (error, CAMEL_ERROR, CAMEL_ERROR_GENERIC, mapi_error->message);
			g_error_free (mapi_error);
		} else {
			g_set_error (error, CAMEL_ERROR, CAMEL_ERROR_GENERIC, _("Offline."));
		}

		return FALSE;
	}

	if (appended_uid)
		*appended_uid = exchange_mapi_util_mapi_ids_to_uid(fid, mid);

	return TRUE;
}

static gboolean
mapi_folder_expunge_sync (CamelFolder *folder,
                          GCancellable *cancellable,
                          GError **error)
{
	CamelMapiStore *mapi_store;
	CamelMapiFolder *mapi_folder;
	CamelMapiMessageInfo *minfo;
	CamelMessageInfo *info;
	CamelFolderChangeInfo *changes;
	CamelStore *parent_store;

	mapi_id_t fid;

	gint i, count;
	gboolean delete = FALSE, status = FALSE;
	gchar *folder_id;
	GSList *deleted_items, *deleted_head;
	GSList *deleted_items_uid, *deleted_items_uid_head;
	const gchar *full_name;

	deleted_items = deleted_head = NULL;
	deleted_items_uid = deleted_items_uid_head = NULL;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	folder_id =  g_strdup (camel_mapi_store_folder_id_lookup (mapi_store, full_name));
	exchange_mapi_util_mapi_id_from_string (folder_id, &fid);

	if ((mapi_folder->type & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
		GError *mapi_error = NULL;
		GPtrArray *folders;
		gint ii;

		/* get deleted messages from all active folders too */
		folders = camel_object_bag_list (parent_store->folders);
		for (ii = 0; ii < folders->len; ii++) {
			CamelFolder *opened_folder = CAMEL_FOLDER (folders->pdata[ii]);
			CamelMapiFolder *mf;

			if (!opened_folder)
				continue;

			mf = CAMEL_MAPI_FOLDER (opened_folder);
			if (mf && (mf->type & CAMEL_FOLDER_TYPE_MASK) != CAMEL_FOLDER_TYPE_TRASH) {
				if (camel_folder_get_deleted_message_count (opened_folder) > 0)
					camel_folder_synchronize_sync (opened_folder, TRUE, cancellable, NULL);
			}

			g_object_unref (opened_folder);
		}
		g_ptr_array_free (folders, TRUE);

		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		status = exchange_mapi_connection_empty_folder (camel_mapi_store_get_exchange_connection (mapi_store), fid, 0, &mapi_error);
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

		if (status) {
			camel_folder_freeze (folder);
			mapi_summary_clear (folder->summary, TRUE);
			camel_folder_thaw (folder);
		} else if (mapi_error) {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Failed to empty Trash: %s"), mapi_error->message);
			g_error_free (mapi_error);
		} else {
			g_set_error_literal (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Failed to empty Trash"));
		}

		return status;
	}

	changes = camel_folder_change_info_new ();
	count = camel_folder_summary_count (folder->summary);

	/*Collect UIDs of deleted messages.*/
	for (i = 0; i < count; i++) {
		info = camel_folder_summary_index (folder->summary, i);
		minfo = (CamelMapiMessageInfo *) info;
		if (minfo && (minfo->info.flags & CAMEL_MESSAGE_DELETED)) {
			const gchar *uid = camel_message_info_uid (info);
			mapi_id_t *mid = g_new0 (mapi_id_t, 1);

			if (!exchange_mapi_util_mapi_ids_from_uid (uid, &fid, mid))
				continue;

			if (deleted_items)
				deleted_items = g_slist_prepend (deleted_items, mid);
			else {
				g_slist_free (deleted_head);
				deleted_head = NULL;
				deleted_head = deleted_items = g_slist_prepend (deleted_items, mid);
			}
			deleted_items_uid = g_slist_prepend (deleted_items_uid, (gpointer) uid);
		}
		camel_message_info_free (info);
	}

	deleted_items_uid_head = deleted_items_uid;

	if (deleted_items) {
		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

		status = exchange_mapi_connection_remove_items (camel_mapi_store_get_exchange_connection (mapi_store), 0, fid, 0, deleted_items, NULL);

		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

		if (status) {
			while (deleted_items_uid) {
				const gchar *uid = (gchar *)deleted_items_uid->data;
				camel_folder_summary_lock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
				camel_folder_change_info_remove_uid (changes, uid);
				camel_folder_summary_remove_uid (folder->summary, uid);
				camel_data_cache_remove(mapi_folder->cache, "cache", uid, NULL);
				camel_folder_summary_unlock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
				deleted_items_uid = g_slist_next (deleted_items_uid);
			}
		}
		delete = TRUE;

		g_slist_foreach (deleted_head, (GFunc)g_free, NULL);
		g_slist_free (deleted_head);
		g_slist_free (deleted_items_uid_head);
	}

	if (delete)
		camel_folder_changed (folder, changes);

	g_free (folder_id);
	camel_folder_change_info_free (changes);

	return TRUE;
}

static CamelMimeMessage *
mapi_folder_get_message_sync (CamelFolder *folder,
                              const gchar *uid,
                              GCancellable *cancellable,
                              GError **error )
{
	CamelMimeMessage *msg = NULL;
	CamelMapiFolder *mapi_folder;
	CamelMapiStore *mapi_store;
	CamelMapiMessageInfo *mi = NULL;
	CamelStream *stream, *cache_stream;
	CamelStore *parent_store;
	mapi_id_t id_folder;
	mapi_id_t id_message;
	MailItem *item = NULL;
	guint32 options = 0;
	GError *mapi_error = NULL;

	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	/* see if it is there in cache */

	mi = (CamelMapiMessageInfo *) camel_folder_summary_uid (folder->summary, uid);
	if (mi == NULL) {
		/* Translators: The first %s is replaced with a message ID,
		   the second %s is replaced with a detailed error string */
		g_set_error (
			error, CAMEL_FOLDER_ERROR,
			CAMEL_FOLDER_ERROR_INVALID_UID,
			_("Cannot get message %s: %s"), uid,
			_("No such message"));
		return NULL;
	}
	cache_stream  = camel_data_cache_get (mapi_folder->cache, "cache", uid, NULL);
	stream = camel_stream_mem_new ();
	if (cache_stream) {
		GError *local_error = NULL;

		msg = camel_mime_message_new ();
		camel_stream_reset (stream, NULL);
		camel_stream_write_to_stream (cache_stream, stream, cancellable, NULL);
		camel_stream_reset (stream, NULL);
		if (!camel_data_wrapper_construct_from_stream_sync ((CamelDataWrapper *) msg, stream, cancellable, &local_error)) {
			if (g_error_matches (local_error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
				g_object_unref (msg);
				g_object_unref (cache_stream);
				g_object_unref (stream);
				camel_message_info_free (&mi->info);
				return NULL;
			} else {
				/* Translators: The %s is replaced with a message ID */
				g_prefix_error (error, "Cannot get message %s: ", uid);
				g_object_unref (msg);
				msg = NULL;
			}
		}
		g_object_unref (cache_stream);
	}
	g_object_unref (stream);

	if (msg != NULL) {
		camel_message_info_free (&mi->info);
		return msg;
	}

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store))) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("This message is not available in offline mode."));
		camel_message_info_free (&mi->info);
		return NULL;
	}

	/* Check if we are really offline */
	if (!camel_mapi_store_connected (mapi_store, NULL)) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("This message is not available in offline mode."));
		camel_message_info_free (&mi->info);
		return NULL;
	}

	options = MAPI_OPTIONS_FETCH_ALL | MAPI_OPTIONS_FETCH_BODY_STREAM |
		MAPI_OPTIONS_GETBESTBODY | MAPI_OPTIONS_FETCH_RECIPIENTS;

	exchange_mapi_util_mapi_ids_from_uid (uid, &id_folder, &id_message);

	if (((CamelMapiFolder *)folder)->type & CAMEL_MAPI_FOLDER_PUBLIC) {
		options |= MAPI_OPTIONS_USE_PFSTORE;
	}

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	exchange_mapi_connection_fetch_item (camel_mapi_store_get_exchange_connection (mapi_store), id_folder, id_message,
					mapi_mail_get_item_prop_list, NULL,
					fetch_props_to_mail_item_cb, &item,
					options, &mapi_error);
	camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	if (item == NULL) {
		if (mapi_error) {
			g_set_error (
				error, CAMEL_SERVICE_ERROR,
				CAMEL_SERVICE_ERROR_INVALID,
				_("Could not get message: %s"), mapi_error->message);
			g_error_free (mapi_error);
		} else {
			g_set_error (
				error, CAMEL_SERVICE_ERROR,
				CAMEL_SERVICE_ERROR_INVALID,
				_("Could not get message"));
		}
		camel_message_info_free (&mi->info);
		return NULL;
	}

	msg = mapi_mail_item_to_mime_message (camel_mapi_store_get_exchange_connection (mapi_store), item);
	mail_item_free (item);

	if (!msg) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_INVALID,
			_("Could not get message"));
		camel_message_info_free (&mi->info);

		return NULL;
	}

	/* add to cache */
	camel_folder_summary_lock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
	if ((cache_stream = camel_data_cache_add (mapi_folder->cache, "cache", uid, NULL))) {
		if (camel_data_wrapper_write_to_stream_sync ((CamelDataWrapper *) msg, cache_stream, cancellable, NULL) == -1
				|| camel_stream_flush (cache_stream, cancellable, NULL) == -1) {
			camel_data_cache_remove (mapi_folder->cache, "cache", uid, NULL);
		} else {
			CamelMimeMessage *msg2;

			/* workaround to get message back from cache, as that one is properly
			   encoded with attachments and so on. Not sure what's going wrong when
			   composing message in memory, but when they are read from the cache
			   they appear properly in the UI. */
			msg2 = camel_mime_message_new ();
			camel_stream_reset (cache_stream, NULL);
			if (!camel_data_wrapper_construct_from_stream_sync (CAMEL_DATA_WRAPPER (msg2), cache_stream, cancellable, NULL)) {
				g_object_unref (msg2);
			} else {
				g_object_unref (msg);
				msg = msg2;
			}
		}
		g_object_unref (cache_stream);
	}

	camel_folder_summary_unlock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);

	camel_message_info_free (&mi->info);

	return msg;
}

static gboolean
mapi_folder_refresh_info_sync (CamelFolder *folder,
                               GCancellable *cancellable,
                               GError **error)
{
	if (!mapi_refresh_folder (folder, cancellable, error))
		return FALSE;

	return update_store_summary (folder, error);
}

static gboolean
mapi_folder_synchronize_sync (CamelFolder *folder,
                              gboolean expunge,
                              GCancellable *cancellable,
                              GError **error)
{
	CamelMapiStore *mapi_store;
	CamelMapiFolder *mapi_folder;
	CamelMessageInfo *info = NULL;
	CamelMapiMessageInfo *mapi_info = NULL;
	CamelStore *parent_store;
	CamelFolderChangeInfo *changes = NULL;

	GSList *read_items = NULL, *unread_items = NULL, *to_free = NULL, *junk_items = NULL, *deleted_items = NULL, *l;
	flags_diff_t diff, unset_flags;
	const gchar *folder_id;
	const gchar *full_name;
	mapi_id_t fid, deleted_items_fid;
	gint count, i;
	guint32 options =0;
	gboolean is_junk_folder;
	gboolean success;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store)) ||
			((CamelService *)mapi_store)->status == CAMEL_SERVICE_DISCONNECTED) {
		return update_store_summary (folder, error);
	}

	if (((CamelMapiFolder *)folder)->type & CAMEL_MAPI_FOLDER_PUBLIC)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, full_name);
	exchange_mapi_util_mapi_id_from_string (folder_id, &fid);

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	if (!camel_mapi_store_connected (mapi_store, NULL)) {
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		return TRUE;
	}
	camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	is_junk_folder = (mapi_folder->type & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_JUNK;

	camel_folder_summary_lock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
	camel_folder_summary_prepare_fetch_all (folder->summary, NULL);

	count = camel_folder_summary_count (folder->summary);
	for (i=0; i < count; i++) {
		info = camel_folder_summary_index (folder->summary, i);
		mapi_info = (CamelMapiMessageInfo *) info;

		if (mapi_info && (mapi_info->info.flags & CAMEL_MESSAGE_FOLDER_FLAGGED)) {
			const gchar *uid;
			mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
			mapi_id_t temp_fid;
			guint32 flags;
			gboolean used = FALSE;

			uid = camel_message_info_uid (info);
			flags= camel_message_info_flags (info);

			/* Why are we getting so much noise here :-/ */
			if (!exchange_mapi_util_mapi_ids_from_uid (uid, &temp_fid, mid)) {
				camel_message_info_free (info);
				g_free (mid);
				continue;
			}

			mapi_utils_do_flags_diff (&diff, mapi_info->server_flags, mapi_info->info.flags);
			mapi_utils_do_flags_diff (&unset_flags, flags, mapi_info->server_flags);

			diff.changed &= folder->permanent_flags;
			if (!diff.changed) {
				camel_message_info_free (info);
				g_free (mid);
				continue;
			}
			if (diff.bits & CAMEL_MESSAGE_DELETED) {
				deleted_items = g_slist_prepend (deleted_items, mid);
				used = TRUE;
			} else if (!is_junk_folder && (diff.bits & CAMEL_MESSAGE_JUNK) != 0) {
				junk_items = g_slist_prepend (junk_items, mid);
				used = TRUE;
			}

			if (diff.bits & CAMEL_MESSAGE_SEEN) {
				read_items = g_slist_prepend (read_items, mid);
				used = TRUE;
			} else if (unset_flags.bits & CAMEL_MESSAGE_SEEN) {
				unread_items = g_slist_prepend (unread_items, mid);
				used = TRUE;
			}

			if (used)
				to_free = g_slist_prepend (to_free, mid);
			else
				g_free (mid);

			mapi_info->server_flags = mapi_info->info.flags;
		}

		if (info)
			camel_message_info_free (info);
	}

	camel_folder_summary_unlock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);

	/*
	   Sync up the READ changes before deleting the message.
	   Note that if a message is marked as unread and then deleted,
	   Evo doesnt not take care of it, as I find that scenario to be impractical.
	*/

	if (read_items) {
		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		exchange_mapi_connection_set_flags (camel_mapi_store_get_exchange_connection (mapi_store), 0, fid, options, read_items, 0, NULL);
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	}

	if (unread_items) {
		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		exchange_mapi_connection_set_flags (camel_mapi_store_get_exchange_connection (mapi_store), 0, fid, options, unread_items, CLEAR_READ_FLAG, NULL);
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	}

	/* Remove messages from server*/
	if (deleted_items) {
		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		if ((mapi_folder->type & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
			exchange_mapi_connection_remove_items (camel_mapi_store_get_exchange_connection (mapi_store), 0, fid, options, deleted_items, NULL);
		} else {
			GError *err = NULL;

			exchange_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderDeletedItems), &deleted_items_fid);
			exchange_mapi_connection_move_items (camel_mapi_store_get_exchange_connection (mapi_store), fid, options, deleted_items_fid, 0, deleted_items, &err);

			if (err) {
				g_warning ("%s: Failed to move deleted items: %s", G_STRFUNC, err->message);
				g_error_free (err);
			}
		}

		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	}

	if (junk_items) {
		mapi_id_t junk_fid = 0;
		GError *err = NULL;

		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		exchange_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderJunk), &junk_fid);
		exchange_mapi_connection_move_items (camel_mapi_store_get_exchange_connection (mapi_store), fid, options, junk_fid, 0, junk_items, &err);
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

		/* in junk_items are only emails which are not deleted */
		deleted_items = g_slist_concat (deleted_items, g_slist_copy (junk_items));

		if (err) {
			g_warning ("%s: Failed to move junk items: %s", G_STRFUNC, err->message);
			g_error_free (err);
		}
	}

	/*Remove messages from local cache*/
	for (l = deleted_items; l; l = l->next) {
		gchar * deleted_msg_uid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X%016" G_GINT64_MODIFIER "X", fid, *(mapi_id_t *)l->data);

		if (!changes)
			changes = camel_folder_change_info_new ();
		camel_folder_change_info_remove_uid (changes, deleted_msg_uid);

		camel_folder_summary_lock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
		camel_folder_summary_remove_uid (folder->summary, deleted_msg_uid);
		camel_data_cache_remove(mapi_folder->cache, "cache", deleted_msg_uid, NULL);
		camel_folder_summary_unlock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
	}

	if (changes) {
		camel_folder_changed (folder, changes);
		camel_folder_change_info_free (changes);
	}

	g_slist_free (read_items);
	g_slist_free (unread_items);
	g_slist_free (deleted_items);
	g_slist_free (junk_items);

	g_slist_foreach (to_free, (GFunc) g_free, NULL);
	g_slist_free (to_free);

	if (expunge) {
		/* TODO */
	}

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	success = update_store_summary (folder, error);
	camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	return success;
}

static gboolean
mapi_folder_transfer_messages_to_sync (CamelFolder *source,
                                       GPtrArray *uids,
                                       CamelFolder *destination,
                                       gboolean delete_originals,
                                       GPtrArray **transferred_uids,
                                       GCancellable *cancellable,
                                       GError **error)
{
	mapi_id_t src_fid, dest_fid;
	guint32 src_fid_options, dest_fid_options;

	CamelOfflineStore *offline;
	CamelMapiStore *mapi_store;
	CamelFolderChangeInfo *changes = NULL;
	CamelStore *source_parent_store;
	CamelStore *destination_parent_store;
	const gchar *folder_id = NULL;
	const gchar *source_full_name;
	const gchar *destination_full_name;
	gint i = 0;
	GSList *src_msg_ids = NULL;
	gboolean success = TRUE;

	if (!CAMEL_IS_MAPI_FOLDER (source) || !CAMEL_IS_MAPI_FOLDER (destination) ||
	    (CAMEL_MAPI_FOLDER (source)->type & CAMEL_MAPI_FOLDER_PUBLIC) != 0 ||
	    (CAMEL_MAPI_FOLDER (destination)->type & CAMEL_MAPI_FOLDER_PUBLIC) != 0) {
		CamelFolderClass *folder_class;

		/* because cannot use MAPI to copy/move messages with public folders,
		   thus fallback to per-message copy/move */
		folder_class = CAMEL_FOLDER_CLASS (camel_mapi_folder_parent_class);
		return folder_class->transfer_messages_to_sync (
			source, uids, destination, delete_originals,
			transferred_uids, cancellable, error);
	}

	source_full_name = camel_folder_get_full_name (source);
	source_parent_store = camel_folder_get_parent_store (source);

	destination_full_name = camel_folder_get_full_name (destination);
	destination_parent_store = camel_folder_get_parent_store (destination);

	mapi_store = CAMEL_MAPI_STORE (source_parent_store);
	offline = CAMEL_OFFLINE_STORE (destination_parent_store);

	/* check for offline operation */
	if (!camel_offline_store_get_online (offline))
		return FALSE;

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, source_full_name);
	exchange_mapi_util_mapi_id_from_string (folder_id, &src_fid);
	src_fid_options = (CAMEL_MAPI_FOLDER (source)->type & CAMEL_MAPI_FOLDER_PUBLIC) != 0 ? MAPI_OPTIONS_USE_PFSTORE : 0;

	folder_id = camel_mapi_store_folder_id_lookup (mapi_store, destination_full_name);
	exchange_mapi_util_mapi_id_from_string (folder_id, &dest_fid);
	dest_fid_options = (CAMEL_MAPI_FOLDER (destination)->type & CAMEL_MAPI_FOLDER_PUBLIC) != 0 ? MAPI_OPTIONS_USE_PFSTORE : 0;

	for (i=0; i < uids->len; i++) {
		mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
		if (!exchange_mapi_util_mapi_ids_from_uid (g_ptr_array_index (uids, i), &src_fid, mid))
			continue;

		src_msg_ids = g_slist_prepend (src_msg_ids, mid);
	}

	if (delete_originals) {
		GError *err = NULL;

		if (!exchange_mapi_connection_move_items (camel_mapi_store_get_exchange_connection (mapi_store), src_fid, src_fid_options, dest_fid, dest_fid_options, src_msg_ids, &err)) {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				"%s", err ? err->message : _("Unknown error"));
			if (err)
				g_error_free (err);
			success = FALSE;
		} else {
			changes = camel_folder_change_info_new ();

			for (i=0; i < uids->len; i++) {
				camel_folder_summary_remove_uid (source->summary, uids->pdata[i]);
				camel_folder_change_info_remove_uid (changes, uids->pdata[i]);
			}
			camel_folder_changed (source, changes);
			camel_folder_change_info_free (changes);

		}
	} else {
		GError *err = NULL;

		if (!exchange_mapi_connection_copy_items (camel_mapi_store_get_exchange_connection (mapi_store), src_fid, src_fid_options, dest_fid, dest_fid_options, src_msg_ids, &err)) {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				"%s", err ? err->message : _("Unknown error"));
			if (err)
				g_error_free (err);
			success = FALSE;
		}
	}

	g_slist_foreach (src_msg_ids, (GFunc) g_free, NULL);
	g_slist_free (src_msg_ids);

	return success;
}

static void
camel_mapi_folder_class_init (CamelMapiFolderClass *class)
{
	GObjectClass *object_class;
	CamelFolderClass *folder_class;

	g_type_class_add_private (class, sizeof (CamelMapiFolderPrivate));

	object_class = G_OBJECT_CLASS (class);
	object_class->dispose = mapi_folder_dispose;
	object_class->constructed = mapi_folder_constructed;

	folder_class = CAMEL_FOLDER_CLASS (class);
	folder_class->rename = mapi_folder_rename;
	folder_class->search_by_expression = mapi_folder_search_by_expression;
	folder_class->cmp_uids = mapi_cmp_uids;
	folder_class->search_by_uids = mapi_folder_search_by_uids;
	folder_class->search_free = mapi_folder_search_free;
	folder_class->set_message_flags = mapi_set_message_flags;
	folder_class->append_message_sync = mapi_folder_append_message_sync;
	folder_class->expunge_sync = mapi_folder_expunge_sync;
	folder_class->get_message_sync = mapi_folder_get_message_sync;
	folder_class->refresh_info_sync = mapi_folder_refresh_info_sync;
	folder_class->synchronize_sync = mapi_folder_synchronize_sync;
	folder_class->transfer_messages_to_sync = mapi_folder_transfer_messages_to_sync;
}

static void
camel_mapi_folder_init (CamelMapiFolder *mapi_folder)
{
	CamelFolder *folder = CAMEL_FOLDER (mapi_folder);

	mapi_folder->priv = CAMEL_MAPI_FOLDER_GET_PRIVATE (mapi_folder);

	folder->permanent_flags = CAMEL_MESSAGE_ANSWERED | CAMEL_MESSAGE_DELETED |
		CAMEL_MESSAGE_DRAFT | CAMEL_MESSAGE_FLAGGED | CAMEL_MESSAGE_SEEN | CAMEL_MESSAGE_JUNK;

	folder->folder_flags = CAMEL_FOLDER_HAS_SUMMARY_CAPABILITY | CAMEL_FOLDER_HAS_SEARCH_CAPABILITY;

#ifdef ENABLE_THREADS
	g_static_mutex_init(&mapi_folder->priv->search_lock);
#endif

	mapi_folder->need_rescan = TRUE;
}

CamelFolder *
camel_mapi_folder_new (CamelStore *store, const gchar *folder_name, const gchar *folder_dir,
		      guint32 flags, GError **error)
{

	CamelFolder	*folder = NULL;
	CamelMapiFolder *mapi_folder;
	CamelMapiStore  *mapi_store = (CamelMapiStore *) store;

	gchar *summary_file, *state_file;
	const gchar *short_name;
	CamelStoreInfo *si;

	short_name = strrchr (folder_name, '/');
	if (short_name)
		short_name++;
	else
		short_name = folder_name;

	folder = g_object_new (
		CAMEL_TYPE_MAPI_FOLDER,
		"name", short_name, "full-name", folder_name,
		"parent-store", store, NULL);

	mapi_folder = CAMEL_MAPI_FOLDER(folder);

	summary_file = g_strdup_printf ("%s/%s/summary",folder_dir, folder_name);

	folder->summary = camel_mapi_summary_new(folder, summary_file);
	g_free(summary_file);

	if (!folder->summary) {
		g_object_unref (CAMEL_OBJECT (folder));
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Could not load summary for %s"),
			folder_name);
		return NULL;
	}

	/* set/load persistent state */
	state_file = g_strdup_printf ("%s/%s/cmeta", folder_dir, folder_name);
	camel_object_set_state_filename (CAMEL_OBJECT (folder), state_file);
	g_free(state_file);
	camel_object_state_read (CAMEL_OBJECT (folder));

	state_file = g_strdup_printf ("%s/%s", folder_dir, folder_name);
	mapi_folder->cache = camel_data_cache_new (state_file, error);
	g_free (state_file);
	if (!mapi_folder->cache) {
		g_object_unref (folder);
		return NULL;
	}

/*	journal_file = g_strdup_printf ("%s/journal", g_strdup_printf ("%s-%s",folder_name, "dir")); */
/*	mapi_folder->journal = camel_mapi_journal_new (mapi_folder, journal_file); */
/*	g_free (journal_file); */
/*	if (!mapi_folder->journal) { */
/*		g_object_unref (folder); */
/*		return NULL; */
/*	} */

	if ((store->flags & CAMEL_STORE_FILTER_INBOX) != 0) {
		CamelFolderInfo *fi;

		fi = camel_store_get_folder_info_sync (store, folder_name, 0, NULL, NULL);
		if (fi) {
			if ((fi->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_INBOX) {
				folder->folder_flags |= CAMEL_FOLDER_FILTER_RECENT;
			}

			camel_store_free_folder_info (store, fi);
		}
	}

	mapi_folder->search = camel_folder_search_new ();
	if (!mapi_folder->search) {
		g_object_unref (folder);
		return NULL;
	}

	si = camel_mapi_store_summary_full_name (mapi_store->summary, folder_name);
	if (si) {
		mapi_folder->type = si->flags;

		if ((si->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH)
			folder->folder_flags |= CAMEL_FOLDER_IS_TRASH;
		else if ((si->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_JUNK)
			folder->folder_flags  |= CAMEL_FOLDER_IS_JUNK;
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
	} else {
		g_warning ("%s: cannot find '%s' in known folders", G_STRFUNC, folder_name);
	}

	return folder;
}
