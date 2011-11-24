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
#include <e-mapi-defs.h>
#include <e-mapi-utils.h>
#include <e-mapi-folder.h>
#include <e-mapi-cal-utils.h>
#include "e-mapi-mail-utils.h"

#include "camel-mapi-store.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-private.h"
#include "camel-mapi-folder-summary.h"

#define DEBUG_FN( ) printf("----%p %s\n", g_thread_self(), G_STRFUNC);
#define SUMMARY_FETCH_BATCH_COUNT 150
#define d(x)

extern gint camel_application_is_exiting;

struct _CamelMapiFolderPrivate {

	GStaticMutex search_lock;	/* for locking the search object */

};

/*for syncing flags back to server*/
typedef struct {
	guint32 changed;
	guint32 bits;
} flags_diff_t;

/*For collecting summary info from server*/

static void mapi_update_cache (CamelFolder *folder, GSList *list, CamelFolderChangeInfo **changeinfo,
			       GCancellable *cancellable, GError **error);

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
		   GCancellable *cancellable, GError **error)
{
	CamelMapiMessageInfo *mi = NULL;
	CamelMessageInfo *pmi = NULL;
	CamelMapiStore *mapi_store;
	CamelStore *parent_store;

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
		camel_folder_get_display_name (folder));

	for (; item_list != NULL; item_list = g_slist_next (item_list) ) {
		MailItem *temp_item;
		MailItem *item;
		gchar *msg_uid;

		exists = FALSE;

		temp_item = (MailItem *)item_list->data;
		item = temp_item;

		camel_operation_progress (cancellable, (100*i)/total_items);

		/************************ First populate summary *************************/
		mi = NULL;
		pmi = NULL;
		msg_uid = e_mapi_util_mapi_id_to_string (item->mid);
		pmi = camel_folder_summary_get (folder->summary, msg_uid);

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

			mi->info.uid = e_mapi_util_mapi_id_to_string (item->mid);
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

				/* Build a SRow structure */
				aRow = &recip->out_SRow;

				type = (uint32_t *) e_mapi_util_find_row_propval (aRow, PR_RECIPIENT_TYPE);

				if (type) {
					name = recip->display_name;
					name = name ? name : e_mapi_util_find_row_propval (aRow, PR_DISPLAY_NAME_UNICODE);
					name = name ? name : e_mapi_util_find_row_propval (aRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
					name = name ? name : e_mapi_util_find_row_propval (aRow, PR_7BIT_DISPLAY_NAME_UNICODE);
					display_name = name ? name : recip->email_id;
					formatted_id = camel_internet_address_format_address(display_name, recip->email_id ? recip->email_id : "");

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
				from_email = e_mapi_connection_ex_to_smtp (camel_mapi_store_get_connection (mapi_store), item->header.from_email, NULL, cancellable, NULL);
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

static void
add_message_to_cache (CamelMapiFolder *mapi_folder, const gchar *uid, CamelMimeMessage **msg, GCancellable *cancellable)
{
	CamelFolder *folder;
	CamelStream *cache_stream;

	g_return_if_fail (mapi_folder != NULL);
	g_return_if_fail (msg != NULL);
	g_return_if_fail (*msg != NULL);

	folder = CAMEL_FOLDER (mapi_folder);
	g_return_if_fail (folder != NULL);

	camel_folder_summary_lock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);

	if ((cache_stream = camel_data_cache_add (mapi_folder->cache, "cache", uid, NULL))) {
		if (camel_data_wrapper_write_to_stream_sync ((CamelDataWrapper *) (*msg), cache_stream, cancellable, NULL) == -1
		    || camel_stream_flush (cache_stream, cancellable, NULL) == -1) {
			camel_data_cache_remove (mapi_folder->cache, "cache", uid, NULL);
		} else {
			CamelMimeMessage *msg2;

			/* workaround to get message back from cache, as that one is properly
			   encoded with attachments and so on. Not sure what's going wrong when
			   composing message in memory, but when they are read from the cache
			   they appear properly in the UI. */
			msg2 = camel_mime_message_new ();
			g_seekable_seek (G_SEEKABLE (cache_stream), 0, G_SEEK_SET, NULL, NULL);
			if (!camel_data_wrapper_construct_from_stream_sync (CAMEL_DATA_WRAPPER (msg2), cache_stream, cancellable, NULL)) {
				g_object_unref (msg2);
			} else {
				g_object_unref (*msg);
				*msg = msg2;
			}
		}

		g_object_unref (cache_stream);
	}

	camel_folder_summary_unlock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
}

struct GatherChangedObjectsData
{
	CamelFolderSummary *summary;
	mapi_id_t fid;
	GSList *to_update; /* mapi_id_t * */
	GHashTable *removed_uids;
	time_t latest_last_modify;
};

static gboolean
gather_changed_objects_to_slist (EMapiConnection *conn,
				 mapi_id_t fid,
				 TALLOC_CTX *mem_ctx,
				 const ListObjectsData *object_data,
				 guint32 obj_index,
				 guint32 obj_total,
				 gpointer user_data,
				 GCancellable *cancellable,
				 GError **perror)
{
	struct GatherChangedObjectsData *gco = user_data;
	gchar *uid_str;
	gboolean update = FALSE;

	g_return_val_if_fail (gco != NULL, FALSE);
	g_return_val_if_fail (object_data != NULL, FALSE);

	uid_str = e_mapi_util_mapi_id_to_string (object_data->mid);
	if (!uid_str)
		return FALSE;

	if (camel_folder_summary_check_uid (gco->summary, uid_str)) {
		CamelMessageInfo *info;

		if (gco->removed_uids)
			g_hash_table_remove (gco->removed_uids, uid_str);

		info = camel_folder_summary_get (gco->summary, uid_str);
		if (info) {
			CamelMapiMessageInfo *minfo = (CamelMapiMessageInfo *) info;

			if (minfo->last_modified != object_data->last_modified) {
				update = TRUE;
			} else {
				guint32 mask = CAMEL_MESSAGE_SEEN | CAMEL_MESSAGE_ATTACHMENTS, flags = 0;

				if ((object_data->msg_flags & MSGFLAG_READ) != 0)
					flags |= CAMEL_MESSAGE_SEEN;
				if ((object_data->msg_flags & MSGFLAG_HASATTACH) != 0)
					flags |= CAMEL_MESSAGE_ATTACHMENTS;

				if ((minfo->info.flags & mask) != (flags & mask)) {
					camel_message_info_set_flags (info, mask, flags);
					minfo->server_flags = camel_message_info_flags (info);
					minfo->info.dirty = TRUE;
				}
			}

			camel_message_info_free (info);
		}
	} else {
		update = TRUE;
	}

	if (update) {
		mapi_id_t *pmid = g_new0 (mapi_id_t, 1);

		*pmid = object_data->mid;

		gco->to_update = g_slist_prepend (gco->to_update, pmid);
	}

	if (gco->latest_last_modify < object_data->last_modified)
		gco->latest_last_modify = object_data->last_modified;

	if (obj_total > 0)
		camel_operation_progress (cancellable, obj_index * 100 / obj_total);

	g_free (uid_str);

	return TRUE;
}

struct GatherObjectSummaryData
{
	CamelFolder *folder;
	CamelFolderChangeInfo *changes;
};

static void
remove_removed_uids_cb (gpointer uid_str, gpointer value, gpointer user_data)
{
	struct GatherObjectSummaryData *gos = user_data;

	g_return_if_fail (gos != NULL);
	g_return_if_fail (gos->folder != NULL);
	g_return_if_fail (gos->changes != NULL);

	camel_folder_change_info_remove_uid (gos->changes, uid_str);
	camel_folder_summary_remove_uid (gos->folder->summary, uid_str);
	camel_data_cache_remove (CAMEL_MAPI_FOLDER (gos->folder)->cache, "cache", uid_str, NULL);
}

static gboolean
gather_object_offline_cb (EMapiConnection *conn,
			  TALLOC_CTX *mem_ctx,
			  /* const */ EMapiObject *object,
			  guint32 obj_index,
			  guint32 obj_total,
			  gpointer user_data,
			  GCancellable *cancellable,
			  GError **perror)
{
	struct GatherObjectSummaryData *gos = user_data;
	CamelMimeMessage *msg;

	g_return_val_if_fail (gos != NULL, FALSE);
	g_return_val_if_fail (gos->folder != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);

	msg = e_mapi_mail_utils_object_to_message (conn, object);
	if (msg) {
		gchar *uid_str;
		const mapi_id_t *pmid;
		const uint32_t *pmsg_flags;
		const struct FILETIME *last_modified;
		uint32_t msg_flags;
		CamelMessageInfo *info;
		gboolean is_new;

		pmid = e_mapi_util_find_array_propval (&object->properties, PR_MID);
		pmsg_flags = e_mapi_util_find_array_propval (&object->properties, PR_MESSAGE_FLAGS);
		last_modified = e_mapi_util_find_array_propval (&object->properties, PR_LAST_MODIFICATION_TIME);

		if (!pmid) {
			g_debug ("%s: Received message [%d/%d] without PR_MID", G_STRFUNC, obj_index, obj_total);
			e_mapi_debug_dump_object (object, TRUE, 3);
			return TRUE;
		}

		if (!last_modified) {
			g_debug ("%s: Received message [%d/%d] without PR_LAST_MODIFICATION_TIME", G_STRFUNC, obj_index, obj_total);
			e_mapi_debug_dump_object (object, TRUE, 3);
		}

		uid_str = e_mapi_util_mapi_id_to_string (*pmid);
		if (!uid_str)
			return FALSE;

		msg_flags = pmsg_flags ? *pmsg_flags : 0;

		is_new = !camel_folder_summary_check_uid (gos->folder->summary, uid_str);
		if (!is_new)
			camel_folder_summary_remove_uid (gos->folder->summary, uid_str);

		info = camel_folder_summary_info_new_from_message (gos->folder->summary, msg, NULL);
		if (info) {
			CamelMapiMessageInfo *minfo = (CamelMapiMessageInfo *) info;
			guint32 flags = 0, mask = CAMEL_MESSAGE_SEEN | CAMEL_MESSAGE_ATTACHMENTS;

			minfo->info.uid = camel_pstring_strdup (uid_str);

			if (last_modified) {
				minfo->last_modified = e_mapi_util_filetime_to_time_t (last_modified);
			} else {
				minfo->last_modified = 0;
			}

			if ((msg_flags & MSGFLAG_READ) != 0)
				flags |= CAMEL_MESSAGE_SEEN;
			if ((msg_flags & MSGFLAG_HASATTACH) != 0)
				flags |= CAMEL_MESSAGE_ATTACHMENTS;

			if ((camel_message_info_flags (info) & mask) != flags) {
				if (is_new)
					minfo->info.flags = flags;
				else
					camel_message_info_set_flags (info, mask, flags);
				minfo->server_flags = camel_message_info_flags (info);
			}

			minfo->info.dirty = TRUE;

			if (is_new) {
				camel_folder_summary_add (gos->folder->summary, info);
				camel_folder_change_info_add_uid (gos->changes, camel_message_info_uid (info));
				camel_folder_change_info_recent_uid (gos->changes, camel_message_info_uid (info));

				camel_message_info_ref (info);
			} else {
				camel_folder_change_info_change_uid (gos->changes, camel_message_info_uid (info));
			}

			add_message_to_cache (CAMEL_MAPI_FOLDER (gos->folder), uid_str, &msg, cancellable);

			camel_message_info_free (info);
		} else {
			g_debug ("%s: Failed to create message info from message", G_STRFUNC);
		}

		g_free (uid_str);
		g_object_unref (msg);
	} else {
		g_debug ("%s: Failed to create message from object", G_STRFUNC);
	}

	if (obj_total > 0)
		camel_operation_progress (cancellable, obj_index * 100 / obj_total);

	return TRUE;
}

static gboolean
gather_object_summary_cb (EMapiConnection *conn,
			  TALLOC_CTX *mem_ctx,
			  /* const */ EMapiObject *object,
			  guint32 obj_index,
			  guint32 obj_total,
			  gpointer user_data,
			  GCancellable *cancellable,
			  GError **perror)
{
	struct GatherObjectSummaryData *gos = user_data;
	gchar *uid_str;
	const mapi_id_t *pmid;
	const uint32_t *pmsg_flags;
	const struct FILETIME *last_modified;
	const gchar *transport_headers;
	uint32_t msg_flags;
	CamelMessageInfo *info;
	gboolean is_new = FALSE;

	g_return_val_if_fail (gos != NULL, FALSE);
	g_return_val_if_fail (gos->folder != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);

	pmid = e_mapi_util_find_array_propval (&object->properties, PR_MID);
	pmsg_flags = e_mapi_util_find_array_propval (&object->properties, PR_MESSAGE_FLAGS);
	last_modified = e_mapi_util_find_array_propval (&object->properties, PR_LAST_MODIFICATION_TIME);
	transport_headers = e_mapi_util_find_array_propval (&object->properties, PR_TRANSPORT_MESSAGE_HEADERS_UNICODE);

	if (!pmid) {
		g_debug ("%s: Received message [%d/%d] without PR_MID", G_STRFUNC, obj_index, obj_total);
		e_mapi_debug_dump_object (object, TRUE, 3);
		return TRUE;
	}

	if (!last_modified) {
		g_debug ("%s: Received message [%d/%d] without PR_LAST_MODIFICATION_TIME", G_STRFUNC, obj_index, obj_total);
		e_mapi_debug_dump_object (object, TRUE, 3);
	}

	uid_str = e_mapi_util_mapi_id_to_string (*pmid);
	if (!uid_str)
		return FALSE;

	msg_flags = pmsg_flags ? *pmsg_flags : 0;

	info = camel_folder_summary_get (gos->folder->summary, uid_str);
	if (!info) {
		is_new = TRUE;

		if (transport_headers && *transport_headers) {
			CamelMimePart *part = camel_mime_part_new ();
			CamelStream *stream;
			CamelMimeParser *parser;

			stream = camel_stream_mem_new_with_buffer (transport_headers, strlen (transport_headers));
			parser = camel_mime_parser_new ();
			camel_mime_parser_init_with_stream (parser, stream, NULL);
			camel_mime_parser_scan_from (parser, FALSE);
			g_object_unref (stream);

			if (camel_mime_part_construct_from_parser_sync (part, parser, NULL, NULL)) {
				info = camel_folder_summary_info_new_from_header (gos->folder->summary, part->headers);
				if (info) {
					CamelMapiMessageInfo *minfo = (CamelMapiMessageInfo *) info;

					minfo->info.uid = camel_pstring_strdup (uid_str);
				}
			}

			g_object_unref (parser);
			g_object_unref (part);
		}

		if (!info) {
			CamelMapiMessageInfo *minfo;
			const gchar *subject, *message_id, *references, *in_reply_to, *display_to, *display_cc;
			const struct FILETIME *delivery_time;
			const uint32_t *msg_size;
			gchar *formatted_addr, *from_name, *from_email;
			CamelAddress *to_addr, *cc_addr, *bcc_addr;

			subject = e_mapi_util_find_array_propval (&object->properties, PR_SUBJECT_UNICODE);
			delivery_time = e_mapi_util_find_array_propval (&object->properties, PR_MESSAGE_DELIVERY_TIME);
			msg_size = e_mapi_util_find_array_propval (&object->properties, PR_MESSAGE_SIZE);
			message_id = e_mapi_util_find_array_propval (&object->properties, PR_INTERNET_MESSAGE_ID);
			references = e_mapi_util_find_array_propval (&object->properties, PR_INTERNET_REFERENCES);
			in_reply_to = e_mapi_util_find_array_propval (&object->properties, PR_IN_REPLY_TO_ID);
			display_to = e_mapi_util_find_array_propval (&object->properties, PR_DISPLAY_TO_UNICODE);
			display_cc = e_mapi_util_find_array_propval (&object->properties, PR_DISPLAY_CC_UNICODE);

			info = camel_message_info_new (gos->folder->summary);
			minfo = (CamelMapiMessageInfo *) info;

			minfo->info.uid = camel_pstring_strdup (uid_str);
			minfo->info.subject = camel_pstring_strdup (subject);
			minfo->info.date_sent = minfo->info.date_received = e_mapi_util_filetime_to_time_t (delivery_time);
			minfo->info.size = msg_size ? *msg_size : 0;

			/* Threading related properties */
			mapi_set_message_id (minfo, message_id);
			if (references || in_reply_to)
				mapi_set_message_references (minfo, references, in_reply_to);

			/* Recipients */
			to_addr = (CamelAddress *) camel_internet_address_new ();
			cc_addr = (CamelAddress *) camel_internet_address_new ();
			bcc_addr = (CamelAddress *) camel_internet_address_new ();

			e_mapi_mail_utils_decode_recipients (conn, object->recipients, to_addr, cc_addr, bcc_addr);

			if (camel_address_length (to_addr) > 0) {
				formatted_addr = camel_address_format (to_addr);
				minfo->info.to = camel_pstring_strdup (formatted_addr);
				g_free (formatted_addr);
			} else {
				minfo->info.to = camel_pstring_strdup (display_to);
			}

			if (camel_address_length (cc_addr) > 0) {
				formatted_addr = camel_address_format (cc_addr);
				minfo->info.cc = camel_pstring_strdup (formatted_addr);
				g_free (formatted_addr);
			} else {
				minfo->info.cc = camel_pstring_strdup (display_cc);
			}

			g_object_unref (to_addr);
			g_object_unref (cc_addr);
			g_object_unref (bcc_addr);

			from_name = NULL;
			from_email = NULL;

			e_mapi_mail_utils_decode_email_address1 (conn, &object->properties,
				PR_SENT_REPRESENTING_NAME_UNICODE,
				PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE,
				PR_SENT_REPRESENTING_ADDRTYPE,
				&from_name, &from_email);

			if (from_email && *from_email) {
				formatted_addr = camel_internet_address_format_address (from_name, from_email);

				minfo->info.from = camel_pstring_strdup (formatted_addr);

				g_free (formatted_addr);
			}
			
			g_free (from_name);
			g_free (from_email);
		}
	}

	if (info) {
		CamelMapiMessageInfo *minfo = (CamelMapiMessageInfo *) info;
		guint32 flags = 0, mask = CAMEL_MESSAGE_SEEN | CAMEL_MESSAGE_ATTACHMENTS;

		if (last_modified) {
			minfo->last_modified = e_mapi_util_filetime_to_time_t (last_modified);
		} else {
			minfo->last_modified = 0;
		}

		if ((msg_flags & MSGFLAG_READ) != 0)
			flags |= CAMEL_MESSAGE_SEEN;
		if ((msg_flags & MSGFLAG_HASATTACH) != 0)
			flags |= CAMEL_MESSAGE_ATTACHMENTS;

		if ((camel_message_info_flags (info) & mask) != flags) {
			if (is_new)
				minfo->info.flags = flags;
			else
				camel_message_info_set_flags (info, mask, flags);
			minfo->server_flags = camel_message_info_flags (info);
		}

		minfo->info.dirty = TRUE;

		if (is_new) {
			camel_folder_summary_add (gos->folder->summary, info);
			camel_folder_change_info_add_uid (gos->changes, camel_message_info_uid (info));
			camel_folder_change_info_recent_uid (gos->changes, camel_message_info_uid (info));

			camel_message_info_ref (info);
		} else {
			camel_folder_change_info_change_uid (gos->changes, camel_message_info_uid (info));
		}

		camel_message_info_free (info);
	}

	if (obj_total > 0)
		camel_operation_progress (cancellable, obj_index * 100 / obj_total);

	g_free (uid_str);

	return TRUE;
}

gboolean
camel_mapi_folder_fetch_summary (CamelFolder *folder, GCancellable *cancellable, GError **mapi_error)
{
	gboolean status;
	gboolean full_download;
	CamelSettings *settings;
	CamelStore *store = camel_folder_get_parent_store (folder);
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);
	CamelMapiFolderSummary *mapi_summary = CAMEL_MAPI_FOLDER_SUMMARY (folder->summary);
	EMapiConnection *conn = camel_mapi_store_get_connection (mapi_store);
	struct FolderBasicPropertiesData fbp;
	struct GatherChangedObjectsData gco;
	mapi_object_t obj_folder;

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (store)))
		return FALSE;

	camel_folder_freeze (folder);

	settings = camel_service_get_settings (CAMEL_SERVICE (store));
	full_download =
		camel_offline_settings_get_stay_synchronized (CAMEL_OFFLINE_SETTINGS (settings)) ||
		camel_offline_folder_get_offline_sync (CAMEL_OFFLINE_FOLDER (folder));

	camel_operation_push_message (cancellable, _("Refreshing folder '%s'"), camel_folder_get_display_name (folder));

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	if ((CAMEL_MAPI_FOLDER (folder)->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0)
		status = e_mapi_connection_open_public_folder (conn, mapi_folder->folder_id, &obj_folder, cancellable, mapi_error);
	else
		status = e_mapi_connection_open_personal_folder (conn, mapi_folder->folder_id, &obj_folder, cancellable, mapi_error);

	if (status) {
		status = e_mapi_connection_get_folder_properties (conn, &obj_folder, NULL, NULL, e_mapi_utils_get_folder_basic_properties_cb, &fbp, cancellable, mapi_error);
		if (status) {
			if (mapi_summary->last_obj_total != fbp.obj_total)
				mapi_summary->latest_last_modify = 0;
		}
	}

	gco.latest_last_modify = 0;
	gco.fid = mapi_object_get_id (&obj_folder);
	gco.summary = folder->summary;
	gco.to_update = NULL;
	gco.removed_uids = NULL;

	if (mapi_summary->latest_last_modify <= 0) {
		GPtrArray *known_uids;

		camel_folder_summary_prepare_fetch_all (folder->summary, NULL);

		gco.removed_uids = g_hash_table_new_full (g_str_hash, g_str_equal, (GDestroyNotify) camel_pstring_free, NULL);
		known_uids = camel_folder_summary_get_array (folder->summary);
		if (known_uids) {
			gint ii;

			for (ii = 0; ii < known_uids->len; ii++) {
				g_hash_table_insert (gco.removed_uids, (gpointer) camel_pstring_strdup (g_ptr_array_index (known_uids, ii)), GINT_TO_POINTER (1));
			}

			camel_folder_summary_free_array (known_uids);
		}
	}

	if (status) {
		status = e_mapi_connection_list_objects (conn, &obj_folder,
			full_download ? NULL : e_mapi_utils_build_last_modify_restriction, &mapi_summary->latest_last_modify,
			gather_changed_objects_to_slist, &gco, cancellable, mapi_error);
	}

	if (status && gco.to_update) {
		struct GatherObjectSummaryData gos;

		gos.folder = folder;
		gos.changes = camel_folder_change_info_new ();

		if (gco.removed_uids)
			g_hash_table_foreach (gco.removed_uids, remove_removed_uids_cb, &gos);

		if (full_download) {
			camel_operation_push_message (cancellable, _("Downloading messages in folder '%s'"), camel_folder_get_display_name (folder));

			status = e_mapi_connection_transfer_objects (conn, &obj_folder, gco.to_update, gather_object_offline_cb, &gos, cancellable, mapi_error);

			camel_operation_pop_message (cancellable);
		} else {
			status = e_mapi_connection_transfer_summary (conn, &obj_folder, gco.to_update, gather_object_summary_cb, &gos, cancellable, mapi_error);
		}

		if (camel_folder_change_info_changed (gos.changes))
			camel_folder_changed (folder, gos.changes);
		camel_folder_change_info_free (gos.changes);
	} else if (status && gco.removed_uids) {
		struct GatherObjectSummaryData gos;

		gos.folder = folder;
		gos.changes = camel_folder_change_info_new ();

		g_hash_table_foreach (gco.removed_uids, remove_removed_uids_cb, &gos);

		if (camel_folder_change_info_changed (gos.changes))
			camel_folder_changed (folder, gos.changes);
		camel_folder_change_info_free (gos.changes);
	}

	e_mapi_connection_close_folder (conn, &obj_folder, cancellable, mapi_error);

	g_slist_free_full (gco.to_update, g_free);
	if (gco.removed_uids)
		g_hash_table_destroy (gco.removed_uids);

	camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	camel_operation_pop_message (cancellable);

	if (status) {
		if (gco.latest_last_modify > 0)
			mapi_summary->latest_last_modify = gco.latest_last_modify;
		mapi_summary->last_obj_total = fbp.obj_total;
	}

	camel_folder_thaw (folder);

	return status;
}

gboolean
mapi_refresh_folder (CamelFolder *folder, GCancellable *cancellable, GError **error)
{

	CamelMapiStore *mapi_store;
	CamelMapiFolder *mapi_folder;
	CamelService *service;
	CamelStore *parent_store;
	gboolean is_locked = FALSE;
	gboolean status;
	gboolean success = TRUE;
	GError *mapi_error = NULL;

	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);
	service = CAMEL_SERVICE (parent_store);

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store)))
		goto end1;

	/* Sync-up the (un)read changes before getting updates,
	so that the getFolderList will reflect the most recent changes too */
	mapi_folder_synchronize_sync (folder, FALSE, cancellable, NULL);

	if (!mapi_folder->folder_id) {
		d(printf ("\nERROR - Folder id not present. Cannot refresh info for %s\n", full_name));
		goto end1;
	}

	if (camel_folder_is_frozen (folder)) {
		mapi_folder->need_refresh = TRUE;
	}

	camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
	is_locked = TRUE;

	if (!camel_mapi_store_connected (mapi_store, NULL))
		goto end1;

	if (!camel_mapi_store_connected (mapi_store, NULL)) {
		/*BUG : Fix exception string.*/
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("This message is not available in offline mode."));
		success = FALSE;
		goto end1;
	}

	status = camel_mapi_folder_fetch_summary (folder, cancellable, &mapi_error);

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

	camel_folder_summary_touch (folder->summary);

	camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
	is_locked = FALSE;

 end1:
	if (is_locked)
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

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

	info = camel_folder_summary_get (folder->summary, uid);
	if (info == NULL)
		return FALSE;

	res = camel_message_info_set_flags (info, flags, set);

	camel_message_info_free (info);
	return res;
}

static void
mapi_folder_dispose (GObject *object)
{
	CamelStore *parent_store;
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (object);

	if (mapi_folder->cache != NULL) {
		g_object_unref (mapi_folder->cache);
		mapi_folder->cache = NULL;
	}

	parent_store = camel_folder_get_parent_store (CAMEL_FOLDER (mapi_folder));
	if (parent_store) {
		camel_store_summary_disconnect_folder_summary (
			(CamelStoreSummary *) ((CamelMapiStore *) parent_store)->summary,
			CAMEL_FOLDER (mapi_folder)->summary);
	}

	/* Chain up to parent's dispose() method. */
	G_OBJECT_CLASS (camel_mapi_folder_parent_class)->dispose (object);
}

static void
mapi_folder_constructed (GObject *object)
{
	CamelNetworkSettings *network_settings;
	CamelSettings *settings;
	CamelStore *parent_store;
	CamelService *service;
	CamelFolder *folder;
	const gchar *full_name;
	const gchar *host;
	const gchar *user;
	gchar *description;

	folder = CAMEL_FOLDER (object);
	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	service = CAMEL_SERVICE (parent_store);
	settings = camel_service_get_settings (service);

	network_settings = CAMEL_NETWORK_SETTINGS (settings);
	host = camel_network_settings_get_host (network_settings);
	user = camel_network_settings_get_user (network_settings);

	description = g_strdup_printf (
		"%s@%s:%s", user, host, full_name);
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
	si = camel_store_summary_path (mapi_store->summary, full_name);
	if (si) {
		folder_flags = si->flags;
		camel_store_summary_info_free (mapi_store->summary, si);
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

	e_mapi_util_mapi_id_from_string (folder_id, &fid);

	/* Convert MIME to Item */
	from = (CamelAddress *) camel_mime_message_get_from (message);

	item = mapi_mime_message_to_mail_item (message, info ? camel_message_info_flags (info) : 0, from, cancellable, error);
	if (item == NULL)
		return FALSE;

	mid = e_mapi_connection_create_item (camel_mapi_store_get_connection (mapi_store), -1, fid,
					 mapi_mail_utils_create_item_build_props, item,
					 item->recipients, item->attachments,
					 item->generic_streams, MAPI_OPTIONS_DONT_SUBMIT, cancellable, &mapi_error);

	if (mid) {
		CamelFolderChangeInfo *changes = camel_folder_change_info_new ();
		GSList *items = g_slist_append (NULL, item);
		guint32 flags;

		item->fid = fid;
		item->mid = mid;

		flags = item->header.flags;
		item->header.flags = 0;
		if (flags & MSGFLAG_READ)
			item->header.flags |= CAMEL_MESSAGE_SEEN;
		if (flags & MSGFLAG_HASATTACH)
			item->header.flags |= CAMEL_MESSAGE_ATTACHMENTS;

		mapi_update_cache (folder, items, &changes, cancellable, error);

		g_slist_free (items);

		if (camel_folder_change_info_changed (changes))
			camel_folder_changed (folder, changes);
		camel_folder_change_info_free (changes);
	}

	mail_item_free (item);

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
		*appended_uid = e_mapi_util_mapi_id_to_string (mid);

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
	GPtrArray *known_uids;
	gint i;
	gboolean delete = FALSE, status = FALSE;
	GSList *deleted_items, *deleted_head;
	GSList *deleted_items_uid, *deleted_items_uid_head;

	deleted_items = deleted_head = NULL;
	deleted_items_uid = deleted_items_uid_head = NULL;

	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	if ((mapi_folder->camel_folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
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
			if (mf && (mf->camel_folder_flags & CAMEL_FOLDER_TYPE_MASK) != CAMEL_FOLDER_TYPE_TRASH) {
				if (camel_folder_get_deleted_message_count (opened_folder) > 0)
					camel_folder_synchronize_sync (opened_folder, TRUE, cancellable, NULL);
			}

			g_object_unref (opened_folder);
		}
		g_ptr_array_free (folders, TRUE);

		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		status = e_mapi_connection_empty_folder (camel_mapi_store_get_connection (mapi_store), mapi_folder->folder_id, 0, cancellable, &mapi_error);
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
	known_uids = camel_folder_summary_get_array (folder->summary);

	/*Collect UIDs of deleted messages.*/
	for (i = 0; known_uids && i < known_uids->len; i++) {
		info = camel_folder_summary_get (folder->summary, g_ptr_array_index (known_uids, i));
		minfo = (CamelMapiMessageInfo *) info;
		if (minfo && (minfo->info.flags & CAMEL_MESSAGE_DELETED)) {
			const gchar *uid = camel_message_info_uid (info);
			mapi_id_t *mid = g_new0 (mapi_id_t, 1);

			if (!e_mapi_util_mapi_id_from_string (uid, mid))
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

	camel_folder_summary_free_array (known_uids);

	deleted_items_uid_head = deleted_items_uid;

	if (deleted_items) {
		camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

		status = e_mapi_connection_remove_items (camel_mapi_store_get_connection (mapi_store), 0, mapi_folder->folder_id, 0, deleted_items, cancellable, NULL);

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

	camel_folder_change_info_free (changes);

	return TRUE;
}

static CamelMimeMessage *
mapi_folder_get_message_cached (CamelFolder *folder,
				 const gchar *message_uid,
				 GCancellable *cancellable)
{
	CamelMapiFolder *mapi_folder;
	CamelMimeMessage *msg = NULL;
	CamelStream *stream, *cache_stream;

	mapi_folder = CAMEL_MAPI_FOLDER (folder);

	if (!camel_folder_summary_check_uid (folder->summary, message_uid))
		return NULL;

	cache_stream  = camel_data_cache_get (mapi_folder->cache, "cache", message_uid, NULL);
	stream = camel_stream_mem_new ();
	if (cache_stream) {
		GError *local_error = NULL;

		msg = camel_mime_message_new ();

		g_seekable_seek (G_SEEKABLE (stream), 0, G_SEEK_SET, NULL, NULL);
		camel_stream_write_to_stream (cache_stream, stream, cancellable, NULL);
		g_seekable_seek (G_SEEKABLE (stream), 0, G_SEEK_SET, NULL, NULL);
		if (!camel_data_wrapper_construct_from_stream_sync ((CamelDataWrapper *) msg, stream, cancellable, &local_error)) {
			g_object_unref (msg);
			msg = NULL;
		}

		g_clear_error (&local_error);
		g_object_unref (cache_stream);
	}

	g_object_unref (stream);

	return msg;
}

static gboolean
transfer_mail_object_cb (EMapiConnection *conn,
			 TALLOC_CTX *mem_ctx,
			 /* const */ EMapiObject *object,
			 guint32 obj_index,
			 guint32 obj_total,
			 gpointer user_data,
			 GCancellable *cancellable,
			 GError **perror)
{
	CamelMimeMessage **pmessage = user_data;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (pmessage != NULL, FALSE);

	*pmessage = e_mapi_mail_utils_object_to_message (conn, object);

	if (obj_total > 0)
		camel_operation_progress (cancellable, obj_index * 100 / obj_total);

	return TRUE;
}

static CamelMimeMessage *
mapi_folder_get_message_sync (CamelFolder *folder,
                              const gchar *uid,
                              GCancellable *cancellable,
                              GError **error)
{
	CamelMimeMessage *msg = NULL;
	CamelMapiFolder *mapi_folder;
	CamelMapiStore *mapi_store;
	CamelMapiMessageInfo *mi = NULL;
	CamelStore *parent_store;
	mapi_id_t id_message;
	EMapiConnection *conn;
	mapi_object_t obj_folder;
	gboolean success;
	GError *mapi_error = NULL;

	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	/* see if it is there in cache */

	mi = (CamelMapiMessageInfo *) camel_folder_summary_get (folder->summary, uid);
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

	msg = mapi_folder_get_message_cached (folder, uid, cancellable);
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

	e_mapi_util_mapi_id_from_string (uid, &id_message);

	conn = camel_mapi_store_get_connection (mapi_store);

	if (mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC)
		success = e_mapi_connection_open_public_folder (conn, mapi_folder->folder_id, &obj_folder, cancellable, &mapi_error);
	else
		success = e_mapi_connection_open_personal_folder (conn, mapi_folder->folder_id, &obj_folder, cancellable, &mapi_error);

	if (success) {
		success = e_mapi_connection_transfer_object (conn, &obj_folder, id_message, transfer_mail_object_cb, &msg, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, NULL);
	}

	if (!msg) {
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

	add_message_to_cache (mapi_folder, uid, &msg, cancellable);

	camel_message_info_free (&mi->info);

	return msg;
}

static gboolean
mapi_folder_refresh_info_sync (CamelFolder *folder,
                               GCancellable *cancellable,
                               GError **error)
{
	return mapi_refresh_folder (folder, cancellable, error);
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
	CamelServiceConnectionStatus status;
	CamelService *service;
	GPtrArray *known_uids;
	GSList *read_items = NULL, *unread_items = NULL, *to_free = NULL, *junk_items = NULL, *deleted_items = NULL, *l;
	flags_diff_t diff, unset_flags;
	const gchar *folder_id;
	const gchar *full_name;
	mapi_id_t fid, deleted_items_fid;
	gint i;
	guint32 options =0;
	gboolean is_junk_folder;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	service = CAMEL_SERVICE (mapi_store);
	status = camel_service_get_connection_status (service);

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store)) ||
	    status == CAMEL_SERVICE_DISCONNECTED) {
		return TRUE;
	}

	if (((CamelMapiFolder *)folder)->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, full_name);
	e_mapi_util_mapi_id_from_string (folder_id, &fid);

	camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
	if (!camel_mapi_store_connected (mapi_store, NULL)) {
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		return TRUE;
	}
	camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

	is_junk_folder = (mapi_folder->camel_folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_JUNK;

	camel_folder_summary_lock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);
	camel_folder_summary_prepare_fetch_all (folder->summary, NULL);

	known_uids = camel_folder_summary_get_array (folder->summary);
	for (i = 0; known_uids && i < known_uids->len; i++) {
		info = camel_folder_summary_get (folder->summary, g_ptr_array_index (known_uids, i));
		mapi_info = (CamelMapiMessageInfo *) info;

		if (mapi_info && (mapi_info->info.flags & CAMEL_MESSAGE_FOLDER_FLAGGED)) {
			const gchar *uid;
			mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
			guint32 flags;
			gboolean used = FALSE;

			uid = camel_message_info_uid (info);
			flags= camel_message_info_flags (info);

			/* Why are we getting so much noise here :-/ */
			if (!e_mapi_util_mapi_id_from_string (uid, mid)) {
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

	camel_folder_summary_free_array (known_uids);
	camel_folder_summary_unlock (folder->summary, CAMEL_FOLDER_SUMMARY_SUMMARY_LOCK);

	/*
	   Sync up the READ changes before deleting the message.
	   Note that if a message is marked as unread and then deleted,
	   Evo doesnt not take care of it, as I find that scenario to be impractical.
	*/

	if (read_items) {
		camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		e_mapi_connection_set_flags (camel_mapi_store_get_connection (mapi_store), 0, fid, options, read_items, 0, cancellable, NULL);
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
	}

	if (unread_items) {
		camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		e_mapi_connection_set_flags (camel_mapi_store_get_connection (mapi_store), 0, fid, options, unread_items, CLEAR_READ_FLAG, cancellable, NULL);
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
	}

	/* Remove messages from server*/
	if (deleted_items) {
		camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		if ((mapi_folder->camel_folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
			e_mapi_connection_remove_items (camel_mapi_store_get_connection (mapi_store), 0, fid, options, deleted_items, cancellable, NULL);
		} else {
			GError *err = NULL;

			e_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderDeletedItems), &deleted_items_fid);
			e_mapi_connection_move_items (camel_mapi_store_get_connection (mapi_store), fid, options, deleted_items_fid, 0, deleted_items, cancellable, &err);

			if (err) {
				g_warning ("%s: Failed to move deleted items: %s", G_STRFUNC, err->message);
				g_error_free (err);
			}
		}

		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
	}

	if (junk_items) {
		mapi_id_t junk_fid = 0;
		GError *err = NULL;

		camel_service_lock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);
		e_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderJunk), &junk_fid);
		e_mapi_connection_move_items (camel_mapi_store_get_connection (mapi_store), fid, options, junk_fid, 0, junk_items, cancellable, &err);
		camel_service_unlock (service, CAMEL_SERVICE_REC_CONNECT_LOCK);

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

	return TRUE;
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
	guint32 src_fid_options, dest_fid_options;

	CamelOfflineStore *offline;
	CamelMapiStore *mapi_store;
	CamelFolderChangeInfo *changes = NULL;
	CamelStore *source_parent_store;
	CamelStore *destination_parent_store;
	CamelMapiFolder *src_mapi_folder, *des_mapi_folder;
	gint i = 0;
	GSList *src_msg_ids = NULL;
	gboolean success = TRUE;

	if (CAMEL_IS_MAPI_FOLDER (source)) {
		/* make sure changed flags are written into the server */
		if (!mapi_folder_synchronize_sync (source, FALSE, cancellable, error))
			return FALSE;
	}

	if (!CAMEL_IS_MAPI_FOLDER (source) || !CAMEL_IS_MAPI_FOLDER (destination) ||
	    (CAMEL_MAPI_FOLDER (source)->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ||
	    (CAMEL_MAPI_FOLDER (destination)->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0) {
		CamelFolderClass *folder_class;

		/* because cannot use MAPI to copy/move messages with public folders,
		   thus fallback to per-message copy/move */
		folder_class = CAMEL_FOLDER_CLASS (camel_mapi_folder_parent_class);
		return folder_class->transfer_messages_to_sync (
			source, uids, destination, delete_originals,
			transferred_uids, cancellable, error);
	}

	source_parent_store = camel_folder_get_parent_store (source);
	destination_parent_store = camel_folder_get_parent_store (destination);

	mapi_store = CAMEL_MAPI_STORE (source_parent_store);
	offline = CAMEL_OFFLINE_STORE (destination_parent_store);

	/* check for offline operation */
	if (!camel_offline_store_get_online (offline))
		return FALSE;

	src_mapi_folder = CAMEL_MAPI_FOLDER (source);
	src_fid_options = (src_mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ? MAPI_OPTIONS_USE_PFSTORE : 0;

	des_mapi_folder = CAMEL_MAPI_FOLDER (destination);
	dest_fid_options = (des_mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ? MAPI_OPTIONS_USE_PFSTORE : 0;

	for (i=0; i < uids->len; i++) {
		mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
		if (!e_mapi_util_mapi_id_from_string (g_ptr_array_index (uids, i), mid))
			continue;

		src_msg_ids = g_slist_prepend (src_msg_ids, mid);
	}

	if (delete_originals) {
		GError *err = NULL;

		if (!e_mapi_connection_move_items (camel_mapi_store_get_connection (mapi_store), src_mapi_folder->folder_id, src_fid_options, des_mapi_folder->folder_id, dest_fid_options, src_msg_ids, cancellable, &err)) {
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

		if (!e_mapi_connection_copy_items (camel_mapi_store_get_connection (mapi_store), src_mapi_folder->folder_id, src_fid_options, des_mapi_folder->folder_id, dest_fid_options, src_msg_ids, cancellable, &err)) {
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

	/* update the destination folder to notice new messages */
	if (success)
		success = mapi_folder_refresh_info_sync (destination, cancellable, error);

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
	folder_class->get_message_cached = mapi_folder_get_message_cached;
	folder_class->refresh_info_sync = mapi_folder_refresh_info_sync;
	folder_class->synchronize_sync = mapi_folder_synchronize_sync;
	folder_class->transfer_messages_to_sync = mapi_folder_transfer_messages_to_sync;
}

static void
camel_mapi_folder_init (CamelMapiFolder *mapi_folder)
{
	CamelFolder *folder = CAMEL_FOLDER (mapi_folder);

	mapi_folder->priv = G_TYPE_INSTANCE_GET_PRIVATE (mapi_folder, CAMEL_TYPE_MAPI_FOLDER, CamelMapiFolderPrivate);

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
	CamelService    *service;
	CamelSettings   *settings;

	gchar *state_file;
	const gchar *short_name;
	CamelStoreInfo *si;
	gboolean filter_inbox;

	service = CAMEL_SERVICE (store);
	settings = camel_service_get_settings (service);

	filter_inbox = camel_store_settings_get_filter_inbox (CAMEL_STORE_SETTINGS (settings));

	short_name = strrchr (folder_name, '/');
	if (short_name)
		short_name++;
	else
		short_name = folder_name;

	folder = g_object_new (
		CAMEL_TYPE_MAPI_FOLDER,
		"display-name", short_name, "full-name", folder_name,
		"parent-store", store, NULL);

	mapi_folder = CAMEL_MAPI_FOLDER(folder);

	folder->summary = camel_mapi_folder_summary_new (folder);

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

	if (filter_inbox) {
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

	si = camel_store_summary_path (mapi_store->summary, folder_name);
	if (si) {
		CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

		mapi_folder->mapi_folder_flags = msi->mapi_folder_flags;
		mapi_folder->camel_folder_flags = msi->camel_folder_flags;
		mapi_folder->folder_id = msi->folder_id;

		if ((si->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH)
			folder->folder_flags |= CAMEL_FOLDER_IS_TRASH;
		else if ((si->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_JUNK)
			folder->folder_flags |= CAMEL_FOLDER_IS_JUNK;
		camel_store_summary_info_free (mapi_store->summary, si);
	} else {
		g_warning ("%s: cannot find '%s' in known folders", G_STRFUNC, folder_name);
	}

	camel_store_summary_connect_folder_summary (
		((CamelMapiStore *) store)->summary,
		folder_name, folder->summary);

	return folder;
}
