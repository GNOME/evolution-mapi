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

#include "evolution-mapi-config.h"

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
#include "camel-mapi-folder-summary.h"

#define DEBUG_FN( ) printf("----%p %s\n", g_thread_self(), G_STRFUNC);
#define SUMMARY_FETCH_BATCH_COUNT 150
#define d(x)

#define CAMEL_MAPI_FOLDER_LOCK(f, l) \
	(g_mutex_lock(&((CamelMapiFolder *)f)->priv->l))
#define CAMEL_MAPI_FOLDER_UNLOCK(f, l) \
	(g_mutex_unlock(&((CamelMapiFolder *)f)->priv->l))

struct _CamelMapiFolderPrivate {
	GMutex search_lock;	/* for locking the search object */

	gchar *foreign_username;
};

static gboolean
cmf_open_folder (CamelMapiFolder *mapi_folder,
		 EMapiConnection *conn,
		 mapi_object_t *obj_folder,
		 GCancellable *cancellable,
		 GError **perror)
{
	gboolean res;
	GError *mapi_error = NULL;

	g_return_val_if_fail (mapi_folder != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (obj_folder != NULL, FALSE);

	if ((mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0)
		res = e_mapi_connection_open_foreign_folder (conn, mapi_folder->priv->foreign_username, mapi_folder->folder_id, obj_folder, cancellable, &mapi_error);
	else if ((mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0)
		res = e_mapi_connection_open_public_folder (conn, mapi_folder->folder_id, obj_folder, cancellable, &mapi_error);
	else
		res = e_mapi_connection_open_personal_folder (conn, mapi_folder->folder_id, obj_folder, cancellable, &mapi_error);

	if (mapi_error) {
		CamelMapiStore *mapi_store;

		mapi_store = CAMEL_MAPI_STORE (camel_folder_get_parent_store (CAMEL_FOLDER (mapi_folder)));
		camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);

		g_propagate_error (perror, mapi_error);
	}

	return res;
}

/*for syncing flags back to server*/
typedef struct {
	guint32 changed;
	guint32 bits;
} flags_diff_t;

/*For collecting summary info from server*/

static gboolean		mapi_folder_synchronize_sync
						(CamelFolder *folder,
						 gboolean expunge,
						 GCancellable *cancellable,
						 GError **error);

G_DEFINE_TYPE (CamelMapiFolder, camel_mapi_folder, CAMEL_TYPE_OFFLINE_FOLDER)

static GPtrArray *
mapi_folder_search_by_expression (CamelFolder *folder,
				  const gchar *expression,
				  GCancellable *cancellable,
				  GError **error)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER(folder);
	GPtrArray *matches;

	CAMEL_MAPI_FOLDER_LOCK(mapi_folder, search_lock);
	camel_folder_search_set_folder (mapi_folder->search, folder);
	matches = camel_folder_search_search(mapi_folder->search, expression, NULL, cancellable, error);
	CAMEL_MAPI_FOLDER_UNLOCK(mapi_folder, search_lock);

	return matches;
}

static GPtrArray *
mapi_folder_search_by_uids (CamelFolder *folder,
			    const gchar *expression,
			    GPtrArray *uids,
			    GCancellable *cancellable,
			    GError **error)
{
	GPtrArray *matches;
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);

	if (uids->len == 0)
		return g_ptr_array_new ();

	CAMEL_MAPI_FOLDER_LOCK (mapi_folder, search_lock);
	camel_folder_search_set_folder (mapi_folder->search, folder);
	matches = camel_folder_search_search (mapi_folder->search, expression, uids, cancellable, error);
	CAMEL_MAPI_FOLDER_UNLOCK (mapi_folder, search_lock);

	return matches;
}

static void
mapi_set_message_id (CamelMessageInfo *mi,
		     const gchar *message_id)
{
	gchar *msgid;
	guint8 *digest;
	gsize length;
	CamelSummaryMessageID tmp_msgid;

	msgid = camel_header_msgid_decode (message_id);
	if (msgid) {
		GChecksum *checksum;

		length = g_checksum_type_get_length (G_CHECKSUM_MD5);
		digest = g_alloca (length);

		checksum = g_checksum_new (G_CHECKSUM_MD5);
		g_checksum_update (checksum, (guchar *) msgid, -1);
		g_checksum_get_digest (checksum, digest, &length);
		g_checksum_free (checksum);

		memcpy (tmp_msgid.id.hash, digest, sizeof (tmp_msgid.id.hash));
		g_free (msgid);

		camel_message_info_set_message_id (mi, tmp_msgid.id.id);
	}
}

static void
mapi_set_message_references (CamelMessageInfo *mi,
			     const gchar *references,
			     const gchar *in_reply_to)
{
	GSList *refs, *irt, *link;
	guint8 *digest;
	gsize length;
	CamelSummaryMessageID tmp_msgid;

	refs = camel_header_references_decode (references);
	irt = camel_header_references_decode (in_reply_to);
	if (refs || irt) {
		GArray *references;

		if (irt) {
			/* The References field is populated from the "References" and/or "In-Reply-To"
			   headers. If both headers exist, take the first thing in the In-Reply-To header
			   that looks like a Message-ID, and append it to the References header. */

			refs = g_slist_concat (irt, refs);
		}

		references = g_array_sized_new (FALSE, FALSE, sizeof (guint64), g_slist_length (refs));

		length = g_checksum_type_get_length (G_CHECKSUM_MD5);
		digest = g_alloca (length);

		for (link = refs; link; link = g_slist_next (link)) {
			GChecksum *checksum;

			checksum = g_checksum_new (G_CHECKSUM_MD5);
			g_checksum_update (checksum, (guchar *) link->data, -1);
			g_checksum_get_digest (checksum, digest, &length);
			g_checksum_free (checksum);

			memcpy (tmp_msgid.id.hash, digest, sizeof (tmp_msgid.id.hash));

			g_array_append_val (references, tmp_msgid.id.id);
		}

		g_slist_free_full (refs, g_free);

		camel_message_info_take_references (mi, references);
	}
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
	GIOStream *base_stream;

	g_return_if_fail (mapi_folder != NULL);
	g_return_if_fail (msg != NULL);
	g_return_if_fail (*msg != NULL);

	folder = CAMEL_FOLDER (mapi_folder);
	g_return_if_fail (folder != NULL);

	camel_folder_summary_lock (camel_folder_get_folder_summary (folder));

	base_stream = camel_data_cache_add (mapi_folder->cache, "cache", uid, NULL);
	if (base_stream != NULL) {
		CamelStream *cache_stream;

		cache_stream = camel_stream_new (base_stream);
		g_object_unref (base_stream);

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

	camel_folder_summary_unlock (camel_folder_get_folder_summary (folder));
}

struct GatherChangedObjectsData
{
	CamelFolderSummary *summary;
	mapi_id_t fid;
	GSList *to_update; /* mapi_id_t * */
	GHashTable *removed_uids;
	time_t latest_last_modify;
	gboolean is_public_folder;
};

static gboolean
gather_changed_objects_to_slist (EMapiConnection *conn,
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
			CamelMapiMessageInfo *minfo = CAMEL_MAPI_MESSAGE_INFO (info);

			if (camel_mapi_message_info_get_last_modified (minfo) != object_data->last_modified
			    && (object_data->msg_flags & MSGFLAG_UNMODIFIED) == 0) {
				update = TRUE;
			} else {
				guint32 mask = CAMEL_MESSAGE_SEEN | CAMEL_MESSAGE_ATTACHMENTS, flags = 0;

				/* do not change unread state for known messages in public folders */
				if (gco->is_public_folder)
					mask &= ~CAMEL_MESSAGE_SEEN;

				if ((object_data->msg_flags & MSGFLAG_READ) != 0)
					flags |= CAMEL_MESSAGE_SEEN;
				if ((object_data->msg_flags & MSGFLAG_HASATTACH) != 0)
					flags |= CAMEL_MESSAGE_ATTACHMENTS;

				if ((camel_message_info_get_flags (info) & CAMEL_MAPI_MESSAGE_WITH_READ_RECEIPT) != 0) {
					if ((object_data->msg_flags & MSGFLAG_RN_PENDING) == 0 &&
					    !camel_message_info_get_user_flag (info, "receipt-handled")) {
						camel_message_info_set_user_flag (info, "receipt-handled", TRUE);
					}
				}

				if ((camel_message_info_get_flags (info) & mask) != (flags & mask)) {
					camel_message_info_set_flags (info, mask, flags);
					camel_mapi_message_info_set_server_flags (minfo, camel_message_info_get_flags (info));
				}
			}

			g_clear_object (&info);
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

static void
update_message_info (CamelMessageInfo *info,
		     /* const */ EMapiObject *object,
		     gboolean is_new,
		     gboolean is_public_folder,
		     gboolean user_has_read)
{
	guint32 flags = 0, mask = CAMEL_MESSAGE_SEEN | CAMEL_MESSAGE_ATTACHMENTS | CAMEL_MESSAGE_ANSWERED | CAMEL_MESSAGE_FORWARDED | CAMEL_MAPI_MESSAGE_WITH_READ_RECEIPT;
	const uint32_t *pmsg_flags, *picon_index;
	const struct FILETIME *last_modified;
	const uint8_t *pread_receipt;
	const gchar *msg_class;
	uint32_t msg_flags;

	g_return_if_fail (info != NULL);
	g_return_if_fail (object != NULL);

	pmsg_flags = e_mapi_util_find_array_propval (&object->properties, PidTagMessageFlags);
	last_modified = e_mapi_util_find_array_propval (&object->properties, PidTagLastModificationTime);
	picon_index = e_mapi_util_find_array_propval (&object->properties, PidTagIconIndex);
	pread_receipt = e_mapi_util_find_array_propval (&object->properties, PidTagReadReceiptRequested);
	msg_class = e_mapi_util_find_array_propval (&object->properties, PidTagMessageClass);

	if (!camel_message_info_get_size (info)) {
		const uint32_t *msg_size;

		msg_size = e_mapi_util_find_array_propval (&object->properties, PidTagMessageSize);
		camel_message_info_set_size (info, msg_size ? *msg_size : 0);
	}

	if (msg_class && g_str_has_prefix (msg_class, "REPORT.IPM.Note.IPNRN"))
		pread_receipt = NULL;

	msg_flags = pmsg_flags ? *pmsg_flags : 0;

	if (!is_new && is_public_folder) {
		/* do not change unread state for known messages in public folders */
		if ((user_has_read ? 1 : 0) != ((msg_flags & MSGFLAG_READ) ? 1 : 0))
			msg_flags = (msg_flags & (~MSGFLAG_READ)) | (user_has_read ? MSGFLAG_READ : 0);
	}

	camel_mapi_message_info_set_last_modified (CAMEL_MAPI_MESSAGE_INFO (info),
		last_modified ? e_mapi_util_filetime_to_time_t (last_modified) : 0);

	if ((msg_flags & MSGFLAG_READ) != 0)
		flags |= CAMEL_MESSAGE_SEEN;
	if ((msg_flags & MSGFLAG_HASATTACH) != 0)
		flags |= CAMEL_MESSAGE_ATTACHMENTS;
	if (picon_index) {
		if (*picon_index == 0x105)
			flags |= CAMEL_MESSAGE_ANSWERED;
		if (*picon_index == 0x106)
			flags |= CAMEL_MESSAGE_FORWARDED;
	}

	if (pread_receipt && *pread_receipt)
		flags |= CAMEL_MAPI_MESSAGE_WITH_READ_RECEIPT;

	if (pread_receipt && *pread_receipt && (msg_flags & MSGFLAG_RN_PENDING) == 0)
		camel_message_info_set_user_flag (info, "receipt-handled", TRUE);

	if ((camel_message_info_get_flags (info) & mask) != flags) {
		if (is_new)
			camel_message_info_set_flags (info, ~0, flags);
		else
			camel_message_info_set_flags (info, mask, flags);
		camel_mapi_message_info_set_server_flags (CAMEL_MAPI_MESSAGE_INFO (info), camel_message_info_get_flags (info));
	}
}

static gsize
camel_mapi_get_message_size (CamelMimeMessage *msg)
{
	if (!CAMEL_IS_DATA_WRAPPER (msg))
		return 0;

	/* do not 'decode', let's be interested in the raw message size */
	return camel_data_wrapper_calculate_size_sync (CAMEL_DATA_WRAPPER (msg), NULL, NULL);
}

struct GatherObjectSummaryData
{
	CamelFolder *folder;
	CamelFolderChangeInfo *changes;
	gboolean is_public_folder;
};

static void
remove_removed_uids_cb (gpointer uid_str, gpointer value, gpointer user_data)
{
	struct GatherObjectSummaryData *gos = user_data;

	g_return_if_fail (gos != NULL);
	g_return_if_fail (gos->folder != NULL);
	g_return_if_fail (gos->changes != NULL);

	camel_folder_change_info_remove_uid (gos->changes, uid_str);
	camel_folder_summary_remove_uid (camel_folder_get_folder_summary (gos->folder), uid_str);
	camel_data_cache_remove (CAMEL_MAPI_FOLDER (gos->folder)->cache, "cache", uid_str, NULL);
}

static gboolean
gather_object_for_offline_cb (EMapiConnection *conn,
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
		CamelFolderSummary *folder_summary;
		gchar *uid_str;
		const mapi_id_t *pmid;
		CamelMessageInfo *info;
		gboolean is_new;
		gboolean user_has_read = FALSE;

		pmid = e_mapi_util_find_array_propval (&object->properties, PidTagMid);

		if (!pmid) {
			g_debug ("%s: Received message [%d/%d] without PidTagMid", G_STRFUNC, obj_index, obj_total);
			e_mapi_debug_dump_object (object, TRUE, 3);
			return TRUE;
		}

		if (!e_mapi_util_find_array_propval (&object->properties, PidTagLastModificationTime)) {
			g_debug ("%s: Received message [%d/%d] without PidTagLastModificationTime", G_STRFUNC, obj_index, obj_total);
			e_mapi_debug_dump_object (object, TRUE, 3);
		}

		uid_str = e_mapi_util_mapi_id_to_string (*pmid);
		if (!uid_str)
			return FALSE;

		folder_summary = camel_folder_get_folder_summary (gos->folder);
		is_new = !camel_folder_summary_check_uid (folder_summary, uid_str);
		if (!is_new) {
			/* keep local read/unread flag on messages from public folders */
			if (gos->is_public_folder) {
				info = camel_folder_summary_get (folder_summary, uid_str);
				if (info) {
					user_has_read = (camel_message_info_get_flags (info) & CAMEL_MESSAGE_SEEN) != 0;
					g_clear_object (&info);
				}
			}

			camel_folder_summary_remove_uid (folder_summary, uid_str);
		}

		info = camel_folder_summary_info_new_from_message (folder_summary, msg);
		if (info) {
			camel_message_info_set_abort_notifications (info, TRUE);

			camel_message_info_set_uid (info, uid_str);

			update_message_info (info, object, is_new, gos->is_public_folder, user_has_read);

			if (!camel_message_info_get_size (info))
				camel_message_info_set_size (info, camel_mapi_get_message_size (msg));

			camel_message_info_set_abort_notifications (info, FALSE);
			camel_folder_summary_add (folder_summary, info, FALSE);

			if (is_new) {
				camel_folder_change_info_add_uid (gos->changes, uid_str);
				camel_folder_change_info_recent_uid (gos->changes, uid_str);
			} else {
				camel_folder_change_info_change_uid (gos->changes, uid_str);
			}

			add_message_to_cache (CAMEL_MAPI_FOLDER (gos->folder), uid_str, &msg, cancellable);

			g_clear_object (&info);
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
	const gchar *transport_headers;
	CamelMessageInfo *info;
	gboolean is_new = FALSE;
	gboolean user_has_read;

	g_return_val_if_fail (gos != NULL, FALSE);
	g_return_val_if_fail (gos->folder != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);

	pmid = e_mapi_util_find_array_propval (&object->properties, PidTagMid);
	transport_headers = e_mapi_util_find_array_propval (&object->properties, PidTagTransportMessageHeaders);

	if (!pmid) {
		g_debug ("%s: Received message [%d/%d] without PidTagMid", G_STRFUNC, obj_index, obj_total);
		e_mapi_debug_dump_object (object, TRUE, 3);
		return TRUE;
	}

	if (!e_mapi_util_find_array_propval (&object->properties, PidTagLastModificationTime)) {
		g_debug ("%s: Received message [%d/%d] without PidTagLastModificationTime", G_STRFUNC, obj_index, obj_total);
		e_mapi_debug_dump_object (object, TRUE, 3);
	}

	uid_str = e_mapi_util_mapi_id_to_string (*pmid);
	if (!uid_str)
		return FALSE;

	info = camel_folder_summary_get (camel_folder_get_folder_summary (gos->folder), uid_str);
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
				info = camel_folder_summary_info_new_from_headers (
					camel_folder_get_folder_summary (gos->folder),
					camel_medium_get_headers (CAMEL_MEDIUM (part)));
				if (info) {
					const uint32_t *msg_size;

					camel_message_info_freeze_notifications (info);
					camel_message_info_set_uid (info, uid_str);

					msg_size = e_mapi_util_find_array_propval (&object->properties, PidTagMessageSize);
					camel_message_info_set_size (info, msg_size ? *msg_size : 0);
				}
			}

			g_object_unref (parser);
			g_object_unref (part);
		}

		if (!info) {
			const gchar *subject, *message_id, *references, *in_reply_to, *display_to, *display_cc;
			const struct FILETIME *delivery_time, *submit_time;
			const uint32_t *msg_size;
			gchar *formatted_addr, *from_name, *from_email;
			CamelAddress *to_addr, *cc_addr, *bcc_addr;

			subject = e_mapi_util_find_array_propval (&object->properties, PidTagSubject);
			delivery_time = e_mapi_util_find_array_propval (&object->properties, PidTagMessageDeliveryTime);
			submit_time = e_mapi_util_find_array_propval (&object->properties, PidTagClientSubmitTime);
			msg_size = e_mapi_util_find_array_propval (&object->properties, PidTagMessageSize);
			message_id = e_mapi_util_find_array_propval (&object->properties, PidTagInternetMessageId);
			references = e_mapi_util_find_array_propval (&object->properties, PidTagInternetReferences);
			in_reply_to = e_mapi_util_find_array_propval (&object->properties, PidTagInReplyToId);
			display_to = e_mapi_util_find_array_propval (&object->properties, PidTagDisplayTo);
			display_cc = e_mapi_util_find_array_propval (&object->properties, PidTagDisplayCc);

			info = camel_message_info_new (camel_folder_get_folder_summary (gos->folder));

			camel_message_info_freeze_notifications (info);

			camel_message_info_set_uid (info, uid_str);
			camel_message_info_set_subject (info, subject);
			camel_message_info_set_date_sent (info, e_mapi_util_filetime_to_time_t (submit_time));
			camel_message_info_set_date_received (info, e_mapi_util_filetime_to_time_t (delivery_time));
			camel_message_info_set_size (info, msg_size ? *msg_size : 0);

			/* Threading related properties */
			mapi_set_message_id (info, message_id);
			if (references || in_reply_to)
				mapi_set_message_references (info, references, in_reply_to);

			/* Recipients */
			to_addr = (CamelAddress *) camel_internet_address_new ();
			cc_addr = (CamelAddress *) camel_internet_address_new ();
			bcc_addr = (CamelAddress *) camel_internet_address_new ();

			e_mapi_mail_utils_decode_recipients (conn, object->recipients, to_addr, cc_addr, bcc_addr);

			if (camel_address_length (to_addr) > 0) {
				formatted_addr = camel_address_format (to_addr);
				camel_message_info_set_to (info, formatted_addr);
				g_free (formatted_addr);
			} else {
				camel_message_info_set_to (info, display_to);
			}

			if (camel_address_length (cc_addr) > 0) {
				formatted_addr = camel_address_format (cc_addr);
				camel_message_info_set_cc (info, formatted_addr);
				g_free (formatted_addr);
			} else {
				camel_message_info_set_cc (info, display_cc);
			}

			g_object_unref (to_addr);
			g_object_unref (cc_addr);
			g_object_unref (bcc_addr);

			from_name = NULL;
			from_email = NULL;

			e_mapi_mail_utils_decode_email_address1 (conn, &object->properties,
				PidTagSentRepresentingName,
				PidTagSentRepresentingEmailAddress,
				PidTagSentRepresentingAddressType,
				&from_name, &from_email);

			if (from_email && *from_email) {
				formatted_addr = camel_internet_address_format_address (from_name, from_email);

				camel_message_info_set_from (info, formatted_addr);

				g_free (formatted_addr);
			}
			
			g_free (from_name);
			g_free (from_email);
		}

		if (!camel_message_info_get_date_sent (info))
			camel_message_info_set_date_sent (info, camel_message_info_get_date_received (info));
		if (!camel_message_info_get_date_received (info))
			camel_message_info_set_date_received (info, camel_message_info_get_date_sent (info));
	} else {
		camel_message_info_freeze_notifications (info);
	}

	user_has_read = (camel_message_info_get_flags (info) & CAMEL_MESSAGE_SEEN) != 0;

	update_message_info (info, object, is_new, gos->is_public_folder, user_has_read);

	camel_message_info_thaw_notifications (info);

	if (is_new) {
		camel_folder_summary_add (camel_folder_get_folder_summary (gos->folder), info, FALSE);
		camel_folder_change_info_add_uid (gos->changes, camel_message_info_get_uid (info));
		camel_folder_change_info_recent_uid (gos->changes, camel_message_info_get_uid (info));
	} else {
		camel_folder_change_info_change_uid (gos->changes, camel_message_info_get_uid (info));
	}

	g_clear_object (&info);

	if (obj_total > 0)
		camel_operation_progress (cancellable, obj_index * 100 / obj_total);

	g_free (uid_str);

	return TRUE;
}

gboolean
camel_mapi_folder_fetch_summary (CamelFolder *folder, GCancellable *cancellable, GError **mapi_error)
{
	gboolean status, has_obj_folder;
	gboolean full_download;
	CamelStore *store = camel_folder_get_parent_store (folder);
	CamelStoreInfo *si = NULL;
	CamelMapiStoreInfo *msi = NULL;
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);
	EMapiConnection *conn = camel_mapi_store_ref_connection (mapi_store, cancellable, mapi_error);
	struct FolderBasicPropertiesData fbp;
	struct GatherChangedObjectsData gco;
	mapi_object_t obj_folder;

	if (!conn)
		return FALSE;

	camel_folder_freeze (folder);

	full_download = camel_offline_folder_can_downsync (CAMEL_OFFLINE_FOLDER (folder));

	camel_operation_push_message (cancellable, _("Refreshing folder “%s”"), camel_folder_get_display_name (folder));

	si = camel_mapi_store_summary_get_folder_id (mapi_store->summary, mapi_folder->folder_id);
	msi = (CamelMapiStoreInfo *) si;

	if (!msi) {
		camel_operation_pop_message (cancellable);
		camel_folder_thaw (folder);
		g_object_unref (conn);

		g_return_val_if_fail (msi != NULL, FALSE);

		return FALSE;
	}

	status = cmf_open_folder (mapi_folder, conn, &obj_folder, cancellable, mapi_error);
	has_obj_folder = status;

	if (status) {
		status = e_mapi_connection_get_folder_properties (conn, &obj_folder, NULL, NULL, e_mapi_utils_get_folder_basic_properties_cb, &fbp, cancellable, mapi_error);
		if (status) {
			if (msi->last_obj_total != fbp.obj_total)
				msi->latest_last_modify = 0;
		}
	}

	gco.latest_last_modify = 0;
	gco.fid = mapi_object_get_id (&obj_folder);
	gco.summary = camel_folder_get_folder_summary (folder);
	gco.to_update = NULL;
	gco.removed_uids = NULL;
	gco.is_public_folder = (mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0;

	if (msi->latest_last_modify <= 0) {
		GPtrArray *known_uids;

		camel_folder_summary_prepare_fetch_all (camel_folder_get_folder_summary (folder), NULL);

		gco.removed_uids = g_hash_table_new_full (g_str_hash, g_str_equal, (GDestroyNotify) camel_pstring_free, NULL);
		known_uids = camel_folder_summary_get_array (camel_folder_get_folder_summary (folder));
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
			full_download ? NULL : e_mapi_utils_build_last_modify_restriction, &msi->latest_last_modify,
			gather_changed_objects_to_slist, &gco, cancellable, mapi_error);
	}

	if (status && gco.to_update) {
		struct GatherObjectSummaryData gos;

		gos.folder = folder;
		gos.changes = camel_folder_change_info_new ();
		gos.is_public_folder = gco.is_public_folder;

		if (gco.removed_uids)
			g_hash_table_foreach (gco.removed_uids, remove_removed_uids_cb, &gos);

		if (full_download) {
			camel_operation_push_message (cancellable, _("Downloading messages in folder “%s”"), camel_folder_get_display_name (folder));

			status = e_mapi_connection_transfer_objects (conn, &obj_folder, gco.to_update, gather_object_for_offline_cb, &gos, cancellable, mapi_error);

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
		gos.is_public_folder = gco.is_public_folder;

		g_hash_table_foreach (gco.removed_uids, remove_removed_uids_cb, &gos);

		if (camel_folder_change_info_changed (gos.changes))
			camel_folder_changed (folder, gos.changes);
		camel_folder_change_info_free (gos.changes);
	}

	if (has_obj_folder)
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, mapi_error);

	g_slist_free_full (gco.to_update, g_free);
	if (gco.removed_uids)
		g_hash_table_destroy (gco.removed_uids);

	camel_operation_pop_message (cancellable);

	if (status) {
		if (gco.latest_last_modify > 0)
			msi->latest_last_modify = gco.latest_last_modify;
		msi->last_obj_total = fbp.obj_total;
	}

	g_object_unref (conn);
	if (mapi_error && *mapi_error)
		camel_mapi_store_maybe_disconnect (mapi_store, *mapi_error);

	camel_folder_summary_save (camel_folder_get_folder_summary (folder), NULL);
	camel_folder_thaw (folder);

	return status;
}

gboolean
mapi_refresh_folder (CamelFolder *folder, GCancellable *cancellable, GError **error)
{

	CamelMapiStore *mapi_store;
	CamelMapiFolder *mapi_folder;
	CamelStore *parent_store;
	gboolean status;
	gboolean success = TRUE;
	GError *mapi_error = NULL;

	parent_store = camel_folder_get_parent_store (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

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

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store))) {
		/*BUG : Fix exception string.*/
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("This message is not available in offline mode."));
		success = FALSE;
		goto end1;
	}

	if (!camel_mapi_store_connected (mapi_store, cancellable, &mapi_error)) {
		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
				g_set_error (
					error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
					_("Fetching items failed: %s"), mapi_error->message);
			g_error_free (mapi_error);
		} else {
			g_set_error_literal (
				error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_UNAVAILABLE,
				_("Fetching items failed"));
		}
		success = FALSE;
		goto end1;
	}

	status = camel_mapi_folder_fetch_summary (folder, cancellable, &mapi_error);

	if (!status) {
		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
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

	camel_folder_summary_touch (camel_folder_get_folder_summary (folder));

end1:
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

static guint32
mapi_folder_get_permanent_flags (CamelFolder *folder)
{
	return CAMEL_MESSAGE_ANSWERED |
		CAMEL_MESSAGE_DELETED |
		CAMEL_MESSAGE_DRAFT |
		CAMEL_MESSAGE_FLAGGED |
		CAMEL_MESSAGE_SEEN |
		CAMEL_MESSAGE_JUNK;
}

static void
mapi_folder_rename (CamelFolder *folder, const gchar *new)
{
	CamelStore *parent_store;

	parent_store = camel_folder_get_parent_store (folder);

	camel_store_summary_disconnect_folder_summary (
		((CamelMapiStore *) parent_store)->summary,
		camel_folder_get_folder_summary (folder));

	((CamelFolderClass *)camel_mapi_folder_parent_class)->rename(folder, new);

	camel_store_summary_connect_folder_summary (
		((CamelMapiStore *) parent_store)->summary,
		camel_folder_get_full_name (folder), camel_folder_get_folder_summary (folder));
}

static gint
mapi_cmp_uids (CamelFolder *folder, const gchar *uid1, const gchar *uid2)
{
	g_return_val_if_fail (uid1 != NULL, 0);
	g_return_val_if_fail (uid2 != NULL, 0);

	return strcmp (uid1, uid2);
}

static void
mapi_folder_dispose (GObject *object)
{
	CamelStore *parent_store;
	CamelFolder *folder = CAMEL_FOLDER (object);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (object);

	camel_folder_summary_save (camel_folder_get_folder_summary (folder), NULL);

	if (mapi_folder->cache != NULL) {
		g_object_unref (mapi_folder->cache);
		mapi_folder->cache = NULL;
	}

	if (mapi_folder->search) {
		g_object_unref (mapi_folder->search);
		mapi_folder->search = NULL;
	}

	parent_store = camel_folder_get_parent_store (CAMEL_FOLDER (mapi_folder));
	if (parent_store) {
		camel_store_summary_disconnect_folder_summary (
			(CamelStoreSummary *) ((CamelMapiStore *) parent_store)->summary,
			camel_folder_get_folder_summary (CAMEL_FOLDER (mapi_folder)));
	}

	/* Chain up to parent's dispose() method. */
	G_OBJECT_CLASS (camel_mapi_folder_parent_class)->dispose (object);
}

static void
mapi_folder_finalize (GObject *object)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (object);

	g_mutex_clear (&mapi_folder->priv->search_lock);

	/* Chain up to parent's finalize() method. */
	G_OBJECT_CLASS (camel_mapi_folder_parent_class)->finalize (object);
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
	gchar *description;
	gchar *host;
	gchar *user;

	/* Chain up to parent's method. */
	G_OBJECT_CLASS (camel_mapi_folder_parent_class)->constructed (object);

	folder = CAMEL_FOLDER (object);
	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	service = CAMEL_SERVICE (parent_store);

	settings = camel_service_ref_settings (service);

	network_settings = CAMEL_NETWORK_SETTINGS (settings);
	host = camel_network_settings_dup_host (network_settings);
	user = camel_network_settings_dup_user (network_settings);

	g_object_unref (settings);

	description = g_strdup_printf (
		"%s@%s:%s", user, host, full_name);
	camel_folder_set_description (folder, description);
	g_free (description);

	g_free (host);
	g_free (user);
}

struct CamelMapiCreateData
{
	CamelMimeMessage *message;
	guint32 message_camel_flags;
};

static gboolean
convert_message_to_object_cb (EMapiConnection *conn,
			      TALLOC_CTX *mem_ctx,
			      EMapiObject **object, /* out */
			      gpointer user_data,
			      GCancellable *cancellable,
			      GError **perror)
{
	struct CamelMapiCreateData *cmc = user_data;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (cmc != NULL, FALSE);
	g_return_val_if_fail (cmc->message != NULL, FALSE);

	return e_mapi_mail_utils_message_to_object (cmc->message, cmc->message_camel_flags, E_MAPI_CREATE_FLAG_NONE, object, mem_ctx, cancellable, perror);
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
	CamelStoreInfo *si;
	CamelStore *parent_store;
	mapi_id_t fid = 0, mid = 0;
	const gchar *folder_id;
	const gchar *full_name;
	guint32 folder_flags = 0;
	EMapiConnection *conn;
	mapi_object_t obj_folder;
	GError *mapi_error = NULL;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);

	mapi_store = CAMEL_MAPI_STORE (parent_store);

	/*Reject outbox / sent & trash*/
	si = camel_store_summary_path (mapi_store->summary, full_name);
	if (si) {
		folder_flags = si->flags;
		camel_store_summary_info_unref (mapi_store->summary, si);
	}

	if (((folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) ||
	    ((folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_OUTBOX)) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Cannot append message to folder “%s”"),
			full_name);
		return FALSE;
	}

	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);
	if (!conn) {
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Offline."));
		return FALSE;
	}

	folder_id = camel_mapi_store_folder_id_lookup (mapi_store, full_name);
	e_mapi_util_mapi_id_from_string (folder_id, &fid);

	/* Convert MIME to Item */
	if (cmf_open_folder (CAMEL_MAPI_FOLDER (folder), conn, &obj_folder, cancellable, &mapi_error)) {
		struct CamelMapiCreateData cmc;

		cmc.message = message;
		cmc.message_camel_flags = info ? camel_message_info_get_flags (info) : 0;

		e_mapi_connection_create_object (conn, &obj_folder, E_MAPI_CREATE_FLAG_NONE, convert_message_to_object_cb, &cmc, &mid, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mid) {
		mapi_refresh_folder (folder, cancellable, error);
	} else {
		g_object_unref (conn);

		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
				g_set_error_literal (error, CAMEL_ERROR, CAMEL_ERROR_GENERIC, mapi_error->message);
			camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
			g_error_free (mapi_error);
		} else {
			g_set_error (error, CAMEL_ERROR, CAMEL_ERROR_GENERIC, _("Offline."));
		}

		return FALSE;
	}

	g_object_unref (conn);

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
	CamelMessageInfo *info;
	CamelFolderChangeInfo *changes;
	CamelFolderSummary *folder_summary;
	CamelStore *parent_store;
	GPtrArray *known_uids;
	gint i;
	gboolean delete = FALSE, status = FALSE;
	GSList *deleted_items, *deleted_head;
	GSList *deleted_items_uid, *deleted_items_uid_head;
	EMapiConnection *conn;

	deleted_items = deleted_head = NULL;
	deleted_items_uid = deleted_items_uid_head = NULL;

	parent_store = camel_folder_get_parent_store (folder);
	folder_summary = camel_folder_get_folder_summary (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);
	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);

	if (!conn)
		return FALSE;

	if ((mapi_folder->camel_folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
		mapi_object_t obj_folder;
		GError *mapi_error = NULL;
		GPtrArray *folders;
		gint ii;

		/* get deleted messages from all active folders too */
		folders = camel_store_dup_opened_folders (parent_store);
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

		status = cmf_open_folder (mapi_folder, conn, &obj_folder, cancellable, &mapi_error);
		if (status) {
			status = e_mapi_connection_empty_folder (conn, &obj_folder, cancellable, &mapi_error);
			e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
		}

		if (status) {
			camel_folder_freeze (folder);
			mapi_summary_clear (folder_summary, TRUE);
			camel_folder_thaw (folder);
		} else if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					_("Failed to empty Trash: %s"), mapi_error->message);
			camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
			g_error_free (mapi_error);
		} else {
			g_set_error_literal (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Failed to empty Trash"));
		}

		g_object_unref (conn);

		return status;
	}

	changes = camel_folder_change_info_new ();
	folder_summary = camel_folder_get_folder_summary (folder);
	known_uids = camel_folder_summary_get_array (folder_summary);

	/*Collect UIDs of deleted messages.*/
	for (i = 0; known_uids && i < known_uids->len; i++) {
		info = camel_folder_summary_get (folder_summary, g_ptr_array_index (known_uids, i));
		if (info && (camel_message_info_get_flags (info) & CAMEL_MESSAGE_DELETED) != 0) {
			const gchar *uid = camel_message_info_get_uid (info);
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
		g_clear_object (&info);
	}

	camel_folder_summary_free_array (known_uids);

	deleted_items_uid_head = deleted_items_uid;

	if (deleted_items) {
		mapi_object_t obj_folder;
		GError *mapi_error = NULL;

		status = cmf_open_folder (mapi_folder, conn, &obj_folder, cancellable, &mapi_error);
		if (status) {
			status = e_mapi_connection_remove_items (conn, &obj_folder, deleted_items, cancellable, &mapi_error);
			e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
		}

		if (mapi_error) {
			camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
			g_clear_error (&mapi_error);
		}

		if (status) {
			while (deleted_items_uid) {
				const gchar *uid = (gchar *)deleted_items_uid->data;
				camel_folder_summary_lock (folder_summary);
				camel_folder_change_info_remove_uid (changes, uid);
				camel_folder_summary_remove_uid (folder_summary, uid);
				camel_data_cache_remove(mapi_folder->cache, "cache", uid, NULL);
				camel_folder_summary_unlock (folder_summary);
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
	g_object_unref (conn);

	return TRUE;
}

static CamelMimeMessage *
mapi_folder_get_message_cached (CamelFolder *folder,
				 const gchar *message_uid,
				 GCancellable *cancellable)
{
	CamelMapiFolder *mapi_folder;
	CamelMimeMessage *msg = NULL;
	CamelStream *stream;
	GIOStream *base_stream;

	mapi_folder = CAMEL_MAPI_FOLDER (folder);

	if (!camel_folder_summary_check_uid (camel_folder_get_folder_summary (folder), message_uid))
		return NULL;

	stream = camel_stream_mem_new ();

	base_stream = camel_data_cache_get (mapi_folder->cache, "cache", message_uid, NULL);
	if (base_stream != NULL) {
		CamelStream *cache_stream;
		GError *local_error = NULL;

		cache_stream = camel_stream_new (base_stream);
		g_object_unref (base_stream);

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
	CamelMessageInfo *mi;
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

	mi = camel_folder_summary_get (camel_folder_get_folder_summary (folder), uid);
	if (mi == NULL) {
		g_set_error (
			error, CAMEL_FOLDER_ERROR,
			CAMEL_FOLDER_ERROR_INVALID_UID,
			/* Translators: The first %s is replaced with a message ID,
			   the second %s is replaced with a detailed error string */
			_("Cannot get message %s: %s"), uid,
			_("No such message"));
		return NULL;
	}

	msg = mapi_folder_get_message_cached (folder, uid, cancellable);
	if (msg != NULL) {
		g_clear_object (&mi);
		return msg;
	}

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store))) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("This message is not available in offline mode."));
		g_clear_object (&mi);
		return NULL;
	}

	/* Check if we are really offline */
	if (!camel_mapi_store_connected (mapi_store, cancellable, &mapi_error)) {
		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
				g_set_error (
					error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_INVALID,
					_("Could not get message: %s"), mapi_error->message);
			g_error_free (mapi_error);
		} else {
			g_set_error (
				error, CAMEL_SERVICE_ERROR,
				CAMEL_SERVICE_ERROR_INVALID,
				_("Could not get message"));
		}
		g_clear_object (&mi);
		return NULL;
	}

	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);
	if (!conn) {
		g_clear_object (&mi);
		return NULL;
	}

	e_mapi_util_mapi_id_from_string (uid, &id_message);

	success = cmf_open_folder (mapi_folder, conn, &obj_folder, cancellable, &mapi_error);
	if (success) {
		success = e_mapi_connection_transfer_object (conn, &obj_folder, id_message, transfer_mail_object_cb, &msg, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, NULL);
	}

	g_object_unref (conn);

	if (!msg) {
		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
				g_set_error (
					error, CAMEL_SERVICE_ERROR, CAMEL_SERVICE_ERROR_INVALID,
					_("Could not get message: %s"), mapi_error->message);
			camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);				
			g_error_free (mapi_error);
		} else {
			g_set_error (
				error, CAMEL_SERVICE_ERROR,
				CAMEL_SERVICE_ERROR_INVALID,
				_("Could not get message"));
		}
		g_clear_object (&mi);
		return NULL;
	}

	add_message_to_cache (mapi_folder, uid, &msg, cancellable);

	g_clear_object (&mi);

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
	CamelStore *parent_store;
	CamelFolderChangeInfo *changes = NULL;
	CamelFolderSummary *folder_summary;
	CamelServiceConnectionStatus status;
	CamelService *service;
	EMapiConnection *conn;
	GPtrArray *known_uids;
	GSList *read_items = NULL, *read_with_receipt = NULL, *unread_items = NULL, *to_free = NULL, *junk_items = NULL, *deleted_items = NULL, *l;
	flags_diff_t diff, unset_flags;
	const gchar *folder_id;
	const gchar *full_name;
	mapi_id_t fid;
	gint i;
	gboolean is_junk_folder, has_obj_folder = FALSE;
	mapi_object_t obj_folder;
	GError *mapi_error = NULL;

	full_name = camel_folder_get_full_name (folder);
	parent_store = camel_folder_get_parent_store (folder);
	folder_summary = camel_folder_get_folder_summary (folder);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);
	mapi_store = CAMEL_MAPI_STORE (parent_store);

	service = CAMEL_SERVICE (mapi_store);
	status = camel_service_get_connection_status (service);

	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store)) ||
	    status == CAMEL_SERVICE_DISCONNECTED) {
		return TRUE;
	}

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, full_name);
	e_mapi_util_mapi_id_from_string (folder_id, &fid);

	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);
	if (!conn)
		return FALSE;

	is_junk_folder = (mapi_folder->camel_folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_JUNK;

	camel_folder_summary_lock (folder_summary);
	camel_folder_summary_prepare_fetch_all (folder_summary, NULL);

	known_uids = camel_folder_summary_get_array (folder_summary);
	for (i = 0; known_uids && i < known_uids->len; i++) {
		info = camel_folder_summary_get (folder_summary, g_ptr_array_index (known_uids, i));

		if (info && camel_message_info_get_folder_flagged (info)) {
			const gchar *uid;
			mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
			guint32 flags, server_flags;
			gboolean used = FALSE;

			uid = camel_message_info_get_uid (info);
			flags = camel_message_info_get_flags (info);

			/* Why are we getting so much noise here :-/ */
			if (!e_mapi_util_mapi_id_from_string (uid, mid)) {
				g_clear_object (&info);
				g_free (mid);
				continue;
			}

			server_flags = camel_mapi_message_info_get_server_flags (CAMEL_MAPI_MESSAGE_INFO (info));
			mapi_utils_do_flags_diff (&diff, server_flags, flags);
			mapi_utils_do_flags_diff (&unset_flags, flags, server_flags);

			diff.changed &= camel_folder_get_permanent_flags (folder);
			if (!diff.changed) {
				g_clear_object (&info);
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
				if (flags & CAMEL_MAPI_MESSAGE_WITH_READ_RECEIPT)
					read_with_receipt = g_slist_prepend (read_with_receipt, mid);
				used = TRUE;
			} else if (unset_flags.bits & CAMEL_MESSAGE_SEEN) {
				unread_items = g_slist_prepend (unread_items, mid);
				used = TRUE;
			}

			if (used)
				to_free = g_slist_prepend (to_free, mid);
			else
				g_free (mid);

			camel_mapi_message_info_set_server_flags (CAMEL_MAPI_MESSAGE_INFO (info), camel_message_info_get_flags (info));
		}

		g_clear_object (&info);
	}

	camel_folder_summary_free_array (known_uids);
	camel_folder_summary_unlock (folder_summary);

	/*
	   Sync up the READ changes before deleting the message.
	   Note that if a message is marked as unread and then deleted,
	   Evo doesnt not take care of it, as I find that scenario to be impractical.
	*/

	has_obj_folder = cmf_open_folder (mapi_folder, conn, &obj_folder, cancellable, &mapi_error);

	if (read_items && has_obj_folder) {
		if (read_with_receipt)
			e_mapi_connection_set_flags (conn, &obj_folder, read_with_receipt, CLEAR_RN_PENDING, cancellable, &mapi_error);
		e_mapi_connection_set_flags (conn, &obj_folder, read_items, 0, cancellable, &mapi_error);
	}

	if (unread_items && has_obj_folder) {
		e_mapi_connection_set_flags (conn, &obj_folder, unread_items, CLEAR_READ_FLAG, cancellable, &mapi_error);
	}

	/* Remove messages from server*/
	if (deleted_items && has_obj_folder) {
		if ((mapi_folder->camel_folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
			e_mapi_connection_remove_items (conn, &obj_folder, deleted_items, cancellable, &mapi_error);
		} else {
			mapi_id_t deleted_items_fid;
			mapi_object_t deleted_obj_folder;

			e_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderDeletedItems), &deleted_items_fid);
			if (e_mapi_connection_open_personal_folder (conn, deleted_items_fid, &deleted_obj_folder, cancellable, &mapi_error)) {
				e_mapi_connection_copymove_items (conn, &obj_folder, &deleted_obj_folder, FALSE, deleted_items, cancellable, &mapi_error);
				e_mapi_connection_close_folder (conn, &deleted_obj_folder, cancellable, &mapi_error);
			}
		}
	}

	if (junk_items && has_obj_folder) {
		mapi_id_t junk_fid = 0;
		mapi_object_t junk_obj_folder;

		if (has_obj_folder) {
			e_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderJunk), &junk_fid);
			if (e_mapi_connection_open_personal_folder (conn, junk_fid, &junk_obj_folder, cancellable, &mapi_error)) {
				e_mapi_connection_copymove_items (conn, &obj_folder, &junk_obj_folder, FALSE, junk_items, cancellable, &mapi_error);
				e_mapi_connection_close_folder (conn, &junk_obj_folder, cancellable, &mapi_error);
			}
		}

		/* in junk_items are only emails which are not deleted */
		deleted_items = g_slist_concat (deleted_items, g_slist_copy (junk_items));
	}

	if (has_obj_folder)
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

	/*Remove messages from local cache*/
	for (l = deleted_items; l; l = l->next) {
		gchar *deleted_msg_uid = e_mapi_util_mapi_id_to_string (*((mapi_id_t *) l->data));

		if (!changes)
			changes = camel_folder_change_info_new ();
		camel_folder_change_info_remove_uid (changes, deleted_msg_uid);

		camel_folder_summary_lock (folder_summary);
		camel_folder_summary_remove_uid (folder_summary, deleted_msg_uid);
		camel_data_cache_remove(mapi_folder->cache, "cache", deleted_msg_uid, NULL);
		camel_folder_summary_unlock (folder_summary);

		g_free (deleted_msg_uid);
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

	g_object_unref (conn);

	if (mapi_error) {
		camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
		g_clear_error (&mapi_error);
	}

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
	CamelOfflineStore *offline;
	CamelMapiStore *mapi_store;
	CamelFolderChangeInfo *changes = NULL;
	CamelStore *source_parent_store;
	CamelStore *destination_parent_store;
	CamelMapiFolder *src_mapi_folder, *des_mapi_folder;
	gint i = 0;
	GSList *src_msg_ids = NULL;
	gboolean success = TRUE;
	GError *mapi_error = NULL;
	mapi_object_t src_obj_folder, des_obj_folder;
	gboolean copymoved = FALSE;
	EMapiConnection *conn;

	if (CAMEL_IS_MAPI_FOLDER (source)) {
		/* make sure changed flags are written into the server */
		if (!mapi_folder_synchronize_sync (source, FALSE, cancellable, error))
			return FALSE;
	}

	source_parent_store = camel_folder_get_parent_store (source);
	mapi_store = CAMEL_MAPI_STORE (source_parent_store);
	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);

	if (!conn || !CAMEL_IS_MAPI_FOLDER (source) || !CAMEL_IS_MAPI_FOLDER (destination) ||
	    (CAMEL_MAPI_FOLDER (source)->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ||
	    (CAMEL_MAPI_FOLDER (destination)->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0) {
		CamelFolderClass *folder_class;

		if (conn)
			g_object_unref (conn);

		/* because cannot use MAPI to copy/move messages with public folders,
		   thus fallback to per-message copy/move */
		folder_class = CAMEL_FOLDER_CLASS (camel_mapi_folder_parent_class);
		return folder_class->transfer_messages_to_sync (
			source, uids, destination, delete_originals,
			transferred_uids, cancellable, error);
	}

	destination_parent_store = camel_folder_get_parent_store (destination);

	offline = CAMEL_OFFLINE_STORE (destination_parent_store);

	/* check for offline operation */
	if (!camel_offline_store_get_online (offline)) {
		g_object_unref (conn);
		return FALSE;
	}

	src_mapi_folder = CAMEL_MAPI_FOLDER (source);
	des_mapi_folder = CAMEL_MAPI_FOLDER (destination);

	for (i=0; i < uids->len; i++) {
		mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
		if (!e_mapi_util_mapi_id_from_string (g_ptr_array_index (uids, i), mid))
			continue;

		src_msg_ids = g_slist_prepend (src_msg_ids, mid);
	}

	if (cmf_open_folder (src_mapi_folder, conn, &src_obj_folder, cancellable, &mapi_error)) {
		if (cmf_open_folder (des_mapi_folder, conn, &des_obj_folder, cancellable, &mapi_error)) {
			copymoved = e_mapi_connection_copymove_items (conn, &src_obj_folder, &des_obj_folder, !delete_originals, src_msg_ids, cancellable, &mapi_error);
			e_mapi_connection_close_folder (conn, &des_obj_folder, cancellable, &mapi_error);
		}

		e_mapi_connection_close_folder (conn, &src_obj_folder, cancellable, &mapi_error);
	}

	if (!copymoved) {
		if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				"%s", mapi_error ? mapi_error->message : _("Unknown error"));
		camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
		g_clear_error (&mapi_error);
		success = FALSE;
	} else if (delete_originals) {
		CamelFolderSummary *source_summary;

		source_summary = camel_folder_get_folder_summary (source);
		changes = camel_folder_change_info_new ();

		for (i = 0; i < uids->len; i++) {
			camel_folder_summary_remove_uid (source_summary, uids->pdata[i]);
			camel_folder_change_info_remove_uid (changes, uids->pdata[i]);
		}
		camel_folder_changed (source, changes);
		camel_folder_change_info_free (changes);

	}

	g_clear_error (&mapi_error);

	g_slist_foreach (src_msg_ids, (GFunc) g_free, NULL);
	g_slist_free (src_msg_ids);

	g_object_unref (conn);

	/* update destination folder only if not frozen, to not update
	   for each single message transfer during filtering
	 */
	if (success && !camel_folder_is_frozen (destination))
		success = mapi_folder_refresh_info_sync (destination, cancellable, error);

	return success;
}

static CamelFolderQuotaInfo *
mapi_folder_get_quota_info_sync (CamelFolder *folder,
				 GCancellable *cancellable,
				 GError **error)
{
	CamelMapiStore *mapi_store;
	CamelFolderQuotaInfo *quota_info = NULL;
	EMapiConnection *conn;
	GError *mapi_error = NULL;
	uint64_t current_size = -1, receive_quota = -1, send_quota = -1;

	g_return_val_if_fail (folder != NULL, NULL);
	g_return_val_if_fail (CAMEL_IS_MAPI_FOLDER (folder), NULL);

	mapi_store = CAMEL_MAPI_STORE (camel_folder_get_parent_store (folder));
	g_return_val_if_fail (mapi_store != NULL, NULL);
	
	/* check for offline operation */
	if (!camel_offline_store_get_online (CAMEL_OFFLINE_STORE (mapi_store)))
		return NULL;

	conn = camel_mapi_store_ref_connection (mapi_store, cancellable, error);
	if (conn && e_mapi_connection_get_store_quotas (conn, NULL, &current_size, &receive_quota, &send_quota, cancellable, &mapi_error)) {
		if (current_size != -1) {
			if (receive_quota != -1) {
				quota_info = camel_folder_quota_info_new (_("Receive quota"), current_size, receive_quota);
			}

			if (send_quota != -1) {
				CamelFolderQuotaInfo *qi;

				qi = camel_folder_quota_info_new (_("Send quota"), current_size, send_quota);
				if (quota_info)
					quota_info->next = qi;
				else
					quota_info = qi;
			}
		}
	}

	if (conn)
		g_object_unref (conn);

	if (!quota_info) {
		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
				g_set_error (
					error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
					"%s", mapi_error ? mapi_error->message : _("Unknown error"));
			camel_mapi_store_maybe_disconnect (mapi_store, mapi_error);
			g_clear_error (&mapi_error);
		} else {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
				_("No quota information available"));
		}
	}

	return quota_info;
}

static void
camel_mapi_folder_class_init (CamelMapiFolderClass *class)
{
	GObjectClass *object_class;
	CamelFolderClass *folder_class;

	g_type_class_add_private (class, sizeof (CamelMapiFolderPrivate));

	object_class = G_OBJECT_CLASS (class);
	object_class->dispose = mapi_folder_dispose;
	object_class->finalize = mapi_folder_finalize;
	object_class->constructed = mapi_folder_constructed;

	folder_class = CAMEL_FOLDER_CLASS (class);
	folder_class->get_permanent_flags = mapi_folder_get_permanent_flags;
	folder_class->rename = mapi_folder_rename;
	folder_class->search_by_expression = mapi_folder_search_by_expression;
	folder_class->cmp_uids = mapi_cmp_uids;
	folder_class->search_by_uids = mapi_folder_search_by_uids;
	folder_class->search_free = mapi_folder_search_free;
	folder_class->append_message_sync = mapi_folder_append_message_sync;
	folder_class->expunge_sync = mapi_folder_expunge_sync;
	folder_class->get_message_sync = mapi_folder_get_message_sync;
	folder_class->get_message_cached = mapi_folder_get_message_cached;
	folder_class->refresh_info_sync = mapi_folder_refresh_info_sync;
	folder_class->synchronize_sync = mapi_folder_synchronize_sync;
	folder_class->transfer_messages_to_sync = mapi_folder_transfer_messages_to_sync;
	folder_class->get_quota_info_sync = mapi_folder_get_quota_info_sync;
}

static void
camel_mapi_folder_init (CamelMapiFolder *mapi_folder)
{
	CamelFolder *folder = CAMEL_FOLDER (mapi_folder);

	mapi_folder->priv = G_TYPE_INSTANCE_GET_PRIVATE (mapi_folder, CAMEL_TYPE_MAPI_FOLDER, CamelMapiFolderPrivate);

	camel_folder_set_flags (folder, CAMEL_FOLDER_HAS_SUMMARY_CAPABILITY);

	g_mutex_init (&mapi_folder->priv->search_lock);

	mapi_folder->need_rescan = TRUE;
}

CamelFolder *
camel_mapi_folder_new (CamelStore *store,
		       const gchar *folder_name,
		       const gchar *folder_dir,
		       guint32 flags,
		       GError **error)
{

	CamelFolder *folder;
	CamelFolderSummary *folder_summary;
	CamelMapiFolder *mapi_folder;
	CamelMapiStore *mapi_store = (CamelMapiStore *) store;
	CamelService *service;
	CamelSettings *settings;
	gchar *state_file;
	const gchar *short_name;
	CamelStoreInfo *si;
	gboolean filter_inbox;
	gboolean offline_limit_by_age = FALSE;
	CamelTimeUnit offline_limit_unit;
	gint offline_limit_value;

	service = CAMEL_SERVICE (store);
	settings = camel_service_ref_settings (service);

	g_object_get (
		settings,
		"filter-inbox", &filter_inbox,
		"limit-by-age", &offline_limit_by_age,
		"limit-unit", &offline_limit_unit,
		"limit-value", &offline_limit_value,
		NULL);

	g_object_unref (settings);

	short_name = strrchr (folder_name, '/');
	if (short_name)
		short_name++;
	else
		short_name = folder_name;

	folder = g_object_new (
		CAMEL_TYPE_MAPI_FOLDER,
		"display-name", short_name,
		"full-name", folder_name,
		"parent-store", store,
		NULL);

	mapi_folder = CAMEL_MAPI_FOLDER (folder);

	folder_summary = camel_mapi_folder_summary_new (folder);

	if (!folder_summary) {
		g_object_unref (folder);
		g_set_error (
			error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
			_("Could not load summary for %s"),
			folder_name);
		return NULL;
	}

	camel_folder_take_folder_summary (folder, folder_summary);

	/* set/load persistent state */
	state_file = g_build_filename (folder_dir, short_name, "cmeta", NULL);
	camel_object_set_state_filename (CAMEL_OBJECT (folder), state_file);
	g_free(state_file);
	camel_object_state_read (CAMEL_OBJECT (folder));

	state_file = g_build_filename (folder_dir, short_name, NULL);
	mapi_folder->cache = camel_data_cache_new (state_file, error);
	g_free (state_file);
	if (!mapi_folder->cache) {
		g_object_unref (folder);
		return NULL;
	}

	if (camel_offline_folder_can_downsync (CAMEL_OFFLINE_FOLDER (folder))) {
		time_t when = (time_t) 0;

		if (offline_limit_by_age)
			when = camel_time_value_apply (when, offline_limit_unit, offline_limit_value);

		if (when <= (time_t) 0)
			when = (time_t) -1;

		/* Ensure cache will expire when set up, otherwise
		 * it causes redownload of messages too soon. */
		camel_data_cache_set_expire_age (mapi_folder->cache, when);
		camel_data_cache_set_expire_access (mapi_folder->cache, when);
	} else {
		/* Set cache expiration for one week. */
		camel_data_cache_set_expire_age (mapi_folder->cache, 60 * 60 * 24 * 7);
		camel_data_cache_set_expire_access (mapi_folder->cache, 60 * 60 * 24 * 7);
	}

	camel_binding_bind_property (store, "online",
		mapi_folder->cache, "expire-enabled",
		G_BINDING_SYNC_CREATE);

	if (filter_inbox) {
		CamelFolderInfo *fi;

		fi = camel_store_get_folder_info_sync (store, folder_name, 0, NULL, NULL);
		if (fi) {
			if ((fi->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_INBOX) {
				camel_folder_set_flags (folder, camel_folder_get_flags (folder) | CAMEL_FOLDER_FILTER_RECENT);
			}

			camel_folder_info_free (fi);
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
		guint32 add_folder_flags = 0;

		mapi_folder->mapi_folder_flags = msi->mapi_folder_flags;
		mapi_folder->camel_folder_flags = msi->camel_folder_flags;
		mapi_folder->folder_id = msi->folder_id;
		if ((mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0) {
			mapi_folder->priv->foreign_username = g_strdup (msi->foreign_username);
		} else {
			mapi_folder->priv->foreign_username = NULL;
		}

		if ((si->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH)
			add_folder_flags |= CAMEL_FOLDER_IS_TRASH;
		else if ((si->flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_JUNK)
			add_folder_flags |= CAMEL_FOLDER_IS_JUNK;
		camel_store_summary_info_unref (mapi_store->summary, si);

		camel_folder_set_flags (folder, camel_folder_get_flags (folder) | add_folder_flags);
	} else {
		g_warning ("%s: cannot find '%s' in known folders", G_STRFUNC, folder_name);
	}

	camel_store_summary_connect_folder_summary (
		((CamelMapiStore *) store)->summary,
		folder_name, folder_summary);

	/* sanity checking */
	if ((mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0)
		g_return_val_if_fail (mapi_folder->priv->foreign_username != NULL, folder);
	if ((mapi_folder->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0)
		g_return_val_if_fail (mapi_folder->priv->foreign_username == NULL, folder);

	return folder;
}
