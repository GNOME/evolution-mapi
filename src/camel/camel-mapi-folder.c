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

#include <pthread.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include <camel/camel-folder-search.h>
#include <camel/camel-mime-part.h>
#include <camel/camel-mime-utils.h>
#include <camel/camel-string-utils.h>
#include <camel/camel-object.h>
#include <camel/camel-mime-message.h>
#include <camel/camel-data-wrapper.h>
#include <camel/camel-multipart.h>
#include <camel/camel-private.h>
#include <camel/camel-session.h>
#include <camel/camel-stream-buffer.h>
#include <camel/camel-stream-mem.h>
#include <camel/camel-debug.h>

#include <libmapi/libmapi.h>
#include <exchange-mapi-defs.h>
#include <exchange-mapi-utils.h>
#include <exchange-mapi-folder.h>
#include <exchange-mapi-cal-utils.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-private.h"
#include "camel-mapi-summary.h"
#include "camel-mapi-utils.h"

#define DEBUG_FN( ) printf("----%u %s\n", (unsigned int)pthread_self(), __FUNCTION__);
#define SUMMARY_FETCH_BATCH_COUNT 150
#define d(x)

static CamelOfflineFolderClass *parent_class = NULL;

struct _CamelMapiFolderPrivate {
	
//#ifdef ENABLE_THREADS
	GStaticMutex search_lock;	/* for locking the search object */
	GStaticRecMutex cache_lock;	/* for locking the cache object */
//#endif

};

/*for syncing flags back to server*/
typedef struct {
	guint32 changed;
	guint32 bits;
} flags_diff_t;

/*For collecting summary info from server*/

static CamelMimeMessage *mapi_folder_item_to_msg( CamelFolder *folder, MapiItem *item, CamelException *ex );
static void mapi_update_cache (CamelFolder *folder, GSList *list, CamelFolderChangeInfo **changeinfo,
			       CamelException *ex, gboolean uid_flag);

static GPtrArray *
mapi_folder_search_by_expression (CamelFolder *folder, const char *expression, CamelException *ex)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER(folder);
	GPtrArray *matches;

	CAMEL_MAPI_FOLDER_LOCK(mapi_folder, search_lock);
	camel_folder_search_set_folder (mapi_folder->search, folder);
	matches = camel_folder_search_search(mapi_folder->search, expression, NULL, ex);
	CAMEL_MAPI_FOLDER_UNLOCK(mapi_folder, search_lock);

	return matches;
}

static GPtrArray *
mapi_folder_search_by_uids (CamelFolder *folder, const gchar *expression, GPtrArray *uids, CamelException *ex)
{
	GPtrArray *matches;
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);

	if (uids->len == 0)
		return g_ptr_array_new ();

	CAMEL_MAPI_FOLDER_LOCK (mapi_folder, search_lock);
	camel_folder_search_set_folder (mapi_folder->search, folder);
	matches = camel_folder_search_search (mapi_folder->search, expression, uids, ex);
	CAMEL_MAPI_FOLDER_UNLOCK (mapi_folder, search_lock);

	return matches;
}

static int
mapi_getv (CamelObject *object, CamelException *ex, CamelArgGetV *args)
{
	CamelFolder *folder = (CamelFolder *)object;
	int i, count = 0;
	guint32 tag;

	for (i=0 ; i<args->argc ; i++) {
		CamelArgGet *arg = &args->argv[i];

		tag = arg->tag;

		switch (tag & CAMEL_ARG_TAG) {

			case CAMEL_OBJECT_ARG_DESCRIPTION:
				if (folder->description == NULL) {
					CamelURL *uri = ((CamelService *)folder->parent_store)->url;

					folder->description = g_strdup_printf("%s@%s:%s", uri->user, uri->host, folder->full_name);
				}
				*arg->ca_str = folder->description;
				break;
			default:
				count++;
				continue;
		}

		arg->tag = (tag & CAMEL_ARG_TYPE) | CAMEL_ARG_IGNORE;
	}

	if (count)
		return ((CamelObjectClass *)parent_class)->getv(object, ex, args);

	return 0;

}

static void
mapi_refresh_info(CamelFolder *folder, CamelException *ex)
{
	CamelStoreInfo *si;
	/*
	 * Checking for the summary->time_string here since the first the a
	 * user views a folder, the read cursor is in progress, and the getQM
	 * should not interfere with the process
	 */
	//	if (summary->time_string && (strlen (summary->time_string) > 0))  {
	if(1){
		mapi_refresh_folder(folder, ex);
		si = camel_store_summary_path ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary, folder->full_name);

		if (si) {
			guint32 unread, total;
			camel_object_get (folder, NULL, CAMEL_FOLDER_TOTAL, &total, CAMEL_FOLDER_UNREAD, &unread, NULL);
			if (si->total != total || si->unread != unread) {
				si->total = total;
				si->unread = unread;
				camel_store_summary_touch ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary);
			}
			camel_store_summary_info_free ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary, si);
		}
		camel_folder_summary_save_to_db (folder->summary, ex);
		camel_store_summary_save ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary);
	} else {
		/* We probably could not get the messages the first time. (get_folder) failed???!
		 * so do a get_folder again. And hope that it works
		 */
		g_print("Reloading folder...something wrong with the summary....\n");
	}
	//#endif

}

void 
mapi_item_free (MapiItem *item)
{
	g_free (item->header.subject);
	g_free (item->header.from);

	g_free (item->header.to);
	g_free (item->header.cc);
	g_free (item->header.bcc);

	g_free (item->header.references);
	g_free (item->header.message_id);
	g_free (item->header.in_reply_to);

	exchange_mapi_util_free_attachment_list (&item->attachments);
	exchange_mapi_util_free_stream_list (&item->generic_streams);
	exchange_mapi_util_free_recipient_list (&item->recipients);

	g_free (item);
}

static gboolean
read_item_common (MapiItem *item, uint32_t ulPropTag, gconstpointer prop_data)
{
	gboolean found = TRUE;

	#define sv(_x,_y) G_STMT_START { g_free (_x); _x = _y; } G_STMT_END

	switch (ulPropTag) {
	case PR_INTERNET_CPID: {
		const uint32_t *ui32 = (const uint32_t *) prop_data;
		if (ui32)
			item->header.cpid = *ui32;
		} break;
	/* FIXME : Instead of duping. Use talloc_steal to reuse the memory */
	case PR_SUBJECT:
		sv (item->header.subject, utf8tolinux (prop_data));
		break;
	case PR_SUBJECT_UNICODE :
		sv (item->header.subject, g_strdup (prop_data));
		break;
	case PR_DISPLAY_TO :
		sv (item->header.to, utf8tolinux (prop_data));
		break;
	case PR_DISPLAY_TO_UNICODE :
		sv (item->header.to, g_strdup (prop_data));
		break;
	case PR_DISPLAY_CC:
		sv (item->header.cc, utf8tolinux (prop_data));
		break;
	case PR_DISPLAY_CC_UNICODE:
		sv (item->header.cc, g_strdup (prop_data));
		break;
	case PR_DISPLAY_BCC:
		sv (item->header.bcc, utf8tolinux (prop_data));
		break;
	case PR_DISPLAY_BCC_UNICODE:
		sv (item->header.bcc, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_NAME:
		sv (item->header.from, utf8tolinux (prop_data));
		break;
	case PR_SENT_REPRESENTING_NAME_UNICODE:
		sv (item->header.from, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
		sv (item->header.from_email, utf8tolinux (prop_data));
		break;
	case PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE:
		sv (item->header.from_email, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_ADDRTYPE:
		sv (item->header.from_type, utf8tolinux (prop_data));
		break;
	case PR_SENT_REPRESENTING_ADDRTYPE_UNICODE:
		sv (item->header.from_type, g_strdup (prop_data));
		break;
	case PR_MESSAGE_SIZE:
		item->header.size = *(glong *)prop_data;
		break;
	case PR_INTERNET_MESSAGE_ID:
		item->header.message_id = g_strdup (prop_data);
		break;
	case PR_INTERNET_REFERENCES:
		item->header.references = g_strdup (prop_data);
		break;
	case PR_IN_REPLY_TO_ID:
		item->header.in_reply_to = g_strdup (prop_data);
		break;
	case PR_TRANSPORT_MESSAGE_HEADERS:
		sv (item->header.transport_headers, utf8tolinux (prop_data));
		break;
	case PR_TRANSPORT_MESSAGE_HEADERS_UNICODE:
		sv (item->header.transport_headers, g_strdup (prop_data));
		break;
	default:
		found = FALSE;
		break;
	}

	#undef sv

	return found;
}

static gboolean
fetch_items_summary_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	fetch_items_data *fi_data = (fetch_items_data *)data;
	
	GSList **slist = &(fi_data->items_list);

	long *flags;
	struct FILETIME *delivery_date = NULL;
	struct FILETIME *last_modification_time = NULL;
	struct timeval item_modification_time = { 0 };
	struct timeval fi_data_mod_time = { 0 };
	guint32 j = 0;
	NTTIME ntdate;

	MapiItem *item = g_new0(MapiItem , 1);

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

		if (read_item_common (item, item_data->properties->lpProps[j].ulPropTag, prop_data))
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
		ntdate = delivery_date->dwHighDateTime;
		ntdate = ntdate << 32;
		ntdate |= delivery_date->dwLowDateTime;
		item->header.recieved_time = nt_time_to_unix(ntdate);
	}

	if (last_modification_time) {
		ntdate = last_modification_time->dwHighDateTime;
		ntdate = ntdate << 32;
		ntdate |= last_modification_time->dwLowDateTime;
		nttime_to_timeval (&item_modification_time, ntdate);
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
		mapi_update_cache (fi_data->folder, *slist, &fi_data->changes, NULL, false);
		g_slist_foreach (*slist, (GFunc)mapi_item_free, NULL);
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
		   CamelException *ex, gboolean uid_flag) 
{
	CamelMapiMessageInfo *mi = NULL;
	CamelMessageInfo *pmi = NULL;
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (folder->parent_store);

	guint32 status_flags = 0;
	CamelFolderChangeInfo *changes = NULL;
	gboolean exists = FALSE;
	GString *str = g_string_new (NULL);
	const gchar *from_email, *folder_id = NULL;
	GSList *item_list = list;
	int total_items = g_slist_length (item_list), i=0;

	changes = *changeinfo;

	folder_id = camel_mapi_store_folder_id_lookup (mapi_store, folder->full_name);

	if (!folder_id) {
		d(printf("\nERROR - Folder id not present. Cannot refresh info\n"));
		return;
	}

	camel_operation_start (NULL, _("Updating local summary cache for new messages in %s"), folder->name);

	for ( ; item_list != NULL ; item_list = g_slist_next (item_list) ) {
		MapiItem *temp_item ;
		MapiItem *item;
		gchar *msg_uid;
		guint64 id;

		exists = FALSE;
		status_flags = 0;

		if (uid_flag == FALSE) {
 			temp_item = (MapiItem *)item_list->data;
			id = temp_item->mid;
			item = temp_item;
		}

		camel_operation_progress (NULL, (100*i)/total_items);

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
				const char *name, *display_name;
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
						count_to ++;
						break;

					case MAPI_CC:
						if (count_cc) {
							gchar *tmp = cc;
							cc = g_strconcat (cc, ", ", formatted_id, NULL);
							g_free (formatted_id);
							g_free (tmp);
						} else
							cc = formatted_id;
						count_cc ++;
						break;

					default:
						continue;
					}
				}
 			}
 			
 			if ((item->header.from_type != NULL) && !g_utf8_collate (item->header.from_type, "EX")) {
 				CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
				from_email = exchange_mapi_util_ex_to_smtp (item->header.from_email);
 				CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

 				g_free (item->header.from_email);
				item->header.from_email = g_strdup (from_email);				
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
			CAMEL_MAPI_FOLDER_REC_LOCK (folder, cache_lock);
			camel_folder_summary_add (folder->summary,(CamelMessageInfo *)mi);
			camel_folder_change_info_add_uid (changes, mi->info.uid);
			camel_folder_change_info_recent_uid (changes, mi->info.uid);
			CAMEL_MAPI_FOLDER_REC_UNLOCK (folder, cache_lock);
		}

		/********************* Summary ends *************************/
		/* FIXME : Don't use folder names for identifying */
		if (!strcmp (folder->full_name, "Junk Mail"))
			continue;

		g_free (msg_uid);
		i++;
	}
	camel_operation_end (NULL);

	g_string_free (str, TRUE);
}

static void 
mapi_sync_summary (CamelFolder *folder, CamelException *ex)
{
	camel_folder_summary_save_to_db (folder->summary, ex);
	camel_store_summary_touch ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary);
	camel_store_summary_save ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary);
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
	GSList **uid_list = (GSList **) data;
	gchar *msg_uid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, 
							     item_data->mid);

	*uid_list = g_slist_prepend (*uid_list, msg_uid);

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

	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (m->folder->parent_store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (m->folder);
	CamelFolderChangeInfo *changes = NULL;
	CamelMessageInfo *info = NULL;

	guint32 index, count, options = 0;
	GSList *server_uid_list = NULL;
	const gchar *uid = NULL;

	/* Currently we don't have simple wrapper over getprops.*/
	const guint32 prop_list[] = { PR_LAST_MODIFICATION_TIME };
	
	if (((CamelOfflineStore *) mapi_store)->state == CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL ||
			((CamelService *)mapi_store)->status == CAMEL_SERVICE_DISCONNECTED) {
	
		return;
	}

	camel_operation_start (NULL, _("Retrieving message IDs from server for %s"), m->folder->name);

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);

	/*Get the UID list from server.*/
	exchange_mapi_connection_fetch_items  (m->folder_id, NULL, NULL,
					       prop_list, G_N_ELEMENTS (prop_list),
					       NULL, NULL,
					       deleted_items_sync_cb, &server_uid_list,
					       options | MAPI_OPTIONS_DONT_OPEN_MESSAGE);

	camel_operation_end (NULL);

	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

	/* Check if we have to stop */
	if (camel_operation_cancel_check(NULL))
		return;

	changes = camel_folder_change_info_new ();

	count = camel_folder_summary_count (m->folder->summary);
	camel_operation_start (NULL, _("Removing deleted messages from cache in %s"), m->folder->name);

	/* Iterate over cache and check if the UID is in server*/
	for (index = 0; index < count; index++) {
		GSList *tmp_list_item = NULL;

		/* Iterate in a reverse order, thus removal will not hurt */
		info = camel_folder_summary_index (m->folder->summary, count - index - 1);
		if (!info) continue; /*This is bad. *Should* not happen*/

		uid = camel_message_info_uid (info);

		if (server_uid_list) {
			/* TODO : Find a better way and avoid this linear search */
			tmp_list_item = g_slist_find_custom (server_uid_list, (gconstpointer) uid, 
						  (GCompareFunc) g_strcmp0);
		}

		/* If it is not in server list, clean our cache */
		if ((!tmp_list_item || !tmp_list_item->data) && uid) {
			CAMEL_MAPI_FOLDER_REC_LOCK (m->folder, cache_lock);
			camel_folder_summary_remove_uid (m->folder->summary, uid);
			camel_data_cache_remove (mapi_folder->cache, "cache", uid, NULL);
			camel_folder_change_info_remove_uid (changes, uid);
			CAMEL_MAPI_FOLDER_REC_UNLOCK (m->folder, cache_lock);
		}

		/* Progress update */
		camel_operation_progress (NULL, (index * 100)/count); /* ;-) */

		/* Check if we have to stop */
		if (camel_operation_cancel_check(NULL)) {
			if (camel_folder_change_info_changed (changes))
				camel_object_trigger_event (m->folder, "folder_changed", changes);
			camel_folder_change_info_free (changes);
			return;
		}
	}

	camel_operation_end (NULL);

	if (camel_folder_change_info_changed (changes))
		camel_object_trigger_event (m->folder, "folder_changed", changes);
	camel_folder_change_info_free (changes);

	m->need_refresh = camel_folder_summary_count (m->folder->summary) != g_slist_length (server_uid_list);

	/* Discard server uid list */
	g_slist_foreach (server_uid_list, (GFunc) g_free, NULL);
	g_slist_free (server_uid_list);
}

static void
mapi_sync_deleted_free (CamelSession *session, CamelSessionThreadMsg *msg)
{
	struct mapi_update_deleted_msg *m = (struct mapi_update_deleted_msg *)msg;

	if (m->need_refresh) {
		CamelMapiSummary *mapi_summary = CAMEL_MAPI_SUMMARY (m->folder->summary);
		if (mapi_summary) {
			CamelException ex = CAMEL_EXCEPTION_INITIALISER;

			CAMEL_SERVICE_REC_LOCK (m->folder->parent_store, connect_lock);
			g_free (mapi_summary->sync_time_stamp);
			mapi_summary->sync_time_stamp = NULL;
			CAMEL_SERVICE_REC_UNLOCK (m->folder->parent_store, connect_lock);

			mapi_refresh_folder (m->folder, &ex);

			if (camel_exception_is_set (&ex))
				g_warning ("%s: %s", G_STRFUNC, ex.desc);
			camel_exception_clear (&ex);
		}
	}

	camel_object_unref (m->folder);
}

static CamelSessionThreadOps deleted_items_sync_ops = {
	mapi_sync_deleted,
	mapi_sync_deleted_free,
};

static void
mapi_sync (CamelFolder *folder, gboolean expunge, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (folder->parent_store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);
	CamelMessageInfo *info = NULL;
	CamelMapiMessageInfo *mapi_info = NULL;

	GSList *read_items = NULL, *unread_items = NULL, *to_free = NULL;
	flags_diff_t diff, unset_flags;
	const char *folder_id;
	mapi_id_t fid, deleted_items_fid;
	gint count, i;
	guint32 options =0;

	GSList *deleted_items, *deleted_head;
	deleted_items = deleted_head = NULL;

	if (((CamelOfflineStore *) mapi_store)->state == CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL || 
			((CamelService *)mapi_store)->status == CAMEL_SERVICE_DISCONNECTED) {
		mapi_sync_summary (folder, ex);
		return;
	}

	if (((CamelMapiFolder *)folder)->type & CAMEL_MAPI_FOLDER_PUBLIC)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, folder->full_name) ;
	exchange_mapi_util_mapi_id_from_string (folder_id, &fid);

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
	if (!camel_mapi_store_connected (mapi_store, ex)) {
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		camel_exception_clear (ex);
		return;
	}
	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

	count = camel_folder_summary_count (folder->summary);
	CAMEL_MAPI_FOLDER_REC_LOCK (folder, cache_lock);
	for (i=0 ; i < count ; i++) {
		info = camel_folder_summary_index (folder->summary, i);
		mapi_info = (CamelMapiMessageInfo *) info;

		if (mapi_info && (mapi_info->info.flags & CAMEL_MESSAGE_FOLDER_FLAGGED)) {
			const char *uid;
			mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
			mapi_id_t temp_fid;
			guint32 flags;
			gboolean used = FALSE;

			uid = camel_message_info_uid (info);
			flags= camel_message_info_flags (info);

			/* Why are we getting so much noise here :-/ */
			if (!exchange_mapi_util_mapi_ids_from_uid (uid, &temp_fid, mid)) {
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
			} else {
				if (diff.bits & CAMEL_MESSAGE_DELETED) {
					if (diff.bits & CAMEL_MESSAGE_SEEN) {
						read_items = g_slist_prepend (read_items, mid);
						used = TRUE;
					}
					if (deleted_items) {
						deleted_items = g_slist_prepend (deleted_items, mid);
						used = TRUE;
					} else {
						g_slist_free (deleted_head);
						deleted_head = NULL;
						deleted_head = deleted_items = g_slist_prepend (deleted_items, mid);
						used = TRUE;
					}
				}
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
		}
		camel_message_info_free (info);
	}
	
	CAMEL_MAPI_FOLDER_REC_UNLOCK (folder, cache_lock);

	/* 
	   Sync up the READ changes before deleting the message. 
	   Note that if a message is marked as unread and then deleted,
	   Evo doesnt not take care of it, as I find that scenario to be impractical.
	*/

	if (read_items) {
		CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
		exchange_mapi_set_flags (0, fid, read_items, 0, options);
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		g_slist_free (read_items);
	}

	/* Remove messages from server*/
	if (deleted_items) {
		CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
		if ((mapi_folder->type & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
			exchange_mapi_remove_items (0, fid, deleted_items);
		} else {
			exchange_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderDeletedItems), &deleted_items_fid);
			exchange_mapi_move_items(fid, deleted_items_fid, deleted_items);
		}

		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
	}

	/*Remove messages from local cache*/
	while (deleted_items) {
		char* deleted_msg_uid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X%016" G_GINT64_MODIFIER "X", fid, *(mapi_id_t *)deleted_items->data);

		CAMEL_MAPI_FOLDER_REC_LOCK (folder, cache_lock);
		camel_folder_summary_remove_uid (folder->summary, deleted_msg_uid);
		camel_data_cache_remove(mapi_folder->cache, "cache", deleted_msg_uid, NULL);
		CAMEL_MAPI_FOLDER_REC_UNLOCK (folder, cache_lock);

		deleted_items = g_slist_next (deleted_items);
	}

	g_slist_free (unread_items);
	g_slist_free (deleted_head);

	g_slist_foreach (to_free, (GFunc) g_free, NULL);
	g_slist_free (to_free);

	if (expunge) {
		/* TODO */
	}

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
	mapi_sync_summary (folder, ex);
	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
}

gboolean
camel_mapi_folder_fetch_summary (CamelStore *store, const mapi_id_t fid, struct mapi_SRestriction *res,
				 struct SSortOrderSet *sort, fetch_items_data *fetch_data, guint32 options)
{
	gboolean status;
	CamelMapiStore *mapi_store = (CamelMapiStore *) store;

	const guint32 summary_prop_list[] = {
		PR_INTERNET_CPID,
		PR_SUBJECT_UNICODE,
		PR_MESSAGE_SIZE,
		PR_MESSAGE_DELIVERY_TIME,
		PR_MESSAGE_FLAGS,
		PR_SENT_REPRESENTING_NAME_UNICODE,
		PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE,
		PR_SENT_REPRESENTING_ADDRTYPE,
		PR_LAST_MODIFICATION_TIME,
		PR_INTERNET_MESSAGE_ID,
		PR_INTERNET_REFERENCES,
		PR_IN_REPLY_TO_ID,
		PR_DISPLAY_TO_UNICODE,
		PR_DISPLAY_CC_UNICODE,
		PR_DISPLAY_BCC_UNICODE,
		PR_TRANSPORT_MESSAGE_HEADERS_UNICODE
	};

	/*TODO : Check for online state*/

	camel_operation_start (NULL, _("Fetching summary information for new messages in")); /* %s"), folder->name); */

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);

	status = exchange_mapi_connection_fetch_items  (fid, res, sort, summary_prop_list,
							G_N_ELEMENTS (summary_prop_list), 
							NULL, NULL, fetch_items_summary_cb,
							fetch_data, options);

	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

	camel_operation_end (NULL);

	return status;
}

void
mapi_refresh_folder(CamelFolder *folder, CamelException *ex)
{

	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (folder->parent_store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);
	CamelMapiSummary *mapi_summary = CAMEL_MAPI_SUMMARY (folder->summary);
	CamelSession *session = ((CamelService *)folder->parent_store)->session;

	gboolean is_proxy = folder->parent_store->flags & CAMEL_STORE_PROXY;
	gboolean is_locked = FALSE;
	gboolean status;

	struct mapi_SRestriction *res = NULL;
	struct SSortOrderSet *sort = NULL;
	struct mapi_update_deleted_msg *deleted_items_op_msg;
	fetch_items_data *fetch_data = g_new0 (fetch_items_data, 1);

	const gchar *folder_id = NULL;

	if (((CamelOfflineStore *) mapi_store)->state == CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL)
		goto end1;

	/* Sync-up the (un)read changes before getting updates,
	so that the getFolderList will reflect the most recent changes too */
	mapi_sync (folder, FALSE, ex);

	//creating a copy
	folder_id = camel_mapi_store_folder_id_lookup (mapi_store, folder->full_name);
	if (!folder_id) {
		d(printf ("\nERROR - Folder id not present. Cannot refresh info for %s\n", folder->full_name));
		goto end1;
	}

	if (camel_folder_is_frozen (folder) ) {
		mapi_folder->need_refresh = TRUE;
	}

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
	is_locked = TRUE;

	if (!camel_mapi_store_connected (mapi_store, ex))
		goto end1;

	/*Get the New Items*/
	if (!is_proxy) {
		mapi_id_t temp_folder_id;
		guint32 options = 0;

		if (mapi_summary->sync_time_stamp && *mapi_summary->sync_time_stamp &&
		    g_time_val_from_iso8601 (mapi_summary->sync_time_stamp, 
					     &fetch_data->last_modification_time)) {
			struct SPropValue sprop;
			struct timeval t;

			res = g_new0 (struct mapi_SRestriction, 1);
			res->rt = RES_PROPERTY;
			/*RELOP_GE acts more like >=. Few extra items are being fetched.*/
			res->res.resProperty.relop = RELOP_GE;
			res->res.resProperty.ulPropTag = PR_LAST_MODIFICATION_TIME;

			t.tv_sec = fetch_data->last_modification_time.tv_sec;
			t.tv_usec = fetch_data->last_modification_time.tv_usec;

			//Creation time ? 
			set_SPropValue_proptag_date_timeval (&sprop, PR_LAST_MODIFICATION_TIME, &t);
			cast_mapi_SPropValue (&(res->res.resProperty.lpProp), &sprop);

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

		if (!camel_mapi_store_connected (mapi_store, ex)) {
			/*BUG : Fix exception string.*/
			camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_UNAVAILABLE,
					     _("This message is not available in offline mode."));
			goto end1;
		}

		options |= MAPI_OPTIONS_FETCH_RECIPIENTS;

		if (((CamelMapiFolder *)folder)->type & CAMEL_MAPI_FOLDER_PUBLIC)
			options |= MAPI_OPTIONS_USE_PFSTORE;

		status = camel_mapi_folder_fetch_summary ((CamelStore *)mapi_store, temp_folder_id, res, sort,
							  fetch_data, options);

		if (!status) {
			camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_INVALID, _("Fetching items failed"));
			goto end1;
		}

		/*Preserve last_modification_time from this fetch for later use with restrictions.*/
		g_free (mapi_summary->sync_time_stamp);
		mapi_summary->sync_time_stamp = g_time_val_to_iso8601 (&fetch_data->last_modification_time);

		camel_folder_summary_touch (folder->summary);
		mapi_sync_summary (folder, ex);

		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		is_locked = FALSE;

		/* Downsync deleted items */
		deleted_items_op_msg = camel_session_thread_msg_new (session, &deleted_items_sync_ops, 
							 sizeof (*deleted_items_op_msg));
		deleted_items_op_msg->folder = folder;
		deleted_items_op_msg->folder_id = temp_folder_id;
		deleted_items_op_msg->need_refresh = FALSE;
		camel_object_ref (folder);

		camel_session_thread_queue (session, &deleted_items_op_msg->msg, 0);

		camel_object_trigger_event (folder, "folder_changed", fetch_data->changes);
		camel_folder_change_info_free (fetch_data->changes);
	}

end1:
	if (is_locked)
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

	g_slist_foreach (fetch_data->items_list, (GFunc) mapi_item_free, NULL);
	g_slist_free (fetch_data->items_list);
	g_free (fetch_data);
}

static const uint32_t camel_GetPropsList[] = {
	PR_FID, 
	PR_MID, 
	PR_INTERNET_CPID,

	PR_TRANSPORT_MESSAGE_HEADERS_UNICODE,
	PR_MESSAGE_CLASS, 
	PR_MESSAGE_SIZE, 
	PR_MESSAGE_FLAGS, 
	PR_MESSAGE_DELIVERY_TIME, 
	PR_MSG_EDITOR_FORMAT, 

	PR_SUBJECT_UNICODE, 
	PR_CONVERSATION_TOPIC_UNICODE, 

	/*Properties used for message threading.*/
	PR_INTERNET_MESSAGE_ID,
	PR_INTERNET_REFERENCES,
	PR_IN_REPLY_TO_ID,

	PR_BODY, 
	PR_BODY_UNICODE, 
	PR_HTML,
	/*Fixme : If this property is fetched, it garbles everything else. */
 	/*PR_BODY_HTML, */
 	/*PR_BODY_HTML_UNICODE, */

	PR_DISPLAY_TO_UNICODE, 
	PR_DISPLAY_CC_UNICODE, 
	PR_DISPLAY_BCC_UNICODE, 

	PR_CREATION_TIME, 
	PR_LAST_MODIFICATION_TIME, 
	PR_PRIORITY, 
	PR_SENSITIVITY, 
	PR_START_DATE, 
	PR_END_DATE, 
	PR_RESPONSE_REQUESTED, 
	PR_OWNER_APPT_ID, 
	PR_PROCESSED, 

	PR_SENT_REPRESENTING_NAME_UNICODE, 
	PR_SENT_REPRESENTING_ADDRTYPE, 
	PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE, 

	PR_SENDER_NAME_UNICODE, 
	PR_SENDER_ADDRTYPE, 
	PR_SENDER_EMAIL_ADDRESS_UNICODE, 

	PR_RCVD_REPRESENTING_NAME_UNICODE, 
	PR_RCVD_REPRESENTING_ADDRTYPE, 
	PR_RCVD_REPRESENTING_EMAIL_ADDRESS_UNICODE
};

static gboolean 
camel_build_name_id (struct mapi_nameid *nameid, gpointer data)
{
	mapi_nameid_lid_add(nameid, 0x8501, PSETID_Common); 	// PT_LONG - ReminderMinutesBeforeStart
	mapi_nameid_lid_add(nameid, 0x8502, PSETID_Common); 	// PT_SYSTIME - ReminderTime
	mapi_nameid_lid_add(nameid, 0x8503, PSETID_Common); 	// PT_BOOLEAN - ReminderSet
	mapi_nameid_lid_add(nameid, 0x8506, PSETID_Common); 	// PT_BOOLEAN - Private
	mapi_nameid_lid_add(nameid, 0x8510, PSETID_Common); 	// PT_LONG - (context menu flags)
	mapi_nameid_lid_add(nameid, 0x8516, PSETID_Common); 	// PT_SYSTIME - CommonStart
	mapi_nameid_lid_add(nameid, 0x8517, PSETID_Common); 	// PT_SYSTIME - CommonEnd
	mapi_nameid_lid_add(nameid, 0x8560, PSETID_Common); 	// PT_SYSTIME - ReminderNextTime

	mapi_nameid_lid_add(nameid, 0x8201, PSETID_Appointment); 	// PT_LONG - ApptSequence
	mapi_nameid_lid_add(nameid, 0x8205, PSETID_Appointment); 	// PT_LONG - BusyStatus
	mapi_nameid_lid_add(nameid, 0x8208, PSETID_Appointment); 	// PT_UNICODE - Location
	mapi_nameid_lid_add(nameid, 0x820D, PSETID_Appointment); 	// PT_SYSTIME - Start/ApptStartWhole
	mapi_nameid_lid_add(nameid, 0x820E, PSETID_Appointment); 	// PT_SYSTIME - End/ApptEndWhole
	mapi_nameid_lid_add(nameid, 0x8213, PSETID_Appointment); 	// PT_LONG - Duration/ApptDuration
	mapi_nameid_lid_add(nameid, 0x8215, PSETID_Appointment); 	// PT_BOOLEAN - AllDayEvent (also called ApptSubType)
	mapi_nameid_lid_add(nameid, 0x8216, PSETID_Appointment); 	// PT_BINARY - (recurrence blob)
	mapi_nameid_lid_add(nameid, 0x8217, PSETID_Appointment); 	// PT_LONG - MeetingStatus
	mapi_nameid_lid_add(nameid, 0x8218, PSETID_Appointment); 	// PT_LONG - ResponseStatus
	mapi_nameid_lid_add(nameid, 0x8223, PSETID_Appointment); 	// PT_BOOLEAN - Recurring
	mapi_nameid_lid_add(nameid, 0x8224, PSETID_Appointment); 	// PT_LONG - IntendedBusyStatus
	mapi_nameid_lid_add(nameid, 0x8228, PSETID_Appointment); 	// PT_SYSTIME - RecurrenceBase
	mapi_nameid_lid_add(nameid, 0x8229, PSETID_Appointment); 	// PT_BOOLEAN - FInvited
	mapi_nameid_lid_add(nameid, 0x8231, PSETID_Appointment); 	// PT_LONG - RecurrenceType
	mapi_nameid_lid_add(nameid, 0x8232, PSETID_Appointment); 	// PT_STRING8 - RecurrencePattern
	mapi_nameid_lid_add(nameid, 0x8235, PSETID_Appointment); 	// PT_SYSTIME - (dtstart)(for recurring events UTC 12 AM of day of start)
	mapi_nameid_lid_add(nameid, 0x8236, PSETID_Appointment); 	// PT_SYSTIME - (dtend)(for recurring events UTC 12 AM of day of end)
	mapi_nameid_lid_add(nameid, 0x823A, PSETID_Appointment); 	// PT_BOOLEAN - AutoFillLocation
	mapi_nameid_lid_add(nameid, 0x8240, PSETID_Appointment); 	// PT_BOOLEAN - IsOnlineMeeting
	mapi_nameid_lid_add(nameid, 0x8257, PSETID_Appointment); 	// PT_BOOLEAN - ApptCounterProposal
	mapi_nameid_lid_add(nameid, 0x825E, PSETID_Appointment); 	// PT_BINARY - (timezone for dtstart)
	mapi_nameid_lid_add(nameid, 0x825F, PSETID_Appointment); 	// PT_BINARY - (timezone for dtend)

	mapi_nameid_lid_add(nameid, 0x0002, PSETID_Meeting); 		// PT_UNICODE - Where
	mapi_nameid_lid_add(nameid, 0x0003, PSETID_Meeting); 		// PT_BINARY - GlobalObjectId
	mapi_nameid_lid_add(nameid, 0x0005, PSETID_Meeting); 		// PT_BOOLEAN - IsRecurring
	mapi_nameid_lid_add(nameid, 0x000a, PSETID_Meeting); 		// PT_BOOLEAN - IsException 
	mapi_nameid_lid_add(nameid, 0x0023, PSETID_Meeting); 		// PT_BINARY - CleanGlobalObjectId
	mapi_nameid_lid_add(nameid, 0x0024, PSETID_Meeting); 		// PT_STRING8 - AppointmentMessageClass 
	mapi_nameid_lid_add(nameid, 0x0026, PSETID_Meeting); 		// PT_LONG - MeetingType

	/* These probably would never be used from Evolution */
//	mapi_nameid_lid_add(nameid, 0x8200, PSETID_Appointment); 	// PT_BOOLEAN - SendAsICAL
//	mapi_nameid_lid_add(nameid, 0x8202, PSETID_Appointment); 	// PT_SYSTIME - ApptSequenceTime
//	mapi_nameid_lid_add(nameid, 0x8214, PSETID_Appointment); 	// PT_LONG - Label
//	mapi_nameid_lid_add(nameid, 0x8234, PSETID_Appointment); 	// PT_STRING8 - display TimeZone
//	mapi_nameid_lid_add(nameid, 0x8238, PSETID_Appointment); 	// PT_STRING8 - AllAttendees
//	mapi_nameid_lid_add(nameid, 0x823B, PSETID_Appointment); 	// PT_STRING8 - ToAttendeesString (dupe PR_DISPLAY_TO)
//	mapi_nameid_lid_add(nameid, 0x823C, PSETID_Appointment); 	// PT_STRING8 - CCAttendeesString (dupe PR_DISPLAY_CC)

	mapi_nameid_lid_add(nameid, 0x8101, PSETID_Task); 	// PT_LONG - Status
	mapi_nameid_lid_add(nameid, 0x8102, PSETID_Task); 	// PT_DOUBLE - PercentComplete
	mapi_nameid_lid_add(nameid, 0x8103, PSETID_Task); 	// PT_BOOLEAN - TeamTask
	mapi_nameid_lid_add(nameid, 0x8104, PSETID_Task); 	// PT_SYSTIME - StartDate/TaskStartDate
	mapi_nameid_lid_add(nameid, 0x8105, PSETID_Task); 	// PT_SYSTIME - DueDate/TaskDueDate
	mapi_nameid_lid_add(nameid, 0x810F, PSETID_Task); 	// PT_SYSTIME - DateCompleted
//	mapi_nameid_lid_add(nameid, 0x8116, PSETID_Task); 	// PT_BINARY - (recurrence blob)
	mapi_nameid_lid_add(nameid, 0x811C, PSETID_Task); 	// PT_BOOLEAN - Complete
	mapi_nameid_lid_add(nameid, 0x811F, PSETID_Task); 	// PT_STRING8 - Owner
	mapi_nameid_lid_add(nameid, 0x8121, PSETID_Task); 	// PT_STRING8 - Delegator
	mapi_nameid_lid_add(nameid, 0x8126, PSETID_Task); 	// PT_BOOLEAN - IsRecurring/TaskFRecur
	mapi_nameid_lid_add(nameid, 0x8127, PSETID_Task); 	// PT_STRING8 - Role
	mapi_nameid_lid_add(nameid, 0x8129, PSETID_Task); 	// PT_LONG - Ownership
	mapi_nameid_lid_add(nameid, 0x812A, PSETID_Task); 	// PT_LONG - DelegationState

	/* These probably would never be used from Evolution */
//	mapi_nameid_lid_add(nameid, 0x8110, PSETID_Task); 	// PT_LONG - ActualWork/TaskActualEffort
//	mapi_nameid_lid_add(nameid, 0x8111, PSETID_Task); 	// PT_LONG - TotalWork/TaskEstimatedEffort

	/* These probably would never be used from Evolution */
//	mapi_nameid_lid_add(nameid, 0x8B00, PSETID_Note); 	// PT_LONG - Color

	return TRUE;
}

static gboolean
fetch_item_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	long *flags;
	struct FILETIME *delivery_date;
	const char *msg_class;
	NTTIME ntdate;
	ExchangeMAPIStream *body;

	MapiItem *item = g_new0(MapiItem , 1);
	MapiItem **i = (MapiItem **)data;
	guint32 j = 0;

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

		if (read_item_common (item, item_data->properties->lpProps[j].ulPropTag, prop_data))
			continue;

		switch (item_data->properties->lpProps[j].ulPropTag) {
		case PR_MESSAGE_CLASS:
		case PR_MESSAGE_CLASS_UNICODE:
			msg_class = (const char *) prop_data;
			break;
		case PR_MESSAGE_DELIVERY_TIME:
			delivery_date = (struct FILETIME *) prop_data;
			break;
		case PR_MESSAGE_FLAGS:
			flags = (long *) prop_data;
			break;
		default:
			break;
		}
	}

	item->is_cal = FALSE;
	if (g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_PREFIX)) {
		guint8 *appointment_body_str = (guint8 *) exchange_mapi_cal_util_camel_helper (item_data->properties, 
											     item_data->streams, 
											     item_data->recipients, item_data->attachments);

		if (appointment_body_str && *appointment_body_str) {
			body = g_new0(ExchangeMAPIStream, 1);
			body->proptag = PR_BODY_UNICODE;
			body->value = g_byte_array_new ();
			body->value = g_byte_array_append (body->value, appointment_body_str, strlen ((const char *)appointment_body_str));

			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);
			item->is_cal = TRUE;
		}

		g_free (appointment_body_str);
	}

	if (!item->is_cal) {
		/* always prefer unicode version, as that can be properly read */
		if (!(body = exchange_mapi_util_find_stream (item_data->streams, PR_BODY_UNICODE)))
			body = exchange_mapi_util_find_stream (item_data->streams, PR_BODY);

		if (body)
			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);

		body = exchange_mapi_util_find_stream (item_data->streams, PR_HTML);
		if (body)
			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);
	}

	if (delivery_date) {
		ntdate = delivery_date->dwHighDateTime;
		ntdate = ntdate << 32;
		ntdate |= delivery_date->dwLowDateTime;
		item->header.recieved_time = nt_time_to_unix(ntdate);
	}

	if ((*flags & MSGFLAG_READ) != 0)
		item->header.flags |= CAMEL_MESSAGE_SEEN;
	if ((*flags & MSGFLAG_HASATTACH) != 0)
		item->header.flags |= CAMEL_MESSAGE_ATTACHMENTS;

	item->attachments = item_data->attachments;

	*i = item;

	return TRUE;
}


static void
mapi_mime_set_recipient_list (CamelMimeMessage *msg, MapiItem *item)
{
	GSList *l = NULL;
	CamelInternetAddress *to_addr, *cc_addr, *bcc_addr;

	g_return_if_fail (item->recipients != NULL);

	to_addr = camel_internet_address_new ();
	cc_addr = camel_internet_address_new ();
	bcc_addr = camel_internet_address_new ();
	
	for (l = item->recipients; l; l=l->next) {
		char *display_name;
		const char *name = NULL;
		uint32_t rcpt_type = MAPI_TO;
		uint32_t *type = NULL; 
		struct SRow *aRow;
		ExchangeMAPIRecipient *recip = (ExchangeMAPIRecipient *)(l->data);
		
		/*Can't continue when there is no email-id*/
		if (!recip->email_id)
			continue;
		
		/* Build a SRow structure */
		aRow = &recip->out_SRow;
		
		/*Name is probably available in one of these props.*/
		name = (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_DISPLAY_NAME_UNICODE);
		name = name ? name : (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
		name = name ? name : (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_7BIT_DISPLAY_NAME_UNICODE);

		type = (uint32_t *) exchange_mapi_util_find_row_propval (aRow, PR_RECIPIENT_TYPE);
		
		/*Fallbacks. Not good*/
		display_name = name ? g_strdup (name) : g_strdup (recip->email_id);
		rcpt_type = (type ? *type : MAPI_TO);
		
		switch (rcpt_type) {
		case MAPI_TO:
			camel_internet_address_add (to_addr, display_name, recip->email_id);
			break;
		case MAPI_CC:
			camel_internet_address_add (cc_addr, display_name, recip->email_id);
			break;
		case MAPI_BCC:
			camel_internet_address_add (bcc_addr, display_name, recip->email_id);
			break;
		}

		g_free (display_name);
	}

	/*Add to message*/
	/*Note : To field is added from PR_TRANSPORT_MESSAGE_HEADERS
	  But, in sent_items folder we don't get TRANSPORT_MESSAGE_HEADERS */
	if (!item->header.transport_headers) {
		camel_mime_message_set_recipients(msg, "To", to_addr);
		camel_mime_message_set_recipients(msg, "Cc", cc_addr);
		camel_mime_message_set_recipients(msg, "Bcc", bcc_addr);
	}

	/*TODO : Unref *_addr ? */
}


static void
mapi_mime_set_msg_headers (CamelFolder *folder, CamelMimeMessage *msg, MapiItem *item)
{
	char *temp_str = NULL;
	const char *from_email;
	time_t recieved_time;
	CamelInternetAddress *addr = NULL;
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE(folder->parent_store);
	int offset = 0;
	time_t actual_time;

	/* Setting headers from PR_TRANSPORT_MESSAGE_HEADERS */
	if (item->header.transport_headers) {
		CamelMimePart *part = camel_mime_part_new ();
		CamelStream *stream;
		CamelMimeParser *parser;

		stream = camel_stream_mem_new_with_buffer (item->header.transport_headers, strlen (item->header.transport_headers));
		parser = camel_mime_parser_new ();
		camel_mime_parser_init_with_stream (parser, stream);
		camel_mime_parser_scan_from (parser, FALSE);
		camel_object_unref (stream);

		if (camel_mime_part_construct_from_parser (part, parser) != -1) {
			struct _camel_header_raw *h;

			for (h = part->headers; h; h = h->next) {
				const gchar *value = h->value;

				/* skip all headers describing content of a message,
				   because it's overwritten on message decomposition */
				if (g_ascii_strncasecmp (h->name, "Content", 7) == 0)
					continue;

				while (value && camel_mime_is_lwsp (*value))
					value++;

				camel_medium_add_header (CAMEL_MEDIUM (msg), h->name, value);
			}
		}

		camel_object_unref (parser);
		camel_object_unref (part);
	}

	/* Overwrite headers if we have specific properties available*/
	temp_str = item->header.subject;
	if(temp_str) 
		camel_mime_message_set_subject (msg, temp_str);

	recieved_time = item->header.recieved_time;

	actual_time = camel_header_decode_date (ctime(&recieved_time), &offset);
	/* camel_mime_message_set_date (msg, actual_time, offset); */

	if (item->header.from) {
		if ((item->header.from_type != NULL) && !g_utf8_collate (item->header.from_type, "EX")) {
			CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
			from_email = exchange_mapi_util_ex_to_smtp (item->header.from_email);
			CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
			g_free (item->header.from_email);
			item->header.from_email = g_strdup (from_email);
		}

		item->header.from_email = item->header.from_email ? 
			item->header.from_email : item->header.from;

		/* add reply to */
		addr = camel_internet_address_new();
		camel_internet_address_add(addr, item->header.from, item->header.from_email);
		camel_mime_message_set_reply_to(msg, addr);
		
		/* add from */
		addr = camel_internet_address_new();
		camel_internet_address_add(addr, item->header.from, item->header.from_email);
		camel_mime_message_set_from(msg, addr);
	}

	/* Threading */
	if (item->header.message_id)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "Message-ID", item->header.message_id);

	if (item->header.references)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "References", item->header.references);

	if (item->header.in_reply_to)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "In-Reply-To", item->header.in_reply_to);

}


static CamelMimePart *
mapi_mime_msg_body (MapiItem *item, const ExchangeMAPIStream *body)
{
	CamelMimePart *part = camel_mime_part_new ();
	camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_8BIT);
	
	if (body && body->value && body->value->len > 0) {
		const gchar* type = NULL;
		gchar *buff = NULL;

		if (item->is_cal)
			type = "text/calendar";
		else
			type = (body->proptag == PR_BODY || body->proptag == PR_BODY_UNICODE) ? 
				"text/plain" : "text/html";

		if (item->header.cpid) {
			if (item->header.cpid >= 28591 && item->header.cpid <= 28599)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-%d\"", type, item->header.cpid % 10);
			else if (item->header.cpid == 28603)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-13\"", type);
			else if (item->header.cpid == 28605)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-15\"", type);
			else if (item->header.cpid == 65000)
				buff = g_strdup_printf ("%s; charset=\"UTF-7\"", type);
			else if (item->header.cpid == 65001)
				buff = g_strdup_printf ("%s; charset=\"UTF-8\"", type);
			else
				buff = g_strdup_printf ("%s; charset=\"CP%d\"", type, item->header.cpid);
			type = buff;
		}

		camel_mime_part_set_content (part, (const char *) body->value->data, body->value->len, type);

		g_free (buff);
	} else
		camel_mime_part_set_content (part, " ", strlen (" "), "text/plain");

	return part;
}

#if 0

/* GCompareFunc. Used for ordering body types in a GSList.*/
static gint
sort_bodies_cb (gconstpointer a, gconstpointer b)
{
	static const gint desired_order[] = { PR_BODY, PR_BODY_UNICODE, PR_HTML };
	const ExchangeMAPIStream *stream_a = a, *stream_b = b;
	gint aidx, bidx;

	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	for (aidx = 0; aidx < G_N_ELEMENTS (desired_order); aidx++) {
		if (desired_order[aidx] == stream_a->proptag)
			break;
	}

	for (bidx = 0; bidx < G_N_ELEMENTS (desired_order); bidx++) {
		if (desired_order[bidx] == stream_b->proptag)
			break;
	}

	return aidx - bidx;
}

#endif

/* Adds parts to multipart. Convenience function. */
static void
mapi_mime_multipart_add_attachments (CamelMultipart *multipart, GSList *attachs)
{
	CamelMimePart *part;
	while (attachs) {
		part = attachs->data;
		camel_multipart_add_part (multipart, part);
		camel_object_unref (part);
		attachs = attachs->next;
	}
}

/* Process body stream and related objects into a MIME mulitpart */
static CamelMultipart *
mapi_mime_build_multipart_related (MapiItem *item, const ExchangeMAPIStream *stream,
				   GSList *inline_attachs)
{
	CamelMimePart *part;
	CamelMultipart *m_related = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_related), "multipart/related");
	camel_multipart_set_boundary (m_related, NULL);
	
	part = mapi_mime_msg_body (item, stream);
	camel_multipart_add_part (m_related, part);
	camel_object_unref (part);

	mapi_mime_multipart_add_attachments (m_related, inline_attachs);

	return m_related;
}

/* Process multiple body types and pack them in a MIME mulitpart */
static CamelMultipart *
mapi_mime_build_multipart_alternative (MapiItem *item, GSList *body_parts, GSList *inline_attachs)
{
	CamelMimePart *part;
	CamelMultipart *m_alternative = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_alternative), 
					  "multipart/alternative");
	camel_multipart_set_boundary (m_alternative, NULL);

	while (body_parts) {
		const ExchangeMAPIStream *stream = (ExchangeMAPIStream *) body_parts->data;
		part = camel_mime_part_new ();
		if ((stream->proptag == PR_HTML || stream->proptag == PR_BODY_HTML_UNICODE)
		    && inline_attachs) {
			CamelMultipart *m_related;
			m_related = mapi_mime_build_multipart_related (item, stream,
								       inline_attachs);
			camel_medium_set_content_object (CAMEL_MEDIUM (part),
							 CAMEL_DATA_WRAPPER (m_related));
			camel_object_unref (m_related);
		} else
			part = mapi_mime_msg_body (item, stream);
		
		camel_multipart_add_part (m_alternative, part);
		camel_object_unref (part);
	}

	return m_alternative;
}

static CamelMultipart *
mapi_mime_build_multipart_mixed (CamelMultipart *content, GSList *attachs)
{
	CamelMimePart *part = camel_mime_part_new ();
	CamelMultipart *m_mixed = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_mixed), 
					  "multipart/mixed");
	camel_multipart_set_boundary (m_mixed, NULL);

	camel_medium_set_content_object (CAMEL_MEDIUM (part), CAMEL_DATA_WRAPPER (content));
	camel_multipart_add_part (m_mixed, part);

	if (attachs)
		mapi_mime_multipart_add_attachments (m_mixed, attachs);

	return m_mixed;
}

/*Takes raw attachment streams and converts to MIME Parts. Parts are added to
  either inline / non-inline lists.*/
static void
mapi_mime_classify_attachments (GSList *attachments, GSList **inline_attachs, GSList **noninline)
{
	for (;attachments != NULL; attachments = attachments->next) {
		ExchangeMAPIAttachment *attach = (ExchangeMAPIAttachment *)attachments->data;
		ExchangeMAPIStream *stream = NULL;
		const char *filename, *mime_type, *content_id = NULL; 
		CamelContentType *content_type;
		CamelMimePart *part;

		stream = exchange_mapi_util_find_stream (attach->streams, PR_ATTACH_DATA_BIN);

		if (!stream || stream->value->len <= 0) {
			continue;
		}

		part = camel_mime_part_new ();

		filename = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps, 
											 PR_ATTACH_LONG_FILENAME_UNICODE);

		if (!(filename && *filename))
			filename = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps, 
												 PR_ATTACH_FILENAME_UNICODE);
		camel_mime_part_set_filename(part, g_strdup(filename));
		camel_content_type_set_param (((CamelDataWrapper *) part)->mime_type, "name", filename);

		/*Content-Type*/
		mime_type = (const char *) exchange_mapi_util_find_SPropVal_array_propval (attach->lpProps, PR_ATTACH_MIME_TAG);
		if (!mime_type)
			mime_type = "application/octet-stream";

		camel_mime_part_set_content (part, (const char *) stream->value->data, stream->value->len, mime_type);


		content_type = camel_mime_part_get_content_type (part);
		if (content_type && camel_content_type_is (content_type, "text", "*"))
			camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_QUOTEDPRINTABLE);
		else
			camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);

		/*Content-ID*/
		content_id = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps, 
											   PR_ATTACH_CONTENT_ID);
		/* TODO : Add disposition */
		if (content_id) {
			camel_mime_part_set_content_id (part, content_id);
			*inline_attachs = g_slist_append (*inline_attachs, part);
		} else
			*noninline = g_slist_append (*noninline, part);
	}
}

static CamelMimeMessage *
mapi_folder_item_to_msg( CamelFolder *folder, MapiItem *item, CamelException *ex )
{
	CamelMimeMessage *msg = NULL;
	CamelMultipart *multipart_body = NULL;

	GSList *attach_list = NULL;
	GSList *inline_attachs =  NULL; /*Used for mulitpart/related*/
	GSList *noninline_attachs = NULL; 

	gboolean build_alternative = FALSE;
	gboolean build_related = FALSE;

	attach_list = item->attachments;
	msg = camel_mime_message_new ();

	mapi_mime_set_recipient_list (msg, item);
	mapi_mime_set_msg_headers (folder, msg, item);
	mapi_mime_classify_attachments (attach_list, &inline_attachs, &noninline_attachs);

	build_alternative = (g_slist_length (item->msg.body_parts) > 1) && inline_attachs;
	build_related = !build_alternative && inline_attachs;

	if (build_alternative) {
		multipart_body = mapi_mime_build_multipart_alternative (item, item->msg.body_parts,
									inline_attachs);
	} else if (build_related) {
		multipart_body = mapi_mime_build_multipart_related (item,
								    item->msg.body_parts->data,
								    inline_attachs);
	} else { /* Simple multipart/mixed */
		CamelMimePart *part;
		multipart_body = camel_multipart_new ();
		camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (multipart_body),
						  "multipart/mixed");
		camel_multipart_set_boundary (multipart_body, NULL);
		part = mapi_mime_msg_body (item, item->msg.body_parts ? item->msg.body_parts->data : NULL);
		camel_multipart_add_part (multipart_body, part);
		camel_object_unref (part);
	}

	if (noninline_attachs) { /* multipart/mixed */
		multipart_body = mapi_mime_build_multipart_mixed (multipart_body, 
								  noninline_attachs);
	}

	camel_medium_set_content_object(CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER(multipart_body));
	camel_object_unref (multipart_body);

	return msg;
}

static CamelMimeMessage *
mapi_folder_get_message( CamelFolder *folder, const char *uid, CamelException *ex )
{
	CamelMimeMessage *msg = NULL;
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER(folder);
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE(folder->parent_store);
	CamelMapiMessageInfo *mi = NULL;

	CamelStream *stream, *cache_stream;
	mapi_id_t id_folder;
	mapi_id_t id_message;
	MapiItem *item = NULL;
	guint32 options = 0;

	/* see if it is there in cache */

	mi = (CamelMapiMessageInfo *) camel_folder_summary_uid (folder->summary, uid);
	if (mi == NULL) {
		camel_exception_setv(ex, CAMEL_EXCEPTION_FOLDER_INVALID_UID,
				_("Cannot get message: %s\n  %s"), uid, _("No such message"));
		return NULL;
	}
	cache_stream  = camel_data_cache_get (mapi_folder->cache, "cache", uid, ex);
	stream = camel_stream_mem_new ();
	if (cache_stream) {
		msg = camel_mime_message_new ();
		camel_stream_reset (stream);
		camel_stream_write_to_stream (cache_stream, stream);
		camel_stream_reset (stream);
		if (camel_data_wrapper_construct_from_stream ((CamelDataWrapper *) msg, stream) == -1) {
			if (errno == EINTR) {
				camel_exception_setv (ex, CAMEL_EXCEPTION_USER_CANCEL, _("Message fetching cancelled by user."));
				camel_object_unref (msg);
				camel_object_unref (cache_stream);
				camel_object_unref (stream);
				camel_message_info_free (&mi->info);
				return NULL;
			} else {
				camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, _("Cannot get message %s: %s"),
						uid, g_strerror (errno));
				camel_object_unref (msg);
				msg = NULL;
			}
		}
		camel_object_unref (cache_stream);
	}
	camel_object_unref (stream);

	if (msg != NULL) {
		camel_message_info_free (&mi->info);
		return msg;
	}

	if (((CamelOfflineStore *) mapi_store)->state == CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL) {
		camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_UNAVAILABLE,
				_("This message is not available in offline mode."));
		camel_message_info_free (&mi->info);
		return NULL;
	}

	/* Check if we are really offline */
	if (!camel_mapi_store_connected (mapi_store, ex)) {
		camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_UNAVAILABLE,
				_("This message is not available in offline mode."));
		camel_message_info_free (&mi->info);
		return NULL;
	}

	options = MAPI_OPTIONS_FETCH_ALL | MAPI_OPTIONS_FETCH_BODY_STREAM | 
		MAPI_OPTIONS_GETBESTBODY | MAPI_OPTIONS_FETCH_RECIPIENTS ;

	exchange_mapi_util_mapi_ids_from_uid (uid, &id_folder, &id_message);

	if (((CamelMapiFolder *)folder)->type & CAMEL_MAPI_FOLDER_PUBLIC){
		options |= MAPI_OPTIONS_USE_PFSTORE;
	} 

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
	exchange_mapi_connection_fetch_item (id_folder, id_message, 
					camel_GetPropsList, G_N_ELEMENTS (camel_GetPropsList), 
					camel_build_name_id, NULL, 
					fetch_item_cb, &item, 
					options);
	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

	if (item == NULL) {
		camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_INVALID, _("Could not get message"));
		camel_message_info_free (&mi->info);
		return NULL;
	}

	msg = mapi_folder_item_to_msg (folder, item, ex);
	mapi_item_free (item);

	if (!msg) {
		camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_INVALID, _("Could not get message"));
		camel_message_info_free (&mi->info);

		return NULL;
	}

	/* add to cache */
	CAMEL_MAPI_FOLDER_REC_LOCK (folder, cache_lock);
	if ((cache_stream = camel_data_cache_add (mapi_folder->cache, "cache", uid, NULL))) {
		if (camel_data_wrapper_write_to_stream ((CamelDataWrapper *) msg, cache_stream) == -1
				|| camel_stream_flush (cache_stream) == -1)
			camel_data_cache_remove (mapi_folder->cache, "cache", uid, NULL);
		camel_object_unref (cache_stream);
	}

	CAMEL_MAPI_FOLDER_REC_UNLOCK (folder, cache_lock);

	camel_message_info_free (&mi->info);

	return msg;
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

static void
camel_mapi_folder_finalize (CamelObject *object)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (object);

	if (mapi_folder->priv)
		g_free(mapi_folder->priv);
	if (mapi_folder->cache)
		camel_object_unref (mapi_folder->cache);
}

#if 0
static CamelMessageInfo*
mapi_get_message_info(CamelFolder *folder, const char *uid)
{ 
	CamelMessageInfo	*msg_info = NULL;
	CamelMessageInfoBase	*mi = (CamelMessageInfoBase *)msg ;
	int			status = 0;
	oc_message_headers_t	headers;

	if (folder->summary) {
		msg_info = camel_folder_summary_uid(folder->summary, uid);
	}
	if (msg_info != NULL) {
		mi = (CamelMessageInfoBase *)msg_info ;
		return (msg_info);
	}
	/* Go online and fetch message summary. */

	msg_info = camel_message_info_new(folder->summary);
	mi = (CamelMessageInfoBase *)msg_info ;

	if (headers.subject) mi->subject = (char *)camel_pstring_strdup(headers.subject);
	if (headers.from) mi->from = (char *)camel_pstring_strdup(headers.from);
	if (headers.to) mi->to = (char *)camel_pstring_strdup(headers.to);
	if (headers.cc) mi->cc = (char *)camel_pstring_strdup(headers.cc);
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
mapi_expunge (CamelFolder *folder, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE(folder->parent_store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);
	CamelMapiMessageInfo *minfo;
	CamelMessageInfo *info;
	CamelFolderChangeInfo *changes;

	mapi_id_t fid;

	int i, count;
	gboolean delete = FALSE, status = FALSE;
	gchar *folder_id;
	GSList *deleted_items, *deleted_head;
	GSList *deleted_items_uid, *deleted_items_uid_head;

	deleted_items = deleted_head = NULL;
	deleted_items_uid = deleted_items_uid_head = NULL;

	folder_id =  g_strdup (camel_mapi_store_folder_id_lookup (mapi_store, folder->full_name)) ;
	exchange_mapi_util_mapi_id_from_string (folder_id, &fid);

	if ((mapi_folder->type & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) {
		CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
		status = exchange_mapi_empty_folder (fid);
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

		if (status) {
			camel_folder_freeze (folder);
			mapi_summary_clear (folder->summary, TRUE);
			camel_folder_thaw (folder);
		} else
			g_warning ("Could not Empty Trash\n");

		return;
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
		CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);

		status = exchange_mapi_remove_items(0, fid, deleted_items);

		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

		if (status) {
			while (deleted_items_uid) {
				const gchar *uid = (gchar *)deleted_items_uid->data;
				CAMEL_MAPI_FOLDER_REC_LOCK (folder, cache_lock);
				camel_folder_change_info_remove_uid (changes, uid);
				camel_folder_summary_remove_uid (folder->summary, uid);
				camel_data_cache_remove(mapi_folder->cache, "cache", uid, NULL);
				CAMEL_MAPI_FOLDER_REC_UNLOCK (folder, cache_lock);
				deleted_items_uid = g_slist_next (deleted_items_uid);
			}
		}
		delete = TRUE;

		g_slist_foreach (deleted_head, (GFunc)g_free, NULL);
		g_slist_free (deleted_head);
		g_slist_free (deleted_items_uid_head);
	}

	if (delete)
		camel_object_trigger_event (CAMEL_OBJECT (folder), "folder_changed", changes);

	g_free (folder_id);
	camel_folder_change_info_free (changes);
}

static void
mapi_transfer_messages_to (CamelFolder *source, GPtrArray *uids, 
		CamelFolder *destination, GPtrArray **transferred_uids, 
		gboolean delete_originals, CamelException *ex)
{
	mapi_id_t src_fid, dest_fid;

	CamelOfflineStore *offline = (CamelOfflineStore *) destination->parent_store;
	CamelMapiStore *mapi_store= CAMEL_MAPI_STORE(source->parent_store);
	CamelFolderChangeInfo *changes = NULL;

	const gchar *folder_id = NULL;
	int i = 0;

	GSList *src_msg_ids = NULL;


	/* check for offline operation */
	if (offline->state == CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL) 
		return;

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, source->full_name) ;
	exchange_mapi_util_mapi_id_from_string (folder_id, &src_fid);

	folder_id = camel_mapi_store_folder_id_lookup (mapi_store, destination->full_name);
	exchange_mapi_util_mapi_id_from_string (folder_id, &dest_fid);

	for (i=0; i < uids->len; i++) {
		mapi_id_t *mid = g_new0 (mapi_id_t, 1); /* FIXME : */
		if (!exchange_mapi_util_mapi_ids_from_uid (g_ptr_array_index (uids, i), &src_fid, mid))
			continue;

		src_msg_ids = g_slist_prepend (src_msg_ids, mid);
	}

	if (delete_originals) {
		if (!exchange_mapi_move_items (src_fid, dest_fid, src_msg_ids)) {
			//TODO : Set exception. 
		} else {
			changes = camel_folder_change_info_new ();

			for (i=0; i < uids->len; i++) {
				camel_folder_summary_remove_uid (source->summary, uids->pdata[i]);
				camel_folder_change_info_remove_uid (changes, uids->pdata[i]);
			}
			camel_object_trigger_event (source, "folder_changed", changes);
			camel_folder_change_info_free (changes);

		}
	} else {
		if (!exchange_mapi_copy_items (src_fid, dest_fid, src_msg_ids)) {
			//TODO : Set exception. 
		}
	}

	g_slist_foreach (src_msg_ids, (GFunc) g_free, NULL);
	g_slist_free (src_msg_ids);

	return;
}

static void
mapi_folder_rename (CamelFolder *folder, const char *new)
{
	((CamelFolderClass *)parent_class)->rename(folder, new);
}

static gint
mapi_cmp_uids (CamelFolder *folder, const char *uid1, const char *uid2)
{
	g_return_val_if_fail (uid1 != NULL, 0);
	g_return_val_if_fail (uid2 != NULL, 0);

	return strcmp (uid1, uid2);
}

static void
mapi_append_message (CamelFolder *folder, CamelMimeMessage *message,
		const CamelMessageInfo *info, gchar **appended_uid,
		CamelException *ex)
{
	CamelMapiStore *mapi_store= CAMEL_MAPI_STORE(folder->parent_store);
	CamelOfflineStore *offline = (CamelOfflineStore *) folder->parent_store;
	CamelAddress *from = NULL;
	CamelStoreInfo *si;

	MapiItem *item = NULL;
	mapi_id_t fid = 0, mid = 0;
	const gchar *folder_id;
	guint32 folder_flags = 0;

	/*Reject outbox / sent & trash*/
	si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, folder->full_name);
	if (si) {
		folder_flags = si->flags;
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
	}

	if (((folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_TRASH) ||
	    ((folder_flags & CAMEL_FOLDER_TYPE_MASK) == CAMEL_FOLDER_TYPE_OUTBOX)) {
		camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, 
				      _("Cannot append message to folder '%s'"),
				      folder->full_name);
		return;
	}

	if (offline->state == CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL) {
		camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, 
				      _("Offline."));
		return;
	}

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store,
							folder->full_name);

	exchange_mapi_util_mapi_id_from_string (folder_id, &fid);

	/* Convert MIME to Item */
	from = (CamelAddress *) camel_mime_message_get_from (message);

	item = camel_mapi_utils_mime_to_item (message, from, ex);

	mid = exchange_mapi_create_item (-1, fid, NULL, NULL, 
					 camel_mapi_utils_create_item_build_props, item,
					 item->recipients, item->attachments,
					 item->generic_streams, 0);

	if (appended_uid)
		*appended_uid = exchange_mapi_util_mapi_ids_to_uid(fid, mid);
}

static void
camel_mapi_folder_class_init (CamelMapiFolderClass *camel_mapi_folder_class)
{
	CamelFolderClass *camel_folder_class = CAMEL_FOLDER_CLASS (camel_mapi_folder_class);

	parent_class = CAMEL_OFFLINE_FOLDER_CLASS (camel_type_get_global_classfuncs (camel_offline_folder_get_type ()));

	((CamelObjectClass *) camel_mapi_folder_class)->getv = mapi_getv;

	camel_folder_class->get_message = mapi_folder_get_message;
 	camel_folder_class->rename = mapi_folder_rename;
	camel_folder_class->search_by_expression = mapi_folder_search_by_expression;
	camel_folder_class->cmp_uids = mapi_cmp_uids;
/* 	camel_folder_class->get_message_info = mapi_get_message_info; */
	camel_folder_class->search_by_uids = mapi_folder_search_by_uids;
	camel_folder_class->search_free = mapi_folder_search_free;
	camel_folder_class->append_message = mapi_append_message;
	camel_folder_class->refresh_info = mapi_refresh_info;
	camel_folder_class->sync = mapi_sync;
	camel_folder_class->expunge = mapi_expunge;
	camel_folder_class->transfer_messages_to = mapi_transfer_messages_to;
}

static void
camel_mapi_folder_init (gpointer object, gpointer klass)
{
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (object);
	CamelFolder *folder = CAMEL_FOLDER (object);


	folder->permanent_flags = CAMEL_MESSAGE_ANSWERED | CAMEL_MESSAGE_DELETED |
		CAMEL_MESSAGE_DRAFT | CAMEL_MESSAGE_FLAGGED | CAMEL_MESSAGE_SEEN;

	folder->folder_flags = CAMEL_FOLDER_HAS_SUMMARY_CAPABILITY | CAMEL_FOLDER_HAS_SEARCH_CAPABILITY;

	mapi_folder->priv = g_malloc0 (sizeof(*mapi_folder->priv));

#ifdef ENABLE_THREADS
	g_static_mutex_init(&mapi_folder->priv->search_lock);
	g_static_rec_mutex_init(&mapi_folder->priv->cache_lock);
#endif

	mapi_folder->need_rescan = TRUE;
}

CamelType
camel_mapi_folder_get_type (void)
{
	static CamelType camel_mapi_folder_type = CAMEL_INVALID_TYPE;


	if (camel_mapi_folder_type == CAMEL_INVALID_TYPE) {
		camel_mapi_folder_type =
			camel_type_register (camel_offline_folder_get_type (),
					"CamelMapiFolder",
					sizeof (CamelMapiFolder),
					sizeof (CamelMapiFolderClass),
					(CamelObjectClassInitFunc) camel_mapi_folder_class_init,
					NULL,
					(CamelObjectInitFunc) camel_mapi_folder_init,
					(CamelObjectFinalizeFunc) camel_mapi_folder_finalize);
	}

	return camel_mapi_folder_type;
}

CamelFolder *
camel_mapi_folder_new (CamelStore *store, const char *folder_name, const char *folder_dir,
		      guint32 flags, CamelException *ex)
{

	CamelFolder	*folder = NULL;
	CamelMapiFolder *mapi_folder;
	CamelMapiStore  *mapi_store = (CamelMapiStore *) store;

	char *summary_file, *state_file;
	char *short_name;
	guint32 i = 0;

	folder = CAMEL_FOLDER (camel_object_new(camel_mapi_folder_get_type ()) );

	mapi_folder = CAMEL_MAPI_FOLDER(folder);
	short_name = strrchr (folder_name, '/');
	if (short_name)
		short_name++;
	else
		short_name = (char *) folder_name;
	camel_folder_construct (folder, store, folder_name, short_name);

	summary_file = g_strdup_printf ("%s/%s/summary",folder_dir, folder_name);

	folder->summary = camel_mapi_summary_new(folder, summary_file);
	g_free(summary_file);

	if (!folder->summary) {
		camel_object_unref (CAMEL_OBJECT (folder));
		camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM,
				_("Could not load summary for %s"),
				folder_name);
		return NULL;
	}

	/* set/load persistent state */
	state_file = g_strdup_printf ("%s/%s/cmeta", folder_dir, folder_name);
	camel_object_set(folder, NULL, CAMEL_OBJECT_STATE_FILE, state_file, NULL);
	g_free(state_file);
	camel_object_state_read(folder);

	state_file = g_strdup_printf ("%s/%s", folder_dir, folder_name);
	mapi_folder->cache = camel_data_cache_new (state_file, 0, ex);
	g_free (state_file);
	if (!mapi_folder->cache) {
		camel_object_unref (folder);
		return NULL;
	}

/* 	journal_file = g_strdup_printf ("%s/journal", g_strdup_printf ("%s-%s",folder_name, "dir")); */
/* 	mapi_folder->journal = camel_mapi_journal_new (mapi_folder, journal_file); */
/* 	g_free (journal_file); */
/* 	if (!mapi_folder->journal) { */
/* 		camel_object_unref (folder); */
/* 		return NULL; */
/* 	} */

	if (camel_url_get_param (((CamelService *) store)->url, "filter"))
		folder->folder_flags |= CAMEL_FOLDER_FILTER_RECENT;

	mapi_folder->search = camel_folder_search_new ();
	if (!mapi_folder->search) {
		camel_object_unref (folder);
		return NULL;
	}

	for (i=0;i<camel_store_summary_count((CamelStoreSummary *)mapi_store->summary);i++) {
		CamelStoreInfo *si = camel_store_summary_index((CamelStoreSummary *)mapi_store->summary, i);
		if (si == NULL) 
			continue;

		if (!strcmp(folder_name, camel_mapi_store_info_full_name (mapi_store->summary, si))) {
			mapi_folder->type = si->flags;
		}

		camel_store_summary_info_free((CamelStoreSummary *)mapi_store->summary, si);
	}
	return folder;
}
