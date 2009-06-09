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
typedef struct {
	GSList *items_list;
	GTimeVal last_modification_time;
	CamelFolder *folder;
	CamelFolderChangeInfo *changes;
}fetch_items_data;

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


/*Using GFunc*/
static void 
mapi_item_free (MapiItem *item, gpointer data)
{
	g_free (item->header.subject);
	g_free (item->header.from);
	/* g_free (item->header.from_email); */
	/* g_free (item->header.from_type); */
	g_free (item->header.to);
	g_free (item->header.cc);
	g_free (item->header.bcc);

	exchange_mapi_util_free_attachment_list (&item->attachments);
	exchange_mapi_util_free_stream_list (&item->generic_streams);
}

static gboolean
fetch_items_cb (FetchItemsCallbackData *item_data, gpointer data)
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

		switch (item_data->properties->lpProps[j].ulPropTag) {
		/* FIXME : Instead of duping. Use talloc_steal to reuse the memory */
		case PR_NORMALIZED_SUBJECT:
		case PR_NORMALIZED_SUBJECT_UNICODE :
			item->header.subject = g_strdup (prop_data);
			break;
		case PR_DISPLAY_TO :
		case PR_DISPLAY_TO_UNICODE :
			item->header.to = g_strdup (prop_data);
			break;
		case PR_DISPLAY_CC:
		case PR_DISPLAY_CC_UNICODE:
			item->header.cc = g_strdup (prop_data);
			break;
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_BCC_UNICODE:
			item->header.bcc = g_strdup (prop_data);
			break;
		case PR_SENT_REPRESENTING_NAME:
		case PR_SENT_REPRESENTING_NAME_UNICODE:
			item->header.from = g_strdup (prop_data);
			break;
		case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
		case PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE:
			item->header.from_email = g_strdup (prop_data);
			break;
		case PR_SENT_REPRESENTING_ADDRTYPE:
		case PR_SENT_REPRESENTING_ADDRTYPE_UNICODE:
			item->header.from_type = g_strdup (prop_data);
			break;
		case PR_MESSAGE_SIZE:
			item->header.size = *(glong *)prop_data;
			break;
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
	if ( (item_data->index % SUMMARY_FETCH_BATCH_COUNT == 0) || item_data->index == item_data->total-1) {
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

	camel_operation_start (NULL, _("Fetching summary information for new messages in %s"), folder->name);

	for ( ; item_list != NULL ; item_list = g_slist_next (item_list) ) {
		MapiItem *temp_item ;
		MapiItem *item;
		gchar *msg_uid, *to = NULL, *from = NULL;
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
 			guint32 i =0;

			mi->info.uid = exchange_mapi_util_mapi_ids_to_uid(item->fid, item->mid);
			mi->info.subject = camel_pstring_strdup(item->header.subject);
			mi->info.date_sent = mi->info.date_received = item->header.recieved_time;
			mi->info.size = (guint32) item->header.size;

 			for (l = item->recipients; l; l=l->next) {
 				char *formatted_id;
				const char *name, *display_name;
 				uint32_t *type = NULL; 
 				struct SRow aRow;
 				ExchangeMAPIRecipient *recip = (ExchangeMAPIRecipient *)(l->data);
 				
 				/*Can't continue when there is no email-id*/
 				if (!recip->email_id)
 					continue;
 				
 				/* Build a SRow structure */
 				aRow.ulAdrEntryPad = 0;
 				aRow.cValues = recip->out.all_cValues;
 				aRow.lpProps = recip->out.all_lpProps;
 				
 				type = (uint32_t *) find_SPropValue_data(&aRow, PR_RECIPIENT_TYPE);
 
 				if (*type == MAPI_TO) {
 					/*Name is probably available in one of these props.*/
 					name = (const char *) find_SPropValue_data(&aRow, PR_DISPLAY_NAME);
 					name = name ? name : (const char *) find_SPropValue_data(&aRow, PR_RECIPIENT_DISPLAY_NAME);
 					name = name ? name : (const char *) find_SPropValue_data(&aRow, 
 												 PR_RECIPIENT_DISPLAY_NAME_UNICODE);
 					name = name ? name : (const char *) find_SPropValue_data(&aRow, 
 												 PR_7BIT_DISPLAY_NAME_UNICODE);
 					display_name = name ? name : g_strdup (recip->email_id);
 					formatted_id = camel_internet_address_format_address(display_name, recip->email_id);
 
 					/* hmm */
 					if (i) 
 						to = g_strconcat (to, ", ", NULL);
 
					to = g_strconcat (to, formatted_id, NULL);

					g_free (formatted_id);
 					i++;
 				}
 
 				/*TODO : from ? */
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
				from = camel_internet_address_format_address (item->header.from, 
 									      item->header.from_email);
 				mi->info.from = camel_pstring_strdup (from);
			} else
				mi->info.from = NULL;
 			mi->info.to = camel_pstring_strdup (to);
		}

		if (exists) {
			camel_folder_change_info_change_uid (changes, mi->info.uid);
			camel_message_info_free (pmi);
		} else {
			camel_folder_summary_add (folder->summary,(CamelMessageInfo *)mi);
			camel_folder_change_info_add_uid (changes, mi->info.uid);
			camel_folder_change_info_recent_uid (changes, mi->info.uid);
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

static void
mapi_sync (CamelFolder *folder, gboolean expunge, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (folder->parent_store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);
	CamelMessageInfo *info = NULL;
	CamelMapiMessageInfo *mapi_info = NULL;

	GSList *read_items = NULL, *unread_items = NULL;
	flags_diff_t diff, unset_flags;
	const char *folder_id;
	mapi_id_t fid, deleted_items_fid;
	int count, i;
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

			uid = camel_message_info_uid (info);
			flags= camel_message_info_flags (info);

			/* Why are we getting so much noise here :-/ */
			if (!exchange_mapi_util_mapi_ids_from_uid (uid, &temp_fid, mid))
				continue;

			mapi_utils_do_flags_diff (&diff, mapi_info->server_flags, mapi_info->info.flags);
			mapi_utils_do_flags_diff (&unset_flags, flags, mapi_info->server_flags);

			diff.changed &= folder->permanent_flags;
			if (!diff.changed) {
				camel_message_info_free(info);
				continue;
			} else {
				if (diff.bits & CAMEL_MESSAGE_DELETED) {
					if (diff.bits & CAMEL_MESSAGE_SEEN) 
						read_items = g_slist_prepend (read_items, mid);
					if (deleted_items)
						deleted_items = g_slist_prepend (deleted_items, mid);
					else {
						g_slist_free (deleted_head);
						deleted_head = NULL;
						deleted_head = deleted_items = g_slist_prepend (deleted_items, mid);
					}

					CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);

					}
				}
				
				if (diff.bits & CAMEL_MESSAGE_SEEN) {
					read_items = g_slist_prepend (read_items, mid);
				} else if (unset_flags.bits & CAMEL_MESSAGE_SEEN) {
					unread_items = g_slist_prepend (unread_items, mid);
				}
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

	if (deleted_items) {
		CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
		if (mapi_folder->type & CAMEL_FOLDER_TYPE_TRASH) {
			exchange_mapi_remove_items (0, fid, deleted_items);
		} else {
			exchange_mapi_util_mapi_id_from_string (camel_mapi_store_system_folder_fid (mapi_store, olFolderDeletedItems), &deleted_items_fid);
			exchange_mapi_move_items(fid, deleted_items_fid, deleted_items);
		}

		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
	}
	/*Remove them from cache*/
	while (deleted_items) {
		char* deleted_msg_uid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X%016" G_GINT64_MODIFIER "X", fid, *(mapi_id_t *)deleted_items->data);

		CAMEL_MAPI_FOLDER_REC_LOCK (folder, cache_lock);
		camel_folder_summary_remove_uid (folder->summary, deleted_msg_uid);
		camel_data_cache_remove(mapi_folder->cache, "cache", deleted_msg_uid, NULL);
		CAMEL_MAPI_FOLDER_REC_UNLOCK (folder, cache_lock);

		deleted_items = g_slist_next (deleted_items);
	}


	if (unread_items) {
		CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
		/* TODO */
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		g_slist_free (unread_items);
	}

	if (expunge) {
		CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
		/* TODO */
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
	}

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);
	mapi_sync_summary (folder, ex);
	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
}


void
mapi_refresh_folder(CamelFolder *folder, CamelException *ex)
{

	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (folder->parent_store);
	CamelMapiFolder *mapi_folder = CAMEL_MAPI_FOLDER (folder);
	CamelMapiSummary *mapi_summary = CAMEL_MAPI_SUMMARY (folder->summary);
	gboolean is_proxy = folder->parent_store->flags & CAMEL_STORE_PROXY;
	gboolean is_locked = FALSE;
	gboolean status;

	struct mapi_SRestriction *res = NULL;
	struct SSortOrderSet *sort = NULL;
	fetch_items_data *fetch_data = g_new0 (fetch_items_data, 1);

	const gchar *folder_id = NULL;

	const guint32 summary_prop_list[] = {
		PR_NORMALIZED_SUBJECT,
		PR_MESSAGE_SIZE,
		PR_MESSAGE_DELIVERY_TIME,
		PR_MESSAGE_FLAGS,
		PR_SENT_REPRESENTING_NAME,
		PR_SENT_REPRESENTING_EMAIL_ADDRESS,
		PR_SENT_REPRESENTING_ADDRTYPE,
		PR_LAST_MODIFICATION_TIME,
		PR_DISPLAY_TO,
		PR_DISPLAY_CC,
		PR_DISPLAY_BCC
	};

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
			goto end2;
		}

		if (((CamelMapiFolder *)folder)->type & CAMEL_MAPI_FOLDER_PUBLIC)
			options |= MAPI_OPTIONS_USE_PFSTORE;

		camel_operation_start (NULL, _("Fetching summary information for new messages in %s"), folder->name);

		status = exchange_mapi_connection_fetch_items  (temp_folder_id, res, sort,
								summary_prop_list, G_N_ELEMENTS (summary_prop_list), 
								NULL, NULL, 
								fetch_items_cb, fetch_data, 
								options);
		camel_operation_end (NULL);

		if (!status) {
			camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_INVALID, _("Fetching items failed"));
			goto end2;
		}

		/*Preserve last_modification_time from this fetch for later use with restrictions.*/
		mapi_summary->sync_time_stamp = g_time_val_to_iso8601 (&fetch_data->last_modification_time);

		camel_folder_summary_touch (folder->summary);
		mapi_sync_summary (folder, ex);

		camel_object_trigger_event (folder, "folder_changed", fetch_data->changes);

		camel_folder_change_info_free (fetch_data->changes);
	}


	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
	is_locked = FALSE;

end2:
	//TODO:
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

	PR_MESSAGE_CLASS, 
	PR_MESSAGE_CLASS_UNICODE, 
	PR_MESSAGE_SIZE, 
	PR_MESSAGE_FLAGS, 
	PR_MESSAGE_DELIVERY_TIME, 
	PR_MSG_EDITOR_FORMAT, 

	PR_SUBJECT, 
	PR_SUBJECT_UNICODE, 
	PR_NORMALIZED_SUBJECT, 
	PR_NORMALIZED_SUBJECT_UNICODE, 
	PR_CONVERSATION_TOPIC, 
	PR_CONVERSATION_TOPIC_UNICODE, 

	PR_BODY, 
	PR_BODY_UNICODE, 
	PR_HTML,
	/*Fixme : If this property is fetched, it garbles everything else. */
 	/*PR_BODY_HTML, */
 	/*PR_BODY_HTML_UNICODE, */

	PR_DISPLAY_TO, 
	PR_DISPLAY_TO_UNICODE, 
	PR_DISPLAY_CC, 
	PR_DISPLAY_CC_UNICODE, 
	PR_DISPLAY_BCC, 
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

	PR_SENT_REPRESENTING_NAME, 
	PR_SENT_REPRESENTING_NAME_UNICODE, 
	PR_SENT_REPRESENTING_ADDRTYPE, 
	PR_SENT_REPRESENTING_ADDRTYPE_UNICODE, 
	PR_SENT_REPRESENTING_EMAIL_ADDRESS, 
	PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE, 

	PR_SENDER_NAME, 
	PR_SENDER_NAME_UNICODE, 
	PR_SENDER_ADDRTYPE, 
	PR_SENDER_ADDRTYPE_UNICODE, 
	PR_SENDER_EMAIL_ADDRESS, 
	PR_SENDER_EMAIL_ADDRESS_UNICODE, 

	PR_RCVD_REPRESENTING_NAME, 
	PR_RCVD_REPRESENTING_NAME_UNICODE, 
	PR_RCVD_REPRESENTING_ADDRTYPE, 
	PR_RCVD_REPRESENTING_ADDRTYPE_UNICODE, 
	PR_RCVD_REPRESENTING_EMAIL_ADDRESS, 
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

		switch (item_data->properties->lpProps[j].ulPropTag) {
		/*FIXME : Instead of duping. Use talloc_steal to reuse the memory*/
		case PR_NORMALIZED_SUBJECT:
		case PR_NORMALIZED_SUBJECT_UNICODE :
			item->header.subject = g_strdup (prop_data);
			break;
		case PR_DISPLAY_TO :
		case PR_DISPLAY_TO_UNICODE :
			item->header.to = g_strdup (prop_data);
			break;
		case PR_DISPLAY_CC:
		case PR_DISPLAY_CC_UNICODE:
			item->header.cc = g_strdup (prop_data);
			break;
		case PR_DISPLAY_BCC:
		case PR_DISPLAY_BCC_UNICODE:
			item->header.bcc = g_strdup (prop_data);
			break;
		case PR_SENT_REPRESENTING_NAME:
		case PR_SENT_REPRESENTING_NAME_UNICODE:
			item->header.from = g_strdup (prop_data);
			break;
		case PR_SENT_REPRESENTING_ADDRTYPE:
		case PR_SENT_REPRESENTING_ADDRTYPE_UNICODE:
			item->header.from_type = g_strdup (prop_data);
			break;
		case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
		case PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE:
			item->header.from_email = g_strdup (prop_data);
			break;
		case PR_MESSAGE_SIZE:
			item->header.size = *(glong *)prop_data;
			break;
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

	if (g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_PREFIX)) {
		guint8 *appointment_body_str = (guint8 *) exchange_mapi_cal_util_camel_helper (item_data->properties, 
											     item_data->streams, 
											     item_data->recipients, item_data->attachments);

		body = g_new0(ExchangeMAPIStream, 1);
		body->proptag = PR_BODY;
		body->value = g_byte_array_new ();
		body->value = g_byte_array_append (body->value, appointment_body_str, g_utf8_strlen ((const gchar *)appointment_body_str, -1));

		item->msg.body_parts = g_slist_append (item->msg.body_parts, body);

		item->is_cal = TRUE;
	} else { 
		if (!((body = exchange_mapi_util_find_stream (item_data->streams, PR_HTML)) || 
		      (body = exchange_mapi_util_find_stream (item_data->streams, PR_BODY))))
			body = exchange_mapi_util_find_stream (item_data->streams, PR_BODY_UNICODE);

		item->msg.body_parts = g_slist_append (item->msg.body_parts, body);

		item->is_cal = FALSE;
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
mapi_msg_set_recipient_list (CamelMimeMessage *msg, MapiItem *item)
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
		struct SRow aRow;
		ExchangeMAPIRecipient *recip = (ExchangeMAPIRecipient *)(l->data);
		
		/*Can't continue when there is no email-id*/
		if (!recip->email_id)
			continue;
		
		/* Build a SRow structure */
		aRow.ulAdrEntryPad = 0;
		aRow.cValues = recip->out.all_cValues;
		aRow.lpProps = recip->out.all_lpProps;
		
		/*Name is probably available in one of these props.*/
		name = (const char *) find_SPropValue_data(&aRow, PR_DISPLAY_NAME);
		name = name ? name : (const char *) find_SPropValue_data(&aRow, PR_RECIPIENT_DISPLAY_NAME);
		name = name ? name : (const char *) find_SPropValue_data(&aRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
		name = name ? name : (const char *) find_SPropValue_data(&aRow, PR_7BIT_DISPLAY_NAME_UNICODE);

		type = (uint32_t *) find_SPropValue_data(&aRow, PR_RECIPIENT_TYPE);
		
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
		/* g_free (display_name); */
	}
	
	/*Add to message*/
	camel_mime_message_set_recipients(msg, "To", to_addr);
	camel_mime_message_set_recipients(msg, "Cc", cc_addr);
	camel_mime_message_set_recipients(msg, "Bcc", bcc_addr);

	/*TODO : Unref *_addr ? */
}


static void
mapi_populate_details_from_item (CamelFolder *folder, CamelMimeMessage *msg, MapiItem *item)
{
	char *temp_str = NULL;
	const char *from_email;
	time_t recieved_time;
	CamelInternetAddress *addr = NULL;
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE(folder->parent_store);

	int offset = 0;
	time_t actual_time;

	temp_str = item->header.subject;
	if(temp_str) 
		camel_mime_message_set_subject (msg, temp_str);

	recieved_time = item->header.recieved_time;

	actual_time = camel_header_decode_date (ctime(&recieved_time), &offset);
	camel_mime_message_set_date (msg, actual_time, offset);

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
}


static void
mapi_populate_msg_body_from_item (CamelMultipart *multipart, MapiItem *item, ExchangeMAPIStream *body)
{
	CamelMimePart *part;
	const char* type = NULL;

	part = camel_mime_part_new ();
	camel_mime_part_set_encoding(part, CAMEL_TRANSFER_ENCODING_8BIT);
	
	if (body) { 
		if (item->is_cal)
			camel_mime_part_set_content(part, (const char *) body->value->data, body->value->len, "text/calendar");
		else {
			type = (body->proptag == PR_BODY || body->proptag == PR_BODY_UNICODE) ? 
				"text/plain" : "text/html";

			/*NOTE : Last byte null mess up CRLF*. Probably needs a fix in e*fetch_items. */
			camel_mime_part_set_content (part, (const char *) body->value->data, body->value->len - 1, type );
		}
	} else
		camel_mime_part_set_content(part, " ", strlen(" "), "text/html");

	camel_multipart_add_part (multipart, part);
	camel_object_unref (part);
}


static CamelMimeMessage *
mapi_folder_item_to_msg( CamelFolder *folder,
		MapiItem *item,
		CamelException *ex )
{
	CamelMimeMessage *msg = NULL;
	CamelMultipart *multipart = NULL;

	GSList *attach_list = NULL;
	/* int errno; */
	/* char *body = NULL; */
	ExchangeMAPIStream *body = NULL;
	GSList *body_part_list = NULL;
	const char *uid = NULL;

	attach_list = item->attachments;

	msg = camel_mime_message_new ();

	multipart = camel_multipart_new ();

	/*FIXME : Using set of default. Fix it during mimewriter*/
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (multipart),
					  "multipart/related");
	camel_content_type_set_param(CAMEL_DATA_WRAPPER (multipart)->mime_type, 
				     "type", "multipart/alternative");

	camel_multipart_set_boundary (multipart, NULL);

	camel_mime_message_set_message_id (msg, uid);
	body_part_list = item->msg.body_parts;
	while (body_part_list){
	       body = body_part_list->data;
	       mapi_populate_msg_body_from_item (multipart, item, body);	       
	       body_part_list = g_slist_next (body_part_list);
	}


	/*Set recipient details*/
	mapi_msg_set_recipient_list (msg, item);
	mapi_populate_details_from_item (folder, msg, item);

	if (attach_list) {
		GSList *al = attach_list;
		for (al = attach_list; al != NULL; al = al->next) {
			ExchangeMAPIAttachment *attach = (ExchangeMAPIAttachment *)al->data;
			ExchangeMAPIStream *stream = NULL;
			const char *filename, *mime_type, *content_id = NULL; 
			CamelMimePart *part;

			stream = exchange_mapi_util_find_stream (attach->streams, PR_ATTACH_DATA_BIN);

			if (!stream || stream->value->len <= 0) {
				continue;
			}

			part = camel_mime_part_new ();

			filename = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps, 
												 PR_ATTACH_LONG_FILENAME);

			if (!(filename && *filename))
				filename = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps, 
													 PR_ATTACH_FILENAME);
			camel_mime_part_set_filename(part, g_strdup(filename));
			camel_content_type_set_param (((CamelDataWrapper *) part)->mime_type, "name", filename);

			/*Content-Type*/
			mime_type = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps, 
												  PR_ATTACH_MIME_TAG);

			camel_mime_part_set_content (part, (const char *) stream->value->data, stream->value->len, mime_type);

			/*Content-ID*/
			content_id = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps, 
												   PR_ATTACH_CONTENT_ID);

			camel_mime_part_set_content_id (part, content_id);

			/*FIXME : Mime Reader / Writer work*/
			//camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);

			camel_multipart_add_part (multipart, part);
			camel_object_unref (part);
			
		}
		exchange_mapi_util_free_attachment_list (&attach_list);
	}

	camel_medium_set_content_object(CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER(multipart));
	camel_object_unref (multipart);

	if (body)
		g_free (body);

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

	exchange_mapi_connection_fetch_item (id_folder, id_message, 
					camel_GetPropsList, G_N_ELEMENTS (camel_GetPropsList), 
					camel_build_name_id, NULL, 
					fetch_item_cb, &item, 
					options);

	if (item == NULL) {
		camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_INVALID, _("Could not get message"));
		camel_message_info_free (&mi->info);
		return NULL;
	}

	msg = mapi_folder_item_to_msg (folder, item, ex);

	g_free (item);

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
	msg_info = camel_message_info_new(folder->summary);
	mi = (CamelMessageInfoBase *)msg_info ;
	//TODO :
/* 	oc_message_headers_init(&headers); */
/* 	oc_thread_connect_lock(); */
/* 	status = oc_message_headers_get_by_id(&headers, uid); */
/* 	oc_thread_connect_unlock(); */

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

	if (mapi_folder->type & CAMEL_FOLDER_TYPE_TRASH) {
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

	folder_id =  camel_mapi_store_folder_id_lookup (mapi_store, destination->full_name) ;
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
/* 	camel_folder_class->search_by_uids = mapi_folder_search_by_uids;  */
	camel_folder_class->search_free = mapi_folder_search_free;
/* 	camel_folder_class->append_message = mapi_append_message; */
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
camel_mapi_folder_new(CamelStore *store, const char *folder_name, const char *folder_dir, guint32 flags, CamelException *ex)
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
	state_file = g_strdup_printf ("%s/cmeta", g_strdup_printf ("%s/%s",folder_dir, folder_name));
	camel_object_set(folder, NULL, CAMEL_OBJECT_STATE_FILE, state_file, NULL);
	g_free(state_file);
	camel_object_state_read(folder);

	mapi_folder->cache = camel_data_cache_new (g_strdup_printf ("%s/%s",folder_dir, folder_name),0 ,ex);
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

	if (!strcmp (folder_name, "Mailbox")) {
		if (camel_url_get_param (((CamelService *) store)->url, "filter"))
			folder->folder_flags |= CAMEL_FOLDER_FILTER_RECENT;
	}

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


