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
 * Copyright (C) 1999-2009 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-folder-summary.h"
#include "camel-mapi-notifications.h"

#include <e-mapi-utils.h>

#define d_notifications(x) (camel_debug ("mapi:notifications") ? (x) : 0)

extern gint camel_application_is_exiting;

struct mapi_push_notification_data {
	guint16 event_mask;
	guint32 connection;
	guint32 event_options;
	gpointer event_data;

	GCancellable *cancellable;
	GThread *thread;
};

static void
process_mapi_new_mail_notif (CamelMapiStore *store, struct NewMailNotification *new_mail_notif)
{
	struct mapi_SRestriction *res = NULL;
	guint32 options = 0;

	fetch_items_data *fetch_data;
	CamelFolder *folder = NULL;
	CamelStore *parent_store;
	gint info_count = -1;
	CamelStoreInfo *si;
	CamelMapiStoreInfo *msi;
	const gchar *folder_name = NULL;

	g_return_if_fail (store != NULL);
	g_return_if_fail (new_mail_notif != NULL);

	/* FIXME : Continue only if we are handling a mail object.*/
	if (0) return;

	/* Get the folder object */

	/*Note : using store info to retrive full_name*/
	info_count = camel_store_summary_count (store->summary) - 1;
	while (info_count >= 0) {
		si = camel_store_summary_index (store->summary, info_count);
		msi = (CamelMapiStoreInfo *) si;
		if (si && msi->folder_mid == new_mail_notif->FID) {
			folder_name = camel_store_info_path (store->summary, si);
			info_count = 0;
		}
		if (si)
			camel_store_summary_info_free (store->summary, si);
		info_count--;
	}

	folder = camel_store_get_folder_sync ((CamelStore *) store, folder_name, 0, NULL, NULL);

	/* Abort on failure*/
	if (!folder)
		return;

	parent_store = camel_folder_get_parent_store (folder);

	/*Use restriction to fetch the message summary based on MID*/
	res = g_new0 (struct mapi_SRestriction, 1);

	res->rt = RES_PROPERTY;
	res->res.resProperty.relop = RES_PROPERTY;
	res->res.resProperty.ulPropTag = PR_MID;
	res->res.resProperty.lpProp.ulPropTag = PR_MID;
	res->res.resProperty.lpProp.value.dbl = new_mail_notif->MID;

	fetch_data = g_new0 (fetch_items_data, 1);
	fetch_data->changes = camel_folder_change_info_new ();
	fetch_data->folder = folder;

	camel_service_lock (CAMEL_SERVICE (store), CAMEL_SERVICE_REC_CONNECT_LOCK);
	camel_mapi_folder_fetch_summary ((CamelStore *)store, folder, new_mail_notif->FID, res, NULL, fetch_data, options, NULL, NULL);
	camel_service_unlock (CAMEL_SERVICE (store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	camel_folder_summary_touch (folder->summary);
	/* mapi_sync_summary */
	camel_folder_summary_save_to_db (folder->summary, NULL);
	camel_store_summary_touch (((CamelMapiStore *)parent_store)->summary);
	camel_store_summary_save (((CamelMapiStore *)parent_store)->summary);

	camel_folder_changed (folder, fetch_data->changes);

	camel_folder_change_info_free (fetch_data->changes);
	g_free (res);
}

static gint
mapi_notifications_filter (guint16 type, gpointer event, gpointer store)
{
	switch (type) {
	/* -- Folder Events -- */
	case fnevObjectCreated:
		d_notifications(printf ("Event : Folder Created\n"));
		d_notifications(mapidump_foldercreated (event, "\t"));
		break;
	case fnevObjectDeleted:
		d_notifications(printf ("Event : Folder Deleted\n"));
		d_notifications(mapidump_folderdeleted (event, "\t"));
		break;
	case fnevObjectMoved:
		d_notifications(printf ("Event : Folder Moved\n"));
		d_notifications(mapidump_foldermoved (event, "\t"));
		break;
	case fnevObjectCopied:
		d_notifications(printf ("Event : Folder Copied\n"));
		d_notifications(mapidump_foldercopied (event, "\t"));
		break;
	/* -- Message Events -- */
	case fnevNewMail:
	case fnevNewMail|fnevMbit:
		d_notifications(printf ("Event : New mail\n"));
		d_notifications(mapidump_newmail (event, "\t"));
		process_mapi_new_mail_notif (store, event);
		return -1;
		break;
	case fnevMbit|fnevObjectCreated:
		d_notifications(printf ("Event : Message created\n"));
		d_notifications(mapidump_messagecreated (event, "\t"));
		break;
	case fnevMbit|fnevObjectDeleted:
		d_notifications(printf ("Event : Message deleted\n"));
		d_notifications(mapidump_messagedeleted (event, "\t"));
	case fnevMbit|fnevObjectModified:
		d_notifications(printf ("Event : Message modified\n"));
		d_notifications(mapidump_messagemodified (event, "\t"));
	case fnevMbit|fnevObjectMoved:
		d_notifications(printf ("Event : Message moved\n"));
		d_notifications(mapidump_messagemoved (event, "\t"));
	case fnevMbit|fnevObjectCopied:
		d_notifications(printf ("Event : Message copied\n"));
		d_notifications(mapidump_messagecopied (event, "\t"));
	default:
		/* Unsupported  */
		break;
	}
	return 0;
}

/*Of type mapi_notify_continue_callback_t*/
static gint
mapi_notifications_continue_check (gpointer data)
{
	struct mapi_push_notification_data *thread_data = data;

	g_return_val_if_fail (data != NULL, 1);

	if (g_cancellable_is_cancelled (thread_data->cancellable) || (camel_application_is_exiting == TRUE))
		return 1;

	/* HACK ALERT : This is a BAD idea. But;-), A bug in MonitorNotification */
	/* makes select() return immediately. We are introducing a artificial delay here */
	/* to avoid high CPU usage. Remove this when libmapi 0.9.1 is out */
	g_usleep (G_USEC_PER_SEC * 2);

	return 0;
}

static gpointer
mapi_push_notification_listener_thread (gpointer data)
{
	struct mapi_push_notification_data *thread_data = data;
	CamelMapiStore *mapi_store = (CamelMapiStore *) thread_data->event_data;
	struct mapi_notify_continue_callback_data *cb_data = g_new0 (struct mapi_notify_continue_callback_data, 1);
	EMapiConnection *conn;

	g_return_val_if_fail (data != NULL, NULL);

	/* Timeout for select in MonitorNotification*/
	cb_data->tv.tv_sec = 2;
	cb_data->tv.tv_usec = 0;

	/* API would consult us if we want to continue with processing events*/
	cb_data->callback = mapi_notifications_continue_check;
	cb_data->data = thread_data;

	camel_service_lock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	conn = camel_mapi_store_get_connection (mapi_store);
	if (!conn) {
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		g_return_val_if_reached (NULL);
	}

	g_object_ref (conn);

	if (e_mapi_connection_events_init (conn, NULL)) {
		e_mapi_connection_events_subscribe (conn, thread_data->event_options, thread_data->event_mask,
						&thread_data->connection, mapi_notifications_filter,
						thread_data->event_data, NULL);

		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);
		e_mapi_connection_events_monitor (conn, cb_data); /*Blocking call. Don't hold locks here*/
		e_mapi_connection_events_unsubscribe (conn, thread_data->connection, NULL);
	} else
		camel_service_unlock (CAMEL_SERVICE (mapi_store), CAMEL_SERVICE_REC_CONNECT_LOCK);

	g_free (cb_data);
	g_object_unref (conn);

	return NULL;
}

gpointer
camel_mapi_notification_listener_start (CamelMapiStore *store, guint16 mask, guint32 options)
{
	struct mapi_push_notification_data *thread_data;
	GError *error = NULL;

	thread_data = g_new0 (struct mapi_push_notification_data, 1);
	thread_data->event_options = options;
	thread_data->event_mask = mask;
	thread_data->event_data = store;
	thread_data->cancellable = g_cancellable_new ();
	thread_data->thread = g_thread_create (mapi_push_notification_listener_thread, thread_data, TRUE, &error);
	if (error) {
		g_warning ("%s: Failed to start thread, %s", G_STRFUNC, error->message ? error->message : "Unknown error");
		g_object_unref (thread_data->cancellable);
		g_free (thread_data);
		return NULL;
	}

	return thread_data;
}

/* start_value is a pointer returned from the start function */
void
camel_mapi_notification_listener_stop (CamelMapiStore *mstore, gpointer start_value)
{
	struct mapi_push_notification_data *thread_data;

	g_return_if_fail (mstore != NULL);
	g_return_if_fail (start_value != NULL);

	thread_data = start_value;

	g_cancellable_cancel (thread_data->cancellable);
	g_thread_join (thread_data->thread);

	g_object_unref (thread_data->cancellable);
	g_free (thread_data);

	g_object_ref (mstore);
	camel_service_lock (CAMEL_SERVICE (mstore), CAMEL_SERVICE_REC_CONNECT_LOCK);
	camel_mapi_store_unset_notification_data (mstore);
	camel_service_unlock (CAMEL_SERVICE (mstore), CAMEL_SERVICE_REC_CONNECT_LOCK);
	g_object_unref (mstore);
}
