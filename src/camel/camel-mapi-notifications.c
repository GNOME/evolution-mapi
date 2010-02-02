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

#include <glib/gstdio.h>

#include <camel/camel-private.h>
#include <camel/camel-session.h>
#include <camel/camel-service.h>
#include <camel/camel-store-summary.h>
#include <camel/camel-i18n.h>
#include <camel/camel-net-utils.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-summary.h"
#include "camel-mapi-notifications.h"

#include <exchange-mapi-utils.h>

#define d_notifications(x) x

static void mapi_push_notification_listener (CamelSession *session, CamelSessionThreadMsg *msg);
static void mapi_push_notification_listener_close (CamelSession *session, CamelSessionThreadMsg *msg);

extern gint camel_application_is_exiting;

/* TODO Doc : What is this message for?*/
struct mapi_push_notification_msg {
	CamelSessionThreadMsg msg;

	guint16 event_mask;
	guint32 connection; 
	guint32 event_options;
	gpointer event_data;
};

/*Used for spawning threads for event actions
  like new_mail, folder_created*/
struct mapi_push_event_action_msg {
	CamelSessionThreadMsg msg;

	uint64_t fid;
	uint64_t mid;
	gpointer data;
};

static void
mapi_new_mail_free (CamelSession *session, CamelSessionThreadMsg *msg)
{
	struct mapi_push_event_action_msg *m = (struct mapi_push_event_action_msg *) msg;

	camel_object_unref (m->data);
}

static void
mapi_new_mail_fetch (CamelSession *session, CamelSessionThreadMsg *msg)
{
	struct mapi_push_event_action_msg *m = (struct mapi_push_event_action_msg *) msg;

	struct mapi_SRestriction *res = NULL;
	guint32 options = 0;

	CamelMapiStore *store = (CamelMapiStore *)m->data;
	fetch_items_data *fetch_data = g_new0 (fetch_items_data, 1);
	CamelFolder *folder = NULL;
	gint info_count = -1;
	CamelStoreInfo *info;
	CamelMapiStoreInfo *mapi_info;
	const gchar *folder_id = exchange_mapi_util_mapi_id_to_string (m->fid);
	const gchar *folder_name = NULL;
	
	/* FIXME : Continue only if we are handling a mail object.*/
	if (0) return;
	
	/*Use restriction to fetch the message summary based on MID*/
	res = g_new0 (struct mapi_SRestriction, 1);

	res->rt = RES_PROPERTY;
	res->res.resProperty.relop = RES_PROPERTY;
	res->res.resProperty.ulPropTag = PR_MID;
	res->res.resProperty.lpProp.ulPropTag = PR_MID;
	res->res.resProperty.lpProp.value.dbl = m->mid;

	/* Get the folder object */

	/*Note : using store info to retrive full_name*/
	info_count = camel_store_summary_count ((CamelStoreSummary *)store->summary) - 1;
	while (info_count >= 0) {
		info = camel_store_summary_index ((CamelStoreSummary *)store->summary, info_count);
		mapi_info = (CamelMapiStoreInfo *)info;
		if (info && !g_strcmp0 (mapi_info->folder_id, folder_id)){
			folder_name = mapi_info->full_name;
		}
		if (info)
			camel_store_summary_info_free ((CamelStoreSummary *)store->summary, info);
		info_count--;
	}

	folder = camel_store_get_folder ((CamelStore *)store, folder_name, 0, NULL);

	/* Abort on failure*/
	if (!folder)
		return;

	fetch_data->changes = camel_folder_change_info_new ();
	fetch_data->folder = folder;

	CAMEL_SERVICE_REC_LOCK (store, connect_lock);
	camel_mapi_folder_fetch_summary ((CamelStore *)store, m->fid, res, NULL, fetch_data, options);
	CAMEL_SERVICE_REC_UNLOCK (store, connect_lock);
	
	camel_folder_summary_touch (folder->summary);
	/* mapi_sync_summary */
	camel_folder_summary_save_to_db (folder->summary, NULL);
	camel_store_summary_touch ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary);
	camel_store_summary_save ((CamelStoreSummary *)((CamelMapiStore *)folder->parent_store)->summary);

	camel_object_trigger_event (folder, "folder_changed", fetch_data->changes);

	camel_folder_change_info_free (fetch_data->changes);
	g_free (res);
}

static CamelSessionThreadOps mapi_new_mail_ops = {
	mapi_new_mail_fetch,
	mapi_new_mail_free,
};


static gint
mapi_notifications_filter (guint16 type, void *event, void *data)
{
	CamelMapiStore *store = (CamelMapiStore *)data;
	CamelSession *session = ((CamelService *)store)->session;
	struct mapi_push_event_action_msg *new_mail_ops_msg ;
	const struct NewMailNotification *new_mail_event;

	switch(type) {
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

		new_mail_ops_msg = camel_session_thread_msg_new (session, &mapi_new_mail_ops,
								 sizeof (*new_mail_ops_msg));

		new_mail_event = event;
		/* copy properties from the event, because it will be processes
	           in a separate thread, some time later */
		new_mail_ops_msg->fid = new_mail_event->FID;
		new_mail_ops_msg->mid = new_mail_event->MID;

		camel_object_ref (data);
		new_mail_ops_msg->data = data;
		camel_session_thread_queue (session, &new_mail_ops_msg->msg, 0);
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


static CamelSessionThreadOps mapi_push_notification_ops = {
	mapi_push_notification_listener,
	mapi_push_notification_listener_close,
};

/*Of type mapi_notify_continue_callback_t*/
static gint
mapi_notifications_continue_check (gpointer data)
{
	if (camel_operation_cancel_check(NULL) || (camel_application_is_exiting == TRUE))
		return 1;

	/* HACK ALERT : This is a BAD idea. But ;-), A bug in MonitorNotification */
	/* makes select() return immediately. We are introducing a artificial delay here */
	/* to avoid high CPU usage. Remove this when libmapi 0.9.1 is out */
	g_usleep (G_USEC_PER_SEC * 2);

	return 0;
}

static void
mapi_push_notification_listener (CamelSession *session, CamelSessionThreadMsg *msg)
{
	struct mapi_push_notification_msg *m = (struct mapi_push_notification_msg *)msg;
	CamelMapiStore *mapi_store = (CamelMapiStore *) m->event_data;
	struct mapi_notify_continue_callback_data *cb_data = g_new0 (struct mapi_notify_continue_callback_data, 1);

	/* Timeout for select in MonitorNotification*/
	cb_data->tv.tv_sec = 2;
	cb_data->tv.tv_usec = 0;

	/* API would consult us if we want to continue with processing events*/
	cb_data->callback = mapi_notifications_continue_check;
	cb_data->data = NULL;

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);

	if (exchange_mapi_events_init ()) {
		exchange_mapi_events_subscribe (0, m->event_options, m->event_mask,
						&m->connection,	mapi_notifications_filter,
						m->event_data);

		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		exchange_mapi_events_monitor (cb_data); /*Blocking call. Don't hold locks here*/
	} else 
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

	g_free (cb_data);
}

static void
mapi_push_notification_listener_close (CamelSession *session, CamelSessionThreadMsg *msg)
{
	/*TODO*/
}

void
camel_mapi_notfication_listener_start (CamelMapiStore *store, guint16 mask, 
				       guint32 options)
{
	CamelSession *session = ((CamelService *)store)->session;
	struct mapi_push_notification_msg *mapi_push_notification_msg_op;

	mapi_push_notification_msg_op =
		camel_session_thread_msg_new (session, &mapi_push_notification_ops, 
					      sizeof (*mapi_push_notification_msg_op));

	mapi_push_notification_msg_op->event_options = options;
	mapi_push_notification_msg_op->event_mask = mask;
	mapi_push_notification_msg_op->event_data = store;

	camel_session_thread_queue (session, &mapi_push_notification_msg_op->msg, 0);
}
