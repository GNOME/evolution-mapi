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

static void
mapi_push_notification_listener (CamelSession *session, CamelSessionThreadMsg *msg);
static void
mapi_push_notification_listener_close (CamelSession *session, CamelSessionThreadMsg *msg);

struct mapi_push_notification_msg {
	CamelSessionThreadMsg msg;

	guint16 event_mask;
	guint32 *connection; 
	guint32 event_options;
	gpointer event_data;
};

static gint
mapi_notifications_filter (guint16 type, void *event, void *private_data)
{
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
		new_mail_handler (event);
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

static void
mapi_push_notification_listener (CamelSession *session, CamelSessionThreadMsg *msg)
{
	struct mapi_push_notification_msg *m = (struct mapi_push_notification_msg *)msg;

	if (exchange_mapi_events_init ()) {
		exchange_mapi_events_subscribe (0, m->event_options, m->event_mask,
						&m->connection,	mapi_notifications_filter,
						m->event_data);

		/* Need a better API for canceling this operation*/
		exchange_mapi_events_monitor (NULL);
	}

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
	mapi_push_notification_msg_op->event_data = NULL;

	camel_session_thread_queue (session, &mapi_push_notification_msg_op->msg, 0);
}
