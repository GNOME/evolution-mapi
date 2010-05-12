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

#include <glib/gi18n-lib.h>

#include <libmapi/libmapi.h>
#include <gen_ndr/exchange.h>

#include "camel-mapi-transport.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-utils.h"
#define d(x) x

#include <exchange-mapi-defs.h>
#include "exchange-mapi-mail-utils.h"

#define STREAM_SIZE 4000

CamelStore *get_store(void);

void	set_store(CamelStore *);

G_DEFINE_TYPE (CamelMapiTransport, camel_mapi_transport, CAMEL_TYPE_TRANSPORT)

/*CreateItem would return the MID of the new message or '0' if we fail.*/
static mapi_id_t
mapi_message_item_send (ExchangeMapiConnection *conn, MailItem *item)
{
	guint64 fid = 0;
	mapi_id_t mid = 0;

	mid = exchange_mapi_connection_create_item (conn, olFolderSentMail, fid,
					 camel_mapi_utils_create_item_build_props, item,
					 item->recipients, item->attachments, item->generic_streams, MAPI_OPTIONS_DELETE_ON_SUBMIT_FAILURE);

	return mid;
}

static gboolean
mapi_send_to (CamelTransport *transport, CamelMimeMessage *message,
	      CamelAddress *from, CamelAddress *recipients, CamelException *ex)
{
	ExchangeMapiConnection *conn;
	MailItem *item = NULL;
	const gchar *namep;
	const gchar *addressp;
	mapi_id_t st = 0;
	CamelURL *url;

	if (!camel_internet_address_get((CamelInternetAddress *)from, 0, &namep, &addressp)) {
		return (FALSE);
	}

	g_return_val_if_fail (CAMEL_IS_SERVICE (transport), FALSE);

	url = CAMEL_SERVICE (transport)->url;
	g_return_val_if_fail (url != NULL, FALSE);

	conn = exchange_mapi_connection_find (camel_url_get_param (url, "profile"));
	if (!conn) {
		camel_exception_setv (ex, CAMEL_EXCEPTION_SERVICE_UNAVAILABLE, _("Could not send message."));
		return FALSE;
	}

	/* Convert MIME to MailItem, attacment lists and recipient list.*/
	item = camel_mapi_utils_mime_to_item (message, from, ex);

	/* send */
	st = mapi_message_item_send (conn, item);

	g_object_unref (conn);

	if (st == 0) {
		/*Fixme : Set a better error message. Would be helful in troubleshooting. */
		camel_exception_setv (ex, CAMEL_EXCEPTION_SERVICE_UNAVAILABLE,_("Could not send message."));
		return FALSE;
	}

	return TRUE;
}

static gchar *
mapi_transport_get_name(CamelService *service, gboolean brief)
{
	if (brief) {
		/* Translators: The %s is replaced with a server's host name */
		return g_strdup_printf (_("Exchange MAPI server %s"), service->url->host);
	} else {
		/* Translators: The first %s is replaced with a user name, the second with a server's host name */
		return g_strdup_printf (_("Exchange MAPI service for %s on %s"),
					service->url->user, service->url->host);
	}
}

static void
camel_mapi_transport_class_init (CamelMapiTransportClass *class)
{
	CamelServiceClass *service_class;
	CamelTransportClass *transport_class;

	service_class = CAMEL_SERVICE_CLASS (class);
	service_class->get_name = mapi_transport_get_name;

	transport_class = CAMEL_TRANSPORT_CLASS (class);
	transport_class->send_to = mapi_send_to;
}

static void
camel_mapi_transport_init (CamelMapiTransport *transport)
{

}

