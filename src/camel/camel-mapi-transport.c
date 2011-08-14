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

#include "camel-mapi-settings.h"
#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#define d(x)

#include <exchange-mapi-defs.h>
#include "exchange-mapi-mail-utils.h"

#define STREAM_SIZE 4000

CamelStore *get_store(void);

void	set_store(CamelStore *);

G_DEFINE_TYPE (CamelMapiTransport, camel_mapi_transport, CAMEL_TYPE_TRANSPORT)

/*CreateItem would return the MID of the new message or '0' if we fail.*/
static mapi_id_t
mapi_message_item_send (ExchangeMapiConnection *conn, MailItem *item, GError **perror)
{
	guint64 fid = 0;
	mapi_id_t mid = 0;

	#define unset(x) g_free (x); x = NULL

	item->header.flags = MSGFLAG_UNSENT;
	unset (item->header.from);
	unset (item->header.from_email);
	unset (item->header.transport_headers);
	item->header.recieved_time = 0;

	#undef unset

	mid = exchange_mapi_connection_create_item (conn, olFolderSentMail, fid,
					 mapi_mail_utils_create_item_build_props, item,
					 item->recipients, item->attachments, item->generic_streams, MAPI_OPTIONS_DELETE_ON_SUBMIT_FAILURE, perror);

	return mid;
}

static gboolean
mapi_send_to_sync (CamelTransport *transport,
                   CamelMimeMessage *message,
                   CamelAddress *from,
                   CamelAddress *recipients,
                   GCancellable *cancellable,
                   GError **error)
{
	ExchangeMapiConnection *conn;
	MailItem *item = NULL;
	const gchar *namep;
	const gchar *addressp;
	mapi_id_t st = 0;
	CamelService *service;
	CamelSettings *settings;
	const gchar *profile;
	GError *mapi_error = NULL;

	if (!camel_internet_address_get((CamelInternetAddress *)from, 0, &namep, &addressp)) {
		return (FALSE);
	}

	g_return_val_if_fail (CAMEL_IS_SERVICE (transport), FALSE);

	service = CAMEL_SERVICE (transport);
	settings = camel_service_get_settings (service);
	profile = camel_mapi_settings_get_profile (CAMEL_MAPI_SETTINGS (settings));

	conn = exchange_mapi_connection_find (profile);
	if (!conn) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Could not send message."));
		return FALSE;
	}

	/* Convert MIME to MailItem, attacment lists and recipient list.*/
	item = mapi_mime_message_to_mail_item (message, 0, from, cancellable, NULL);

	/* send */
	st = mapi_message_item_send (conn, item, error);

	g_object_unref (conn);

	if (st == 0) {
		if (mapi_error) {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Could not send message: %s"), mapi_error->message);
			g_error_free (mapi_error);
		} else {
			g_set_error (
				error, CAMEL_ERROR, CAMEL_ERROR_GENERIC,
				_("Could not send message."));
		}
		return FALSE;
	}

	return TRUE;
}

static gchar *
mapi_transport_get_name(CamelService *service, gboolean brief)
{
	CamelURL *url;

	url = camel_service_get_camel_url (service);

	if (brief) {
		/* Translators: The %s is replaced with a server's host name */
		return g_strdup_printf (_("Exchange MAPI server %s"), url->host);
	} else {
		/* Translators: The first %s is replaced with a user name, the second with a server's host name */
		return g_strdup_printf (_("Exchange MAPI service for %s on %s"),
					url->user, url->host);
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
	transport_class->send_to_sync = mapi_send_to_sync;
}

static void
camel_mapi_transport_init (CamelMapiTransport *transport)
{

}

