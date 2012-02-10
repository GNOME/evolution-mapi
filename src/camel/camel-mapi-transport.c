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

#include <e-mapi-defs.h>
#include "e-mapi-mail-utils.h"
#include "e-mapi-utils.h"

#define STREAM_SIZE 4000

G_DEFINE_TYPE (CamelMapiTransport, camel_mapi_transport, CAMEL_TYPE_TRANSPORT)

static gboolean
convert_message_to_object_cb (EMapiConnection *conn,
			      TALLOC_CTX *mem_ctx,
			      EMapiObject **object, /* out */
			      gpointer user_data,
			      GCancellable *cancellable,
			      GError **perror)
{
	CamelMimeMessage *message = user_data;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	return e_mapi_mail_utils_message_to_object (message, 0, E_MAPI_CREATE_FLAG_SUBMIT, object, mem_ctx, cancellable, perror);
}

static gboolean
mapi_send_to_sync (CamelTransport *transport,
                   CamelMimeMessage *message,
                   CamelAddress *from,
                   CamelAddress *recipients,
                   GCancellable *cancellable,
                   GError **error)
{
	EMapiConnection *conn;
	const gchar *namep;
	const gchar *addressp;
	mapi_id_t mid = 0;
	mapi_object_t obj_folder;
	CamelService *service;
	CamelSettings *settings;
	const gchar *profile;
	GError *mapi_error = NULL;

	if (!camel_internet_address_get (CAMEL_INTERNET_ADDRESS (from), 0, &namep, &addressp)) {
		return (FALSE);
	}

	g_return_val_if_fail (CAMEL_IS_SERVICE (transport), FALSE);

	service = CAMEL_SERVICE (transport);
	settings = camel_service_get_settings (service);
	profile = camel_mapi_settings_get_profile (CAMEL_MAPI_SETTINGS (settings));
	if (!profile) {
		/* try to find corresponding CamelStore with profile name filled */
		const gchar *my_uid = camel_service_get_uid (service);
		CamelSession *session = camel_service_get_session (service);
		GList *services, *s;

		services = camel_session_list_services (session);
		for (s = services; s && my_uid && !profile; s = s->next) {
			CamelService *store = s->data;
			const gchar *store_uid;

			if (!CAMEL_IS_STORE (store))
				continue;

			store_uid = camel_service_get_uid (store);
			if (!store_uid)
				continue;

			if (g_strcmp0 (my_uid, store_uid) == 0 ||
			    g_str_has_prefix (my_uid, store_uid) ||
			    g_str_has_prefix (store_uid, my_uid)) {
				settings = camel_service_get_settings (store);
				profile = camel_mapi_settings_get_profile (CAMEL_MAPI_SETTINGS (settings));
			}
		}

		g_list_free (services);
	}

	conn = e_mapi_connection_find (profile);
	if (!conn) {
		g_set_error (
			error, CAMEL_SERVICE_ERROR,
			CAMEL_SERVICE_ERROR_UNAVAILABLE,
			_("Could not send message."));
		return FALSE;
	}

	if (e_mapi_connection_open_default_folder (conn, olFolderSentMail, &obj_folder, cancellable, &mapi_error)) {
		e_mapi_connection_create_object (conn, &obj_folder, E_MAPI_CREATE_FLAG_SUBMIT, convert_message_to_object_cb, message, &mid, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	g_object_unref (conn);

	if (mid == 0) {
		if (mapi_error) {
			if (!e_mapi_utils_propagate_cancelled_error (mapi_error, error))
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
	CamelNetworkSettings *network_settings;
	CamelSettings *settings;
	const gchar *host;
	const gchar *user;

	settings = camel_service_get_settings (service);

	network_settings = CAMEL_NETWORK_SETTINGS (settings);
	host = camel_network_settings_get_host (network_settings);
	user = camel_network_settings_get_user (network_settings);

	if (brief) {
		/* Translators: The %s is replaced with a server's host name */
		return g_strdup_printf (_("Exchange MAPI server %s"), host);
	} else {
		/* Translators: The first %s is replaced with a user name, the second with a server's host name */
		return g_strdup_printf (_("Exchange MAPI service for %s on %s"),
					user, host);
	}
}

static void
camel_mapi_transport_class_init (CamelMapiTransportClass *class)
{
	CamelServiceClass *service_class;
	CamelTransportClass *transport_class;

	service_class = CAMEL_SERVICE_CLASS (class);
	service_class->get_name = mapi_transport_get_name;
	service_class->settings_type = CAMEL_TYPE_MAPI_SETTINGS;

	transport_class = CAMEL_TRANSPORT_CLASS (class);
	transport_class->send_to_sync = mapi_send_to_sync;
}

static void
camel_mapi_transport_init (CamelMapiTransport *transport)
{
}
