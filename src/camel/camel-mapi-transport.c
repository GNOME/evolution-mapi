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

#include <libmapi/libmapi.h>
#include <gen_ndr/exchange.h>

#include <camel/camel-data-wrapper.h>
#include <camel/camel-exception.h>
#include <camel/camel-mime-filter-crlf.h>
#include <camel/camel-mime-message.h>
#include <camel/camel-multipart.h>
#include <camel/camel-session.h>
#include <camel/camel-stream-filter.h>
#include <camel/camel-stream-mem.h>


#include "camel-mapi-transport.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <camel/camel-sasl.h>
#include <camel/camel-utf8.h>
#include <camel/camel-tcp-stream-raw.h>

#ifdef HAVE_SSL
#include <camel/camel-tcp-stream-ssl.h>
#endif


#include <camel/camel-private.h>
#include <glib/gi18n-lib.h>
#include <camel/camel-net-utils.h>
#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-utils.h"
#include <camel/camel-session.h>
#include <camel/camel-store-summary.h>
#define d(x) x

#include <camel/camel-seekable-stream.h>
#include <exchange-mapi-defs.h>

#define STREAM_SIZE 4000

CamelStore *get_store(void);

void	set_store(CamelStore *);


/*CreateItem would return the MID of the new message or '0' if we fail.*/
static mapi_id_t
mapi_message_item_send (MapiItem *item)
{
	guint64 fid = 0;
	mapi_id_t mid = 0;

	mid = exchange_mapi_create_item (olFolderSentMail, fid, NULL, NULL, 
					 camel_mapi_utils_create_item_build_props,
					 item, item->recipients,
					 item->attachments, item->generic_streams, MAPI_OPTIONS_DELETE_ON_SUBMIT_FAILURE);

	return mid;
}

static gboolean
mapi_send_to (CamelTransport *transport, CamelMimeMessage *message,
	      CamelAddress *from, CamelAddress *recipients, CamelException *ex)
{
	MapiItem *item = NULL;
	const char *namep;
	const char *addressp;
	mapi_id_t st = 0;

	if (!camel_internet_address_get((const CamelInternetAddress *)from, 0, &namep, &addressp)) {
		return (FALSE);
	}

	/* Convert MIME to MAPIItem, attacment lists and recipient list.*/
	item = camel_mapi_utils_mime_to_item (message, from, ex);

	/* send */
	st = mapi_message_item_send(item);

	if (st == 0) {
		/*Fixme : Set a better error message. Would be helful in troubleshooting. */
		camel_exception_setv (ex, CAMEL_EXCEPTION_SERVICE_UNAVAILABLE,_("Could not send message."));
		return FALSE;
	}
	
	return TRUE;
}


static char*
mapi_transport_get_name(CamelService *service, gboolean brief)
{
	if (brief) {
		return g_strdup_printf (_("Exchange MAPI server %s"), service->url->host);
	} else {
		return g_strdup_printf (_("Exchange MAPI service for %s on %s"),
					service->url->user, service->url->host);
	}
}


static void
camel_mapi_transport_class_init(CamelMapiTransportClass *camel_mapi_transport_class)
{
	CamelTransportClass *camel_transport_class =
		CAMEL_TRANSPORT_CLASS (camel_mapi_transport_class);
	CamelServiceClass *camel_service_class =
		CAMEL_SERVICE_CLASS (camel_mapi_transport_class);
  
	camel_service_class->get_name = mapi_transport_get_name;
	camel_transport_class->send_to = mapi_send_to;
}

static void
camel_mapi_transport_init (CamelTransport *transport)
{

}

CamelType
camel_mapi_transport_get_type (void)
{
	static CamelType camel_mapi_transport_type = CAMEL_INVALID_TYPE;
  
	if (camel_mapi_transport_type == CAMEL_INVALID_TYPE) {
		camel_mapi_transport_type =
			camel_type_register (CAMEL_TRANSPORT_TYPE,
					     "CamelMapiTransport",
					     sizeof (CamelMapiTransport),
					     sizeof (CamelMapiTransportClass),
					     (CamelObjectClassInitFunc) camel_mapi_transport_class_init,
					     NULL,
					     (CamelObjectInitFunc) camel_mapi_transport_init,
					     NULL);
	}

	return camel_mapi_transport_type;
}

