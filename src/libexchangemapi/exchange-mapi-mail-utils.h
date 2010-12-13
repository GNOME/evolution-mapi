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
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef EXCHANGE_MAPI_MAIL_UTILS_H
#define EXCHANGE_MAPI_MAIL_UTILS_H 

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <libmapi/libmapi.h>

#include <exchange-mapi-connection.h>

typedef enum  {
	PART_TYPE_PLAIN_TEXT=1,
	PART_TYPE_TEXT_HTML
} MailItemPartType;

typedef struct {
	gchar *subject;
	gchar *from;
	gchar *from_email;
	gchar *from_type;

	gchar *references;
	gchar *message_id;
	gchar *in_reply_to;
	/*TODO : Obsolete this. Moved to recipient list*/
	gchar *to;
	gchar *cc;
	gchar *bcc;

	gint flags;
	glong size;
	time_t recieved_time;
	time_t send_time;
	guint cpid; /* codepage id */
	gchar *transport_headers;
	gchar *content_class;
} MailItemHeader;

typedef struct {
	GSList *body_parts;
} MailItemMessage;

typedef struct  {
	mapi_id_t fid;
	mapi_id_t mid;
	gchar *msg_class;

	MailItemHeader header;
	MailItemMessage msg;

	gboolean is_cal;

	GSList *recipients;
	GSList *attachments;
	GSList *generic_streams;
}MailItem;

void mail_item_free (MailItem *item);

/* fetch callback, the 'data' is pointer to a MailItem pointer, where new MailItem will be placed */
gboolean fetch_props_to_mail_item_cb (FetchItemsCallbackData *item_data, gpointer data);

/* returns TRUE when filled an entry in the MailItem based on the propTag and its value */
gboolean fetch_read_item_common_data (MailItem *item, uint32_t propTag, gconstpointer prop_data);

gboolean mapi_mail_get_item_prop_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data);

struct _CamelMimeMessage;
struct _CamelMimeMessage *mapi_mail_item_to_mime_message (ExchangeMapiConnection *conn, MailItem *item);

#endif /* EXCHANGE_MAPI_MAIL_UTILS */
