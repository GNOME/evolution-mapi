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

#ifndef E_MAPI_MAIL_UTILS_H
#define E_MAPI_MAIL_UTILS_H 

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <gio/gio.h>

#include <libmapi/libmapi.h>

#include <e-mapi-connection.h>

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

typedef struct _MailItem {
	mapi_id_t fid;
	mapi_id_t mid;
	gchar *msg_class;
	gchar *pid_name_content_type; /* for PidNameContentType */

	MailItemHeader header;
	MailItemMessage msg;

	gboolean is_cal;

	GSList *recipients;
	GSList *attachments;
	GSList *generic_streams;
} MailItem;

void mail_item_free (MailItem *item);

/* fetch callback, the 'data' is pointer to a MailItem pointer, where new MailItem will be placed */
gboolean fetch_props_to_mail_item_cb (FetchItemsCallbackData *item_data,
				      gpointer data,
				      GCancellable *cancellable,
				      GError **perror);

/* returns TRUE when filled an entry in the MailItem based on the propTag and its value */
gboolean fetch_read_item_common_data (MailItem *item, uint32_t propTag, gconstpointer prop_data);

gboolean mapi_mail_get_item_prop_list (EMapiConnection *conn,
				       mapi_id_t fid,
				       TALLOC_CTX *mem_ctx,
				       struct SPropTagArray *props, gpointer data,
				       GCancellable *cancellable,
				       GError **perror);

struct _CamelAddress;
struct _CamelMimeMessage;

struct _CamelMimeMessage *mapi_mail_item_to_mime_message (EMapiConnection *conn, MailItem *item);

struct _CamelMimeMessage *e_mapi_mail_utils_object_to_message	(EMapiConnection *conn,
								 /* const */ EMapiObject *object);
void			e_mapi_mail_utils_decode_email_address	(EMapiConnection *conn,
								 struct mapi_SPropValue_array *properties,
								 const uint32_t *name_proptags,
								 guint name_proptags_len,
								 const uint32_t *email_proptags,
								 guint email_proptags_len,
								 uint32_t email_type_proptag,
								 uint32_t email_proptag,
								 gchar **name,
								 gchar **email);
void			e_mapi_mail_utils_decode_email_address1	(EMapiConnection *conn,
								 struct mapi_SPropValue_array *properties,
								 uint32_t name_proptag,
								 uint32_t email_proptag,
								 uint32_t email_type_proptag,
								 gchar **name,
								 gchar **email);
void			e_mapi_mail_utils_decode_recipients	(EMapiConnection *conn,
								 EMapiRecipient *recipients,
								 struct _CamelAddress *to,
								 struct _CamelAddress *cc,
								 struct _CamelAddress *bcc);

MailItem *mapi_mime_message_to_mail_item (struct _CamelMimeMessage *message, gint32 message_camel_flags, struct _CamelAddress *from, GCancellable *cancellable, GError **error);

/* uses MailItem * as 'data' pointer */
gboolean  mapi_mail_utils_create_item_build_props (EMapiConnection *conn,
						   mapi_id_t fid,
						   TALLOC_CTX *mem_ctx,
						   struct SPropValue **values,
						   uint32_t *n_values,
						   gpointer data,
						   GCancellable *cancellable,
						   GError **perror);

#endif /* E_MAPI_MAIL_UTILS */
