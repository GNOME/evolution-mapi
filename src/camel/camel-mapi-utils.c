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

/* -- Generate MIME to ITEM -- */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib/gi18n-lib.h>

#include <libmapi/libmapi.h>
#include <gen_ndr/exchange.h>

#include <exchange-mapi-defs.h>
#include "exchange-mapi-utils.h"
#include "exchange-mapi-mail-utils.h"

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-utils.h"

#define d(x)

#define STREAM_SIZE 4000

static void
mail_item_add_recipient (const gchar *recipients, OlMailRecipientType type, GSList **recipient_list)
{
	ExchangeMAPIRecipient *recipient;
	uint32_t val = 0;
	uint8_t bVal;
	const gchar *str = NULL;

	if (!recipients)
		return;

	recipient = g_new0 (ExchangeMAPIRecipient, 1);

	recipient->email_id = recipients;

	/* this memory should be freed somewhere, perhaps in the existing
	 * exchange_mapi_util_free_recipient_list() */
	recipient->in.req_cValues = 2;
	recipient->in.req_lpProps = g_new0 (struct SPropValue, recipient->in.req_cValues + 1);

	set_SPropValue_proptag (&(recipient->in.req_lpProps[0]), PR_RECIPIENT_TYPE, (gconstpointer ) &type);

	val = 0;
	set_SPropValue_proptag (&(recipient->in.req_lpProps[1]), PR_SEND_INTERNET_ENCODING, (gconstpointer )&val);

	/* External recipient properties - set them only when the recipient is unresolved */
	recipient->in.ext_cValues = 8;
	recipient->in.ext_lpProps = g_new0 (struct SPropValue, recipient->in.ext_cValues + 1);

	val = DT_MAILUSER;
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[0]), PR_DISPLAY_TYPE, (gconstpointer )&val);
	val = MAPI_MAILUSER;
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[1]), PR_OBJECT_TYPE, (gconstpointer )&val);
	str = "SMTP";
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[2]), PR_ADDRTYPE_UNICODE, (gconstpointer )(str));
	str = recipient->email_id;
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[3]), PR_SMTP_ADDRESS_UNICODE, (gconstpointer )(str));
	/* FIXME: Please add the correct names here instead of the e-mail ID */
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[4]), PR_GIVEN_NAME_UNICODE, (gconstpointer )(str));
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[5]), PR_DISPLAY_NAME_UNICODE, (gconstpointer )(str));
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[6]), PR_7BIT_DISPLAY_NAME_UNICODE, (gconstpointer )(str));

	bVal = FALSE;
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[7]), PR_SEND_RICH_INFO, &bVal);

	*recipient_list = g_slist_append (*recipient_list, recipient);
}

static void
mail_item_set_from(MailItem *item, const gchar *from_name, const gchar *from_email)
{
	if (item->header.from)
		g_free (item->header.from);
	if (item->header.from_email)
		g_free (item->header.from_email);

	item->header.from = g_strdup (from_name);
	item->header.from_email = g_strdup (from_email);
}

static void
mail_item_set_subject(MailItem *item, const gchar *subject)
{
	if (item->header.subject)
		g_free (item->header.subject);

	item->header.subject = g_strdup (subject);
}

#define MAX_READ_SIZE 0x1000

static void
mail_item_set_body_stream (MailItem *item, CamelStream *body, MailItemPartType part_type, GCancellable *cancellable)
{
	guint8 *buf = g_new0 (guint8 , STREAM_SIZE);
	guint32	read_size = 0, i;
	ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1);
	gboolean contains_only_7bit = TRUE, is_null_terminated = FALSE;

	camel_seekable_stream_seek((CamelSeekableStream *)body, 0, CAMEL_STREAM_SET, NULL);

	stream->value = g_byte_array_new ();

	while (read_size = camel_stream_read (body, (gchar *)buf, STREAM_SIZE, cancellable, NULL), read_size > 0) {
		stream->value = g_byte_array_append (stream->value, buf, read_size);

		is_null_terminated = buf [read_size - 1] == 0;

		for (i = 0; i < read_size && contains_only_7bit; i++) {
			contains_only_7bit = buf[i] < 128;
		}
	}

	g_free (buf);

	switch (part_type) {
	case PART_TYPE_TEXT_HTML :
		stream->proptag = PR_HTML;
		break;
	case PART_TYPE_PLAIN_TEXT:
		stream->proptag = PR_BODY_UNICODE;
		break;
	}

	if (stream->value->len < MAX_READ_SIZE && contains_only_7bit) {
		if (!is_null_terminated)
			g_byte_array_append (stream->value, (const guint8 *)"", 1);

		item->msg.body_parts = g_slist_append (item->msg.body_parts, stream);
	} else if (stream->proptag == PR_HTML) {
		/* PR_HTML shouldn't be in UTF-16 */
		if (!is_null_terminated)
			g_byte_array_append (stream->value, (const guint8 *)"", 1);

		item->generic_streams = g_slist_append (item->generic_streams, stream);
	} else {
		gsize written = 0;
		gchar *in_unicode;

		if (is_null_terminated)
			stream->value->len--;

		/* convert to unicode, because stream is supposed to be in it */
		in_unicode = g_convert ((const gchar *)stream->value->data, stream->value->len, "UTF-16", "UTF-8", NULL, &written, NULL);
		if (in_unicode && written > 0) {
			g_byte_array_set_size (stream->value, 0);
			/* skip Unicode marker, if there */
			if (written >= 2 && (const guchar) in_unicode[0] == 0xFF && (const guchar) in_unicode[1] == 0xFE)
				g_byte_array_append (stream->value, (const guint8 *) in_unicode + 2, written - 2);
			else
				g_byte_array_append (stream->value, (const guint8 *) in_unicode, written);

			/* null-terminated unicode string */
			g_byte_array_append (stream->value, (const guint8 *)"", 1);
			g_byte_array_append (stream->value, (const guint8 *)"", 1);
		}
		g_free (in_unicode);

		item->generic_streams = g_slist_append (item->generic_streams, stream);
	}

}

static gboolean
mail_item_add_attach (MailItem *item, CamelMimePart *part, CamelStream *content_stream, GCancellable *cancellable)
{
	guint8 *buf = g_new0 (guint8 , STREAM_SIZE);
	const gchar *content_id = NULL;
	guint32	read_size, flag, i = 0;
	CamelContentType *content_type;

	ExchangeMAPIAttachment *item_attach;
	ExchangeMAPIStream *stream;

	const gchar *filename = camel_mime_part_get_filename (part);

	item_attach = g_new0 (ExchangeMAPIAttachment, 1);

	item_attach->lpProps = g_new0 (struct SPropValue, 6 + 1);

	flag = ATTACH_BY_VALUE;
	set_SPropValue_proptag(&(item_attach->lpProps[i++]), PR_ATTACH_METHOD, (gconstpointer ) (&flag));

	/* MSDN Documentation: When the supplied offset is -1 (0xFFFFFFFF), the
	 * attachment is not rendered using the PR_RENDERING_POSITION property.
	 * All values other than -1 indicate the position within PR_BODY at which
	 * the attachment is to be rendered.
	 */
	flag = 0xFFFFFFFF;
	set_SPropValue_proptag(&(item_attach->lpProps[i++]), PR_RENDERING_POSITION, (gconstpointer ) (&flag));

	if (filename) {
		set_SPropValue_proptag(&(item_attach->lpProps[i++]),
				       PR_ATTACH_FILENAME_UNICODE,
				       (gconstpointer ) g_strdup(filename));

		set_SPropValue_proptag(&(item_attach->lpProps[i++]),
				       PR_ATTACH_LONG_FILENAME_UNICODE,
				       (gconstpointer ) g_strdup(filename));
	}

	/* mime type : multipart/related */
	content_id = camel_mime_part_get_content_id (part);
	if (content_id) {
		set_SPropValue_proptag(&(item_attach->lpProps[i++]),
				       PR_ATTACH_CONTENT_ID,
				       (gconstpointer ) g_strdup(content_id));
	}

	content_type  = camel_mime_part_get_content_type (part);
	if (content_type) {
		gchar *ct = camel_content_type_simple (content_type);
		if (ct) {
			set_SPropValue_proptag (&(item_attach->lpProps[i++]),
					PR_ATTACH_MIME_TAG,
					(gconstpointer ) ct);
		}
	}

	item_attach->cValues = i;

	stream = g_new0 (ExchangeMAPIStream, 1);
	stream->proptag = PR_ATTACH_DATA_BIN;
	stream->value = g_byte_array_new ();

	camel_seekable_stream_seek((CamelSeekableStream *)content_stream, 0, CAMEL_STREAM_SET, NULL);
	while (read_size = camel_stream_read(content_stream, (gchar *)buf, STREAM_SIZE, cancellable, NULL), read_size > 0) {
		stream->value = g_byte_array_append (stream->value, buf, read_size);
	}

	item_attach->streams = g_slist_append (item_attach->streams, stream);
	item->attachments = g_slist_append(item->attachments, item_attach);

	return TRUE;
}

static gboolean
mapi_do_multipart (CamelMultipart *mp, MailItem *item, gboolean *is_first, GCancellable *cancellable)
{
	CamelDataWrapper *dw;
	CamelStream *content_stream;
	CamelContentType *type;
	CamelMimePart *part;
	gint n_part, i_part;
	const gchar *filename;
	const gchar *description;
	const gchar *content_id;
	gint content_size;

	g_return_val_if_fail (is_first != NULL, FALSE);

	n_part = camel_multipart_get_number(mp);
	for (i_part = 0; i_part < n_part; i_part++) {
		/* getting part */
		part = camel_multipart_get_part(mp, i_part);
		dw = camel_medium_get_content (CAMEL_MEDIUM (part));
		if (CAMEL_IS_MULTIPART(dw)) {
			/* recursive */
			if (!mapi_do_multipart (CAMEL_MULTIPART (dw), item, is_first, cancellable))
				return FALSE;
			continue;
		}
		/* filename */
		filename = camel_mime_part_get_filename(part);

		content_stream = camel_stream_mem_new();
		content_size = camel_data_wrapper_decode_to_stream_sync (
			dw, (CamelStream *) content_stream, cancellable, NULL);

		camel_seekable_stream_seek((CamelSeekableStream *)content_stream, 0, CAMEL_STREAM_SET, NULL);

		description = camel_mime_part_get_description(part);
		content_id = camel_mime_part_get_content_id(part);

		type = camel_mime_part_get_content_type(part);

		if (i_part == 0 && (*is_first) && camel_content_type_is (type, "text", "plain")) {
			mail_item_set_body_stream (item, content_stream, PART_TYPE_PLAIN_TEXT, cancellable);
			*is_first = FALSE;
		} else if (camel_content_type_is (type, "text", "html")) {
			mail_item_set_body_stream (item, content_stream, PART_TYPE_TEXT_HTML, cancellable);
		} else {
			mail_item_add_attach (item, part, content_stream, cancellable);
		}
	}

	return TRUE;
}

static void
mail_item_set_time (time_t *item_time, time_t camel_time, gint camel_offset)
{
	if (camel_time == CAMEL_MESSAGE_DATE_CURRENT) {
		*item_time = 0;
	} else {
		/* Convert to UTC */
		/*camel_time -= (camel_offset / 100) * 60 * 60;
		camel_time -= (camel_offset % 100) * 60;*/
		*item_time = camel_time;
	}
}

MailItem *
camel_mapi_utils_mime_to_item (CamelMimeMessage *message, gint32 message_camel_flags, CamelAddress *from, GCancellable *cancellable, GError **error)
{
	CamelDataWrapper *dw = NULL;
	CamelContentType *type;
	CamelStream *content_stream;
	CamelMultipart *multipart;
	CamelInternetAddress *to, *cc, *bcc;
	MailItem *item = g_new0 (MailItem, 1);
	const gchar *namep = NULL;
	const gchar *addressp = NULL;
	const gchar *content_type;
	time_t msg_time = 0;
	gint msg_time_offset = 0;
	GArray *headers;

	gssize	content_size;
	GSList *recipient_list = NULL;
	gint i = 0;

	/* headers */

	if (from) {
		if (!camel_internet_address_get ((CamelInternetAddress *)from, 0, &namep, &addressp)) {
			g_warning ("%s: Invalid 'from' passed in", G_STRFUNC);
			g_free (item);
			return NULL;
		}
	} else {
		/* though invalid, then possible, to pass in a message without any 'from' */
		namep = NULL;
	}

	item->header.flags = 0;
	if (message_camel_flags & CAMEL_MESSAGE_SEEN)
		item->header.flags |= MSGFLAG_READ;
	if (message_camel_flags & CAMEL_MESSAGE_ATTACHMENTS)
		item->header.flags |= MSGFLAG_HASATTACH;

	mail_item_set_from (item, namep, addressp);

	msg_time = camel_mime_message_get_date (message, &msg_time_offset);
	if (msg_time == CAMEL_MESSAGE_DATE_CURRENT)
		msg_time = camel_mime_message_get_date_received (message, &msg_time_offset);
	mail_item_set_time (&item->header.recieved_time, msg_time, msg_time_offset);

	to = camel_mime_message_get_recipients(message, CAMEL_RECIPIENT_TYPE_TO);
	for (i = 0; to && camel_internet_address_get (to, i, &namep, &addressp); i++) {
		mail_item_add_recipient (addressp, olTo, &recipient_list);
	}

	cc = camel_mime_message_get_recipients(message, CAMEL_RECIPIENT_TYPE_CC);
	for (i = 0; cc && camel_internet_address_get (cc, i, &namep, &addressp); i++) {
		mail_item_add_recipient (addressp, olCC, &recipient_list);
	}

	bcc = camel_mime_message_get_recipients(message, CAMEL_RECIPIENT_TYPE_BCC);
	for (i = 0; bcc && camel_internet_address_get (bcc, i, &namep, &addressp); i++) {
		mail_item_add_recipient (addressp, olBCC, &recipient_list);
	}

	if (camel_mime_message_get_subject(message)) {
		mail_item_set_subject(item, camel_mime_message_get_subject(message));
	}

	headers = camel_medium_get_headers (CAMEL_MEDIUM (message));
	if (headers) {
		GString *hstr = g_string_new ("");
		gint i;

		for (i = 0; i < headers->len; i++) {
			CamelMediumHeader *h = &g_array_index (headers, CamelMediumHeader, i);

			if (!h->name || !*h->name || g_ascii_strncasecmp (h->name, "X-Evolution", 11) == 0)
				continue;

			g_string_append_printf (hstr, "%s: %s\n", h->name, h->value ? h->value : "");
		}

		camel_medium_free_headers (CAMEL_MEDIUM (message), headers);

		item->header.transport_headers = g_string_free (hstr, hstr->len == 0);
	}

	/*Add message threading properties */
	item->header.references = g_strdup (camel_medium_get_header ((CamelMedium *) message, "References"));
	item->header.in_reply_to = g_strdup (camel_medium_get_header ((CamelMedium *) message, "In-Reply-To"));
	item->header.message_id = g_strdup (camel_medium_get_header ((CamelMedium *) message, "Message-ID"));

	/* contents body */
	multipart = (CamelMultipart *)camel_medium_get_content (CAMEL_MEDIUM (message));

	if (CAMEL_IS_MULTIPART(multipart)) {
		gboolean is_first = TRUE;
		if (!mapi_do_multipart (CAMEL_MULTIPART(multipart), item, &is_first, cancellable))
			printf("camel message multi part error\n");
	} else {
		dw = camel_medium_get_content (CAMEL_MEDIUM (message));
		if (dw) {
			type = camel_mime_part_get_content_type((CamelMimePart *)message);
			content_type = camel_content_type_simple (type);

			content_stream = (CamelStream *)camel_stream_mem_new();
			content_size = camel_data_wrapper_decode_to_stream_sync (
				dw, (CamelStream *)content_stream, cancellable, NULL);

			mail_item_set_body_stream (item, content_stream, PART_TYPE_PLAIN_TEXT, cancellable);
		}
	}

	item->recipients = recipient_list;

	return item;
}

gboolean
camel_mapi_utils_create_item_build_props (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropValue **values, uint32_t *n_values, gpointer data)
{

	MailItem *item = (MailItem *) data;
	GSList *l;
	bool send_rich_info;
	uint32_t cpid;

	#define set_value(hex, val) G_STMT_START { \
		if (!exchange_mapi_utils_add_spropvalue (mem_ctx, values, n_values, hex, val)) \
			return FALSE;	\
		} G_STMT_END

	cpid = 65001; /* UTF8 - also used with PR_HTML */
	set_value (PR_INTERNET_CPID, &cpid);
	set_value (PR_SUBJECT_UNICODE, item->header.subject);
	/* PR_CONVERSATION_TOPIC_UNICODE and PR_NORMALIZED_SUBJECT_UNICODE, together with PR_SUBJECT_PREFIX_UNICODE
	   are computed from PR_SUBJECT by the server */

	send_rich_info = false;
	set_value (PR_SEND_RICH_INFO, &send_rich_info);

	set_value (PR_MESSAGE_FLAGS, &item->header.flags);

	if (item->header.from && *item->header.from)
		set_value (PR_SENT_REPRESENTING_NAME_UNICODE, item->header.from);

	if (item->header.from_email && *item->header.from_email) {
		set_value (PR_SENT_REPRESENTING_ADDRTYPE_UNICODE, "SMTP");
		set_value (PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE, item->header.from_email);
	}

	if (item->header.recieved_time != 0) {
		struct FILETIME msg_date = { 0 };

		exchange_mapi_util_time_t_to_filetime (item->header.recieved_time, &msg_date);

		set_value (PR_MESSAGE_DELIVERY_TIME, &msg_date);
	}

	if (item->header.transport_headers && *item->header.transport_headers)
		set_value (PR_TRANSPORT_MESSAGE_HEADERS_UNICODE, item->header.transport_headers);

	/* Message threading information */
	if (item->header.references)
		set_value (PR_INTERNET_REFERENCES, item->header.references);

	if (item->header.in_reply_to)
		set_value (PR_IN_REPLY_TO_ID, item->header.in_reply_to);

	if (item->header.message_id)
		set_value (PR_INTERNET_MESSAGE_ID, item->header.message_id);

	for (l = item->msg.body_parts; l; l = l->next) {
		ExchangeMAPIStream *stream = (ExchangeMAPIStream *) (l->data);
		struct SBinary_short *bin = g_new0 (struct SBinary_short, 1);

		bin->cb = stream->value->len;
		bin->lpb = (uint8_t *)stream->value->data;
		if (stream->proptag == PR_HTML)
			set_value (stream->proptag, bin);
		else if (stream->proptag == PR_BODY_UNICODE)
			set_value (stream->proptag, stream->value->data);
	}

	/*  FIXME : */
	/* editor = EDITOR_FORMAT_PLAINTEXT; */
	/* set_value (PR_MSG_EDITOR_FORMAT, &editor); */

	return TRUE;
}

/* -- Generate MIME to ITEM -- */
