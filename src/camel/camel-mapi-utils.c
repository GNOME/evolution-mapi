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

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib/gi18n.h>

#include <libmapi/libmapi.h>
#include <gen_ndr/exchange.h>

#include <exchange-mapi-defs.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-utils.h"

#define d(x) x

#define STREAM_SIZE 4000

static void
mapi_item_add_recipient (const gchar *recipients, OlMailRecipientType type, GSList **recipient_list)
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
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[2]), PR_ADDRTYPE, (gconstpointer )(str));
	str = recipient->email_id;
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[3]), PR_SMTP_ADDRESS, (gconstpointer )(str));
	/* FIXME: Please add the correct names here instead of the e-mail ID */
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[4]), PR_GIVEN_NAME, (gconstpointer )(str));
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[5]), PR_DISPLAY_NAME, (gconstpointer )(str));
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[6]), PR_7BIT_DISPLAY_NAME, (gconstpointer )(str));

	bVal = FALSE;
	set_SPropValue_proptag (&(recipient->in.ext_lpProps[7]), PR_SEND_RICH_INFO, &bVal);

	*recipient_list = g_slist_append (*recipient_list, recipient);
}

static void
mapi_item_set_from(MapiItem *item, const gchar *from)
{
	if (item->header.from)
		g_free (item->header.from);

	item->header.from = g_strdup (from);
}

static void
mapi_item_set_subject(MapiItem *item, const gchar *subject)
{
	if (item->header.subject)
		g_free (item->header.subject);

	item->header.subject = g_strdup (subject);
}

#define MAX_READ_SIZE 0x1000

static void
mapi_item_set_body_stream (MapiItem *item, CamelStream *body, MapiItemPartType part_type)
{
	guint8 *buf = g_new0 (guint8 , STREAM_SIZE);
	guint32	read_size = 0, i;
	ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1);
	gboolean contains_only_7bit = TRUE, is_null_terminated = FALSE;

	camel_seekable_stream_seek((CamelSeekableStream *)body, 0, CAMEL_STREAM_SET);

	stream->value = g_byte_array_new ();

	while (read_size = camel_stream_read (body, (gchar *)buf, STREAM_SIZE), read_size > 0) {
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
	} else {
		gsize written = 0;
		gchar *in_unicode;

		if (is_null_terminated)
			stream->value->len--;

		/* convert to unicode, because stream is supposed to be in it */
		in_unicode = g_convert ((const gchar *)stream->value->data, stream->value->len, "UTF-16", "UTF-8", NULL, &written, NULL);
		if (in_unicode && written > 0) {
			g_byte_array_set_size (stream->value, 0);
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
mapi_item_add_attach (MapiItem *item, CamelMimePart *part, CamelStream *content_stream)
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
				       PR_ATTACH_FILENAME,
				       (gconstpointer ) g_strdup(filename));

		set_SPropValue_proptag(&(item_attach->lpProps[i++]),
				       PR_ATTACH_LONG_FILENAME,
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

	camel_seekable_stream_seek((CamelSeekableStream *)content_stream, 0, CAMEL_STREAM_SET);
	while (read_size = camel_stream_read(content_stream, (gchar *)buf, STREAM_SIZE), read_size > 0) {
		stream->value = g_byte_array_append (stream->value, buf, read_size);
	}

	item_attach->streams = g_slist_append (item_attach->streams, stream);
	item->attachments = g_slist_append(item->attachments, item_attach);

	return TRUE;
}

static gboolean
mapi_do_multipart (CamelMultipart *mp, MapiItem *item, gboolean *is_first)
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
			if (!mapi_do_multipart (CAMEL_MULTIPART (dw), item, is_first))
				return FALSE;
			continue;
		}
		/* filename */
		filename = camel_mime_part_get_filename(part);

		content_stream = camel_stream_mem_new();
		content_size = camel_data_wrapper_decode_to_stream (dw, (CamelStream *) content_stream);

		camel_seekable_stream_seek((CamelSeekableStream *)content_stream, 0, CAMEL_STREAM_SET);

		description = camel_mime_part_get_description(part);
		content_id = camel_mime_part_get_content_id(part);

		type = camel_mime_part_get_content_type(part);

		if (i_part == 0 && (*is_first) && camel_content_type_is (type, "text", "plain")) {
			mapi_item_set_body_stream (item, content_stream, PART_TYPE_PLAIN_TEXT);
			*is_first = FALSE;
		} else if (camel_content_type_is (type, "text", "html")) {
			mapi_item_set_body_stream (item, content_stream, PART_TYPE_TEXT_HTML);
		} else {
			mapi_item_add_attach (item, part, content_stream);
		}
	}

	return TRUE;
}

MapiItem *
camel_mapi_utils_mime_to_item (CamelMimeMessage *message, CamelAddress *from, CamelException *ex)
{
	CamelDataWrapper *dw = NULL;
	CamelContentType *type;
	CamelStream *content_stream;
	CamelMultipart *multipart;
	CamelInternetAddress *to, *cc, *bcc;
	MapiItem *item = g_new0 (MapiItem, 1);
	const gchar *namep;
	const gchar *addressp;
	const gchar *content_type;

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

	mapi_item_set_from (item, namep);

	to = camel_mime_message_get_recipients(message, CAMEL_RECIPIENT_TYPE_TO);
	for (i = 0; to && camel_internet_address_get (to, i, &namep, &addressp); i++) {
		mapi_item_add_recipient (addressp, olTo, &recipient_list);
	}

	cc = camel_mime_message_get_recipients(message, CAMEL_RECIPIENT_TYPE_CC);
	for (i = 0; cc && camel_internet_address_get (cc, i, &namep, &addressp); i++) {
		mapi_item_add_recipient (addressp, olCC, &recipient_list);
	}

	bcc = camel_mime_message_get_recipients(message, CAMEL_RECIPIENT_TYPE_BCC);
	for (i = 0; bcc && camel_internet_address_get (bcc, i, &namep, &addressp); i++) {
		mapi_item_add_recipient (addressp, olBCC, &recipient_list);
	}

	if (camel_mime_message_get_subject(message)) {
		mapi_item_set_subject(item, camel_mime_message_get_subject(message));
	}

	/*Add message threading properties */
	item->header.references = g_strdup (camel_medium_get_header ((CamelMedium *) message, "References"));
	item->header.in_reply_to = g_strdup (camel_medium_get_header ((CamelMedium *) message, "In-Reply-To"));
	item->header.message_id = g_strdup (camel_medium_get_header ((CamelMedium *) message, "Message-ID"));

	/* contents body */
	multipart = (CamelMultipart *)camel_medium_get_content (CAMEL_MEDIUM (message));

	if (CAMEL_IS_MULTIPART(multipart)) {
		gboolean is_first = TRUE;
		if (!mapi_do_multipart (CAMEL_MULTIPART(multipart), item, &is_first))
			printf("camel message multi part error\n");
	} else {
		dw = camel_medium_get_content (CAMEL_MEDIUM (message));
		if (dw) {
			type = camel_mime_part_get_content_type((CamelMimePart *)message);
			content_type = camel_content_type_simple (type);

			content_stream = (CamelStream *)camel_stream_mem_new();
			content_size = camel_data_wrapper_decode_to_stream(dw, (CamelStream *)content_stream);

			mapi_item_set_body_stream (item, content_stream, PART_TYPE_PLAIN_TEXT);
		}
	}

	item->recipients = recipient_list;

	return item;
}

gint
camel_mapi_utils_create_item_build_props (struct SPropValue **value, struct SPropTagArray *SPropTagArray, gpointer data)
{

	MapiItem *item = (MapiItem *) data;
	struct SPropValue *props;
	GSList *l;
	bool *send_rich_info = g_new0 (bool, 1);
	uint32_t *msgflag = g_new0 (uint32_t, 1);
	uint32_t *cpid = g_new0 (uint32_t, 1);
	gint i=0;

	props = g_new0 (struct SPropValue, 11 + 1);

	*cpid = 65001; /* UTF8 */
	set_SPropValue_proptag(&props[i++], PR_INTERNET_CPID, cpid);
	set_SPropValue_proptag(&props[i++], PR_SUBJECT_UNICODE, g_strdup (item->header.subject));
	set_SPropValue_proptag(&props[i++], PR_CONVERSATION_TOPIC_UNICODE, g_strdup (item->header.subject));
	set_SPropValue_proptag(&props[i++], PR_NORMALIZED_SUBJECT_UNICODE, g_strdup (item->header.subject));

	*send_rich_info = false;
	set_SPropValue_proptag(&props[i++], PR_SEND_RICH_INFO, (gconstpointer ) send_rich_info);

	*msgflag = MSGFLAG_UNSENT;
	set_SPropValue_proptag(&props[i++], PR_MESSAGE_FLAGS, (gpointer)msgflag);

	/* Message threading information */
	if (item->header.references)
		set_SPropValue_proptag(&props[i++], PR_INTERNET_REFERENCES, g_strdup (item->header.references));

	if (item->header.in_reply_to)
		set_SPropValue_proptag(&props[i++], PR_IN_REPLY_TO_ID, g_strdup (item->header.in_reply_to));

	if (item->header.message_id)
		set_SPropValue_proptag(&props[i++], PR_INTERNET_MESSAGE_ID, g_strdup (item->header.message_id));

	for (l = item->msg.body_parts; l; l = l->next) {
		ExchangeMAPIStream *stream = (ExchangeMAPIStream *) (l->data);
		struct SBinary_short *bin = g_new0 (struct SBinary_short, 1);

		bin->cb = stream->value->len;
		bin->lpb = (uint8_t *)stream->value->data;
		if (stream->proptag == PR_HTML)
			set_SPropValue_proptag(&props[i++], stream->proptag, (gpointer)bin);
		else if (stream->proptag == PR_BODY_UNICODE)
			set_SPropValue_proptag(&props[i++], stream->proptag, (gpointer)stream->value->data);
	}

	/*  FIXME : */
	/* editor = EDITOR_FORMAT_PLAINTEXT; */
	/* set_SPropValue_proptag(&props[i++], PR_MSG_EDITOR_FORMAT, (gconstpointer )editor); */

	*value = props;
	return i;
}

/* -- Generate MIME to ITEM -- */
