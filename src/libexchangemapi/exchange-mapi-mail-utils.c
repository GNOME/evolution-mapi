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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <camel/camel.h>

#include "exchange-mapi-defs.h"
#include "exchange-mapi-utils.h"
#include "exchange-mapi-cal-utils.h"
#include "exchange-mapi-mail-utils.h"

void
mail_item_free (MailItem *item)
{
	g_free (item->header.subject);
	g_free (item->header.from);

	g_free (item->header.to);
	g_free (item->header.cc);
	g_free (item->header.bcc);

	g_free (item->header.references);
	g_free (item->header.message_id);
	g_free (item->header.in_reply_to);

	exchange_mapi_util_free_attachment_list (&item->attachments);
	exchange_mapi_util_free_stream_list (&item->generic_streams);
	exchange_mapi_util_free_recipient_list (&item->recipients);

	g_free (item);
}

gboolean
fetch_props_to_mail_item_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	long *flags = NULL;
	struct FILETIME *delivery_date = NULL;
	const gchar *msg_class = NULL;
	ExchangeMAPIStream *body = NULL;

	MailItem *item;
	MailItem **i = (MailItem **)data;
	guint32 j = 0;

	g_return_val_if_fail (item_data != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);

	if (camel_debug_start("mapi:folder")) {
		exchange_mapi_debug_property_dump (item_data->properties);
		camel_debug_end();
	}

	item = g_new0 (MailItem , 1);
	item->fid = item_data->fid;
	item->mid = item_data->mid;

	/*Hold a reference to Recipient List*/
	item->recipients = item_data->recipients;

	for (j = 0; j < item_data->properties->cValues; j++) {

		gconstpointer prop_data = get_mapi_SPropValue_data(&item_data->properties->lpProps[j]);

		if (fetch_read_item_common_data (item, item_data->properties->lpProps[j].ulPropTag, prop_data))
			continue;

		switch (item_data->properties->lpProps[j].ulPropTag) {
		case PR_MESSAGE_CLASS:
		case PR_MESSAGE_CLASS_UNICODE:
			msg_class = (const gchar *) prop_data;
			break;
		case PR_MESSAGE_DELIVERY_TIME:
			delivery_date = (struct FILETIME *) prop_data;
			break;
		case PR_MESSAGE_FLAGS:
			flags = (long *) prop_data;
			break;
		default:
			break;
		}
	}

	item->is_cal = FALSE;
	if (msg_class && g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_PREFIX)) {
		guint8 *appointment_body_str = (guint8 *) exchange_mapi_cal_util_camel_helper (item_data->conn, item_data->fid, item_data->mid, NULL, msg_class,
												item_data->streams, item_data->recipients, item_data->attachments);

		if (appointment_body_str && *appointment_body_str) {
			body = g_new0(ExchangeMAPIStream, 1);
			body->proptag = PR_BODY_UNICODE;
			body->value = g_byte_array_new ();
			body->value = g_byte_array_append (body->value, appointment_body_str, strlen ((const gchar *)appointment_body_str));

			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);
			item->is_cal = TRUE;
		}

		g_free (appointment_body_str);
	}

	if (!item->is_cal) {
		/* always prefer unicode version, as that can be properly read */
		if (!(body = exchange_mapi_util_find_stream (item_data->streams, PR_BODY_UNICODE)))
			body = exchange_mapi_util_find_stream (item_data->streams, PR_BODY);

		if (body)
			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);

		body = exchange_mapi_util_find_stream (item_data->streams, PR_HTML);
		if (body)
			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);
	}

	if (delivery_date) {
		NTTIME ntdate = { 0 };

		ntdate = delivery_date->dwHighDateTime;
		ntdate = ntdate << 32;
		ntdate |= delivery_date->dwLowDateTime;
		item->header.recieved_time = nt_time_to_unix(ntdate);
	}

	if (flags && (*flags & MSGFLAG_READ) != 0)
		item->header.flags |= CAMEL_MESSAGE_SEEN;
	if (flags && (*flags & MSGFLAG_HASATTACH) != 0)
		item->header.flags |= CAMEL_MESSAGE_ATTACHMENTS;

	item->attachments = item_data->attachments;

	*i = item;

	return TRUE;
}

gboolean
fetch_read_item_common_data (MailItem *item, uint32_t propTag, gconstpointer prop_data)
{
	gboolean found = TRUE;

	#define sv(_x,_y) G_STMT_START { g_free (_x); _x = _y; } G_STMT_END

	switch (propTag) {
	case PR_INTERNET_CPID: {
		const uint32_t *ui32 = (const uint32_t *) prop_data;
		if (ui32)
			item->header.cpid = *ui32;
		} break;
	/* FIXME : Instead of duping. Use talloc_steal to reuse the memory */
	case PR_SUBJECT:
		sv (item->header.subject, utf8tolinux (prop_data));
		break;
	case PR_SUBJECT_UNICODE :
		sv (item->header.subject, g_strdup (prop_data));
		break;
	case PR_DISPLAY_TO :
		sv (item->header.to, utf8tolinux (prop_data));
		break;
	case PR_DISPLAY_TO_UNICODE :
		sv (item->header.to, g_strdup (prop_data));
		break;
	case PR_DISPLAY_CC:
		sv (item->header.cc, utf8tolinux (prop_data));
		break;
	case PR_DISPLAY_CC_UNICODE:
		sv (item->header.cc, g_strdup (prop_data));
		break;
	case PR_DISPLAY_BCC:
		sv (item->header.bcc, utf8tolinux (prop_data));
		break;
	case PR_DISPLAY_BCC_UNICODE:
		sv (item->header.bcc, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_NAME:
		sv (item->header.from, utf8tolinux (prop_data));
		break;
	case PR_SENT_REPRESENTING_NAME_UNICODE:
		sv (item->header.from, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
		sv (item->header.from_email, utf8tolinux (prop_data));
		break;
	case PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE:
		sv (item->header.from_email, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_ADDRTYPE:
		sv (item->header.from_type, utf8tolinux (prop_data));
		break;
	case PR_SENT_REPRESENTING_ADDRTYPE_UNICODE:
		sv (item->header.from_type, g_strdup (prop_data));
		break;
	case PR_MESSAGE_SIZE:
		item->header.size = *(glong *)prop_data;
		break;
	case PR_INTERNET_MESSAGE_ID:
		item->header.message_id = g_strdup (prop_data);
		break;
	case PR_INTERNET_REFERENCES:
		item->header.references = g_strdup (prop_data);
		break;
	case PR_IN_REPLY_TO_ID:
		item->header.in_reply_to = g_strdup (prop_data);
		break;
	case PR_TRANSPORT_MESSAGE_HEADERS:
		sv (item->header.transport_headers, utf8tolinux (prop_data));
		break;
	case PR_TRANSPORT_MESSAGE_HEADERS_UNICODE:
		sv (item->header.transport_headers, g_strdup (prop_data));
		break;
	default:
		found = FALSE;
		break;
	}

	#undef sv

	return found;
}

gboolean
mapi_mail_get_item_prop_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
{
	static const uint32_t item_props[] = {
		PR_FID,
		PR_MID,
		PR_INTERNET_CPID,

		PR_TRANSPORT_MESSAGE_HEADERS_UNICODE,
		PR_MESSAGE_CLASS,
		PR_MESSAGE_SIZE,
		PR_MESSAGE_FLAGS,
		PR_MESSAGE_DELIVERY_TIME,
		PR_MSG_EDITOR_FORMAT,

		PR_SUBJECT_UNICODE,
		PR_CONVERSATION_TOPIC_UNICODE,

		/*Properties used for message threading.*/
		PR_INTERNET_MESSAGE_ID,
		PR_INTERNET_REFERENCES,
		PR_IN_REPLY_TO_ID,

		PR_BODY,
		PR_BODY_UNICODE,
		PR_HTML,
		/*Fixme : If this property is fetched, it garbles everything else. */
		/*PR_BODY_HTML, */
		/*PR_BODY_HTML_UNICODE, */

		PR_DISPLAY_TO_UNICODE,
		PR_DISPLAY_CC_UNICODE,
		PR_DISPLAY_BCC_UNICODE,

		PR_CREATION_TIME,
		PR_LAST_MODIFICATION_TIME,
		PR_PRIORITY,
		PR_SENSITIVITY,
		PR_START_DATE,
		PR_END_DATE,
		PR_RESPONSE_REQUESTED,
		PR_OWNER_APPT_ID,
		PR_PROCESSED,

		PR_SENT_REPRESENTING_NAME_UNICODE,
		PR_SENT_REPRESENTING_ADDRTYPE_UNICODE,
		PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE,

		PR_SENDER_NAME_UNICODE,
		PR_SENDER_ADDRTYPE_UNICODE,
		PR_SENDER_EMAIL_ADDRESS_UNICODE,

		PR_RCVD_REPRESENTING_NAME_UNICODE,
		PR_RCVD_REPRESENTING_ADDRTYPE_UNICODE,
		PR_RCVD_REPRESENTING_EMAIL_ADDRESS_UNICODE
	};

	g_return_val_if_fail (props != NULL, FALSE);

	return exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, item_props, G_N_ELEMENTS (item_props));
}


static void
mapi_mime_set_recipient_list (CamelMimeMessage *msg, MailItem *item)
{
	GSList *l = NULL;
	CamelInternetAddress *to_addr, *cc_addr, *bcc_addr;

	g_return_if_fail (item->recipients != NULL);

	to_addr = camel_internet_address_new ();
	cc_addr = camel_internet_address_new ();
	bcc_addr = camel_internet_address_new ();

	for (l = item->recipients; l; l=l->next) {
		gchar *display_name;
		const gchar *name = NULL;
		uint32_t rcpt_type = MAPI_TO;
		uint32_t *type = NULL;
		struct SRow *aRow;
		ExchangeMAPIRecipient *recip = (ExchangeMAPIRecipient *)(l->data);

		/*Can't continue when there is no email-id*/
		if (!recip->email_id)
			continue;

		/* Build a SRow structure */
		aRow = &recip->out_SRow;

		/*Name is probably available in one of these props.*/
		name = (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_DISPLAY_NAME_UNICODE);
		name = name ? name : (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
		name = name ? name : (const gchar *) exchange_mapi_util_find_row_propval (aRow, PR_7BIT_DISPLAY_NAME_UNICODE);

		type = (uint32_t *) exchange_mapi_util_find_row_propval (aRow, PR_RECIPIENT_TYPE);

		/*Fallbacks. Not good*/
		display_name = name ? g_strdup (name) : g_strdup (recip->email_id);
		rcpt_type = (type ? *type : MAPI_TO);

		switch (rcpt_type) {
		case MAPI_TO:
			camel_internet_address_add (to_addr, display_name, recip->email_id);
			break;
		case MAPI_CC:
			camel_internet_address_add (cc_addr, display_name, recip->email_id);
			break;
		case MAPI_BCC:
			camel_internet_address_add (bcc_addr, display_name, recip->email_id);
			break;
		}

		g_free (display_name);
	}

	/*Add to message*/
	/*Note : To field is added from PR_TRANSPORT_MESSAGE_HEADERS
	  But, in sent_items folder we don't get TRANSPORT_MESSAGE_HEADERS */
	if (!item->header.transport_headers) {
		camel_mime_message_set_recipients(msg, "To", to_addr);
		camel_mime_message_set_recipients(msg, "Cc", cc_addr);
		camel_mime_message_set_recipients(msg, "Bcc", bcc_addr);
	}

	/*TODO : Unref *_addr ? */
}

static void
mapi_mime_set_msg_headers (ExchangeMapiConnection *conn, CamelMimeMessage *msg, MailItem *item)
{
	gchar *temp_str = NULL;
	const gchar *from_email;
	time_t recieved_time;
	CamelInternetAddress *addr = NULL;
	gint offset = 0;
	time_t actual_time;

	/* Setting headers from PR_TRANSPORT_MESSAGE_HEADERS */
	if (item->header.transport_headers) {
		CamelMimePart *part = camel_mime_part_new ();
		CamelStream *stream;
		CamelMimeParser *parser;

		stream = camel_stream_mem_new_with_buffer (item->header.transport_headers, strlen (item->header.transport_headers));
		parser = camel_mime_parser_new ();
		camel_mime_parser_init_with_stream (parser, stream, NULL);
		camel_mime_parser_scan_from (parser, FALSE);
		g_object_unref (stream);

		if (camel_mime_part_construct_from_parser (part, parser, NULL) != -1) {
			struct _camel_header_raw *h;

			for (h = part->headers; h; h = h->next) {
				const gchar *value = h->value;

				/* skip all headers describing content of a message,
				   because it's overwritten on message decomposition */
				if (g_ascii_strncasecmp (h->name, "Content", 7) == 0)
					continue;

				while (value && camel_mime_is_lwsp (*value))
					value++;

				camel_medium_add_header (CAMEL_MEDIUM (msg), h->name, value);
			}
		}

		g_object_unref (parser);
		g_object_unref (part);
	}

	/* Overwrite headers if we have specific properties available*/
	temp_str = item->header.subject;
	if (temp_str)
		camel_mime_message_set_subject (msg, temp_str);

	recieved_time = item->header.recieved_time;

	actual_time = camel_header_decode_date (ctime(&recieved_time), &offset);
	/* camel_mime_message_set_date (msg, actual_time, offset); */

	if (item->header.from) {
		if ((item->header.from_type != NULL) && !g_utf8_collate (item->header.from_type, "EX")) {
			from_email = exchange_mapi_connection_ex_to_smtp (conn, item->header.from_email);
			g_free (item->header.from_email);
			item->header.from_email = g_strdup (from_email);
		}

		item->header.from_email = item->header.from_email ?
			item->header.from_email : item->header.from;

		/* add reply to */
		addr = camel_internet_address_new();
		camel_internet_address_add(addr, item->header.from, item->header.from_email);
		camel_mime_message_set_reply_to(msg, addr);

		/* add from */
		addr = camel_internet_address_new();
		camel_internet_address_add(addr, item->header.from, item->header.from_email);
		camel_mime_message_set_from(msg, addr);
	}

	/* Threading */
	if (item->header.message_id)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "Message-ID", item->header.message_id);

	if (item->header.references)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "References", item->header.references);

	if (item->header.in_reply_to)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "In-Reply-To", item->header.in_reply_to);

}

static CamelMimePart *
mapi_mime_msg_body (MailItem *item, const ExchangeMAPIStream *body)
{
	CamelMimePart *part = camel_mime_part_new ();
	camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_8BIT);

	if (body && body->value && body->value->len > 0) {
		const gchar *type = NULL;
		gchar *buff = NULL;

		if (item->is_cal)
			type = "text/calendar";
		else
			type = (body->proptag == PR_BODY || body->proptag == PR_BODY_UNICODE) ?
				"text/plain" : "text/html";

		if (item->header.cpid && (body->proptag & 0xFFFF) != PT_UNICODE) {
			if (item->header.cpid == 20127)
				buff = g_strdup_printf ("%s; charset=\"us-ascii\"", type);
			else if (item->header.cpid >= 28591 && item->header.cpid <= 28599)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-%d\"", type, item->header.cpid % 10);
			else if (item->header.cpid == 28603)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-13\"", type);
			else if (item->header.cpid == 28605)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-15\"", type);
			else if (item->header.cpid == 65000)
				buff = g_strdup_printf ("%s; charset=\"UTF-7\"", type);
			else if (item->header.cpid == 65001)
				buff = g_strdup_printf ("%s; charset=\"UTF-8\"", type);
			else
				buff = g_strdup_printf ("%s; charset=\"CP%d\"", type, item->header.cpid);
			type = buff;
		}

		camel_mime_part_set_content (part, (const gchar *) body->value->data, body->value->len, type);

		g_free (buff);
	} else
		camel_mime_part_set_content (part, " ", strlen (" "), "text/plain");

	return part;
}

#if 0

/* GCompareFunc. Used for ordering body types in a GSList.*/
static gint
sort_bodies_cb (gconstpointer a, gconstpointer b)
{
	static const gint desired_order[] = { PR_BODY, PR_BODY_UNICODE, PR_HTML };
	const ExchangeMAPIStream *stream_a = a, *stream_b = b;
	gint aidx, bidx;

	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	for (aidx = 0; aidx < G_N_ELEMENTS (desired_order); aidx++) {
		if (desired_order[aidx] == stream_a->proptag)
			break;
	}

	for (bidx = 0; bidx < G_N_ELEMENTS (desired_order); bidx++) {
		if (desired_order[bidx] == stream_b->proptag)
			break;
	}

	return aidx - bidx;
}

#endif

/* Adds parts to multipart. Convenience function. */
static void
mapi_mime_multipart_add_attachments (CamelMultipart *multipart, GSList *attachs)
{
	CamelMimePart *part;
	while (attachs) {
		part = attachs->data;
		camel_multipart_add_part (multipart, part);
		g_object_unref (part);
		attachs = attachs->next;
	}
}

/* Process body stream and related objects into a MIME mulitpart */
static CamelMultipart *
mapi_mime_build_multipart_related (MailItem *item, const ExchangeMAPIStream *stream,
				   GSList *inline_attachs)
{
	CamelMimePart *part;
	CamelMultipart *m_related = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_related), "multipart/related");
	camel_multipart_set_boundary (m_related, NULL);

	part = mapi_mime_msg_body (item, stream);
	camel_multipart_add_part (m_related, part);
	g_object_unref (part);

	mapi_mime_multipart_add_attachments (m_related, inline_attachs);

	return m_related;
}

/* Process multiple body types and pack them in a MIME mulitpart */
static CamelMultipart *
mapi_mime_build_multipart_alternative (MailItem *item, GSList *body_parts, GSList *inline_attachs)
{
	CamelMimePart *part;
	CamelMultipart *m_alternative = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_alternative),
					  "multipart/alternative");
	camel_multipart_set_boundary (m_alternative, NULL);

	while (body_parts) {
		const ExchangeMAPIStream *stream = (ExchangeMAPIStream *) body_parts->data;
		part = camel_mime_part_new ();
		if ((stream->proptag == PR_HTML || stream->proptag == PR_BODY_HTML_UNICODE)
		    && inline_attachs) {
			CamelMultipart *m_related;
			m_related = mapi_mime_build_multipart_related (item, stream,
								       inline_attachs);
			camel_medium_set_content (CAMEL_MEDIUM (part),
						  CAMEL_DATA_WRAPPER (m_related));
			g_object_unref (m_related);
		} else
			part = mapi_mime_msg_body (item, stream);

		camel_multipart_add_part (m_alternative, part);
		g_object_unref (part);
	}

	return m_alternative;
}

static CamelMultipart *
mapi_mime_build_multipart_mixed (CamelMultipart *content, GSList *attachs)
{
	CamelMimePart *part = camel_mime_part_new ();
	CamelMultipart *m_mixed = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_mixed),
					  "multipart/mixed");
	camel_multipart_set_boundary (m_mixed, NULL);

	camel_medium_set_content (CAMEL_MEDIUM (part), CAMEL_DATA_WRAPPER (content));
	camel_multipart_add_part (m_mixed, part);

	if (attachs)
		mapi_mime_multipart_add_attachments (m_mixed, attachs);

	return m_mixed;
}

static gboolean
is_apple_attachment (ExchangeMAPIAttachment *attach, guint32 *data_len, guint32 *resource_len)
{
	gboolean is_apple = FALSE;
	ExchangeMAPIStream *enc_stream = exchange_mapi_util_find_stream (attach->streams, PR_ATTACH_ENCODING);
	guint8 apple_enc_magic[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0B, 0x01 };

	if (enc_stream && enc_stream->value && enc_stream->value->len == G_N_ELEMENTS (apple_enc_magic)) {
		gint idx;

		is_apple = TRUE;
		for (idx = 0; idx < enc_stream->value->len && is_apple; idx++) {
			is_apple = apple_enc_magic[idx] == enc_stream->value->data[idx];
		}
	} else {
		const struct Binary_r *bin = exchange_mapi_util_find_SPropVal_array_propval (attach->lpProps, PR_ATTACH_ENCODING);
		if (bin && bin->cb == G_N_ELEMENTS (apple_enc_magic)) {
			gint idx;

			is_apple = TRUE;
			for (idx = 0; idx < bin->cb && is_apple; idx++) {
				is_apple = apple_enc_magic[idx] == bin->lpb[idx];
			}
		}
	}

	if (is_apple) {
		/* check boundaries too */
		ExchangeMAPIStream *data_stream = exchange_mapi_util_find_stream (attach->streams, PR_ATTACH_DATA_BIN);

		is_apple = data_stream && data_stream->value && data_stream->value->len > 128;

		if (is_apple) {
			const guint8 *bin = data_stream->value->data;

			/* in big-endian format */
			*data_len = (bin[83] << 24) | (bin[84] << 16) | (bin[85] << 8) | (bin[86]);
			*resource_len = (bin[87] << 24) | (bin[88] << 16) | (bin[89] << 8) | (bin[90]);

			/* +/- mod 128 (but the first 128 is a header length) */
			is_apple = 128 + *data_len + *resource_len <= data_stream->value->len && bin[1] < 64;
		}
	}

	return is_apple;
}

/*Takes raw attachment streams and converts to MIME Parts. Parts are added to
  either inline / non-inline lists.*/
static void
mapi_mime_classify_attachments (ExchangeMapiConnection *conn, mapi_id_t fid, GSList *attachments, GSList **inline_attachs, GSList **noninline)
{
	for (;attachments != NULL; attachments = attachments->next) {
		ExchangeMAPIAttachment *attach = (ExchangeMAPIAttachment *)attachments->data;
		ExchangeMAPIStream *stream = NULL;
		const gchar *filename, *mime_type, *content_id = NULL;
		CamelContentType *content_type;
		CamelMimePart *part;
		const uint32_t *ui32;
		gboolean is_apple;
		guint32 apple_data_len = 0, apple_resource_len = 0;

		stream = exchange_mapi_util_find_stream (attach->streams, PR_ATTACH_DATA_BIN);

		if (!stream || stream->value->len <= 0) {
			continue;
		}

		is_apple = is_apple_attachment (attach, &apple_data_len, &apple_resource_len);

		/*Content-Type*/
		ui32 = (const uint32_t *) exchange_mapi_util_find_SPropVal_array_propval (attach->lpProps, PR_ATTACH_METHOD);
		if (ui32 && *ui32 == ATTACH_EMBEDDED_MSG) {
			mime_type = "message/rfc822";
		} else {
			mime_type = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (attach->lpProps, PR_ATTACH_MIME_TAG);
			if (!mime_type)
				mime_type = "application/octet-stream";
		}

		if (is_apple) {
			mime_type = "application/applefile";
		} else if (strstr (mime_type, "apple") != NULL) {
			mime_type = "application/octet-stream";
		}

		part = camel_mime_part_new ();

		filename = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps,
											 PR_ATTACH_LONG_FILENAME_UNICODE);

		if (!(filename && *filename))
			filename = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps,
												 PR_ATTACH_FILENAME_UNICODE);
		camel_mime_part_set_filename (part, filename);
		camel_content_type_set_param (((CamelDataWrapper *) part)->mime_type, "name", filename);

		if (is_apple) {
			ExchangeMAPIStream *strm;
			CamelMultipart *mp;
			uint32_t proptag;
			gchar *apple_filename;

			mp = camel_multipart_new ();
			camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (mp), "multipart/appledouble");
			camel_multipart_set_boundary (mp, NULL);

			camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);

			strm = NULL;
			proptag = exchange_mapi_connection_resolve_named_prop (conn, fid, PidNameAttachmentMacInfo);
			if (proptag != MAPI_E_RESERVED)
				strm = exchange_mapi_util_find_stream (attach->streams, proptag);
			if (!strm)
				strm = exchange_mapi_util_find_stream (attach->streams, PidNameAttachmentMacInfo);

			if (strm && strm->value && strm->value->len > 0) {
				camel_mime_part_set_content (part, (const gchar *) strm->value->data, strm->value->len, mime_type);
			} else {
				/* RFC 1740 */
				guint8 header[] = {
					0x00, 0x05, 0x16, 0x07, /* magic */
					0x00, 0x02, 0x00, 0x00, /* version */
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* filler */
					0x00, 0x01, /* number of entries */
					0x00, 0x00, 0x00, 0x02, /* entry ID - resource fork */
					0x00, 0x00, 0x00, 0x26, /* entry offset - 38th byte*/
					0x00, 0x00, 0x00, 0x00  /* entry length */
				};

				GByteArray *arr = g_byte_array_sized_new (apple_resource_len + G_N_ELEMENTS (header));

				header[34] = (apple_resource_len >> 24) & 0xFF;
				header[35] = (apple_resource_len >> 16) & 0xFF;
				header[36] = (apple_resource_len >>  8) & 0xFF;
				header[37] = (apple_resource_len      ) & 0xFF;

				g_byte_array_append (arr, header, G_N_ELEMENTS (header));
				g_byte_array_append (arr, stream->value->data + 128 + apple_data_len + (apple_data_len % 128), apple_resource_len);

				camel_mime_part_set_content (part, (const gchar *) arr->data, arr->len, mime_type);

				g_byte_array_free (arr, TRUE);
			}

			camel_multipart_add_part (mp, part);
			g_object_unref (part);

			part = camel_mime_part_new ();

			apple_filename = g_strndup ((gchar *)stream->value->data + 2, stream->value->data[1]);
			camel_mime_part_set_filename (part, (apple_filename && *apple_filename) ? apple_filename : filename);
			g_free (apple_filename);

			mime_type = exchange_mapi_util_find_SPropVal_array_namedid (attach->lpProps, conn, fid, PidNameAttachmentMacContentType);
			if (!mime_type)
				mime_type = "application/octet-stream";

			camel_mime_part_set_content (part, (const gchar *) stream->value->data + 128, apple_data_len, mime_type);
			camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);
			camel_multipart_add_part (mp, part);
			g_object_unref (part);

			part = camel_mime_part_new ();
			camel_medium_set_content (CAMEL_MEDIUM (part), CAMEL_DATA_WRAPPER (mp));
			g_object_unref (mp);
		} else {
			camel_mime_part_set_content (part, (const gchar *) stream->value->data, stream->value->len, mime_type);

			content_type = camel_mime_part_get_content_type (part);
			if (content_type && camel_content_type_is (content_type, "text", "*"))
				camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_QUOTEDPRINTABLE);
			else if (!ui32 || *ui32 != ATTACH_EMBEDDED_MSG)
				camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);
		}

		/*Content-ID*/
		content_id = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval(attach->lpProps,
											   PR_ATTACH_CONTENT_ID);
		/* TODO : Add disposition */
		if (content_id && !is_apple) {
			camel_mime_part_set_content_id (part, content_id);
			*inline_attachs = g_slist_append (*inline_attachs, part);
		} else
			*noninline = g_slist_append (*noninline, part);
	}
}

CamelMimeMessage *
mapi_mail_item_to_mime_message (ExchangeMapiConnection *conn, MailItem *item)
{
	CamelMimeMessage *msg = NULL;
	CamelMultipart *multipart_body = NULL;

	GSList *attach_list = NULL;
	GSList *inline_attachs =  NULL; /*Used for mulitpart/related*/
	GSList *noninline_attachs = NULL;

	gboolean build_alternative = FALSE;
	gboolean build_related = FALSE;

	g_return_val_if_fail (conn != NULL, NULL);
	g_return_val_if_fail (item != NULL, NULL);

	attach_list = item->attachments;
	msg = camel_mime_message_new ();

	mapi_mime_set_recipient_list (msg, item);
	mapi_mime_set_msg_headers (conn, msg, item);
	mapi_mime_classify_attachments (conn, item->fid, attach_list, &inline_attachs, &noninline_attachs);

	build_alternative = (g_slist_length (item->msg.body_parts) > 1) && inline_attachs;
	build_related = !build_alternative && inline_attachs;

	if (build_alternative) {
		multipart_body = mapi_mime_build_multipart_alternative (item, item->msg.body_parts,
									inline_attachs);
	} else if (build_related) {
		multipart_body = mapi_mime_build_multipart_related (item,
								    item->msg.body_parts->data,
								    inline_attachs);
	} else { /* Simple multipart/mixed */
		CamelMimePart *part;
		multipart_body = camel_multipart_new ();
		camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (multipart_body),
						  "multipart/mixed");
		camel_multipart_set_boundary (multipart_body, NULL);
		part = mapi_mime_msg_body (item, item->msg.body_parts ? item->msg.body_parts->data : NULL);
		camel_multipart_add_part (multipart_body, part);
		g_object_unref (part);
	}

	if (noninline_attachs) { /* multipart/mixed */
		multipart_body = mapi_mime_build_multipart_mixed (multipart_body,
								  noninline_attachs);
	}

	camel_medium_set_content (CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER(multipart_body));
	g_object_unref (multipart_body);

	return msg;
}
