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
#include <libecal/e-cal-util.h>

#include "e-mapi-defs.h"
#include "e-mapi-utils.h"
#include "e-mapi-cal-utils.h"
#include "e-mapi-mail-utils.h"

extern gint camel_application_is_exiting;

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
	g_free (item->header.content_class);
	g_free (item->header.transport_headers);

	e_mapi_util_free_attachment_list (&item->attachments);
	e_mapi_util_free_stream_list (&item->generic_streams);
	e_mapi_util_free_recipient_list (&item->recipients);

	g_free (item->msg_class);
	g_free (item->pid_name_content_type);

	g_free (item);
}

gboolean
fetch_props_to_mail_item_cb (FetchItemsCallbackData *item_data,
			     gpointer data,
			     GCancellable *cancellable,
			     GError **perror)
{
	long *flags = NULL;
	struct FILETIME *delivery_date = NULL;
	const gchar *msg_class = NULL, *content_class = NULL;
	ExchangeMAPIStream *body = NULL;
	uint32_t content_class_pid;

	MailItem *item;
	MailItem **i = (MailItem **)data;
	guint32 j = 0;

	g_return_val_if_fail (item_data != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);

	if (camel_debug_start("mapi:folder")) {
		e_mapi_debug_dump_properties (item_data->conn, item_data->fid, item_data->properties, 3);
		camel_debug_end();
	}

	content_class_pid = e_mapi_connection_resolve_named_prop (item_data->conn, item_data->fid, PidNameContentClass, cancellable, perror);
	if (content_class_pid == MAPI_E_RESERVED)
		content_class_pid = 0;

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
			if (content_class_pid != 0 && item_data->properties->lpProps[j].ulPropTag == content_class_pid)
				content_class = (const gchar *) prop_data;
			break;
		}
	}

	item->msg_class = g_strdup (msg_class);
	item->header.content_class = g_strdup (content_class);

	item->is_cal = FALSE;
	if (msg_class && g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_PREFIX)) {
		guint8 *appointment_body_str = (guint8 *) e_mapi_cal_util_camel_helper (item_data->conn, item_data->fid, item_data->mid, NULL, msg_class,
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
		if (!(body = e_mapi_util_find_stream (item_data->streams, PR_BODY_UNICODE)))
			body = e_mapi_util_find_stream (item_data->streams, PR_BODY);

		if (body)
			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);

		body = e_mapi_util_find_stream (item_data->streams, PR_HTML);
		if (body)
			item->msg.body_parts = g_slist_append (item->msg.body_parts, body);
	}

	if (delivery_date) {
		item->header.recieved_time = e_mapi_util_filetime_to_time_t (delivery_date);
	}

	if (flags && (*flags & MSGFLAG_READ) != 0)
		item->header.flags |= CAMEL_MESSAGE_SEEN;
	if (flags && (*flags & MSGFLAG_HASATTACH) != 0)
		item->header.flags |= CAMEL_MESSAGE_ATTACHMENTS;

	item->attachments = item_data->attachments;

	*i = item;

	if (camel_application_is_exiting)
		return FALSE;

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
		sv (item->header.subject, g_strdup (prop_data));
		break;
	case PR_SUBJECT_UNICODE :
		sv (item->header.subject, g_strdup (prop_data));
		break;
	case PR_DISPLAY_TO :
		sv (item->header.to, g_strdup (prop_data));
		break;
	case PR_DISPLAY_TO_UNICODE :
		sv (item->header.to, g_strdup (prop_data));
		break;
	case PR_DISPLAY_CC:
		sv (item->header.cc, g_strdup (prop_data));
		break;
	case PR_DISPLAY_CC_UNICODE:
		sv (item->header.cc, g_strdup (prop_data));
		break;
	case PR_DISPLAY_BCC:
		sv (item->header.bcc, g_strdup (prop_data));
		break;
	case PR_DISPLAY_BCC_UNICODE:
		sv (item->header.bcc, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_NAME:
		sv (item->header.from, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_NAME_UNICODE:
		sv (item->header.from, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_EMAIL_ADDRESS:
		sv (item->header.from_email, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE:
		sv (item->header.from_email, g_strdup (prop_data));
		break;
	case PR_SENT_REPRESENTING_ADDRTYPE:
		sv (item->header.from_type, g_strdup (prop_data));
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
		sv (item->header.transport_headers, g_strdup (prop_data));
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
mapi_mail_get_item_prop_list (EMapiConnection *conn,
			      mapi_id_t fid,
			      TALLOC_CTX *mem_ctx,
			      struct SPropTagArray *props,
			      gpointer data,
			      GCancellable *cancellable,
			      GError **perror)
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

	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData nids[] = {
		{ PidNameContentClass, 0 }
	};

	g_return_val_if_fail (props != NULL, FALSE);

	if (!e_mapi_utils_add_props_to_props_array (mem_ctx, props, item_props, G_N_ELEMENTS (item_props)))
		return FALSE;

	return e_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids), cancellable, perror);
}

static gboolean
name_is_email_user (const gchar *name, const gchar *email_id)
{
	gint name_len, email_len;

	if (!name || !email_id)
		return FALSE;

	if (!*name || !*email_id || g_ascii_strcasecmp (email_id, name) == 0)
		return TRUE;

	name_len = strlen (name);
	email_len = strlen (email_id);

	return name_len < email_len && g_ascii_strncasecmp (email_id, name, name_len) == 0 && email_id[name_len] == '@';
}

static void
mapi_mime_set_recipient_list (EMapiConnection *conn, CamelMimeMessage *msg, MailItem *item)
{
	GSList *l = NULL;
	CamelInternetAddress *to_addr, *cc_addr, *bcc_addr;

	if (!item->recipients || item->header.transport_headers)
		return;

	to_addr = camel_internet_address_new ();
	cc_addr = camel_internet_address_new ();
	bcc_addr = camel_internet_address_new ();

	for (l = item->recipients; l; l=l->next) {
		gchar *display_name = NULL;
		const gchar *name = NULL;
		uint32_t rcpt_type = MAPI_TO;
		uint32_t *type = NULL;
		struct SRow *aRow;
		ExchangeMAPIRecipient *recip = (ExchangeMAPIRecipient *)(l->data);

		/* Build a SRow structure */
		aRow = &recip->out_SRow;

		/*Name is probably available in one of these props.*/
		name = recip->display_name;
		name = name ? name : e_mapi_util_find_row_propval (aRow, PR_DISPLAY_NAME_UNICODE);
		name = name ? name : e_mapi_util_find_row_propval (aRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
		if (!name) {
			name = e_mapi_util_find_row_propval (aRow, PR_7BIT_DISPLAY_NAME_UNICODE);
			if (name && !strchr (name, '@')) {
				gchar *to_free;

				to_free = e_mapi_connection_ex_to_smtp (conn, recip->email_id, &display_name, NULL, NULL);
				g_free (to_free);
			}
		}

		type = (uint32_t *) e_mapi_util_find_row_propval (aRow, PR_RECIPIENT_TYPE);

		if (!display_name && name && (!recip->email_id || !name_is_email_user (name, recip->email_id)))
			display_name = g_strdup (name);
		rcpt_type = (type ? *type : MAPI_TO);

		if (!display_name && (!recip->email_id || !*recip->email_id))
			break;

		switch (rcpt_type) {
		case MAPI_TO:
			camel_internet_address_add (to_addr, display_name, recip->email_id ? recip->email_id : "");
			break;
		case MAPI_CC:
			camel_internet_address_add (cc_addr, display_name, recip->email_id ? recip->email_id : "");
			break;
		case MAPI_BCC:
			camel_internet_address_add (bcc_addr, display_name, recip->email_id ? recip->email_id : "");
			break;
		}

		g_free (display_name);
	}

	if (l != NULL) {
		/* some recipient didn't have set email or
		   display name, fallback to PR_DISPLAY_TO/_CC/_BCC */
		camel_address_remove (CAMEL_ADDRESS (to_addr), -1);
		camel_address_remove (CAMEL_ADDRESS (cc_addr), -1);
		camel_address_remove (CAMEL_ADDRESS (bcc_addr), -1);

		if (item->header.to && *item->header.to)
			camel_address_decode (CAMEL_ADDRESS (to_addr), item->header.to);
		if (item->header.cc && *item->header.cc)
			camel_address_decode (CAMEL_ADDRESS (cc_addr), item->header.cc);
		if (item->header.bcc && *item->header.bcc)
			camel_address_decode (CAMEL_ADDRESS (bcc_addr), item->header.bcc);
	}

	/*Add to message*/
	camel_mime_message_set_recipients (msg, "To", to_addr);
	camel_mime_message_set_recipients (msg, "Cc", cc_addr);
	camel_mime_message_set_recipients (msg, "Bcc", bcc_addr);

	g_object_unref (to_addr);
	g_object_unref (cc_addr);
	g_object_unref (bcc_addr);
}

static void
mapi_mime_set_msg_headers (EMapiConnection *conn, CamelMimeMessage *msg, MailItem *item)
{
	gchar *temp_str = NULL;
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

		if (camel_mime_part_construct_from_parser_sync (part, parser, NULL, NULL)) {
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
	} else {
		recieved_time = item->header.recieved_time;
		actual_time = camel_header_decode_date (ctime(&recieved_time), &offset);
		camel_mime_message_set_date (msg, actual_time, offset);
	}

	if (item->header.content_class)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "Content-class", item->header.content_class);

	/* Overwrite headers if we have specific properties available*/
	temp_str = item->header.subject;
	if (temp_str)
		camel_mime_message_set_subject (msg, temp_str);

	if (item->header.from) {
		if ((item->header.from_type != NULL) && !g_utf8_collate (item->header.from_type, "EX")) {
			gchar *from_email;

			from_email = e_mapi_connection_ex_to_smtp (conn, item->header.from_email, NULL, NULL, NULL);
			g_free (item->header.from_email);
			item->header.from_email = from_email;
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
		gboolean strip_last_null;

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

		strip_last_null = body->value->len > 0 && body->value->data[body->value->len - 1] == '\0';
		camel_mime_part_set_content (part, (const gchar *) body->value->data, body->value->len + (strip_last_null ? -1 : 0), type);

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
		if ((stream->proptag == PR_HTML)
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

		body_parts = body_parts->next;
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
	ExchangeMAPIStream *enc_stream = e_mapi_util_find_stream (attach->streams, PR_ATTACH_ENCODING);
	guint8 apple_enc_magic[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0B, 0x01 };

	if (enc_stream && enc_stream->value && enc_stream->value->len == G_N_ELEMENTS (apple_enc_magic)) {
		gint idx;

		is_apple = TRUE;
		for (idx = 0; idx < enc_stream->value->len && is_apple; idx++) {
			is_apple = apple_enc_magic[idx] == enc_stream->value->data[idx];
		}
	} else {
		const struct Binary_r *bin = e_mapi_util_find_SPropVal_array_propval (attach->lpProps, PR_ATTACH_ENCODING);
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
		ExchangeMAPIStream *data_stream = e_mapi_util_find_stream (attach->streams, PR_ATTACH_DATA_BIN);

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
mapi_mime_classify_attachments (EMapiConnection *conn, mapi_id_t fid, const gchar *msg_class, GSList *attachments, GSList **inline_attachs, GSList **noninline)
{
	/* SMIME encrypted are without ending dot */
	gboolean is_smime = msg_class && strstr (msg_class, ".SMIME.") > msg_class;

	for (;attachments != NULL; attachments = attachments->next) {
		ExchangeMAPIAttachment *attach = (ExchangeMAPIAttachment *)attachments->data;
		ExchangeMAPIStream *stream = NULL;
		const gchar *filename, *mime_type, *content_id = NULL;
		CamelContentType *content_type;
		CamelMimePart *part;
		const uint32_t *ui32;
		gboolean is_apple;
		guint32 apple_data_len = 0, apple_resource_len = 0;

		stream = e_mapi_util_find_stream (attach->streams, PR_ATTACH_DATA_BIN);

		if (!stream || stream->value->len <= 0) {
			continue;
		}

		is_apple = is_apple_attachment (attach, &apple_data_len, &apple_resource_len);

		/*Content-Type*/
		ui32 = (const uint32_t *) e_mapi_util_find_SPropVal_array_propval (attach->lpProps, PR_ATTACH_METHOD);
		if (ui32 && *ui32 == ATTACH_EMBEDDED_MSG) {
			mime_type = "message/rfc822";
		} else {
			mime_type = (const gchar *) e_mapi_util_find_SPropVal_array_propval (attach->lpProps, PR_ATTACH_MIME_TAG);
			if (!mime_type)
				mime_type = "application/octet-stream";
		}

		if (is_apple) {
			mime_type = "application/applefile";
		} else if (strstr (mime_type, "apple") != NULL) {
			mime_type = "application/octet-stream";
		}

		part = camel_mime_part_new ();

		filename = (const gchar *) e_mapi_util_find_SPropVal_array_propval(attach->lpProps,
											 PR_ATTACH_LONG_FILENAME_UNICODE);

		if (!(filename && *filename))
			filename = (const gchar *) e_mapi_util_find_SPropVal_array_propval(attach->lpProps,
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
			proptag = e_mapi_connection_resolve_named_prop (conn, fid, PidNameAttachmentMacInfo, NULL, NULL);
			if (proptag != MAPI_E_RESERVED)
				strm = e_mapi_util_find_stream (attach->streams, proptag);
			if (!strm)
				strm = e_mapi_util_find_stream (attach->streams, PidNameAttachmentMacInfo);

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

			mime_type = e_mapi_util_find_SPropVal_array_namedid (attach->lpProps, conn, fid, PidNameAttachmentMacContentType);
			if (!mime_type)
				mime_type = "application/octet-stream";

			camel_mime_part_set_content (part, (const gchar *) stream->value->data + 128, apple_data_len, mime_type);
			camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);
			camel_multipart_add_part (mp, part);
			g_object_unref (part);

			part = camel_mime_part_new ();
			camel_medium_set_content (CAMEL_MEDIUM (part), CAMEL_DATA_WRAPPER (mp));
			g_object_unref (mp);
		} else if (is_smime) {
			CamelMimeParser *parser;
			CamelStream *mem;

			mem = camel_stream_mem_new ();
			camel_stream_write (mem, (const gchar *) stream->value->data, stream->value->len, NULL, NULL);
			g_seekable_seek (G_SEEKABLE (mem), 0, G_SEEK_SET, NULL, NULL);

			parser = camel_mime_parser_new ();
			camel_mime_parser_scan_from (parser, FALSE);
			camel_mime_parser_scan_pre_from (parser, FALSE);
			camel_mime_parser_init_with_stream (parser, mem, NULL);

			if (camel_mime_parser_step (parser, NULL, NULL) == CAMEL_MIME_PARSER_STATE_HEADER
			    && camel_mime_parser_content_type (parser) != NULL) {
				g_object_unref (part);
				part = camel_mime_part_new ();

				camel_data_wrapper_set_mime_type_field (CAMEL_DATA_WRAPPER (part), camel_mime_parser_content_type (parser));
				camel_mime_part_construct_content_from_parser (part, parser, NULL, NULL);
			} else {
				is_smime = FALSE;
			}

			g_object_unref (parser);
			g_object_unref (mem);
		} 

		if (!is_smime && !is_apple) {
			camel_mime_part_set_content (part, (const gchar *) stream->value->data, stream->value->len, mime_type);

			content_type = camel_mime_part_get_content_type (part);
			if (content_type && camel_content_type_is (content_type, "text", "*"))
				camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_QUOTEDPRINTABLE);
			else if (!ui32 || *ui32 != ATTACH_EMBEDDED_MSG)
				camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);
		}

		/*Content-ID*/
		content_id = (const gchar *) e_mapi_util_find_SPropVal_array_propval(attach->lpProps,
											   PR_ATTACH_CONTENT_ID);
		/* TODO : Add disposition */
		if (content_id && !is_apple && !is_smime) {
			camel_mime_part_set_content_id (part, content_id);
			*inline_attachs = g_slist_append (*inline_attachs, part);
		} else
			*noninline = g_slist_append (*noninline, part);
	}
}

CamelMimeMessage *
mapi_mail_item_to_mime_message (EMapiConnection *conn, MailItem *item)
{
	CamelMimeMessage *msg = NULL;
	CamelMultipart *multipart_body = NULL;

	GSList *attach_list = NULL;
	GSList *inline_attachs =  NULL; /*Used for mulitpart/related*/
	GSList *noninline_attachs = NULL;

	gboolean build_alternative = FALSE;
	gboolean build_related = FALSE;
	gboolean skip_set_content = FALSE;

	g_return_val_if_fail (conn != NULL, NULL);
	g_return_val_if_fail (item != NULL, NULL);

	attach_list = item->attachments;
	msg = camel_mime_message_new ();

	mapi_mime_set_recipient_list (conn, msg, item);
	mapi_mime_set_msg_headers (conn, msg, item);
	mapi_mime_classify_attachments (conn, item->fid, item->msg_class, attach_list, &inline_attachs, &noninline_attachs);

	build_alternative = g_slist_length (item->msg.body_parts) > 1;
	build_related = !build_alternative && inline_attachs;

	if (build_alternative) {
		multipart_body = mapi_mime_build_multipart_alternative (item, item->msg.body_parts,
									inline_attachs);
	} else if (build_related) {
		multipart_body = mapi_mime_build_multipart_related (item,
								    item->msg.body_parts ? item->msg.body_parts->data : NULL,
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
		if (build_alternative || build_related) {
			multipart_body = mapi_mime_build_multipart_mixed (multipart_body, noninline_attachs);
		} else if (g_slist_length (noninline_attachs) == 1 && item->msg_class && strstr (item->msg_class, ".SMIME") > item->msg_class) {
			CamelMimePart *part = noninline_attachs->data;

			skip_set_content = TRUE;

			camel_medium_set_content (CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER (part));

			if (!strstr (item->msg_class, ".SMIME.")) {
				/* encrypted */
				camel_medium_set_content (CAMEL_MEDIUM (msg), camel_medium_get_content (CAMEL_MEDIUM (part)));
				camel_mime_part_set_encoding (CAMEL_MIME_PART (msg), camel_mime_part_get_encoding (part));
			} else {
				/* signed */
				camel_medium_set_content (CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER (part));
			}
		} else {
			mapi_mime_multipart_add_attachments (multipart_body, noninline_attachs);
		}
	}

	if (!skip_set_content)
		camel_medium_set_content (CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER(multipart_body));

	g_object_unref (multipart_body);
	g_slist_free (inline_attachs);
	g_slist_free (noninline_attachs);

	return msg;
}

void
e_mapi_mail_utils_decode_email_address (EMapiConnection *conn,
					struct mapi_SPropValue_array *properties,
					const uint32_t *name_proptags,
					guint name_proptags_len,
					const uint32_t *smtp_proptags,
					guint smtp_proptags_len,
					uint32_t email_type_proptag,
					uint32_t email_proptag,
					gchar **name,
					gchar **email)
{
	gint ii;
	const gchar *cname = NULL, *cemail = NULL;

	g_return_if_fail (conn != NULL);
	g_return_if_fail (properties != NULL);
	g_return_if_fail (name_proptags_len == 0 || name_proptags != NULL);
	g_return_if_fail (smtp_proptags_len == 0 || smtp_proptags != NULL);
	g_return_if_fail (name != NULL);
	g_return_if_fail (email != NULL);

	*name = NULL;
	*email = NULL;

	for (ii = 0; ii < name_proptags_len && !cname; ii++) {
		cname = e_mapi_util_find_array_propval (properties, name_proptags[ii]);
	}

	for (ii = 0; ii < smtp_proptags_len && !cemail; ii++) {
		cemail = e_mapi_util_find_array_propval (properties, smtp_proptags[ii]);
	}

	if (!cemail) {
		const gchar *addr_type = e_mapi_util_find_array_propval (properties, email_type_proptag);
		const gchar *email_addr = e_mapi_util_find_array_propval (properties, email_proptag);

		if (addr_type && g_ascii_strcasecmp (addr_type, "EX") == 0 && email_addr)
			*email = e_mapi_connection_ex_to_smtp (conn, email_addr, name, NULL, NULL);
		else if (addr_type && g_ascii_strcasecmp (addr_type, "SMTP") == 0)
			cemail = email_addr;
	}

	if (!*email) {
		*name = g_strdup (cname);
		*email = g_strdup (cemail);
	}
}

void
e_mapi_mail_utils_decode_email_address1 (EMapiConnection *conn,
					 struct mapi_SPropValue_array *properties,
					 uint32_t name_proptag,
					 uint32_t email_proptag,
					 uint32_t email_type_proptag,
					 gchar **name,
					 gchar **email)
{
	uint32_t names[1];

	names[0] = name_proptag;

	e_mapi_mail_utils_decode_email_address (conn, properties, names, 1, NULL, 0, email_type_proptag, email_proptag, name, email);
}

void
e_mapi_mail_utils_decode_recipients (EMapiConnection *conn,
				     EMapiRecipient *recipients,
				     CamelAddress *to_addr,
				     CamelAddress *cc_addr,
				     CamelAddress *bcc_addr)
{
	const uint32_t name_proptags[] = {
		PROP_TAG (PT_UNICODE, 0x6001), /* PidTagNickname for Recipients table */
		PidTagNickname,
		PidTagDisplayName,
		PidTagRecipientDisplayName,
		PidTag7BitDisplayName
	};

	const uint32_t email_proptags[] = {
		PidTagPrimarySmtpAddress,
		PidTagSmtpAddress
	};

	EMapiRecipient *recipient;

	g_return_if_fail (conn != NULL);
	g_return_if_fail (to_addr != NULL);
	g_return_if_fail (cc_addr != NULL);
	g_return_if_fail (bcc_addr != NULL);

	for (recipient = recipients; recipient; recipient = recipient->next) {
		const uint32_t *recip_type = e_mapi_util_find_array_propval (&recipient->properties, PidTagRecipientType);
		gchar *name = NULL, *email = NULL;
		CamelAddress *addr = NULL;

		if (!recip_type)
			continue;

		switch (*recip_type) {
		case MAPI_TO:
			addr = to_addr;
			break;
		case MAPI_CC:
			addr = cc_addr;
			break;
		case MAPI_BCC:
			addr = bcc_addr;
			break;
		default:
			break;
		}

		if (!addr)
			continue;

		e_mapi_mail_utils_decode_email_address (conn, &recipient->properties,
					name_proptags, G_N_ELEMENTS (name_proptags),
					email_proptags, G_N_ELEMENTS (email_proptags),
					PidTagAddressType, PidTagEmailAddress,
					&name, &email);

		camel_internet_address_add (CAMEL_INTERNET_ADDRESS (addr), name, email ? email : "");

		g_free (name);
		g_free (email);
	}
}

static void
build_body_part_content (CamelMimePart *part, EMapiObject *object, uint32_t proptag)
{
	gconstpointer value;

	g_return_if_fail (part != NULL);
	g_return_if_fail (object != NULL);
	g_return_if_fail (proptag == PidTagHtml || proptag == PidTagBody);

	camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_8BIT);

	value = e_mapi_util_find_array_propval (&object->properties, proptag);
	if (value) {
		const gchar *type = NULL;
		gchar *buff = NULL, *in_utf8;
		const uint32_t *pcpid = e_mapi_util_find_array_propval (&object->properties, PidTagInternetCodepage);

		if (proptag == PidTagBody) {
			type = "text/plain";
		} else {
			type = "text/html";
		}

		proptag = e_mapi_util_find_array_proptag (&object->properties, proptag);
		if (pcpid && *pcpid && (proptag & 0xFFFF) != PT_UNICODE) {
			uint32_t cpid = *pcpid;
	
			if (cpid == 20127)
				buff = g_strdup_printf ("%s; charset=\"us-ascii\"", type);
			else if (cpid >= 28591 && cpid <= 28599)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-%d\"", type, cpid % 10);
			else if (cpid == 28603)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-13\"", type);
			else if (cpid == 28605)
				buff = g_strdup_printf ("%s; charset=\"ISO-8859-15\"", type);
			else if (cpid == 65000)
				buff = g_strdup_printf ("%s; charset=\"UTF-7\"", type);
			else if (cpid == 65001)
				buff = g_strdup_printf ("%s; charset=\"UTF-8\"", type);
			else
				buff = g_strdup_printf ("%s; charset=\"CP%d\"", type, cpid);
			type = buff;
		}

		in_utf8 = NULL;

		if (proptag == PidTagHtml) {
			const struct SBinary_short *html_bin = value;

			if (e_mapi_utils_ensure_utf8_string (proptag, pcpid, html_bin->lpb, html_bin->cb, &in_utf8))
				camel_mime_part_set_content (part, in_utf8, strlen (in_utf8), type);
			else
				camel_mime_part_set_content (part, (const gchar *) html_bin->lpb, html_bin->cb, type);
			
		} else {
			const gchar *str = value;

			if (e_mapi_utils_ensure_utf8_string (proptag, pcpid, (const guint8 *) str, strlen (str), &in_utf8))
				str = in_utf8;

			camel_mime_part_set_content (part, str, strlen (str), type);
		}

		g_free (in_utf8);
		g_free (buff);
	} else
		camel_mime_part_set_content (part, " ", strlen (" "), "text/plain");
}

static gboolean
is_apple_attach (EMapiAttachment *attach, guint32 *data_len, guint32 *resource_len)
{
	gboolean is_apple = FALSE;
	const struct SBinary_short *encoding_bin = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachEncoding);
	guint8 apple_enc_magic[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0B, 0x01 };

	if (encoding_bin && encoding_bin->lpb && encoding_bin->cb == G_N_ELEMENTS (apple_enc_magic)) {
		gint idx;

		is_apple = TRUE;
		for (idx = 0; idx < encoding_bin->cb && is_apple; idx++) {
			is_apple = apple_enc_magic[idx] == encoding_bin->lpb[idx];
		}
	}

	if (is_apple) {
		/* check boundaries too */
		const struct SBinary_short *data_bin = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachDataBinary);

		is_apple = data_bin && data_bin->lpb && data_bin->cb > 128;

		if (is_apple) {
			const guint8 *bin = data_bin->lpb;

			/* in big-endian format */
			*data_len = (bin[83] << 24) | (bin[84] << 16) | (bin[85] << 8) | (bin[86]);
			*resource_len = (bin[87] << 24) | (bin[88] << 16) | (bin[89] << 8) | (bin[90]);

			/* +/- mod 128 (but the first 128 is a header length) */
			is_apple = 128 + *data_len + *resource_len <= data_bin->cb && bin[1] < 64;
		}
	}

	return is_apple;
}

static void
classify_attachments (EMapiConnection *conn, EMapiAttachment *attachments, const gchar *msg_class, GSList **inline_attachments, GSList **noninline_attachments)
{
	EMapiAttachment *attach;
	gboolean is_smime = msg_class && strstr (msg_class, ".SMIME.") > msg_class;

	g_return_if_fail (inline_attachments != NULL);
	g_return_if_fail (noninline_attachments != NULL);

	for (attach = attachments; attach != NULL; attach = attach->next) {
		const gchar *filename, *mime_type, *content_id = NULL;
		CamelContentType *content_type;
		CamelMimePart *part;
		const uint32_t *ui32;
		const struct SBinary_short *data_bin;
		gboolean is_apple;
		guint32 apple_data_len = 0, apple_resource_len = 0;

		data_bin = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachDataBinary);
		if (!data_bin && !attach->embedded_object) {
			g_debug ("%s: Skipping attachment without data and without embedded object", G_STRFUNC);
			continue;
		}

		is_apple = is_apple_attach (attach, &apple_data_len, &apple_resource_len);

		/* Content-Type */
		ui32 = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachMethod);
		if (ui32 && *ui32 == ATTACH_EMBEDDED_MSG) {
			mime_type = "message/rfc822";
		} else {
			mime_type = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachMimeTag);
			if (!mime_type)
				mime_type = "application/octet-stream";
		}

		if (is_apple) {
			mime_type = "application/applefile";
		} else if (strstr (mime_type, "apple") != NULL) {
			mime_type = "application/octet-stream";
		}

		part = camel_mime_part_new ();

		filename = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachLongFilename);
		if (!filename || !*filename)
			filename = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachFilename);
		camel_mime_part_set_filename (part, filename);
		camel_content_type_set_param (((CamelDataWrapper *) part)->mime_type, "name", filename);

		if (is_apple) {
			CamelMultipart *mp;
			gchar *apple_filename;
			const struct SBinary_short *mac_info_bin;

			mp = camel_multipart_new ();
			camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (mp), "multipart/appledouble");
			camel_multipart_set_boundary (mp, NULL);

			camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);

			mac_info_bin = e_mapi_util_find_array_propval (&attach->properties, PidNameAttachmentMacInfo);
			if (mac_info_bin && mac_info_bin->lpb && mac_info_bin->cb > 0) {
				camel_mime_part_set_content (part, (const gchar *) mac_info_bin->lpb, mac_info_bin->cb, mime_type);
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
				g_byte_array_append (arr, data_bin->lpb + 128 + apple_data_len + (apple_data_len % 128), apple_resource_len);

				camel_mime_part_set_content (part, (const gchar *) arr->data, arr->len, mime_type);

				g_byte_array_free (arr, TRUE);
			}

			camel_multipart_add_part (mp, part);
			g_object_unref (part);

			part = camel_mime_part_new ();

			apple_filename = g_strndup ((const gchar *) data_bin->lpb + 2, data_bin->lpb[1]);
			camel_mime_part_set_filename (part, (apple_filename && *apple_filename) ? apple_filename : filename);
			g_free (apple_filename);

			mime_type = e_mapi_util_find_array_propval (&attach->properties, PidNameAttachmentMacContentType);
			if (!mime_type)
				mime_type = "application/octet-stream";

			camel_mime_part_set_content (part, (const gchar *) data_bin->lpb + 128, apple_data_len, mime_type);
			camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);
			camel_multipart_add_part (mp, part);
			g_object_unref (part);

			part = camel_mime_part_new ();
			camel_medium_set_content (CAMEL_MEDIUM (part), CAMEL_DATA_WRAPPER (mp));
			g_object_unref (mp);
		} else if (is_smime) {
			CamelMimeParser *parser;
			CamelStream *mem;

			mem = camel_stream_mem_new ();
			camel_stream_write (mem, (const gchar *) data_bin->lpb, data_bin->cb, NULL, NULL);
			g_seekable_seek (G_SEEKABLE (mem), 0, G_SEEK_SET, NULL, NULL);

			parser = camel_mime_parser_new ();
			camel_mime_parser_scan_from (parser, FALSE);
			camel_mime_parser_scan_pre_from (parser, FALSE);
			camel_mime_parser_init_with_stream (parser, mem, NULL);

			if (camel_mime_parser_step (parser, NULL, NULL) == CAMEL_MIME_PARSER_STATE_HEADER
			    && camel_mime_parser_content_type (parser) != NULL) {
				g_object_unref (part);
				part = camel_mime_part_new ();

				camel_data_wrapper_set_mime_type_field (CAMEL_DATA_WRAPPER (part), camel_mime_parser_content_type (parser));
				camel_mime_part_construct_content_from_parser (part, parser, NULL, NULL);
			} else {
				is_smime = FALSE;
			}

			g_object_unref (parser);
			g_object_unref (mem);
		} 

		if (!is_smime && !is_apple) {
			if (ui32 && *ui32 == ATTACH_EMBEDDED_MSG && attach->embedded_object) {
				CamelMimeMessage *embedded_msg;

				embedded_msg = e_mapi_mail_utils_object_to_message (conn, attach->embedded_object);
				if (embedded_msg) {
					CamelStream *mem = camel_stream_mem_new ();
					GByteArray *data;

					data = g_byte_array_new ();

					mem = camel_stream_mem_new ();
					camel_stream_mem_set_byte_array (CAMEL_STREAM_MEM (mem), data);
					camel_data_wrapper_write_to_stream_sync (
						CAMEL_DATA_WRAPPER (embedded_msg), mem, NULL, NULL);

					g_object_unref (mem);
					g_object_unref (embedded_msg);

					camel_mime_part_set_content (part, (const gchar *) data->data, data->len, mime_type);

					g_byte_array_free (data, TRUE);
				} else {
					camel_mime_part_set_content (part, (const gchar *) data_bin->lpb, data_bin->cb, mime_type);
				}
			} else {
				camel_mime_part_set_content (part, (const gchar *) data_bin->lpb, data_bin->cb, mime_type);
			}

			content_type = camel_mime_part_get_content_type (part);
			if (content_type && camel_content_type_is (content_type, "text", "*"))
				camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_QUOTEDPRINTABLE);
			else if (!ui32 || *ui32 != ATTACH_EMBEDDED_MSG)
				camel_mime_part_set_encoding (part, CAMEL_TRANSFER_ENCODING_BASE64);
		}

		/* Content-ID */
		content_id = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachContentId);

		/* TODO : Add disposition */
		if (content_id && !is_apple && !is_smime) {
			camel_mime_part_set_content_id (part, content_id);
			*inline_attachments = g_slist_append (*inline_attachments, part);
		} else
			*noninline_attachments = g_slist_append (*noninline_attachments, part);
	}
}

static void
add_multipart_attachments (CamelMultipart *multipart, GSList *attachments)
{
	CamelMimePart *part;
	while (attachments) {
		part = attachments->data;
		camel_multipart_add_part (multipart, part);
		attachments = attachments->next;
	}
}

static CamelMultipart *
build_multipart_related (EMapiObject *object, GSList *inline_attachments)
{
	CamelMimePart *part;
	CamelMultipart *m_related = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_related), "multipart/related");
	camel_multipart_set_boundary (m_related, NULL);

	if (e_mapi_util_find_array_propval (&object->properties, PidTagHtml)) {
		part = camel_mime_part_new ();
		build_body_part_content (part, object, PidTagHtml);
		camel_multipart_add_part (m_related, part);
		g_object_unref (part);
	} else if (e_mapi_util_find_array_propval (&object->properties, PidTagBody)) {
		part = camel_mime_part_new ();
		build_body_part_content (part, object, PidTagBody);
		camel_multipart_add_part (m_related, part);
		g_object_unref (part);
	}

	add_multipart_attachments (m_related, inline_attachments);

	return m_related;
}

static CamelMultipart *
build_multipart_alternative (EMapiObject *object, GSList *inline_attachments)
{
	CamelMimePart *part;
	CamelMultipart *m_alternative;

	m_alternative = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_alternative), "multipart/alternative");
	camel_multipart_set_boundary (m_alternative, NULL);

	if (e_mapi_util_find_array_propval (&object->properties, PidTagBody)) {
		part = camel_mime_part_new ();
		build_body_part_content (part, object, PidTagBody);
		camel_multipart_add_part (m_alternative, part);
		g_object_unref (part);
	}

	if (e_mapi_util_find_array_propval (&object->properties, PidTagHtml)) {
		part = camel_mime_part_new ();
		if (inline_attachments) {
			CamelMultipart *m_related;

			m_related = build_multipart_related (object, inline_attachments);
			camel_medium_set_content (CAMEL_MEDIUM (part), CAMEL_DATA_WRAPPER (m_related));
			g_object_unref (m_related);
		} else {
			build_body_part_content (part, object, PidTagHtml);
		}
		camel_multipart_add_part (m_alternative, part);
		g_object_unref (part);
	}

	return m_alternative;
}

static CamelMultipart *
build_multipart_mixed (CamelMultipart *content, GSList *attachments)
{
	CamelMimePart *part = camel_mime_part_new ();
	CamelMultipart *m_mixed = camel_multipart_new ();
	camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (m_mixed), "multipart/mixed");
	camel_multipart_set_boundary (m_mixed, NULL);

	camel_medium_set_content (CAMEL_MEDIUM (part), CAMEL_DATA_WRAPPER (content));
	camel_multipart_add_part (m_mixed, part);

	add_multipart_attachments (m_mixed, attachments);

	return m_mixed;
}

static gchar *
build_ical_string (EMapiConnection *conn,
		   EMapiObject *object,
		   const gchar *msg_class)
{
	gchar *ical_string = NULL, *use_uid;
	icalcomponent_kind ical_kind = ICAL_NO_COMPONENT;
	icalproperty_method ical_method = ICAL_METHOD_NONE;
	const uint64_t *pmid;
	ECalComponent *comp;
	icalcomponent *icalcomp;
	GSList *detached_components = NULL, *iter;

	g_return_val_if_fail (conn != NULL, NULL);
	g_return_val_if_fail (object != NULL, NULL);
	g_return_val_if_fail (msg_class != NULL, NULL);

	if (!g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_REQUEST)) {
		ical_method = ICAL_METHOD_REQUEST;
		ical_kind = ICAL_VEVENT_COMPONENT;
	} else if (!g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_CANCELED)) {
		ical_method = ICAL_METHOD_CANCEL;
		ical_kind = ICAL_VEVENT_COMPONENT;
	} else if (g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_RESP_PREFIX)) {
		ical_method = ICAL_METHOD_REPLY;
		ical_kind = ICAL_VEVENT_COMPONENT;
	} else {
		return NULL;
	}

	pmid = e_mapi_util_find_array_propval (&object->properties, PidTagMid);
	if (pmid)
		use_uid = e_mapi_util_mapi_id_to_string (*pmid);
	else
		use_uid = e_cal_component_gen_uid ();

	comp = e_mapi_cal_util_object_to_comp (conn, object, ical_kind, ical_method == ICAL_METHOD_REPLY, NULL, use_uid, &detached_components);

	g_free (use_uid);

	if (!comp)
		return NULL;

	icalcomp = e_cal_util_new_top_level ();
	icalcomponent_set_method (icalcomp, ical_method);
	if (comp)
		icalcomponent_add_component (icalcomp,
			icalcomponent_new_clone (e_cal_component_get_icalcomponent (comp)));
	for (iter = detached_components; iter; iter = g_slist_next (iter)) {
		icalcomponent_add_component (icalcomp,
				icalcomponent_new_clone (e_cal_component_get_icalcomponent (iter->data)));
	}

	ical_string = icalcomponent_as_ical_string_r (icalcomp);

	icalcomponent_free (icalcomp);
	g_slist_free_full (detached_components, g_object_unref);
	g_object_unref (comp);

	return ical_string;
}

CamelMimeMessage *
e_mapi_mail_utils_object_to_message (EMapiConnection *conn, /* const */ EMapiObject *object)
{
	CamelMimeMessage *msg;
	CamelMultipart *multipart_body = NULL;
	GSList *inline_attachments, *noninline_attachments;
	gboolean build_alternative, build_related, build_calendar;
	const gchar *str, *msg_class;
	gboolean skip_set_content = FALSE;
	gchar *ical_string = NULL;

	g_return_val_if_fail (conn != NULL, NULL);
	g_return_val_if_fail (object != NULL, NULL);

	msg = camel_mime_message_new ();

	str = e_mapi_util_find_array_propval (&object->properties, PidTagTransportMessageHeaders);
	if (str && *str) {
		CamelMimePart *part = camel_mime_part_new ();
		CamelStream *stream;
		CamelMimeParser *parser;

		stream = camel_stream_mem_new_with_buffer (str, strlen (str));
		parser = camel_mime_parser_new ();
		camel_mime_parser_init_with_stream (parser, stream, NULL);
		camel_mime_parser_scan_from (parser, FALSE);
		g_object_unref (stream);

		if (camel_mime_part_construct_from_parser_sync (part, parser, NULL, NULL)) {
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
	} else {
		CamelInternetAddress *to_addr, *cc_addr, *bcc_addr;
		const struct FILETIME *delivery_time;
		gchar *name, *email;

		to_addr = camel_internet_address_new ();
		cc_addr = camel_internet_address_new ();
		bcc_addr = camel_internet_address_new ();

		e_mapi_mail_utils_decode_recipients (conn, object->recipients, (CamelAddress *) to_addr, (CamelAddress *) cc_addr, (CamelAddress *) bcc_addr);

		camel_mime_message_set_recipients (msg, CAMEL_RECIPIENT_TYPE_TO, to_addr);
		camel_mime_message_set_recipients (msg, CAMEL_RECIPIENT_TYPE_CC, cc_addr);
		camel_mime_message_set_recipients (msg, CAMEL_RECIPIENT_TYPE_BCC, bcc_addr);

		g_object_unref (to_addr);
		g_object_unref (cc_addr);
		g_object_unref (bcc_addr);

		delivery_time = e_mapi_util_find_array_propval (&object->properties, PidTagMessageDeliveryTime);
		if (delivery_time) {
			time_t received_time, actual_time;
			gint offset = 0;

			received_time = e_mapi_util_filetime_to_time_t (delivery_time);
			actual_time = camel_header_decode_date (ctime (&received_time), &offset);
			camel_mime_message_set_date (msg, actual_time, offset);
		}

		str = e_mapi_util_find_array_propval (&object->properties, PidTagSubject);
		if (str)
			camel_mime_message_set_subject (msg, str);

		name = NULL;
		email = NULL;

		e_mapi_mail_utils_decode_email_address1 (conn, &object->properties,
			PidTagSentRepresentingName,
			PidTagSentRepresentingEmailAddress,
			PidTagSentRepresentingAddressType,
			&name, &email);

		if (email && *email) {
			CamelInternetAddress *addr;

			addr = camel_internet_address_new();
			camel_internet_address_add (addr, name, email);
			camel_mime_message_set_from (msg, addr);
		}
		
		g_free (name);
		g_free (email);

		/* Threading */
		str = e_mapi_util_find_array_propval (&object->properties, PidTagInternetMessageId);
		if (str)
			camel_medium_add_header (CAMEL_MEDIUM (msg), "Message-ID", str);

		str = e_mapi_util_find_array_propval (&object->properties, PidTagInternetReferences);
		if (str)
			camel_medium_add_header (CAMEL_MEDIUM (msg), "References", str);

		str = e_mapi_util_find_array_propval (&object->properties, PidTagInReplyToId);
		if (str)
			camel_medium_add_header (CAMEL_MEDIUM (msg), "In-Reply-To", str);
	}

	str = e_mapi_util_find_array_propval (&object->properties, PidNameContentClass);
	if (str)
		camel_medium_add_header (CAMEL_MEDIUM (msg), "Content-class", str);

	inline_attachments = NULL;
	noninline_attachments = NULL;
	msg_class = e_mapi_util_find_array_propval (&object->properties, PidTagMessageClass);
	classify_attachments (conn, object->attachments, msg_class, &inline_attachments, &noninline_attachments);

	build_calendar = msg_class && g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_PREFIX);
	if (build_calendar) {
		ical_string = build_ical_string (conn, object, msg_class);
		if (!ical_string)
			build_calendar = FALSE;
	}

	build_alternative = !build_calendar
		&& e_mapi_util_find_array_propval (&object->properties, PidTagHtml)
		&& e_mapi_util_find_array_propval (&object->properties, PidTagBody);
	build_related = !build_calendar && !build_alternative && inline_attachments;

	if (build_calendar) {
		g_return_val_if_fail (ical_string != NULL, msg);

		camel_mime_part_set_content (CAMEL_MIME_PART (msg), ical_string, strlen (ical_string), "text/calendar");
	} else if (build_alternative) {
		multipart_body = build_multipart_alternative (object, inline_attachments);
	} else if (build_related) {
		multipart_body = build_multipart_related (object, inline_attachments);
	} else if (noninline_attachments) {
		/* Simple multipart/mixed */
		CamelMimePart *part = camel_mime_part_new ();

		multipart_body = camel_multipart_new ();
		camel_data_wrapper_set_mime_type (CAMEL_DATA_WRAPPER (multipart_body), "multipart/mixed");
		camel_multipart_set_boundary (multipart_body, NULL);
		if (e_mapi_util_find_array_propval (&object->properties, PidTagHtml))
			build_body_part_content (part, object, PidTagHtml);
		else
			build_body_part_content (part, object, PidTagBody);
		camel_multipart_add_part (multipart_body, part);
		g_object_unref (part);
	} else {
		/* Flat message */
		if (e_mapi_util_find_array_propval (&object->properties, PidTagHtml))
			build_body_part_content (CAMEL_MIME_PART (msg), object, PidTagHtml);
		else
			build_body_part_content (CAMEL_MIME_PART (msg), object, PidTagBody);
	}

	if (noninline_attachments) { /* multipart/mixed */
		if (build_alternative || build_related || build_calendar) {
			multipart_body = build_multipart_mixed (multipart_body, noninline_attachments);
		} else if (g_slist_length (noninline_attachments) == 1 && msg_class && strstr (msg_class, ".SMIME") > msg_class) {
			CamelMimePart *part = noninline_attachments->data;

			skip_set_content = TRUE;

			camel_medium_set_content (CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER (part));

			if (!strstr (msg_class, ".SMIME.")) {
				/* encrypted */
				camel_medium_set_content (CAMEL_MEDIUM (msg), camel_medium_get_content (CAMEL_MEDIUM (part)));
				camel_mime_part_set_encoding (CAMEL_MIME_PART (msg), camel_mime_part_get_encoding (part));
			} else {
				/* signed */
				camel_medium_set_content (CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER (part));
			}
		} else {
			add_multipart_attachments (multipart_body, noninline_attachments);
		}
	}

	if (!skip_set_content && multipart_body)
		camel_medium_set_content (CAMEL_MEDIUM (msg), CAMEL_DATA_WRAPPER (multipart_body));

	if (multipart_body)
		g_object_unref (multipart_body);
	g_slist_free_full (inline_attachments, g_object_unref);
	g_slist_free_full (noninline_attachments, g_object_unref);
	g_free (ical_string);

	return msg;
}

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
	 * e_mapi_util_free_recipient_list() */
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

	g_seekable_seek (G_SEEKABLE (body), 0, G_SEEK_SET, NULL, NULL);

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

	g_seekable_seek (G_SEEKABLE (content_stream), 0, G_SEEK_SET, NULL, NULL);
	while (read_size = camel_stream_read(content_stream, (gchar *)buf, STREAM_SIZE, cancellable, NULL), read_size > 0) {
		stream->value = g_byte_array_append (stream->value, buf, read_size);
	}

	item_attach->streams = g_slist_append (item_attach->streams, stream);
	item->attachments = g_slist_append(item->attachments, item_attach);

	g_free (buf);

	return TRUE;
}

static CamelStream *
get_content_stream (CamelMimePart *part, GCancellable *cancellable)
{
	CamelStream *content_stream;
	CamelStream *filter_stream = NULL;
	CamelMimeFilterWindows *windows = NULL;
	CamelDataWrapper *dw;

	g_return_val_if_fail (part != NULL, NULL);

	dw = camel_medium_get_content (CAMEL_MEDIUM (part));
	g_return_val_if_fail (dw != NULL, NULL);

	content_stream = camel_stream_mem_new();

	if (camel_mime_part_get_content_type (part)) {
		const gchar *charset = camel_content_type_param (camel_mime_part_get_content_type (part), "charset");

		if (charset && *charset && g_ascii_strcasecmp (charset, "utf8") != 0 && g_ascii_strcasecmp (charset, "utf-8") != 0) {
			if (g_ascii_strncasecmp (charset, "iso-8859-", 9) == 0) {
				CamelStream *null;

				/* Since a few Windows mailers like to claim they sent
				 * out iso-8859-# encoded text when they really sent
				 * out windows-cp125#, do some simple sanity checking
				 * before we move on... */

				null = camel_stream_null_new ();
				filter_stream = camel_stream_filter_new (null);
				g_object_unref (null);

				windows = (CamelMimeFilterWindows *)camel_mime_filter_windows_new (charset);
				camel_stream_filter_add (
					CAMEL_STREAM_FILTER (filter_stream),
					CAMEL_MIME_FILTER (windows));

				camel_data_wrapper_decode_to_stream_sync (
					dw, (CamelStream *)filter_stream, cancellable, NULL);
				camel_stream_flush ((CamelStream *)filter_stream, cancellable, NULL);
				g_object_unref (filter_stream);

				charset = camel_mime_filter_windows_real_charset (windows);
			}

			if (charset && *charset) {
				CamelMimeFilter *filter;

				filter_stream = camel_stream_filter_new (content_stream);

				if ((filter = camel_mime_filter_charset_new (charset, "UTF-8"))) {
					camel_stream_filter_add (
						CAMEL_STREAM_FILTER (filter_stream),
						CAMEL_MIME_FILTER (filter));
					g_object_unref (filter);
				} else {
					g_object_unref (filter_stream);
					filter_stream = NULL;
				}
			}
		}
	}

	if (filter_stream) {
		camel_data_wrapper_decode_to_stream_sync (dw, (CamelStream *) filter_stream, cancellable, NULL);
		camel_stream_flush (filter_stream, cancellable, NULL);
		g_object_unref (filter_stream);
	} else {
		camel_data_wrapper_decode_to_stream_sync (dw, (CamelStream *) content_stream, cancellable, NULL);
	}

	g_seekable_seek (G_SEEKABLE (content_stream), 0, G_SEEK_SET, NULL, NULL);

	return content_stream;
}

static void
mapi_do_smime_signed (MailItem *item, CamelMultipart *multipart, GCancellable *cancellable, GError **error)
{
	CamelMimePart *content, *signature;
	ExchangeMAPIAttachment *item_attach;
	ExchangeMAPIStream *stream;
	CamelStream *content_stream;
	CamelContentType *type;
	CamelDataWrapper *dw;
	uint32_t ui32;
	guint8 *buf;
	guint32	read_size;
	gchar *content_type_str;

	g_free (item->msg_class);
	item->msg_class = g_strdup ("IPM.Note.SMIME.MultipartSigned");

	content = camel_multipart_get_part (multipart, CAMEL_MULTIPART_SIGNED_CONTENT);
	signature = camel_multipart_get_part (multipart, CAMEL_MULTIPART_SIGNED_SIGNATURE);

	g_return_if_fail (content != NULL);
	g_return_if_fail (signature != NULL);

	content_stream = get_content_stream (content, cancellable);
	type = camel_mime_part_get_content_type (content);

	if (camel_content_type_is (type, "text", "plain")) {
		mail_item_set_body_stream (item, content_stream, PART_TYPE_PLAIN_TEXT, cancellable);
	} else if (camel_content_type_is (type, "text", "html")) {
		mail_item_set_body_stream (item, content_stream, PART_TYPE_TEXT_HTML, cancellable);
	} else {
		mail_item_add_attach (item, content, content_stream, cancellable);
	}

	if (content_stream)
		g_object_unref (content_stream);

	content_stream = camel_stream_mem_new ();
	dw = CAMEL_DATA_WRAPPER (multipart);
	type = camel_data_wrapper_get_mime_type_field (dw);
	content_type_str = camel_content_type_format (type);

	#define wstr(str) camel_stream_write (content_stream, str, strlen (str), cancellable, NULL)
	wstr("Content-Type: ");
	wstr(content_type_str);
	wstr("\n\n");
	#undef wstr

	g_free (content_type_str);

	camel_data_wrapper_write_to_stream_sync (dw, (CamelStream *) content_stream, cancellable, NULL);

	item_attach = g_new0 (ExchangeMAPIAttachment, 1);
	item_attach->lpProps = g_new0 (struct SPropValue, 6 + 1);
	item_attach->cValues = 6;

	ui32 = ATTACH_BY_VALUE;
	set_SPropValue_proptag (&(item_attach->lpProps[0]), PR_ATTACH_METHOD, &ui32);
	ui32 = -1;
	set_SPropValue_proptag (&(item_attach->lpProps[1]), PR_RENDERING_POSITION, &ui32);
	set_SPropValue_proptag (&(item_attach->lpProps[2]), PR_ATTACH_MIME_TAG, "multipart/signed");
	set_SPropValue_proptag (&(item_attach->lpProps[3]), PR_ATTACH_FILENAME_UNICODE, "SMIME.txt");
	set_SPropValue_proptag (&(item_attach->lpProps[4]), PR_ATTACH_LONG_FILENAME_UNICODE, "SMIME.txt");
	set_SPropValue_proptag (&(item_attach->lpProps[5]), PR_DISPLAY_NAME_UNICODE, "SMIME.txt");

	stream = g_new0 (ExchangeMAPIStream, 1);
	stream->proptag = PR_ATTACH_DATA_BIN;
	stream->value = g_byte_array_new ();

	buf = g_new0 (guint8 , STREAM_SIZE);

	g_seekable_seek (G_SEEKABLE (content_stream), 0, G_SEEK_SET, NULL, NULL);
	while (read_size = camel_stream_read (content_stream, (gchar *) buf, STREAM_SIZE, cancellable, NULL), read_size > 0) {
		stream->value = g_byte_array_append (stream->value, buf, read_size);
	}

	g_free (buf);
	g_object_unref (content_stream);

	item_attach->streams = g_slist_append (item_attach->streams, stream);
	item->attachments = g_slist_append (item->attachments, item_attach);
}

static void
mapi_do_smime_encrypted (MailItem *item, CamelMedium *message, GCancellable *cancellable, GError **error)
{
	ExchangeMAPIAttachment *item_attach;
	ExchangeMAPIStream *stream;
	CamelStream *content_stream;
	CamelDataWrapper *dw;
	CamelContentType *type;
	uint32_t ui32;
	guint8 *buf;
	guint32	read_size;
	gchar *content_type_str;

	g_free (item->msg_class);
	item->msg_class = g_strdup ("IPM.Note.SMIME");

	type = camel_data_wrapper_get_mime_type_field (CAMEL_DATA_WRAPPER (message));
	dw = camel_medium_get_content (message);

	content_type_str = camel_content_type_format (type);

	g_free (item->pid_name_content_type);
	item->pid_name_content_type = content_type_str; /* will be freed with the MailItem structure */

	content_stream = camel_stream_mem_new ();
	camel_data_wrapper_decode_to_stream_sync (dw, (CamelStream *) content_stream, cancellable, NULL);

	item_attach = g_new0 (ExchangeMAPIAttachment, 1);
	item_attach->lpProps = g_new0 (struct SPropValue, 6 + 1);
	item_attach->cValues = 6;

	ui32 = ATTACH_BY_VALUE;
	set_SPropValue_proptag (&(item_attach->lpProps[0]), PR_ATTACH_METHOD, &ui32);
	ui32 = -1;
	set_SPropValue_proptag (&(item_attach->lpProps[1]), PR_RENDERING_POSITION, &ui32);
	set_SPropValue_proptag (&(item_attach->lpProps[2]), PR_ATTACH_MIME_TAG, content_type_str);
	set_SPropValue_proptag (&(item_attach->lpProps[3]), PR_ATTACH_FILENAME_UNICODE, "SMIME.txt");
	set_SPropValue_proptag (&(item_attach->lpProps[4]), PR_ATTACH_LONG_FILENAME_UNICODE, "SMIME.txt");
	set_SPropValue_proptag (&(item_attach->lpProps[5]), PR_DISPLAY_NAME_UNICODE, "SMIME.txt");

	stream = g_new0 (ExchangeMAPIStream, 1);
	stream->proptag = PR_ATTACH_DATA_BIN;
	stream->value = g_byte_array_new ();

	buf = g_new0 (guint8 , STREAM_SIZE);

	g_seekable_seek (G_SEEKABLE (content_stream), 0, G_SEEK_SET, NULL, NULL);
	while (read_size = camel_stream_read (content_stream, (gchar *) buf, STREAM_SIZE, cancellable, NULL), read_size > 0) {
		stream->value = g_byte_array_append (stream->value, buf, read_size);
	}

	g_free (buf);
	g_object_unref (content_stream);

	item_attach->streams = g_slist_append (item_attach->streams, stream);
	item->attachments = g_slist_append (item->attachments, item_attach);
}

static gboolean
mapi_do_multipart (CamelMultipart *mp, MailItem *item, gboolean *is_first, GCancellable *cancellable)
{
	CamelDataWrapper *dw;
	CamelStream *content_stream;
	CamelContentType *type;
	CamelMimePart *part;
	gint n_part, i_part;

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

		if (CAMEL_IS_MIME_MESSAGE (dw)) {
			CamelMimeMessage *message;
			CamelInternetAddress *message_from;
			CamelAddress *use_from = NULL;
			MailItem *mail;

			message = CAMEL_MIME_MESSAGE (dw);
			message_from = camel_mime_message_get_from (message);
			if (message_from)
				use_from = CAMEL_ADDRESS (message_from);
			mail = mapi_mime_message_to_mail_item (message, 0, use_from, cancellable, NULL);
			if (mail) {
				ExchangeMAPIAttachment *item_attach = g_new0 (ExchangeMAPIAttachment, 1);

				item_attach->mail = mail;
				item->attachments = g_slist_append (item->attachments, item_attach);

				continue;
			}
		}

		content_stream = get_content_stream (part, cancellable);

		type = camel_mime_part_get_content_type(part);

		if (i_part == 0 && (*is_first) && camel_content_type_is (type, "text", "plain")) {
			mail_item_set_body_stream (item, content_stream, PART_TYPE_PLAIN_TEXT, cancellable);
			*is_first = FALSE;
		} else if (camel_content_type_is (type, "text", "html")) {
			mail_item_set_body_stream (item, content_stream, PART_TYPE_TEXT_HTML, cancellable);
		} else {
			mail_item_add_attach (item, part, content_stream, cancellable);
		}

		if (content_stream)
			g_object_unref (content_stream);
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
mapi_mime_message_to_mail_item (CamelMimeMessage *message, gint32 message_camel_flags, CamelAddress *from, GCancellable *cancellable, GError **error)
{
	CamelDataWrapper *dw = NULL;
	CamelStream *content_stream;
	CamelMultipart *multipart;
	CamelContentType *content_type;
	CamelInternetAddress *to, *cc, *bcc;
	MailItem *item = g_new0 (MailItem, 1);
	const gchar *namep = NULL;
	const gchar *addressp = NULL;
	time_t msg_time = 0;
	gint msg_time_offset = 0;
	GArray *headers;

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

	item->recipients = recipient_list;

	content_type = camel_data_wrapper_get_mime_type_field (CAMEL_DATA_WRAPPER (message));
	g_return_val_if_fail (content_type != NULL, item);

	if (camel_content_type_is (content_type, "application", "x-pkcs7-mime") || camel_content_type_is (content_type, "application", "pkcs7-mime")) {
		mapi_do_smime_encrypted (item, CAMEL_MEDIUM (message), cancellable, error);
	} else {
		/* contents body */
		dw = camel_medium_get_content (CAMEL_MEDIUM (message));

		if (CAMEL_IS_MULTIPART (dw)) {
			gboolean is_first = TRUE;

			multipart = CAMEL_MULTIPART (dw);

			if (CAMEL_IS_MULTIPART_SIGNED (multipart) && camel_multipart_get_number (multipart) == 2) {
				mapi_do_smime_signed (item, multipart, cancellable, error);
			} else {
				mapi_do_multipart (multipart, item, &is_first, cancellable);
			}
		} else if (dw) {
			content_stream = get_content_stream ((CamelMimePart *) message, cancellable);

			mail_item_set_body_stream (item, content_stream, PART_TYPE_PLAIN_TEXT, cancellable);

			if (content_stream)
				g_object_unref (content_stream);
		}
	}

	return item;
}

gboolean
mapi_mail_utils_create_item_build_props (EMapiConnection *conn,
					 mapi_id_t fid,
					 TALLOC_CTX *mem_ctx,
					 struct SPropValue **values,
					 uint32_t *n_values,
					 gpointer data,
					 GCancellable *cancellable,
					 GError **perror)
{

	MailItem *item = (MailItem *) data;
	GSList *l;
	bool send_rich_info;
	uint32_t cpid;

	#define set_value(hex, val) G_STMT_START { \
		if (!e_mapi_utils_add_spropvalue (mem_ctx, values, n_values, hex, val)) \
			return FALSE;	\
		} G_STMT_END

	if (item->msg_class) {
		set_value (PR_MESSAGE_CLASS, item->msg_class);
	}
	
	if (item->pid_name_content_type) {
		if (!e_mapi_utils_add_spropvalue_namedid (conn, fid, mem_ctx, values, n_values, PidNameContentType, item->pid_name_content_type, cancellable, perror))
			return FALSE;
	}

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

		e_mapi_util_time_t_to_filetime (item->header.recieved_time, &msg_date);

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
