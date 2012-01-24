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
#include "e-mapi-book-utils.h"
#include "e-mapi-cal-utils.h"
#include "e-mapi-mail-utils.h"

#define STREAM_SIZE 4000

extern gint camel_application_is_exiting;

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
	const gchar *addr_type, *email_addr;

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

	addr_type = e_mapi_util_find_array_propval (properties, email_type_proptag);
	email_addr = e_mapi_util_find_array_propval (properties, email_proptag);

	if (addr_type && g_ascii_strcasecmp (addr_type, "SMTP") == 0)
		cemail = email_addr;

	for (ii = 0; ii < smtp_proptags_len && !cemail; ii++) {
		cemail = e_mapi_util_find_array_propval (properties, smtp_proptags[ii]);
	}

	if (!cemail && addr_type && g_ascii_strcasecmp (addr_type, "EX") == 0 && email_addr) {
		*email = e_mapi_connection_ex_to_smtp (conn, email_addr, name, NULL, NULL);
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
			else if (cpid == 20866)
				buff = g_strdup_printf ("%s; charset=\"koi8-r\"", type);
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

	if (g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_REQUEST) == 0) {
		ical_method = ICAL_METHOD_REQUEST;
		ical_kind = ICAL_VEVENT_COMPONENT;
	} else if (g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_CANCELED) == 0) {
		ical_method = ICAL_METHOD_CANCEL;
		ical_kind = ICAL_VEVENT_COMPONENT;
	} else if (g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_RESP_PREFIX)) {
		ical_method = ICAL_METHOD_REPLY;
		ical_kind = ICAL_VEVENT_COMPONENT;
	} else if (g_ascii_strcasecmp (msg_class, IPM_APPOINTMENT) == 0) {
		ical_method = ICAL_METHOD_NONE;
		ical_kind = ICAL_VEVENT_COMPONENT;
	} else if (g_ascii_strcasecmp (msg_class, IPM_TASK) == 0) {
		ical_method = ICAL_METHOD_NONE;
		ical_kind = ICAL_VTODO_COMPONENT;
	} else if (g_ascii_strcasecmp (msg_class, IPM_STICKYNOTE) == 0) {
		ical_method = ICAL_METHOD_NONE;
		ical_kind = ICAL_VJOURNAL_COMPONENT;
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

	if (ical_method != ICAL_METHOD_NONE || detached_components) {
		icalcomp = e_cal_util_new_top_level ();
		if (ical_method != ICAL_METHOD_NONE)
			icalcomponent_set_method (icalcomp, ical_method);

		icalcomponent_add_component (icalcomp,
			icalcomponent_new_clone (e_cal_component_get_icalcomponent (comp)));
		for (iter = detached_components; iter; iter = g_slist_next (iter)) {
			icalcomponent_add_component (icalcomp,
				icalcomponent_new_clone (e_cal_component_get_icalcomponent (iter->data)));
		}

		ical_string = icalcomponent_as_ical_string_r (icalcomp);

		icalcomponent_free (icalcomp);
	} else {
		ical_string = e_cal_component_get_as_string (comp);
	}

	g_slist_free_full (detached_components, g_object_unref);
	g_object_unref (comp);

	return ical_string;
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
				const gchar *embedded_msg_class = e_mapi_util_find_array_propval (&attach->embedded_object->properties, PidTagMessageClass);
				gboolean fallback = FALSE;

				if (embedded_msg_class &&
				    (g_ascii_strcasecmp (embedded_msg_class, IPM_CONTACT) == 0 ||
				     g_ascii_strcasecmp (embedded_msg_class, IPM_DISTLIST) == 0)) {
					EContact *contact = e_mapi_book_utils_contact_from_object (conn, attach->embedded_object, NULL);

					if (contact) {
						gchar *str;

						if (!e_contact_get_const (contact, E_CONTACT_UID))
							e_contact_set (contact, E_CONTACT_UID, "");

						str = e_vcard_to_string (E_VCARD (contact), EVC_FORMAT_VCARD_30);
						if (str) {
							camel_mime_part_set_content (part, str, strlen (str), "text/x-vcard");

							g_free (str);
						} else {
							fallback = TRUE;
						}

						g_object_unref (contact);
					} else {
						fallback = TRUE;
					}
				} else if (embedded_msg_class &&
				    (g_ascii_strcasecmp (embedded_msg_class, IPM_APPOINTMENT) == 0 ||
				     g_ascii_strcasecmp (embedded_msg_class, IPM_TASK) == 0 ||
				     g_ascii_strcasecmp (embedded_msg_class, IPM_STICKYNOTE) == 0)) {
					gchar *str = build_ical_string (conn, attach->embedded_object, embedded_msg_class);

					if (str) {
						camel_mime_part_set_content (part, str, strlen (str), "text/calendar");

						g_free (str);
					} else {
						fallback = TRUE;
					}
				} else {
					fallback = TRUE;
				}

				if (fallback) {
					CamelMimeMessage *embedded_msg;

					embedded_msg = e_mapi_mail_utils_object_to_message (conn, attach->embedded_object);
					if (embedded_msg) {
						CamelStream *mem;
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

		/* Content-Disposition */
		ui32 = e_mapi_util_find_array_propval (&attach->properties, PidTagRenderingPosition);
		if (ui32 && *ui32 != 0xFFFFFFFF)
			camel_mime_part_set_disposition (part, "attachment; inline");
		else
			camel_mime_part_set_disposition (part, "attachment");

		/* Content-ID */
		content_id = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachContentId);
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
	g_object_unref (part);

	add_multipart_attachments (m_mixed, attachments);

	return m_mixed;
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
		const struct FILETIME *msg_date;
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

		msg_date = e_mapi_util_find_array_propval (&object->properties, PidTagClientSubmitTime);
		if (!msg_date)
			msg_date = e_mapi_util_find_array_propval (&object->properties, PidTagMessageDeliveryTime);
		if (msg_date) {
			time_t msg_date_t, actual_time;
			gint offset = 0;

			msg_date_t = e_mapi_util_filetime_to_time_t (msg_date);
			actual_time = camel_header_decode_date (ctime (&msg_date_t), &offset);
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

static void
e_mapi_mail_add_recipients (EMapiObject *object,
			    CamelInternetAddress *addresses,
			    OlMailRecipientType recip_type)
{
	gint ii;
	const gchar *name = NULL, *email = NULL;

	g_return_if_fail (object != NULL);

	for (ii = 0; addresses && camel_internet_address_get (addresses, ii, &name, &email); ii++) {
		EMapiRecipient *recipient;
		uint32_t ui32 = 0;
		bool bl;

		recipient = e_mapi_recipient_new (object);
		e_mapi_object_add_recipient (object, recipient);

		#define set_value(pt,vl) {								\
			if (!e_mapi_utils_add_property (&recipient->properties, pt, vl, recipient)) {	\
				g_warning ("%s: Failed to set property 0x%x", G_STRFUNC, pt);		\
													\
				return;									\
			}										\
		}

		ui32 = recip_type;
		set_value (PidTagRecipientType, &ui32);

		if (!name || !*name)
			name = email;

		if (name && *name) {
			set_value (PidTagDisplayName, name);
			set_value (PidTagRecipientDisplayName, name);
		}
		if (email && *email) {
			set_value (PidTagAddressType, "SMTP");
			set_value (PidTagEmailAddress, email);

			set_value (PidTagSmtpAddress, email);
			set_value (PidTagPrimarySmtpAddress, email);
		}

		ui32 = 0;
		set_value (PidTagSendInternetEncoding, &ui32);

		ui32 = DT_MAILUSER;
		set_value (PidTagDisplayType, &ui32);

		ui32 = MAPI_MAILUSER;
		set_value (PidTagObjectType, &ui32);

		bl = false;
		set_value (PidTagSendRichInfo, &bl);

		#undef set_value

		name = NULL;
		email = NULL;
	}
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

	if (windows)
		g_object_unref (windows);

	g_seekable_seek (G_SEEKABLE (content_stream), 0, G_SEEK_SET, NULL, NULL);

	return content_stream;
}

static void
e_mapi_mail_content_stream_to_bin (CamelStream *content_stream,
				   struct SBinary_short *bin,
				   TALLOC_CTX *mem_ctx,
				   GCancellable *cancellable)
{
	guint8 *buf;
	guint32	read_size;

	g_return_if_fail (content_stream != NULL);
	g_return_if_fail (bin != NULL);
	g_return_if_fail (mem_ctx != NULL);

	buf = g_new0 (guint8 , STREAM_SIZE);

	bin->cb = 0;
	bin->lpb = NULL;

	g_seekable_seek (G_SEEKABLE (content_stream), 0, G_SEEK_SET, NULL, NULL);
	while (read_size = camel_stream_read (content_stream, (gchar *) buf, STREAM_SIZE, cancellable, NULL), read_size > 0) {
		bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + read_size);
		memcpy (bin->lpb + bin->cb, buf, read_size);
		bin->cb += read_size;
	}

	g_free (buf);
}

#define set_attach_value(pt,vl) {						\
	if (!e_mapi_utils_add_property (&attach->properties, pt, vl, attach)) {	\
		g_warning ("%s: Failed to set property 0x%x", G_STRFUNC, pt);	\
		return FALSE;							\
	}									\
}

static gboolean
e_mapi_mail_add_attach (EMapiObject *object,
			CamelMimePart *part,
			CamelStream *content_stream,
			GCancellable *cancellable)
{
	EMapiAttachment *attach;
	CamelContentType *content_type;
	const gchar *content_id;
	const gchar *filename;
	struct SBinary_short bin;
	uint32_t ui32;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (part != NULL, FALSE);
	g_return_val_if_fail (content_stream != NULL, FALSE);

	attach = e_mapi_attachment_new (object);
	e_mapi_object_add_attachment (object, attach);

	ui32 = ATTACH_BY_VALUE;
	set_attach_value (PidTagAttachMethod, &ui32);
	ui32 = -1;
	set_attach_value (PidTagRenderingPosition, &ui32);

	filename = camel_mime_part_get_filename (part);
	if (filename) {
		set_attach_value (PidTagAttachFilename, filename);
		set_attach_value (PidTagAttachLongFilename, filename);
	}

	content_id = camel_mime_part_get_content_id (part);
	if (content_id)
		set_attach_value (PidTagAttachContentId, content_id);

	content_type  = camel_mime_part_get_content_type (part);
	if (content_type) {
		gchar *ct = camel_content_type_simple (content_type);
		if (ct)
			set_attach_value (PidTagAttachMimeTag, ct);
		g_free (ct);
	}

	e_mapi_mail_content_stream_to_bin (content_stream, &bin, attach, cancellable);
	set_attach_value (PidTagAttachDataBinary, &bin);

	return TRUE;
}

static gboolean
e_mapi_mail_add_body (EMapiObject *object,
		      CamelStream *content_stream,
		      uint32_t proptag,
		      GCancellable *cancellable)
{
	struct SBinary_short bin = { 0 };
	gchar *str;

	e_mapi_mail_content_stream_to_bin (content_stream, &bin, object, cancellable);
	str = talloc_strndup (object, (const gchar *) bin.lpb, bin.cb);
	talloc_free (bin.lpb);

	if ((proptag & 0xFFFF) == PT_BINARY) {
		bin.lpb = (uint8_t *) (str ? str : "");
		bin.cb = strlen ((const gchar *) bin.lpb) + 1;
		/* include trailing zero ................ ^^^ */

		return e_mapi_utils_add_property (&object->properties, proptag, &bin, object);
	} else if (str) {
		if (!e_mapi_utils_add_property (&object->properties, proptag, str, object)) {
			talloc_free (str);
			return FALSE;
		}

		talloc_free (str);
	} else {
		return e_mapi_utils_add_property (&object->properties, proptag, "", object);
	}

	return TRUE;
}

static gboolean
e_mapi_mail_do_smime_encrypted (EMapiObject *object,
				CamelMedium *message,
				gchar **pmsg_class,
				gchar **ppid_name_content_type,
				GCancellable *cancellable)
{
	EMapiAttachment *attach;
	CamelStream *content_stream;
	CamelDataWrapper *dw;
	CamelContentType *type;
	uint32_t ui32;
	struct SBinary_short bin;
	gchar *content_type_str;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (pmsg_class != NULL, FALSE);
	g_return_val_if_fail (ppid_name_content_type != NULL, FALSE);

	g_free (*pmsg_class);
	*pmsg_class = g_strdup ("IPM.Note.SMIME");

	type = camel_data_wrapper_get_mime_type_field (CAMEL_DATA_WRAPPER (message));
	dw = camel_medium_get_content (message);
	content_type_str = camel_content_type_format (type);

	g_free (*ppid_name_content_type);
	*ppid_name_content_type = content_type_str; /* will be freed within the caller */

	content_stream = camel_stream_mem_new ();
	camel_data_wrapper_decode_to_stream_sync (dw, (CamelStream *) content_stream, cancellable, NULL);

	attach = e_mapi_attachment_new (object);
	e_mapi_object_add_attachment (object, attach);

	ui32 = ATTACH_BY_VALUE;
	set_attach_value (PidTagAttachMethod, &ui32);
	ui32 = -1;
	set_attach_value (PidTagRenderingPosition, &ui32);
	set_attach_value (PidTagAttachMimeTag, content_type_str);
	set_attach_value (PidTagAttachFilename, "SMIME.txt");
	set_attach_value (PidTagAttachLongFilename, "SMIME.txt");
	set_attach_value (PidTagDisplayName, "SMIME.txt");

	e_mapi_mail_content_stream_to_bin (content_stream, &bin, attach, cancellable);
	set_attach_value (PidTagAttachDataBinary, &bin);

	g_object_unref (content_stream);

	return TRUE;
}

static gboolean
e_mapi_mail_do_smime_signed (EMapiObject *object,
			     CamelMultipart *multipart,
			     gchar **pmsg_class,
			     GCancellable *cancellable)
{
	EMapiAttachment *attach;
	CamelMimePart *content, *signature;
	CamelStream *content_stream;
	CamelContentType *type;
	CamelDataWrapper *dw;
	uint32_t ui32;
	struct SBinary_short bin;
	gchar *content_type_str;

	g_free (*pmsg_class);
	*pmsg_class = g_strdup ("IPM.Note.SMIME.MultipartSigned");

	content = camel_multipart_get_part (multipart, CAMEL_MULTIPART_SIGNED_CONTENT);
	signature = camel_multipart_get_part (multipart, CAMEL_MULTIPART_SIGNED_SIGNATURE);

	g_return_val_if_fail (content != NULL, FALSE);
	g_return_val_if_fail (signature != NULL, FALSE);

	content_stream = get_content_stream (content, cancellable);
	type = camel_mime_part_get_content_type (content);

	if (camel_content_type_is (type, "text", "plain")) {
		e_mapi_mail_add_body (object, content_stream, PidTagBody, cancellable);
	} else if (camel_content_type_is (type, "text", "html")) {
		e_mapi_mail_add_body (object, content_stream, PidTagHtml, cancellable);
	} else {
		e_mapi_mail_add_attach (object, content, content_stream, cancellable);
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

	attach = e_mapi_attachment_new (object);
	e_mapi_object_add_attachment (object, attach);

	ui32 = ATTACH_BY_VALUE;
	set_attach_value (PidTagAttachMethod, &ui32);
	ui32 = -1;
	set_attach_value (PidTagRenderingPosition, &ui32);
	set_attach_value (PidTagAttachMimeTag, "multipart/signed");
	set_attach_value (PidTagAttachFilename, "SMIME.txt");
	set_attach_value (PidTagAttachLongFilename, "SMIME.txt");
	set_attach_value (PidTagDisplayName, "SMIME.txt");

	e_mapi_mail_content_stream_to_bin (content_stream, &bin, attach, cancellable);
	set_attach_value (PidTagAttachDataBinary, &bin);

	g_object_unref (content_stream);

	return TRUE;
}

static gboolean
e_mapi_mail_do_multipart (EMapiObject *object,
			  CamelMultipart *mp,
			  gboolean *is_first,
			  GCancellable *cancellable)
{
	CamelDataWrapper *dw;
	CamelStream *content_stream;
	CamelContentType *type;
	CamelMimePart *part;
	gint nn, ii;

	g_return_val_if_fail (is_first != NULL, FALSE);

	nn = camel_multipart_get_number (mp);
	for (ii = 0; ii < nn; ii++) {
		/* getting part */
		part = camel_multipart_get_part (mp, ii);
		if (!part)
			continue;

		dw = camel_medium_get_content (CAMEL_MEDIUM (part));
		if (CAMEL_IS_MULTIPART (dw)) {
			/* recursive */
			if (!e_mapi_mail_do_multipart (object, CAMEL_MULTIPART (dw), is_first, cancellable))
				return FALSE;
			continue;
		}

		if (CAMEL_IS_MIME_MESSAGE (dw)) {
			CamelMimeMessage *message;
			EMapiObject *embedded = NULL;
			EMapiAttachment *attach;

			attach = e_mapi_attachment_new (object);
			message = CAMEL_MIME_MESSAGE (dw);
			if (e_mapi_mail_utils_message_to_object (message, 0, E_MAPI_CREATE_FLAG_NONE, &embedded, attach, cancellable, NULL)) {
				uint32_t ui32;
				const gchar *str;

				e_mapi_object_add_attachment (object, attach);
				attach->embedded_object = embedded;
				embedded->parent = object;

				ui32 = ATTACH_EMBEDDED_MSG;
				set_attach_value (PidTagAttachMethod, &ui32);
				ui32 = 0;
				set_attach_value (PidTagRenderingPosition, &ui32);
				set_attach_value (PidTagAttachMimeTag, "message/rfc822");

				str = camel_mime_message_get_subject (message);
				if (str)
					set_attach_value (PidTagAttachFilename, str);
				continue;
			} else {
				e_mapi_attachment_free (attach);
			}
		}

		content_stream = get_content_stream (part, cancellable);
		type = camel_mime_part_get_content_type (part);

		if (ii == 0 && (*is_first) && camel_content_type_is (type, "text", "plain")) {
			e_mapi_mail_add_body (object, content_stream, PidTagBody, cancellable);
			*is_first = FALSE;
		} else if (camel_content_type_is (type, "text", "html")) {
			e_mapi_mail_add_body (object, content_stream, PidTagHtml, cancellable);
		} else {
			e_mapi_mail_add_attach (object, part, content_stream, cancellable);
		}

		if (content_stream)
			g_object_unref (content_stream);
	}

	return TRUE;
}

#undef set_attach_value

gboolean
e_mapi_mail_utils_message_to_object (struct _CamelMimeMessage *message,
				     guint32 message_camel_flags,
				     EMapiCreateFlags create_flags,
				     EMapiObject **pobject,
				     TALLOC_CTX *mem_ctx,
				     GCancellable *cancellable,
				     GError **perror)
{
	EMapiObject *object;
	CamelContentType *content_type;
	CamelInternetAddress *addresses;
	const gchar *namep = NULL, *addressp = NULL;
	const gchar *str;
	gchar *msg_class = NULL;
	gchar *pid_name_content_type = NULL;
	gint ii = 0;
	uint32_t ui32;
	bool bl;

	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (pobject != NULL, FALSE);
	g_return_val_if_fail (*pobject == NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);

	content_type = camel_data_wrapper_get_mime_type_field (CAMEL_DATA_WRAPPER (message));
	g_return_val_if_fail (content_type != NULL, FALSE);

	/* headers */
	if ((create_flags & E_MAPI_CREATE_FLAG_SUBMIT) == 0) {
		/* though invalid, then possible, to pass in a message without any 'from' */
		CamelInternetAddress *from = camel_mime_message_get_from (message);
		if (!from || !camel_internet_address_get (from, 0, &namep, &addressp))
			namep = NULL;
	}

	object = e_mapi_object_new (mem_ctx);

	#define set_value(pt,vl) {							\
		if (!e_mapi_utils_add_property (&object->properties, pt, vl, object)) {	\
			e_mapi_object_free (object);					\
			g_free (msg_class);						\
			g_free (pid_name_content_type);					\
											\
			g_warning ("%s: Failed to set property 0x%x", G_STRFUNC, pt);	\
											\
			return FALSE;							\
		}									\
	}

	ui32 = 65001; /* UTF8 - also used with PR_HTML */
	set_value (PidTagInternetCodepage, &ui32);

	if ((create_flags & E_MAPI_CREATE_FLAG_SUBMIT) == 0) {
		if ((message_camel_flags & CAMEL_MESSAGE_ANSWERED) != 0 ||
		    (message_camel_flags & CAMEL_MESSAGE_ANSWERED_ALL) != 0) {
			ui32 = 0x105;
			set_value (PidTagIconIndex, &ui32);
		} else if ((message_camel_flags & CAMEL_MESSAGE_FORWARDED) != 0) {
			ui32 = 0x106;
			set_value (PidTagIconIndex, &ui32);
		}

		ui32 = 0;
		if (message_camel_flags & CAMEL_MESSAGE_SEEN)
			ui32 |= MSGFLAG_READ;
		if (message_camel_flags & CAMEL_MESSAGE_ATTACHMENTS)
			ui32 |= MSGFLAG_HASATTACH;
	} else {
		ui32 = MSGFLAG_UNSENT;
	}
	set_value (PidTagMessageFlags, &ui32);

	bl = false;
	set_value (PidTagSendRichInfo, &bl);

	/* PidTagConversationTopic and PidTagNormalizedSubject, together with PidTagSubjectPrefix
	   are computed from PidTagSubject by a server */
	str = camel_mime_message_get_subject (message);
	if (str)
		set_value (PidTagSubject, str);

	/* some properties may not be set when submitting a message */
	if ((create_flags & E_MAPI_CREATE_FLAG_SUBMIT) == 0) {
		time_t msg_time = 0;
		gint msg_time_offset = 0;
		GArray *headers;

		if (namep && *namep)
			set_value (PidTagSentRepresentingName, namep);

		if (addressp && *addressp) {
			set_value (PidTagSentRepresentingAddressType, "SMTP");
			set_value (PidTagSentRepresentingEmailAddress, addressp);
		}

		msg_time = camel_mime_message_get_date (message, &msg_time_offset);
		if (msg_time == CAMEL_MESSAGE_DATE_CURRENT)
			msg_time = camel_mime_message_get_date_received (message, &msg_time_offset);
		if (msg_time != 0) {
			struct FILETIME msg_date = { 0 };

			e_mapi_util_time_t_to_filetime (msg_time, &msg_date);

			set_value (PidTagClientSubmitTime, &msg_date);
		}

		msg_time = camel_mime_message_get_date_received (message, &msg_time_offset);
		if (msg_time != 0) {
			struct FILETIME msg_date = { 0 };

			e_mapi_util_time_t_to_filetime (msg_time, &msg_date);

			set_value (PidTagMessageDeliveryTime, &msg_date);
		}

		headers = camel_medium_get_headers (CAMEL_MEDIUM (message));
		if (headers) {
			GString *hstr = g_string_new ("");

			for (ii = 0; ii < headers->len; ii++) {
				CamelMediumHeader *h = &g_array_index (headers, CamelMediumHeader, ii);

				if (!h->name || !*h->name || g_ascii_strncasecmp (h->name, "X-Evolution", 11) == 0)
					continue;

				g_string_append_printf (hstr, "%s: %s\n", h->name, h->value ? h->value : "");
			}

			camel_medium_free_headers (CAMEL_MEDIUM (message), headers);

			if (hstr->len && hstr->str)
				set_value (PidTagTransportMessageHeaders, hstr->str);

			g_string_free (hstr, TRUE);
		}
	}

	str = camel_medium_get_header ((CamelMedium *) message, "References");
	if (str)
		set_value (PidTagInternetReferences, str);

	str = camel_medium_get_header ((CamelMedium *) message, "In-Reply-To");
	if (str)
		set_value (PidTagInReplyToId, str);

	str = camel_medium_get_header ((CamelMedium *) message, "Message-ID");
	if (str)
		set_value (PidTagInternetMessageId, str);

	addresses = camel_mime_message_get_recipients (message, CAMEL_RECIPIENT_TYPE_TO);
	e_mapi_mail_add_recipients (object, addresses, olTo);

	addresses = camel_mime_message_get_recipients (message, CAMEL_RECIPIENT_TYPE_CC);
	e_mapi_mail_add_recipients (object, addresses, olCC);

	addresses = camel_mime_message_get_recipients (message, CAMEL_RECIPIENT_TYPE_BCC);
	e_mapi_mail_add_recipients (object, addresses, olBCC);

	if (camel_content_type_is (content_type, "application", "x-pkcs7-mime") ||
	    camel_content_type_is (content_type, "application", "pkcs7-mime")) {
		e_mapi_mail_do_smime_encrypted (object, CAMEL_MEDIUM (message), &msg_class, &pid_name_content_type, cancellable);
	} else {
		CamelDataWrapper *dw = NULL;
		CamelStream *content_stream;
		CamelMultipart *multipart;

		/* contents body */
		dw = camel_medium_get_content (CAMEL_MEDIUM (message));
		if (CAMEL_IS_MULTIPART (dw)) {
			gboolean is_first = TRUE;

			multipart = CAMEL_MULTIPART (dw);

			if (CAMEL_IS_MULTIPART_SIGNED (multipart) && camel_multipart_get_number (multipart) == 2) {
				e_mapi_mail_do_smime_signed (object, multipart, &msg_class, cancellable);
			} else {
				e_mapi_mail_do_multipart (object, multipart, &is_first, cancellable);
			}
		} else if (dw) {
			CamelContentType *type;
			CamelMimePart *part = CAMEL_MIME_PART (message);

			content_stream = get_content_stream (part, cancellable);
			type = camel_data_wrapper_get_mime_type_field (dw);

			if (camel_content_type_is (type, "text", "plain")) {
				e_mapi_mail_add_body (object, content_stream, PidTagBody, cancellable);
			} else if (camel_content_type_is (type, "text", "html")) {
				e_mapi_mail_add_body (object, content_stream, PidTagHtml, cancellable);
			} else {
				e_mapi_mail_add_attach (object, part, content_stream, cancellable);
			}

			if (content_stream)
				g_object_unref (content_stream);
		}
	}

	if (msg_class)
		set_value (PidTagMessageClass, msg_class);

	if (pid_name_content_type)
		set_value (PidNameContentType, pid_name_content_type);

	g_free (msg_class);
	g_free (pid_name_content_type);

	*pobject = object;

	#undef set_value

	return TRUE;
}
