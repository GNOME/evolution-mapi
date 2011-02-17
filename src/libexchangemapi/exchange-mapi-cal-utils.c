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
 *    Suman Manjunath <msuman@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gstdio.h>
#include <fcntl.h>
#include <libecal/e-cal-util.h>
#include "exchange-mapi-cal-utils.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* This property changed names in openchange, try to support both */
#ifndef PidLidTaskAcceptanceState
	#define PidLidTaskAcceptanceState PidLidAcceptanceState
#endif

#define d(x) 

static gboolean appt_build_name_id (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props);
static gboolean task_build_name_id (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props);
static gboolean note_build_name_id (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props);

static icalparameter_role
get_role_from_type (OlMailRecipientType type)
{
	switch (type) {
		case olCC   : return ICAL_ROLE_OPTPARTICIPANT;
		case olOriginator :
		case olTo   :
		case olBCC  :
		default     : return ICAL_ROLE_REQPARTICIPANT;
	}
}

static OlMailRecipientType
get_type_from_role (icalparameter_role role)
{
	switch (role) {
		case ICAL_ROLE_OPTPARTICIPANT	: return olCC;
		case ICAL_ROLE_CHAIR		:
		case ICAL_ROLE_REQPARTICIPANT	:
		case ICAL_ROLE_NONPARTICIPANT	:
		default				: return olTo;
	}
}

static icalparameter_partstat
get_partstat_from_trackstatus (uint32_t trackstatus)
{
	switch (trackstatus) {
		case olResponseOrganized :
		case olResponseAccepted  : return ICAL_PARTSTAT_ACCEPTED;
		case olResponseTentative : return ICAL_PARTSTAT_TENTATIVE;
		case olResponseDeclined  : return ICAL_PARTSTAT_DECLINED;
		default			: return ICAL_PARTSTAT_NEEDSACTION;
	}
}

static uint32_t
get_trackstatus_from_partstat (icalparameter_partstat partstat)
{
	switch (partstat) {
		case ICAL_PARTSTAT_ACCEPTED	: return olResponseAccepted;
		case ICAL_PARTSTAT_TENTATIVE	: return olResponseTentative;
		case ICAL_PARTSTAT_DECLINED	: return olResponseDeclined;
		default				: return olResponseNone;
	}
}

static icalproperty_transp
get_transp_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
		case olFree		:
		case olTentative	: return ICAL_TRANSP_TRANSPARENT;
		case olBusy		:
		case olOutOfOffice	:
		default			: return ICAL_TRANSP_OPAQUE;
	}
}

static uint32_t
get_prop_from_transp (icalproperty_transp transp)
{
	/* FIXME: is this mapping correct ? */
	switch (transp) {
		case ICAL_TRANSP_TRANSPARENT		:
		case ICAL_TRANSP_TRANSPARENTNOCONFLICT	: return olFree;
		case ICAL_TRANSP_OPAQUE			:
		case ICAL_TRANSP_OPAQUENOCONFLICT	:
		default					: return olBusy;
	}
}

static icalproperty_status
get_taskstatus_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
		case olTaskComplete	: return ICAL_STATUS_COMPLETED;
		case olTaskWaiting	:
		case olTaskInProgress	: return ICAL_STATUS_INPROCESS;
		case olTaskDeferred	: return ICAL_STATUS_CANCELLED;
		case olTaskNotStarted	:
		default			: return ICAL_STATUS_NEEDSACTION;
	}
}

static uint32_t
get_prop_from_taskstatus (icalproperty_status status)
{
	/* FIXME: is this mapping correct ? */
	switch (status) {
		case ICAL_STATUS_INPROCESS	: return olTaskInProgress;
		case ICAL_STATUS_COMPLETED	: return olTaskComplete;
		case ICAL_STATUS_CANCELLED	: return olTaskDeferred;
		default				: return olTaskNotStarted;
	}
}

static icalproperty_class
get_class_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
		case olPersonal		:
		case olPrivate		: return ICAL_CLASS_PRIVATE;
		case olConfidential	: return ICAL_CLASS_CONFIDENTIAL;
		case olNormal		:
		default			: return ICAL_CLASS_PUBLIC;
	}
}

static uint32_t
get_prop_from_class (icalproperty_class class)
{
	/* FIXME: is this mapping correct ? */
	switch (class) {
		case ICAL_CLASS_PRIVATE		: return olPrivate;
		case ICAL_CLASS_CONFIDENTIAL	: return olConfidential;
		default				: return olNormal;
	}
}

static gint
get_priority_from_prop (uint32_t prop)
{
	switch (prop) {
		case PRIORITY_LOW	: return 7;
		case PRIORITY_HIGH	: return 1;
		case PRIORITY_NORMAL	:
		default			: return 5;
	}
}

static uint32_t
get_prio_prop_from_priority (gint priority)
{
	if (priority > 0 && priority <= 4)
		return PRIORITY_HIGH;
	else if (priority > 5 && priority <= 9)
		return PRIORITY_LOW;
	else
		return PRIORITY_NORMAL;
}

static uint32_t
get_imp_prop_from_priority (gint priority)
{
	if (priority > 0 && priority <= 4)
		return IMPORTANCE_HIGH;
	else if (priority > 5 && priority <= 9)
		return IMPORTANCE_LOW;
	else
		return IMPORTANCE_NORMAL;
}

void
exchange_mapi_cal_util_fetch_attachments (ECalComponent *comp, GSList **attach_list, const gchar *local_store_uri)
{
	GSList *comp_attach_list = NULL, *new_attach_list = NULL;
	GSList *l;
	const gchar *uid;

	e_cal_component_get_attachment_list (comp, &comp_attach_list);
	e_cal_component_get_uid (comp, &uid);

	for (l = comp_attach_list; l; l = l->next) {
		gchar *sfname_uri = (gchar *) l->data;
		gchar *sfname = NULL, *filename = NULL;
		GMappedFile *mapped_file;
		GError *error = NULL;

		sfname = g_filename_from_uri (sfname_uri, NULL, NULL);
		mapped_file = g_mapped_file_new (sfname, FALSE, &error);
		filename = g_path_get_basename (sfname);

		if (mapped_file) {
			ExchangeMAPIAttachment *attach_item;
			ExchangeMAPIStream *stream;
			guint8 *attach = (guint8 *) g_mapped_file_get_contents (mapped_file);
			guint filelength = g_mapped_file_get_length (mapped_file);
			const gchar *split_name;
			uint32_t flag;

			if (g_str_has_prefix (filename, uid)) {
				split_name = (filename + strlen (uid) + strlen ("-"));
			} else {
				split_name = filename;
			}

			new_attach_list = g_slist_append (new_attach_list, g_strdup (sfname_uri));

			attach_item = g_new0 (ExchangeMAPIAttachment, 1);

			attach_item->cValues = 4;
			attach_item->lpProps = g_new0 (struct SPropValue, attach_item->cValues + 1);

			flag = ATTACH_BY_VALUE;
			set_SPropValue_proptag(&(attach_item->lpProps[0]), PR_ATTACH_METHOD, (gconstpointer ) (&flag));

			/* MSDN Documentation: When the supplied offset is -1 (0xFFFFFFFF), the
			 * attachment is not rendered using the PR_RENDERING_POSITION property.
			 * All values other than -1 indicate the position within PR_BODY at which
			 * the attachment is to be rendered.
			 */
			flag = 0xFFFFFFFF;
			set_SPropValue_proptag(&(attach_item->lpProps[1]), PR_RENDERING_POSITION, (gconstpointer ) (&flag));

			set_SPropValue_proptag(&(attach_item->lpProps[2]), PR_ATTACH_FILENAME_UNICODE, (gconstpointer ) g_strdup(split_name));
			set_SPropValue_proptag(&(attach_item->lpProps[3]), PR_ATTACH_LONG_FILENAME_UNICODE, (gconstpointer ) g_strdup(split_name));

			stream = g_new0 (ExchangeMAPIStream, 1);
			stream->proptag = PR_ATTACH_DATA_BIN;
			stream->value = g_byte_array_sized_new (filelength);
			stream->value = g_byte_array_append (stream->value, attach, filelength);
			attach_item->streams = g_slist_append (attach_item->streams, stream);

			*attach_list = g_slist_append (*attach_list, attach_item);

#if GLIB_CHECK_VERSION(2,21,3)
			g_mapped_file_unref (mapped_file);
#else
			g_mapped_file_free (mapped_file);
#endif
		} else if (error) {
			g_debug ("Could not map %s: %s \n", sfname_uri, error->message);
			g_error_free (error);
		}

		g_free (filename);
	}

	e_cal_component_set_attachment_list (comp, new_attach_list);

	for (l = new_attach_list; l != NULL; l = l->next)
		g_free (l->data);
	g_slist_free (new_attach_list);
}

#define RECIP_SENDABLE  0x1
#define RECIP_ORGANIZER 0x2

void
exchange_mapi_cal_util_fetch_organizer (ECalComponent *comp, GSList **recip_list)
{
	icalcomponent *icalcomp = e_cal_component_get_icalcomponent (comp);
	icalproperty *org_prop = NULL;
	const gchar *org = NULL;

	org_prop = icalcomponent_get_first_property (icalcomp, ICAL_ORGANIZER_PROPERTY);
	org = icalproperty_get_organizer (org_prop);
	if (org && *org) {
		ExchangeMAPIRecipient *recipient;
		uint32_t val = 0;
		const gchar *str = NULL;
		icalparameter *param;

		recipient = g_new0 (ExchangeMAPIRecipient, 1);

		if (!g_ascii_strncasecmp (org, "mailto:", 7))
			recipient->email_id = (org) + 7;
		else
			recipient->email_id = (org);

		/* Required properties - set them always */
		recipient->in.req_cValues = 5;
		recipient->in.req_lpProps = g_new0 (struct SPropValue, recipient->in.req_cValues + 1);

		val = 0;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[0]), PR_SEND_INTERNET_ENCODING, (gconstpointer )&val);

		val = RECIP_SENDABLE | RECIP_ORGANIZER;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[1]), PR_RECIPIENT_FLAGS, (gconstpointer )&val);

		val = olResponseNone;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[2]), PR_RECIPIENT_TRACKSTATUS, (gconstpointer )&val);

		val = olTo;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[3]), PR_RECIPIENT_TYPE, (gconstpointer ) &val);

		param = icalproperty_get_first_parameter (org_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		if (!(str && *str))
			str = "";
		set_SPropValue_proptag (&(recipient->in.req_lpProps[4]), PR_RECIPIENT_DISPLAY_NAME_UNICODE, (gconstpointer )(str));

		/* External recipient properties - set them only when the recipient is unresolved */
		recipient->in.ext_cValues = 5;
		recipient->in.ext_lpProps = g_new0 (struct SPropValue, recipient->in.ext_cValues + 1);

		val = DT_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[0]), PR_DISPLAY_TYPE, (gconstpointer )&val);
		val = MAPI_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[1]), PR_OBJECT_TYPE, (gconstpointer )&val);
		str = "SMTP";
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[2]), PR_ADDRTYPE_UNICODE, (gconstpointer )(str));
		str = recipient->email_id;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[3]), PR_SMTP_ADDRESS_UNICODE, (gconstpointer )(str));

		param = icalproperty_get_first_parameter (org_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		if (!(str && *str))
			str = "";
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[4]), PR_DISPLAY_NAME_UNICODE, (gconstpointer )(str));

		*recip_list = g_slist_append (*recip_list, recipient);
	}
}

void
exchange_mapi_cal_util_fetch_recipients (ECalComponent *comp, GSList **recip_list)
{
	icalcomponent *icalcomp = e_cal_component_get_icalcomponent (comp);
	icalproperty *org_prop = NULL, *att_prop = NULL;
	const gchar *org = NULL;

	org_prop = icalcomponent_get_first_property (icalcomp, ICAL_ORGANIZER_PROPERTY);
	org = icalproperty_get_organizer (org_prop);
	if (!org)
		org = "";

	att_prop = icalcomponent_get_first_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	while (att_prop) {
		ExchangeMAPIRecipient *recipient;
		uint32_t val = 0;
		const gchar *str = NULL;
		icalparameter *param;

		str = icalproperty_get_attendee (att_prop);
		if (!str || g_ascii_strcasecmp (str, org) == 0) {
			att_prop = icalcomponent_get_next_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
			continue;
		}

		recipient = g_new0 (ExchangeMAPIRecipient, 1);

		if (!g_ascii_strncasecmp (str, "mailto:", 7))
			recipient->email_id = (str) + 7;
		else
			recipient->email_id = (str);

		/* Required properties - set them always */
		recipient->in.req_cValues = 5;
		recipient->in.req_lpProps = g_new0 (struct SPropValue, recipient->in.req_cValues + 1);

		val = 0;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[0]), PR_SEND_INTERNET_ENCODING, (gconstpointer )&val);

		val = RECIP_SENDABLE | (!g_ascii_strcasecmp(str, org) ? RECIP_ORGANIZER : 0);
		set_SPropValue_proptag (&(recipient->in.req_lpProps[1]), PR_RECIPIENT_FLAGS, (gconstpointer )&val);

		param = icalproperty_get_first_parameter (att_prop, ICAL_PARTSTAT_PARAMETER);
		val = get_trackstatus_from_partstat (icalparameter_get_partstat(param));
		set_SPropValue_proptag (&(recipient->in.req_lpProps[2]), PR_RECIPIENT_TRACKSTATUS, (gconstpointer )&val);

		param = icalproperty_get_first_parameter (att_prop, ICAL_ROLE_PARAMETER);
		val = get_type_from_role (icalparameter_get_role(param));
		set_SPropValue_proptag (&(recipient->in.req_lpProps[3]), PR_RECIPIENT_TYPE, (gconstpointer ) &val);

		param = icalproperty_get_first_parameter (att_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		str = (str) ? str : recipient->email_id;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[4]), PR_RECIPIENT_DISPLAY_NAME_UNICODE, (gconstpointer )(str));

		/* External recipient properties - set them only when the recipient is unresolved */
		recipient->in.ext_cValues = 7;
		recipient->in.ext_lpProps = g_new0 (struct SPropValue, recipient->in.ext_cValues + 1);

		val = DT_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[0]), PR_DISPLAY_TYPE, (gconstpointer )&val);
		val = MAPI_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[1]), PR_OBJECT_TYPE, (gconstpointer )&val);
		str = "SMTP";
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[2]), PR_ADDRTYPE_UNICODE, (gconstpointer )(str));
		str = recipient->email_id;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[3]), PR_SMTP_ADDRESS_UNICODE, (gconstpointer )(str));

		param = icalproperty_get_first_parameter (att_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		str = (str) ? str : recipient->email_id;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[4]), PR_GIVEN_NAME_UNICODE, (gconstpointer )(str));
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[5]), PR_DISPLAY_NAME_UNICODE, (gconstpointer )(str));
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[6]), PR_7BIT_DISPLAY_NAME_UNICODE, (gconstpointer )(str));

		*recip_list = g_slist_append (*recip_list, recipient);

		att_prop = icalcomponent_get_next_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	}
}

static void
set_attachments_to_cal_component (ECalComponent *comp, GSList *attach_list, const gchar *local_store_uri)
{
	GSList *comp_attach_list = NULL, *l;
	const gchar *uid;

	g_return_if_fail (comp != NULL);

	e_cal_component_get_uid (comp, &uid);
	for (l = attach_list; l; l = l->next) {
		ExchangeMAPIAttachment *attach_item = (ExchangeMAPIAttachment *) (l->data);
		ExchangeMAPIStream *stream;
		gchar *attach_file_url, *filename;
		const gchar *str, *attach;
		GError *error = NULL;
		guint len;
		gint fd = -1;

		stream = exchange_mapi_util_find_stream (attach_item->streams, PR_ATTACH_DATA_BIN);
		if (!stream)
			continue;

		attach = (const gchar *)stream->value->data;
		len = stream->value->len;

		str = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval(attach_item->lpProps, PR_ATTACH_LONG_FILENAME_UNICODE);
		if (!(str && *str))
			str = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval(attach_item->lpProps, PR_ATTACH_FILENAME_UNICODE);
		filename = g_strconcat (local_store_uri, G_DIR_SEPARATOR_S, uid, "-", str, NULL);
		attach_file_url = g_filename_to_uri (filename, NULL, &error);
	
		if (!attach_file_url) {
			g_message ("Could not get attach_file_url %s \n", error->message);
			g_clear_error (&error);
			g_free (filename);
			return;
		}

		fd = g_open (filename, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600);
		if (fd == -1) {
			/* skip gracefully */
			g_debug ("Could not open %s for writing \n", filename);
		} else if (len && write (fd, attach, len) == -1) {
			/* skip gracefully */
			g_debug ("Attachment write failed \n");
		}
		if (fd != -1) {
			close (fd);
			comp_attach_list = g_slist_append (comp_attach_list, g_strdup (attach_file_url));
		}

		g_free (filename);
		g_free (attach_file_url);
	}

	e_cal_component_set_attachment_list (comp, comp_attach_list);
}

static void
ical_attendees_from_props (icalcomponent *ical_comp, GSList *recipients, gboolean rsvp)
{
	GSList *l;
	for (l=recipients; l; l=l->next) {
		ExchangeMAPIRecipient *recip = (ExchangeMAPIRecipient *)(l->data);
		icalproperty *prop = NULL;
		icalparameter *param;
		gchar *val;
		const uint32_t *ui32;
		const gchar *str;
		const uint32_t *flags;

		if (recip->email_id)
			val = g_strdup_printf ("MAILTO:%s", recip->email_id);
		else
			continue;

		flags = (const uint32_t *) get_SPropValue_SRow_data (&recip->out_SRow, PR_RECIPIENT_FLAGS);

		if (flags && (*flags & RECIP_ORGANIZER)) {
			prop = icalproperty_new_organizer (val);

			/* CN */
			str = (const gchar *) exchange_mapi_util_find_row_propval (&recip->out_SRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
			if (!str)
				str = (const gchar *) exchange_mapi_util_find_row_propval (&recip->out_SRow, PR_DISPLAY_NAME_UNICODE);
			if (str) {
				param = icalparameter_new_cn (str);
				icalproperty_add_parameter (prop, param);
			}
		} else {
			prop = icalproperty_new_attendee (val);

			/* CN */
			str = (const gchar *) exchange_mapi_util_find_row_propval (&recip->out_SRow, PR_RECIPIENT_DISPLAY_NAME_UNICODE);
			if (!str)
				str = (const gchar *) exchange_mapi_util_find_row_propval (&recip->out_SRow, PR_DISPLAY_NAME_UNICODE);
			if (str) {
				param = icalparameter_new_cn (str);
				icalproperty_add_parameter (prop, param);
			}
			/* RSVP */
			param = icalparameter_new_rsvp (rsvp ? ICAL_RSVP_TRUE : ICAL_RSVP_FALSE);
			icalproperty_add_parameter (prop, param);
			/* PARTSTAT */
			ui32 = (const uint32_t *) get_SPropValue_SRow_data (&recip->out_SRow, PR_RECIPIENT_TRACKSTATUS);
			param = icalparameter_new_partstat (get_partstat_from_trackstatus (ui32 ? *ui32 : olResponseNone));
			icalproperty_add_parameter (prop, param);
			/* ROLE */
			ui32 = (const uint32_t *) get_SPropValue_SRow_data (&recip->out_SRow, PR_RECIPIENT_TYPE);
			param = icalparameter_new_role (get_role_from_type (ui32 ? *ui32 : olTo));
			icalproperty_add_parameter (prop, param);

			/* CALENDAR USER TYPE */
			param = NULL;
			if (ui32 && *ui32 == 0x03)
				param = icalparameter_new_cutype (ICAL_CUTYPE_RESOURCE);
			if (!param)
				param = icalparameter_new_cutype (ICAL_CUTYPE_INDIVIDUAL);
			icalproperty_add_parameter (prop, param);
		}

		if (prop)
			icalcomponent_add_property (ical_comp, prop);

		g_free (val);
	}
}

static const uint8_t GID_START_SEQ[] = {
	0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xe0, 0x00,
	0x74, 0xc5, 0xb7, 0x10, 0x1a, 0x82, 0xe0, 0x08
};

void
exchange_mapi_cal_util_generate_globalobjectid (gboolean is_clean, const gchar *uid, struct Binary_r *sb)
{
	GByteArray *ba;
	guint32 flag32;
	guchar *buf = NULL;
	gsize len;
	d(guint32 i);

	ba = g_byte_array_new ();

	ba = g_byte_array_append (ba, GID_START_SEQ, (sizeof (GID_START_SEQ) / sizeof (GID_START_SEQ[0])));

	/* FIXME for exceptions */
	if (is_clean || TRUE) {
		flag32 = 0;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));
	}

	/* creation time - may be all 0's  */
	flag32 = 0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));
	flag32 = 0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* RESERVED - should be all 0's  */
	flag32 = 0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));
	flag32 = 0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* FIXME: cleanup the UID first */

	/* We put Evolution's UID in base64 here */
	buf = g_base64_decode (uid, &len);
	if (len % 2 != 0)
		--len;
	flag32 = len;

	/* Size in bytes of the following data */
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));
	/* Data */
	ba = g_byte_array_append (ba, (const guint8 *)buf, flag32);
	g_free (buf);

	sb->lpb = ba->data;
	sb->cb = ba->len;

	d(g_message ("New GlobalObjectId.. Length: %d bytes.. Hex-data follows:", ba->len));
	d(for (i = 0; i < ba->len; i++)
		g_print("0x%02X ", ba->data[i]));

	g_byte_array_free (ba, FALSE);
}

static gchar *
id_to_string (GByteArray *ba)
{
	guint8 *ptr;
	guint len;
	gchar *buf = NULL;
	guint32 flag32, i, j;

	g_return_val_if_fail (ba != NULL, NULL);
	/* MSDN docs: the globalID must have an even number of bytes */
	if ((ba->len)%2 != 0)
		return NULL;

	ptr = ba->data;
	len = ba->len;

	/* starting seq - len = 16 bytes */
	for (i = 0, j = 0;(i < len) && (j < sizeof (GID_START_SEQ)); ++i, ++ptr, ++j)
		if (*ptr != GID_START_SEQ[j])
			return NULL;

	/* FIXME: for exceptions - len = 4 bytes */
	flag32 = *((guint32 *)ptr);
	i += sizeof (guint32);
	if (!(i < len) || flag32 != 0)
		return NULL;
	ptr += sizeof (guint32);

	/* Creation time - len = 8 bytes - skip it */
	flag32 = *((guint32 *)ptr);
	i += sizeof (guint32);
	if (!(i < len))
		return NULL;
	ptr += sizeof (guint32);

	flag32 = *((guint32 *)ptr);
	i += sizeof (guint32);
	if (!(i < len))
		return NULL;
	ptr += sizeof (guint32);

	/* Reserved bytes - len = 8 bytes */
	flag32 = *((guint32 *)ptr);
	i += sizeof (guint32);
	if (!(i < len) || flag32 != 0)
		return NULL;
	ptr += sizeof (guint32);

	flag32 = *((guint32 *)ptr);
	i += sizeof (guint32);
	if (!(i < len) || flag32 != 0)
		return NULL;
	ptr += sizeof (guint32);

	/* This is the real data */
	flag32 = *((guint32 *)ptr);
	i += sizeof (guint32);
	if (!(i < len) || flag32 != (len - i))
		return NULL;
	ptr += sizeof (guint32);

	buf = g_base64_encode (ptr, flag32);

	return buf;
}

ECalComponent *
exchange_mapi_cal_util_mapi_props_to_comp (ExchangeMapiConnection *conn, icalcomponent_kind kind, const gchar *mid, struct mapi_SPropValue_array *properties,
					   GSList *streams, GSList *recipients, GSList *attachments,
					   const gchar *local_store_uri, const icaltimezone *default_zone, gboolean is_reply)
{
	ECalComponent *comp = NULL;
	struct timeval t;
	ExchangeMAPIStream *body_stream;
	const gchar *subject = NULL, *body = NULL;
	const uint32_t *ui32;
	const bool *b;
	icalcomponent *ical_comp;
	icalproperty *prop = NULL;
	icalparameter *param = NULL;
	const icaltimezone *utc_zone;

	switch (kind) {
		case ICAL_VEVENT_COMPONENT:
		case ICAL_VTODO_COMPONENT:
		case ICAL_VJOURNAL_COMPONENT:
			comp = e_cal_component_new ();
			ical_comp = icalcomponent_new (kind);
			e_cal_component_set_icalcomponent (comp, ical_comp);
			icalcomponent_set_uid (ical_comp, mid);
			e_cal_component_set_uid (comp, mid);
			break;
		default:
			return NULL;
	}

	utc_zone = icaltimezone_get_utc_timezone ();

	subject = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_SUBJECT_UNICODE);
	if (!subject)
		subject = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_NORMALIZED_SUBJECT_UNICODE);
	if (!subject)
		subject = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_CONVERSATION_TOPIC_UNICODE);
	if (!subject)
		subject = "";

	body = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_BODY_UNICODE);
	if (!body) {
		body_stream = exchange_mapi_util_find_stream (streams, PR_HTML);
		body = body_stream ? (const gchar *) body_stream->value->data : "";
	}

	/* set dtstamp - in UTC */
	if (get_mapi_SPropValue_array_date_timeval (&t, properties, PR_CREATION_TIME) == MAPI_E_SUCCESS)
		icalcomponent_set_dtstamp (ical_comp, icaltime_from_timet_with_zone (t.tv_sec, 0, utc_zone));

	/* created - in UTC */
	prop = icalproperty_new_created (icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ()));
	icalcomponent_add_property (ical_comp, prop);

	/* last modified - in UTC */
	if (get_mapi_SPropValue_array_date_timeval (&t, properties, PR_LAST_MODIFICATION_TIME) == MAPI_E_SUCCESS) {
		prop = icalproperty_new_lastmodified (icaltime_from_timet_with_zone (t.tv_sec, 0, utc_zone));
		icalcomponent_add_property (ical_comp, prop);
	}

	icalcomponent_set_summary (ical_comp, subject);
	icalcomponent_set_description (ical_comp, body);

	if (icalcomponent_isa (ical_comp) == ICAL_VEVENT_COMPONENT) {
		const gchar *location = NULL;
		const gchar *dtstart_tz_location = NULL, *dtend_tz_location = NULL;
		gboolean all_day;
		ExchangeMAPIStream *stream;

		/* CleanGlobalObjectId */
		stream = exchange_mapi_util_find_stream (streams, PidLidCleanGlobalObjectId);
		if (stream) {
			gchar *value = id_to_string (stream->value);
			prop = icalproperty_new_x (value);
			icalproperty_set_x_name (prop, "X-EVOLUTION-MAPI-CLEAN-GLOBALID");
			icalcomponent_add_property (ical_comp, prop);
			g_free (value);
		}

		/* GlobalObjectId */
		stream = exchange_mapi_util_find_stream (streams, PidLidGlobalObjectId);
		if (stream) {
			gchar *value = id_to_string (stream->value);
			prop = icalproperty_new_x (value);
			icalproperty_set_x_name (prop, "X-EVOLUTION-MAPI-GLOBALID");
			icalcomponent_add_property (ical_comp, prop);
			if (value && *value) {
				e_cal_component_set_uid (comp, value);

				if (!g_str_equal (value, mid)) {
					prop = icalproperty_new_x (mid);
					icalproperty_set_x_name (prop, "X-EVOLUTION-MAPI-MID");
					icalcomponent_add_property (ical_comp, prop);
				}
			}

			g_free (value);
		}

		/* AppointmentSequence */
		ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PidLidAppointmentSequence);
		if (ui32) {
			gchar *value = g_strdup_printf ("%d", *ui32);
			prop = icalproperty_new_x (value);
			icalproperty_set_x_name (prop, "X-EVOLUTION-MAPI-APPTSEQ");
			icalcomponent_add_property (ical_comp, prop);
			g_free (value);
		}

		location = (const gchar *)exchange_mapi_util_find_array_propval(properties, PidLidLocation);
		if (location && *location)
			icalcomponent_set_location (ical_comp, location);

		b = (const bool *)find_mapi_SPropValue_data(properties, PidLidAppointmentSubType);
		all_day = b && *b;

		stream = exchange_mapi_util_find_stream (streams, PidLidAppointmentTimeZoneDefinitionStartDisplay);
		if (stream) {
			gchar *buf = exchange_mapi_cal_util_bin_to_mapi_tz (stream->value);
			dtstart_tz_location = exchange_mapi_cal_tz_util_get_ical_equivalent (buf);
			g_free (buf);
		}

		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PidLidAppointmentStartWhole) == MAPI_E_SUCCESS) {
			icaltimezone *zone = dtstart_tz_location ? icaltimezone_get_builtin_timezone (dtstart_tz_location) : (icaltimezone *)default_zone;
			prop = icalproperty_new_dtstart (icaltime_from_timet_with_zone (t.tv_sec, all_day, zone));
			if (!all_day && zone && icaltimezone_get_tzid (zone)) {
				icalproperty_add_parameter (prop, icalparameter_new_tzid (icaltimezone_get_tzid (zone)));
			}

			icalcomponent_add_property (ical_comp, prop);
		}

		stream = exchange_mapi_util_find_stream (streams, PidLidAppointmentTimeZoneDefinitionEndDisplay);
		if (stream) {
			gchar *buf = exchange_mapi_cal_util_bin_to_mapi_tz (stream->value);
			dtend_tz_location = exchange_mapi_cal_tz_util_get_ical_equivalent (buf);
			g_free (buf);
		}

		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PidLidAppointmentEndWhole) == MAPI_E_SUCCESS) {
			icaltimezone *zone = dtend_tz_location ? icaltimezone_get_builtin_timezone (dtend_tz_location) : (icaltimezone *)default_zone;
			prop = icalproperty_new_dtend (icaltime_from_timet_with_zone (t.tv_sec, all_day, zone));
			if (!all_day && zone && icaltimezone_get_tzid (zone)) {
				icalproperty_add_parameter (prop, icalparameter_new_tzid (icaltimezone_get_tzid (zone)));
			}

			icalcomponent_add_property (ical_comp, prop);
		}

		ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PidLidBusyStatus);
		if (ui32) {
			prop = icalproperty_new_transp (get_transp_from_prop (*ui32));
			icalcomponent_add_property (ical_comp, prop);
		}

		if (recipients) {
			b = (const bool *)find_mapi_SPropValue_data(properties, PR_RESPONSE_REQUESTED);
			ical_attendees_from_props (ical_comp, recipients, (b && *b));
			if (is_reply) {
				if (icalcomponent_get_first_property (ical_comp, ICAL_ORGANIZER_PROPERTY) == NULL) {
					gchar *val, *to_free = NULL;
					const gchar *name = exchange_mapi_util_find_array_propval (properties, PR_RCVD_REPRESENTING_NAME_UNICODE);
					const gchar *email_type = exchange_mapi_util_find_array_propval (properties, PR_RCVD_REPRESENTING_ADDRTYPE_UNICODE);
					const gchar *email = exchange_mapi_util_find_array_propval (properties, PR_RCVD_REPRESENTING_EMAIL_ADDRESS_UNICODE);

					if (!name)
						name = "";
					if (!email_type)
						email_type = "";
					if (!email)
						email = "";

					if (g_str_equal (email_type, "EX")) {
						to_free = exchange_mapi_connection_ex_to_smtp (conn, email, NULL);
						email = to_free;
					}

					val = g_strdup_printf ("MAILTO:%s", email);
					prop = icalproperty_new_organizer (val);
					g_free (val);

					/* CN */
					param = icalparameter_new_cn (name);
					icalproperty_add_parameter (prop, param);

					icalcomponent_add_property (ical_comp, prop);

					g_free (to_free);
				}

				if (icalcomponent_get_first_property (ical_comp, ICAL_ATTENDEE_PROPERTY) == NULL) {
					const uint32_t *ui32;
					gchar *val, *to_free = NULL;
					const gchar *name = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_NAME_UNICODE);
					const gchar *email_type = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE_UNICODE);
					const gchar *email = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE);

					if (!name)
						name = "";
					if (!email_type)
						email_type = "";
					if (!email)
						email = "";

					if (g_str_equal (email_type, "EX")) {
						to_free = exchange_mapi_connection_ex_to_smtp (conn, email, NULL);
						email = to_free;
					}

					val = g_strdup_printf ("MAILTO:%s", email);
					prop = icalproperty_new_attendee (val);
					g_free (val);

					/* CN */
					param = icalparameter_new_cn (name);
					icalproperty_add_parameter (prop, param);

					ui32 = exchange_mapi_util_find_array_propval (properties, PidLidResponseStatus);
					param = icalparameter_new_partstat (get_partstat_from_trackstatus (ui32 ? *ui32 : olResponseNone));
					icalproperty_add_parameter (prop, param);

					icalcomponent_add_property (ical_comp, prop);

					g_free (to_free);
				}
			} else if (icalcomponent_get_first_property (ical_comp, ICAL_ORGANIZER_PROPERTY) == NULL) {
				gchar *val, *sender_free = NULL, *sent_free = NULL;
				const gchar *sender_email_type = (const gchar *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_ADDRTYPE_UNICODE);
				const gchar *sender_email = (const gchar *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_EMAIL_ADDRESS_UNICODE);
				const gchar *sent_name = (const gchar *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_NAME_UNICODE);
				const gchar *sent_email_type = (const gchar *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE_UNICODE);
				const gchar *sent_email = (const gchar *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE);

				if (!g_utf8_collate (sender_email_type, "EX")) {
					sender_free = exchange_mapi_connection_ex_to_smtp (conn, sender_email, NULL);
					sender_email = sender_free;
				}
				if (!g_utf8_collate (sent_email_type, "EX")) {
					sent_free = exchange_mapi_connection_ex_to_smtp (conn, sent_email, NULL);
					sent_email = sent_free;
				}

				val = g_strdup_printf ("MAILTO:%s", sent_email);
				prop = icalproperty_new_organizer (val);
				g_free (val);
				/* CN */
				param = icalparameter_new_cn (sent_name);
				icalproperty_add_parameter (prop, param);
				/* SENTBY */
				if (g_utf8_collate (sent_email, sender_email)) {
					val = g_strdup_printf ("MAILTO:%s", sender_email);
					param = icalparameter_new_sentby (val);
					icalproperty_add_parameter (prop, param);
					g_free (val);
				}

				icalcomponent_add_property (ical_comp, prop);

				g_free (sender_free);
				g_free (sent_free);
			}
		}

		b = (const bool *)find_mapi_SPropValue_data(properties, PidLidRecurring);
		if (b && *b) {
			stream = exchange_mapi_util_find_stream (streams, PidLidAppointmentRecur);
			if (stream) {
				exchange_mapi_cal_util_bin_to_rrule (stream->value, comp);
			}
		}

		b = (const bool *)find_mapi_SPropValue_data(properties, PidLidReminderSet);
		if (b && *b) {
			struct timeval start, displaytime;

			if ((get_mapi_SPropValue_array_date_timeval (&start, properties, PidLidReminderTime) == MAPI_E_SUCCESS)
			 && (get_mapi_SPropValue_array_date_timeval (&displaytime, properties, PidLidReminderSignalTime) == MAPI_E_SUCCESS)) {
				ECalComponentAlarm *e_alarm = e_cal_component_alarm_new ();
				ECalComponentAlarmTrigger trigger;

				trigger.type = E_CAL_COMPONENT_ALARM_TRIGGER_RELATIVE_START;
				trigger.u.rel_duration = icaltime_subtract (icaltime_from_timet_with_zone (displaytime.tv_sec, 0, 0),
									    icaltime_from_timet_with_zone (start.tv_sec, 0, 0));

				e_cal_component_alarm_set_action (e_alarm, E_CAL_COMPONENT_ALARM_DISPLAY);
				e_cal_component_alarm_set_trigger (e_alarm, trigger);

				e_cal_component_add_alarm (comp, e_alarm);
			}
		} else
			e_cal_component_remove_all_alarms (comp);

	} else if (icalcomponent_isa (ical_comp) == ICAL_VTODO_COMPONENT) {
		const double *complete = NULL;
		const uint64_t *status = NULL;

		/* NOTE: Exchange tasks are DATE values, not DATE-TIME values, but maybe someday, we could expect Exchange to support it;) */
		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PidLidTaskStartDate) == MAPI_E_SUCCESS)
			icalcomponent_set_dtstart (ical_comp, icaltime_from_timet_with_zone (t.tv_sec, 1, default_zone));
		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PidLidTaskDueDate) == MAPI_E_SUCCESS)
			icalcomponent_set_due (ical_comp, icaltime_from_timet_with_zone (t.tv_sec, 1, default_zone));

		status = (const uint64_t *)find_mapi_SPropValue_data(properties, PidLidTaskStatus);
		if (status) {
			icalcomponent_set_status (ical_comp, get_taskstatus_from_prop(*status));
			if (*status == olTaskComplete
			&& get_mapi_SPropValue_array_date_timeval (&t, properties, PidLidTaskDateCompleted) == MAPI_E_SUCCESS) {
				prop = icalproperty_new_completed (icaltime_from_timet_with_zone (t.tv_sec, 1, default_zone));
				icalcomponent_add_property (ical_comp, prop);
			}
		}

		complete = (const double *)find_mapi_SPropValue_data(properties, PidLidPercentComplete);
		if (complete) {
			prop = icalproperty_new_percentcomplete ((gint)(*complete * 100 + 1e-9));
			icalcomponent_add_property (ical_comp, prop);
		}

		b = (const bool *)find_mapi_SPropValue_data(properties, PidLidTaskFRecurring);
		if (b && *b) {
			/* FIXME: Evolution does not support recurring tasks */
			g_warning ("Encountered a recurring task.");
		}

		b = (const bool *)find_mapi_SPropValue_data(properties, PidLidReminderSet);
		if (b && *b) {
			struct timeval abs;

			if (get_mapi_SPropValue_array_date_timeval (&abs, properties, PidLidReminderTime) == MAPI_E_SUCCESS) {
				ECalComponentAlarm *e_alarm = e_cal_component_alarm_new ();
				ECalComponentAlarmTrigger trigger;

				trigger.type = E_CAL_COMPONENT_ALARM_TRIGGER_ABSOLUTE;
				trigger.u.abs_time = icaltime_from_timet_with_zone (abs.tv_sec, 0, default_zone);

				e_cal_component_alarm_set_action (e_alarm, E_CAL_COMPONENT_ALARM_DISPLAY);
				e_cal_component_alarm_set_trigger (e_alarm, trigger);

				e_cal_component_add_alarm (comp, e_alarm);
			}
		} else
			e_cal_component_remove_all_alarms (comp);

	} else if (icalcomponent_isa (ical_comp) == ICAL_VJOURNAL_COMPONENT) {
		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PR_LAST_MODIFICATION_TIME) == MAPI_E_SUCCESS)
			icalcomponent_set_dtstart (ical_comp, icaltime_from_timet_with_zone (t.tv_sec, 1, default_zone));
	}

	if (icalcomponent_isa (ical_comp) == ICAL_VEVENT_COMPONENT || icalcomponent_isa (ical_comp) == ICAL_VTODO_COMPONENT) {
		/* priority */
		ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PR_PRIORITY);
		if (ui32) {
			prop = icalproperty_new_priority (get_priority_from_prop (*ui32));
			icalcomponent_add_property (ical_comp, prop);
		}
	}

	/* classification */
	ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PR_SENSITIVITY);
	if (ui32) {
		prop = icalproperty_new_class (get_class_from_prop (*ui32));
		icalcomponent_add_property (ical_comp, prop);
	}

	/* FIXME: categories */

	set_attachments_to_cal_component (comp, attachments, local_store_uri);

	e_cal_component_rescan (comp);

	return comp;
}

struct fetch_camel_cal_data {
	icalcomponent_kind kind;
	icalproperty_method method;
	gchar *result_data;
};

static gboolean
fetch_camel_cal_comp_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct fetch_camel_cal_data *fccd = data;
	ECalComponent *comp = NULL;
	mapi_id_t mid = 0;
	icalcomponent *icalcomp = NULL;
	gchar *str = NULL, *smid = NULL, *filepath;

	g_return_val_if_fail (item_data != NULL, FALSE);
	g_return_val_if_fail (fccd != NULL, FALSE);

	filepath = g_strdup (g_get_tmp_dir ());

	if (!comp) {
		/* read component from a mail, if not found in the calendar */
		if (mid)
			smid = exchange_mapi_util_mapi_id_to_string (mid);
		else if (item_data->mid)
			smid = exchange_mapi_util_mapi_id_to_string (item_data->mid);
		else
			smid = e_cal_component_gen_uid();
		comp = exchange_mapi_cal_util_mapi_props_to_comp (item_data->conn, fccd->kind, smid,
							item_data->properties, item_data->streams, item_data->recipients,
							item_data->attachments, filepath, NULL, TRUE);

		g_free (smid);
	}

	g_free (filepath);

	icalcomp = e_cal_util_new_top_level ();
	icalcomponent_set_method (icalcomp, fccd->method);
	if (comp)
		icalcomponent_add_component (icalcomp,
			icalcomponent_new_clone(e_cal_component_get_icalcomponent(comp)));
	str = icalcomponent_as_ical_string_r (icalcomp);
	icalcomponent_free (icalcomp);
	if (comp)
		g_object_unref (comp);

	exchange_mapi_util_free_stream_list (&item_data->streams);
	exchange_mapi_util_free_recipient_list (&item_data->recipients);
	exchange_mapi_util_free_attachment_list (&item_data->attachments);

	fccd->result_data = str;

	return TRUE;
}

gchar *
exchange_mapi_cal_util_camel_helper (ExchangeMapiConnection *conn, mapi_id_t orig_fid, mapi_id_t orig_mid, mapi_object_t *obj_message, const gchar *msg_class,
				   GSList *streams, GSList *recipients, GSList *attachments)
{
	struct fetch_camel_cal_data fccd = { 0 };

	fccd.kind = ICAL_NO_COMPONENT;
	fccd.method = ICAL_METHOD_NONE;

	g_return_val_if_fail (msg_class && *msg_class, NULL);
	g_return_val_if_fail (conn != NULL, NULL);

	if (!g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_REQUEST)) {
		fccd.method = ICAL_METHOD_REQUEST;
		fccd.kind = ICAL_VEVENT_COMPONENT;
	} else if (!g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_CANCELED)) {
		fccd.method = ICAL_METHOD_CANCEL;
		fccd.kind = ICAL_VEVENT_COMPONENT;
	} else if (g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_RESP_PREFIX)) {
		fccd.method = ICAL_METHOD_REPLY;
		fccd.kind = ICAL_VEVENT_COMPONENT;
	} else
		return NULL;

	if (obj_message)
		exchange_mapi_connection_fetch_object_props (conn, NULL, orig_fid, orig_mid, obj_message,
					exchange_mapi_cal_utils_get_props_cb, GINT_TO_POINTER (fccd.kind),
					fetch_camel_cal_comp_cb, &fccd,
					MAPI_OPTIONS_FETCH_ALL, NULL);
	else
		exchange_mapi_connection_fetch_item (conn, orig_fid, orig_mid,
					exchange_mapi_cal_utils_get_props_cb, GINT_TO_POINTER (fccd.kind),
					fetch_camel_cal_comp_cb, &fccd,
					MAPI_OPTIONS_FETCH_ALL, NULL);

	return fccd.result_data;
}

/* call with props = NULL to fetch named ids into the connection cache */
gboolean
exchange_mapi_cal_utils_add_named_ids (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gint pkind)
{
	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData common_nids[] = {
		{ PidLidReminderDelta, 0 },
		{ PidLidReminderTime, 0 },
		{ PidLidReminderSet, 0 },
		{ PidLidPrivate, 0 },
		{ PidLidSideEffects, 0 },
		{ PidLidCommonStart, 0 },
		{ PidLidCommonEnd, 0 },
		{ PidLidTaskMode, 0 },
		{ PidLidReminderSignalTime, 0 },
		{ PidLidTimeZoneStruct, 0 },
		{ PidLidTimeZoneDescription, 0 }
	};
	icalcomponent_kind kind = pkind;

	if (!props) {
		if (!exchange_mapi_connection_resolve_named_props (conn, fid, common_nids, G_N_ELEMENTS (common_nids), NULL))
			return FALSE;
	} else if (!exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, common_nids, G_N_ELEMENTS (common_nids)))
		return FALSE;

	if (kind == ICAL_VEVENT_COMPONENT)
		return appt_build_name_id (conn, fid, mem_ctx, props);
	else if (kind == ICAL_VTODO_COMPONENT)
		return task_build_name_id (conn, fid, mem_ctx, props);
	else if (kind == ICAL_VJOURNAL_COMPONENT)
		return note_build_name_id (conn, fid, mem_ctx, props);

	return TRUE;
}

#define DEFAULT_APPT_REMINDER_MINS 15

static gboolean
appt_build_name_id (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props)
{
	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData nids[] = {
		{ PidLidAppointmentSequence, 0 },
		{ PidLidBusyStatus, 0 },
		{ PidLidLocation, 0 },
		{ PidLidAppointmentStartWhole, 0 },
		{ PidLidAppointmentEndWhole, 0 },
		{ PidLidAppointmentDuration, 0 },
		{ PidLidAppointmentSubType, 0 },
		{ PidLidAppointmentRecur, 0 },
		{ PidLidAppointmentStateFlags, 0 },
		{ PidLidResponseStatus, 0 },
		{ PidLidRecurring, 0 },
		{ PidLidIntendedBusyStatus, 0 },
		{ PidLidExceptionReplaceTime, 0 },
		{ PidLidFInvited, 0 },
		{ PidLidRecurrenceType, 0 },
		{ PidLidClipStart, 0 },
		{ PidLidClipEnd, 0 },
		{ PidLidAutoFillLocation, 0 },
		{ PidLidAppointmentCounterProposal, 0 },
		{ PidLidAppointmentNotAllowPropose, 0 },
		{ PidLidAppointmentTimeZoneDefinitionStartDisplay, 0 },
		{ PidLidAppointmentTimeZoneDefinitionEndDisplay, 0 },
		{ PidLidWhere, 0 },
		{ PidLidGlobalObjectId, 0 },
		{ PidLidIsRecurring, 0 },
		{ PidLidIsException, 0 },
		{ PidLidCleanGlobalObjectId, 0 },
		{ PidLidAppointmentMessageClass, 0 },
		{ PidLidMeetingType, 0 }
	};

	if (!props)
		return exchange_mapi_connection_resolve_named_props (conn, fid, nids, G_N_ELEMENTS (nids), NULL);

	return exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids));
}

#define DEFAULT_TASK_REMINDER_MINS 1080

static gboolean
task_build_name_id (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props)
{
	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData nids[] = {
		{ PidLidTaskStatus, 0 },
		{ PidLidPercentComplete, 0 },
		{ PidLidTeamTask, 0 },
		{ PidLidTaskStartDate, 0 },
		{ PidLidTaskDueDate, 0 },
		{ PidLidTaskDateCompleted, 0 },
		/*{ PidLidTaskRecurrence, 0 },*/
		{ PidLidTaskComplete, 0 },
		{ PidLidTaskOwner, 0 },
		{ PidLidTaskAssigner, 0 },
		{ PidLidTaskFRecurring, 0 },
		{ PidLidTaskRole, 0 },
		{ PidLidTaskOwnership, 0 },
		{ PidLidTaskAcceptanceState, 0 }
	};

	if (!props)
		return exchange_mapi_connection_resolve_named_props (conn, fid, nids, G_N_ELEMENTS (nids), NULL);

	return exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids));
}

static gboolean
note_build_name_id (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props)
{
	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData nids[] = {
		{ PidLidNoteColor, 0 },
		{ PidLidNoteWidth, 0 },
		{ PidLidNoteHeight, 0 }
	};

	if (!props)
		return exchange_mapi_connection_resolve_named_props (conn, fid, nids, G_N_ELEMENTS (nids), NULL);

	return exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids));
}

/* retrieves timezone location from a timezone ID */
static const gchar *
get_tzid_location (const gchar *tzid, struct cal_cbdata *cbdata)
{
	icaltimezone *zone = NULL;

	if (!tzid || !*tzid || g_str_equal (tzid, "UTC"))
		return NULL;

	/* ask backend first, if any */
	if (cbdata && cbdata->get_timezone)
		zone = cbdata->get_timezone (cbdata->get_tz_data, tzid);

	if (!zone)
		zone = icaltimezone_get_builtin_timezone_from_tzid (tzid);

	/* the old TZID prefix used in previous versions of evolution-mapi */
	#define OLD_TZID_PREFIX "/softwarestudio.org/Tzfile/"

	if (!zone && g_str_has_prefix (tzid, OLD_TZID_PREFIX))
		zone = icaltimezone_get_builtin_timezone (tzid + strlen (OLD_TZID_PREFIX));

	#undef OLD_TZID_PREFIX

	if (!zone)
		return NULL;

	return icaltimezone_get_location (zone);
}

#define MINUTES_IN_HOUR 60
#define SECS_IN_MINUTE 60

gboolean
exchange_mapi_cal_utils_write_props_cb (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropValue **values, uint32_t *n_values, gpointer data)
{
	struct cal_cbdata *cbdata = (struct cal_cbdata *) data;
	ECalComponent *comp;
	icalcomponent *ical_comp;
	icalcomponent_kind kind;
	uint32_t flag32;
	bool b;
	icalproperty *prop;
	struct icaltimetype dtstart, dtend, utc_dtstart, utc_dtend, all_day_dtstart = {0}, all_day_dtend = {0};
	const icaltimezone *utc_zone;
	const gchar *dtstart_tz_location, *dtend_tz_location, *text = NULL;
	time_t tt;
	gboolean is_all_day;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (values != NULL, FALSE);
	g_return_val_if_fail (n_values != NULL, FALSE);
	g_return_val_if_fail (cbdata != NULL, FALSE);

	switch (cbdata->kind) {
		case ICAL_VEVENT_COMPONENT:
		case ICAL_VTODO_COMPONENT:
		case ICAL_VJOURNAL_COMPONENT:
			if (!exchange_mapi_cal_utils_add_named_ids (conn, fid, mem_ctx, NULL, cbdata->kind))
				return FALSE;
			break;
		default:
			return FALSE;
	}

	comp = cbdata->comp;
	ical_comp = e_cal_component_get_icalcomponent (comp);
	kind = icalcomponent_isa (ical_comp);
	g_return_val_if_fail (kind == cbdata->kind, FALSE);

	#define set_value(hex, val) G_STMT_START { \
		if (!exchange_mapi_utils_add_spropvalue (mem_ctx, values, n_values, hex, val)) \
			return FALSE;	\
		} G_STMT_END

	#define set_named_value(named_id, val) G_STMT_START { \
		if (!exchange_mapi_utils_add_spropvalue_named_id (conn, fid, mem_ctx, values, n_values, named_id, val)) \
			return FALSE;	\
		} G_STMT_END

	#define set_datetime_value(hex, dtval) G_STMT_START {		\
		struct FILETIME	filetime;				\
									\
		exchange_mapi_util_time_t_to_filetime (dtval, &filetime); \
									\
		if (!exchange_mapi_utils_add_spropvalue (mem_ctx, values, n_values, hex, &filetime)) \
			return FALSE;	\
		} G_STMT_END

	#define set_named_datetime_value(named_id, dtval) G_STMT_START { \
		struct FILETIME	filetime;				\
									\
		exchange_mapi_util_time_t_to_filetime (dtval, &filetime); \
									\
		if (!exchange_mapi_utils_add_spropvalue_named_id (conn, fid, mem_ctx, values, n_values, named_id, &filetime)) \
			return FALSE;	\
		} G_STMT_END

	utc_zone = icaltimezone_get_utc_timezone ();

	dtstart = icalcomponent_get_dtstart (ical_comp);

	/* For VEVENTs */
	if (icalcomponent_get_first_property (ical_comp, ICAL_DTEND_PROPERTY) != 0)
		dtend = icalcomponent_get_dtend (ical_comp);
	/* For VTODOs */
	else if (icalcomponent_get_first_property (ical_comp, ICAL_DUE_PROPERTY) != 0)
		dtend = icalcomponent_get_due (ical_comp);
	else
		dtend = icalcomponent_get_dtstart (ical_comp);

	dtstart_tz_location = get_tzid_location (icaltime_get_tzid (dtstart), cbdata);
	dtend_tz_location = get_tzid_location (icaltime_get_tzid (dtend), cbdata);

	is_all_day = kind == ICAL_VEVENT_COMPONENT && icaltime_is_date (dtstart) && icaltime_is_date (dtend);
	if (is_all_day) {
		const gchar *def_location;
		icaltimezone *use_zone = NULL;

		/* all-day events expect times not in UTC but in local time;
		   if this differs from the server timezone, then the event
		   is shown spread among (two) days */
		def_location = get_tzid_location ("*default-zone*", cbdata);
		if (def_location && *def_location)
			use_zone = icaltimezone_get_builtin_timezone (def_location);

		if (!use_zone)
			use_zone = (icaltimezone *) utc_zone;

		dtstart.is_date = 0;
		dtstart.hour = 0;
		dtstart.minute = 0;
		dtstart.second = 0;
		all_day_dtstart = icaltime_convert_to_zone (dtstart, use_zone);
		dtstart.is_date = 1;
		all_day_dtstart = icaltime_convert_to_zone (all_day_dtstart, (icaltimezone *) utc_zone);

		dtend.is_date = 0;
		dtend.hour = 0;
		dtend.minute = 0;
		dtend.second = 0;
		all_day_dtend = icaltime_convert_to_zone (dtend, use_zone);
		dtend.is_date = 1;
		all_day_dtend = icaltime_convert_to_zone (all_day_dtend, (icaltimezone *) utc_zone);
	}

	utc_dtstart = icaltime_convert_to_zone (dtstart, (icaltimezone *)utc_zone);
	utc_dtend = icaltime_convert_to_zone (dtend, (icaltimezone *)utc_zone);

	text = icalcomponent_get_summary (ical_comp);
	if (!(text && *text))
		text = "";
	set_value (PR_SUBJECT_UNICODE, text);
	set_value (PR_NORMALIZED_SUBJECT_UNICODE, text);
	if (cbdata->appt_seq == 0)
		set_value (PR_CONVERSATION_TOPIC_UNICODE, text);
	text = NULL;

	/* we don't support HTML event/task/memo editor */
	flag32 = olEditorText;
	set_value (PR_MSG_EDITOR_FORMAT, &flag32);

	/* it'd be better to convert, then set it in unicode */
	text = icalcomponent_get_description (ical_comp);
	if (!(text && *text) || !g_utf8_validate (text, -1, NULL))
		text = "";
	set_value (PR_BODY_UNICODE, text);
	text = NULL;

	/* Priority and Importance */
	prop = icalcomponent_get_first_property (ical_comp, ICAL_PRIORITY_PROPERTY);
	flag32 = prop ? get_prio_prop_from_priority (icalproperty_get_priority (prop)) : PRIORITY_NORMAL;
	set_value (PR_PRIORITY, &flag32);
	flag32 = prop ? get_imp_prop_from_priority (icalproperty_get_priority (prop)) : IMPORTANCE_NORMAL;
	set_value (PR_IMPORTANCE, &flag32);

	set_value (PR_SENT_REPRESENTING_NAME_UNICODE, cbdata->ownername);
	set_value (PR_SENT_REPRESENTING_ADDRTYPE_UNICODE, cbdata->owneridtype);
	set_value (PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE, cbdata->ownerid);
	set_value (PR_SENDER_NAME_UNICODE, cbdata->username);
	set_value (PR_SENDER_ADDRTYPE_UNICODE, cbdata->useridtype);
	set_value (PR_SENDER_EMAIL_ADDRESS_UNICODE, cbdata->userid);

	flag32 = cbdata->msgflags;
	set_value (PR_MESSAGE_FLAGS, &flag32);

	flag32 = 0x0;
	b = e_cal_component_has_alarms (comp);
	if (b) {
		/* We know there would be only a single alarm of type:DISPLAY [static properties of the backend] */
		GList *alarm_uids = e_cal_component_get_alarm_uids (comp);
		ECalComponentAlarm *alarm = e_cal_component_get_alarm (comp, (const gchar *)(alarm_uids->data));
		ECalComponentAlarmAction action;
		e_cal_component_alarm_get_action (alarm, &action);
		if (action == E_CAL_COMPONENT_ALARM_DISPLAY) {
			ECalComponentAlarmTrigger trigger;
			gint dur_int = 0;
			e_cal_component_alarm_get_trigger (alarm, &trigger);
			switch (trigger.type) {
			case E_CAL_COMPONENT_ALARM_TRIGGER_RELATIVE_START :
				dur_int = (icaldurationtype_as_int (trigger.u.rel_duration)) / SECS_IN_MINUTE;
			/* we cannot set an alarm to popup after the start of an appointment on Exchange */
				flag32 = (dur_int < 0) ? -(dur_int) : 0;
				break;
			default :
				break;
			}
		}
		e_cal_component_alarm_free (alarm);
		cal_obj_uid_list_free (alarm_uids);
	}
	if (!flag32)
		switch (kind) {
			case ICAL_VEVENT_COMPONENT:
				flag32 = DEFAULT_APPT_REMINDER_MINS;
				break;
			case ICAL_VTODO_COMPONENT:
				flag32 = DEFAULT_TASK_REMINDER_MINS;
				break;
			default:
				break;
		}
	set_named_value (PidLidReminderSet, &b);
	set_named_value (PidLidReminderDelta, &flag32);
	tt = icaltime_as_timet (utc_dtstart);
	set_named_datetime_value (PidLidReminderTime, tt);
	tt = icaltime_as_timet (utc_dtstart) - (flag32 * SECS_IN_MINUTE);
	/* ReminderNextTime: FIXME for recurrence */
	set_named_datetime_value (PidLidReminderSignalTime, tt);

	/* Sensitivity, Private */
	flag32 = olNormal;	/* default */
	b = 0;			/* default */
	prop = icalcomponent_get_first_property (ical_comp, ICAL_CLASS_PROPERTY);
	if (prop)
		flag32 = get_prop_from_class (icalproperty_get_class (prop));
	if (flag32 == olPrivate || flag32 == olConfidential)
		b = 1;
	set_value (PR_SENSITIVITY, &flag32);
	set_named_value (PidLidPrivate, &b);

	tt = icaltime_as_timet (is_all_day ? all_day_dtstart : utc_dtstart);
	set_named_datetime_value (PidLidCommonStart, tt);
	set_datetime_value (PR_START_DATE, tt);

	tt = icaltime_as_timet (is_all_day ? all_day_dtend : utc_dtend);
	set_named_datetime_value (PidLidCommonEnd, tt);
	set_datetime_value (PR_END_DATE, tt);

	b = 1;
	set_value (PR_RESPONSE_REQUESTED, &b);

	/* PR_OWNER_APPT_ID needs to be set in certain cases only */
	/* PR_ICON_INDEX needs to be set appropriately */

	b = 0;
	set_value (PR_RTF_IN_SYNC, &b);

	if (kind == ICAL_VEVENT_COMPONENT) {
		const gchar *mapi_tzid;
		struct Binary_r start_tz, end_tz;

		set_named_value (PidLidAppointmentMessageClass, IPM_APPOINTMENT);

		/* Busy Status */
		flag32 = olBusy;	/* default */
		prop = icalcomponent_get_first_property (ical_comp, ICAL_TRANSP_PROPERTY);
		if (prop)
			flag32 = get_prop_from_transp (icalproperty_get_transp (prop));
		if (cbdata->meeting_type == MEETING_CANCEL)
			flag32 = olFree;
		set_named_value (PidLidIntendedBusyStatus, &flag32);

		if (cbdata->meeting_type == MEETING_REQUEST || cbdata->meeting_type == MEETING_REQUEST_RCVD) {
			flag32 = olTentative;
			set_named_value (PidLidBusyStatus, &flag32);
		} else if (cbdata->meeting_type == MEETING_CANCEL) {
			flag32 = olFree;
			set_named_value (PidLidBusyStatus, &flag32);
		} else
			set_named_value (PidLidBusyStatus, &flag32);

		/* Location */
		text = icalcomponent_get_location (ical_comp);
		if (!(text && *text))
			text = "";
		set_named_value (PidLidLocation, text);
		set_named_value (PidLidWhere, text);
		text = NULL;
		/* Auto-Location is always FALSE - Evolution doesn't work that way */
		b = 0;
		set_named_value (PidLidAutoFillLocation, &b);

		/* All-day event */
		b = is_all_day ? 1 : 0;
		set_named_value (PidLidAppointmentSubType, &b);

		/* Start */
		tt = icaltime_as_timet (is_all_day ? all_day_dtstart : utc_dtstart);
		set_named_datetime_value (PidLidAppointmentStartWhole, tt);
		/* FIXME: for recurrence */
		set_named_datetime_value (PidLidClipStart, tt);

		/* Start TZ */
		mapi_tzid = exchange_mapi_cal_tz_util_get_mapi_equivalent ((dtstart_tz_location && *dtstart_tz_location) ? dtstart_tz_location : "UTC");
		if (mapi_tzid && *mapi_tzid) {
			exchange_mapi_cal_util_mapi_tz_to_bin (mapi_tzid, &start_tz);
			set_named_value (PidLidAppointmentTimeZoneDefinitionStartDisplay, &start_tz);
		}
		set_named_value (PidLidTimeZoneDescription, mapi_tzid ? mapi_tzid : "");

		/* End */
		tt = icaltime_as_timet (is_all_day ? all_day_dtend : utc_dtend);
		set_named_datetime_value (PidLidAppointmentEndWhole, tt);
		/* FIXME: for recurrence */
		set_named_datetime_value (PidLidClipEnd, tt);

		/* End TZ */
		mapi_tzid = exchange_mapi_cal_tz_util_get_mapi_equivalent ((dtend_tz_location && *dtend_tz_location) ? dtend_tz_location : "UTC");
		if (mapi_tzid && *mapi_tzid) {
			exchange_mapi_cal_util_mapi_tz_to_bin (mapi_tzid, &end_tz);
			set_named_value (PidLidAppointmentTimeZoneDefinitionEndDisplay, &end_tz);
		}

		/* Duration */
		flag32 = icaldurationtype_as_int (icaltime_subtract (dtend, dtstart));
		flag32 /= MINUTES_IN_HOUR;
		set_named_value (PidLidAppointmentDuration, &flag32);

		if (e_cal_component_has_recurrences (comp)) {
			GSList *rrule_list = NULL;
			struct icalrecurrencetype *rt = NULL;

			e_cal_component_get_rrule_list (comp, &rrule_list);
			rt = (struct icalrecurrencetype *)(rrule_list->data);

			if (rt->freq == ICAL_DAILY_RECURRENCE)
				flag32 = rectypeDaily;
			else if (rt->freq == ICAL_WEEKLY_RECURRENCE)
				flag32 = rectypeWeekly;
			else if (rt->freq == ICAL_MONTHLY_RECURRENCE)
				flag32 = rectypeMonthly;
			else if (rt->freq == ICAL_YEARLY_RECURRENCE)
				flag32 = rectypeYearly;
			else
				flag32 = rectypeNone;

			e_cal_component_free_recur_list (rrule_list);
		} else
			flag32 = rectypeNone;
		set_named_value (PidLidRecurrenceType, &flag32);

		flag32 = cbdata->appt_id;
		set_value (PR_OWNER_APPT_ID, &flag32);

		flag32 = cbdata->appt_seq;
		set_named_value (PidLidAppointmentSequence, &flag32);

		if (cbdata->cleanglobalid) {
			set_named_value (PidLidCleanGlobalObjectId, cbdata->cleanglobalid);
		}

		if (cbdata->globalid) {
			set_named_value (PidLidGlobalObjectId, cbdata->globalid);
		}

		flag32 = cbdata->resp;
		set_named_value (PidLidResponseStatus, &flag32);

		switch (cbdata->meeting_type) {
		case MEETING_OBJECT :
			set_value (PR_MESSAGE_CLASS, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet;
			set_value (PR_ICON_INDEX, &flag32);

			flag32 = 0x0171;
			set_named_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting;
			set_named_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgRequest;
			set_named_value (PidLidMeetingType, &flag32);

			b = 1;
			set_named_value (PidLidFInvited, &b);

			break;
		case MEETING_OBJECT_RCVD :
			set_value (PR_MESSAGE_CLASS, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet;
			set_value (PR_ICON_INDEX, (gconstpointer ) &flag32);

			flag32 = 0x0171;
			set_named_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived;
			set_named_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgRequest;
			set_named_value (PidLidMeetingType, &flag32);

			b = 1;
			set_named_value (PidLidFInvited, &b);

			break;
		case MEETING_REQUEST :
			set_value (PR_MESSAGE_CLASS, IPM_SCHEDULE_MEETING_REQUEST);

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */
			set_value (PR_ICON_INDEX, &flag32);

			flag32 = 0x1C61;
			set_named_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived;
			set_named_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = (cbdata->appt_seq == 0) ? mtgRequest : mtgFull;
			set_named_value (PidLidMeetingType, &flag32);

			b = 1;
			set_named_value (PidLidFInvited, &b);

			break;
		case MEETING_REQUEST_RCVD :
			set_value (PR_MESSAGE_CLASS, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet;
			set_value (PR_ICON_INDEX, &flag32);

			flag32 = 0x0171;
			set_named_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived;
			set_named_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgRequest;
			set_named_value (PidLidMeetingType, &flag32);

			b = 1;
			set_named_value (PidLidFInvited, &b);

			break;
		case MEETING_CANCEL :
			set_value (PR_MESSAGE_CLASS, IPM_SCHEDULE_MEETING_CANCELED);

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */
			set_value (PR_ICON_INDEX, &flag32);

			flag32 = 0x1C61;
			set_named_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived | asfCanceled;
			set_named_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgEmpty;
			set_named_value (PidLidMeetingType, &flag32);

			b = 1;
			set_named_value (PidLidFInvited, &b);

			break;
		case MEETING_RESPONSE :
			if (cbdata->resp == olResponseAccepted) {
				text = IPM_SCHEDULE_MEETING_RESP_POS;
			} else if (cbdata->resp == olResponseTentative) {
				text = IPM_SCHEDULE_MEETING_RESP_TENT;
			} else if (cbdata->resp == olResponseDeclined) {
				text = IPM_SCHEDULE_MEETING_RESP_NEG;
			} else {
				text = "";
			}
			set_value (PR_MESSAGE_CLASS, text);
			text = NULL;

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */
			set_value (PR_ICON_INDEX, &flag32);

			flag32 = 0x1C61;
			set_named_value (PidLidSideEffects, &flag32);

			flag32 = asfNone;
			set_named_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgEmpty;
			set_named_value (PidLidMeetingType, &flag32);

			break;
		case NOT_A_MEETING :
		default :
			set_value (PR_MESSAGE_CLASS, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurAppt : SingleAppt;
			set_value (PR_ICON_INDEX, &flag32);

			flag32 = 0x0171;
			set_named_value (PidLidSideEffects, &flag32);

			flag32 = 0;
			set_named_value (PidLidAppointmentStateFlags, &flag32);

			b = 0;
			set_named_value (PidLidFInvited, &b);

			break;
		}

		b = e_cal_component_has_recurrences (comp);
		set_named_value (PidLidRecurring, &b);
		set_named_value (PidLidIsRecurring, &b);
		/* FIXME: Modified exceptions */
		b = e_cal_component_has_exceptions (comp) && FALSE; b = 0;
		set_named_value (PidLidIsException, &b);

		/* Counter Proposal for appointments : not supported */
		b = 1;
		set_named_value (PidLidAppointmentNotAllowPropose, &b);
		b = 0;
		set_named_value (PidLidAppointmentCounterProposal, &b);

	} else if (kind == ICAL_VTODO_COMPONENT) {
		gdouble d;

		set_value (PR_MESSAGE_CLASS, IPM_TASK);

		/* Context menu flags */ /* FIXME: for assigned tasks */
		flag32 = 0x0110;
		set_named_value (PidLidSideEffects, &flag32);

		/* Status, Percent complete, IsComplete */
		flag32 = olTaskNotStarted;	/* default */
		b = 0;				/* default */
		d = 0.0;
		prop = icalcomponent_get_first_property (ical_comp, ICAL_PERCENTCOMPLETE_PROPERTY);
		if (prop)
			d = 0.01 * icalproperty_get_percentcomplete (prop);

		flag32 = get_prop_from_taskstatus (icalcomponent_get_status (ical_comp));
		if (flag32 == olTaskComplete) {
			b = 1;
			d = 1.0;
		}

		set_named_value (PidLidTaskStatus, &flag32);
		set_named_value (PidLidPercentComplete, &d);
		set_named_value (PidLidTaskComplete, &b);

		/* Date completed */
		if (b) {
			struct icaltimetype completed;
			prop = icalcomponent_get_first_property (ical_comp, ICAL_COMPLETED_PROPERTY);
			completed = icalproperty_get_completed (prop);

			completed.hour = completed.minute = completed.second = 0; completed.is_date = completed.is_utc = 1;
			tt = icaltime_as_timet (completed);
			set_named_datetime_value (PidLidTaskDateCompleted, tt);
		}

		/* Start */
		dtstart.hour = dtstart.minute = dtstart.second = 0; dtstart.is_date = dtstart.is_utc = 1;
		tt = icaltime_as_timet (dtstart);
		if (!icaltime_is_null_time (dtstart)) {
			set_named_datetime_value (PidLidTaskStartDate, tt);
		}

		/* Due */
		dtend.hour = dtend.minute = dtend.second = 0; dtend.is_date = dtend.is_utc = 1;
		tt = icaltime_as_timet (dtend);
		if (!icaltime_is_null_time (dtend)) {
			set_named_datetime_value (PidLidTaskDueDate, tt);
		}

		/* FIXME: Evolution does not support recurring tasks */
		b = 0;
		set_named_value (PidLidTaskFRecurring, &b);

	} else if (kind == ICAL_VJOURNAL_COMPONENT) {
		uint32_t color = olYellow;

		set_value (PR_MESSAGE_CLASS, IPM_STICKYNOTE);

		/* Context menu flags */
		flag32 = 0x0110;
		set_named_value (PidLidSideEffects, &flag32);

		flag32 = 0x0300 + color;
		set_value (PR_ICON_INDEX, &flag32);

		flag32 = color;
		set_named_value (PidLidNoteColor, &flag32);

		/* some random value */
		flag32 = 0x00FF;
		set_named_value (PidLidNoteWidth, &flag32);

		/* some random value */
		flag32 = 0x00FF;
		set_named_value (PidLidNoteHeight, &flag32);
	}

	return TRUE;
}

uint32_t
exchange_mapi_cal_util_get_new_appt_id (ExchangeMapiConnection *conn, mapi_id_t fid)
{
	struct mapi_SRestriction res;
	struct SPropValue sprop;
	uint32_t id;
	gboolean found = FALSE;

	res.rt = RES_PROPERTY;
	res.res.resProperty.relop = RELOP_EQ;
	res.res.resProperty.ulPropTag = PR_OWNER_APPT_ID;

	while (!found) {
		id = g_random_int ();
		if (id) {
			GSList *ids = NULL;
			TALLOC_CTX *mem_ctx = talloc_init ("ExchangeMAPI_get_new_appt_id");

			set_SPropValue_proptag (&sprop, PR_OWNER_APPT_ID, (gconstpointer ) &id);
			cast_mapi_SPropValue (
				#ifdef HAVE_MEMCTX_ON_CAST_MAPI_SPROPVALUE
				mem_ctx,
				#endif
				&(res.res.resProperty.lpProp), &sprop);
			ids = exchange_mapi_connection_check_restriction (conn, fid, 0, &res, NULL);
			if (ids) {
				GSList *l;
				for (l = ids; l; l = l->next)
					g_free (l->data);
			} else
				found = TRUE;

			talloc_free (mem_ctx);
		}
	};

	return id;
}

static time_t
mapi_get_date_from_string (const gchar *dtstring)
{
	time_t t = 0;
	GTimeVal t_val;

	g_return_val_if_fail (dtstring != NULL, 0);

	if (g_time_val_from_iso8601 (dtstring, &t_val)) {
		t = (time_t) t_val.tv_sec;
	} else if (strlen (dtstring) == 8) {
		/* It might be a date value */
		GDate date;
		struct tm tt;
		guint16 year;
		guint month;
		guint8 day;

		g_date_clear (&date, 1);
#define digit_at(x,y) (x[y] - '0')
		year = digit_at (dtstring, 0) * 1000
			+ digit_at (dtstring, 1) * 100
			+ digit_at (dtstring, 2) * 10
			+ digit_at (dtstring, 3);
		month = digit_at (dtstring, 4) * 10 + digit_at (dtstring, 5);
		day = digit_at (dtstring, 6) * 10 + digit_at (dtstring, 7);

		g_date_set_year (&date, year);
		g_date_set_month (&date, month);
		g_date_set_day (&date, day);

		g_date_to_struct_tm (&date, &tt);
		t = mktime (&tt);

	} else
		g_warning ("Could not parse the string \n");

        return t;
}

static void
populate_freebusy_data (struct Binary_r *bin, uint32_t month, uint32_t year, GList **freebusy, const gchar *accept_type, ECalComponent *comp)
{
	uint16_t	event_start;
	uint16_t	event_end;
	uint32_t	i;
	uint32_t	hour;
	uint32_t	day;
	const gchar	*month_name;
	uint32_t	minutes;
	uint32_t	real_month;
	gchar *date_string = NULL;
	gchar *start = NULL, *end = NULL;
	time_t start_date, end_date;
	icalcomponent *icalcomp = NULL;

	if (!bin)
		return;
	/* bin.cb must be a multiple of 4 */
	if (bin->cb % 4)
		return;

	year = mapidump_freebusy_year(month, year);
	month_name = mapidump_freebusy_month(month, year);
	if (!month_name)
		return;

	for (i = 0; i < bin->cb; i+= 4) {
		event_start = (bin->lpb[i + 1] << 8) | bin->lpb[i];
		event_end = (bin->lpb[i + 3] << 8) | bin->lpb[i + 2];

		for (hour = 0; hour < 24; hour++) {
			if (!(((event_start - (60 * hour)) % 1440) && (((event_start - (60 * hour)) % 1440) - 30))) {
				struct icalperiodtype ipt;
				icalproperty *icalprop;
				icaltimetype itt;

				day = ((event_start - (60 * hour)) / 1440) + 1;
				minutes = (event_start - (60 * hour)) % 1440;
				real_month = month - (year * 16);

				date_string = g_strdup_printf ("%.2u-%.2u-%.2u", year, real_month, day);
				start = g_strdup_printf ("%sT%.2u:%.2u:00Z", date_string, hour + daylight, minutes);
				g_free (date_string);

				day = ((event_end - (60 * hour)) / 1440) + 1;
				minutes = (event_end - (60 * hour)) % 1440;

				if (minutes >= 60) {
					hour += minutes / 60;
					minutes %= 60;
				}

				date_string = g_strdup_printf ("%.2u-%.2u-%.2u", year, real_month, day);
				end = g_strdup_printf ("%sT%.2u:%.2u:00Z", date_string, hour + daylight, minutes);
				g_free (date_string);

				start_date = mapi_get_date_from_string (start);
				end_date = mapi_get_date_from_string (end);

				memset (&ipt, 0, sizeof (struct icalperiodtype));

				itt = icaltime_from_timet_with_zone (start_date, 0, icaltimezone_get_utc_timezone ());
				ipt.start = itt;

				itt = icaltime_from_timet_with_zone (end_date, 0, icaltimezone_get_utc_timezone ());
				ipt.end = itt;

				icalcomp = e_cal_component_get_icalcomponent (comp);
				icalprop = icalproperty_new_freebusy (ipt);

				if (!strcmp (accept_type, "Busy"))
					icalproperty_set_parameter_from_string (icalprop, "FBTYPE", "BUSY");
				else if (!strcmp (accept_type, "Tentative"))
					icalproperty_set_parameter_from_string (icalprop, "FBTYPE", "BUSY-TENTATIVE");
				else if (!strcmp (accept_type, "OutOfOffice"))
					icalproperty_set_parameter_from_string (icalprop, "FBTYPE", "BUSY-UNAVAILABLE");

				icalcomponent_add_property(icalcomp, icalprop);
				g_free (start);
				g_free (end);
			}
		}
	}
}

gboolean
exchange_mapi_cal_utils_get_free_busy_data (ExchangeMapiConnection *conn, const GList *users, time_t start, time_t end, GList **freebusy, GError **mapi_error)
{
	struct SRow		aRow;
	enum MAPISTATUS		ms;
	uint32_t		i;
	mapi_object_t           obj_store;
	const GList *l;

	const uint32_t			*publish_start;
	const struct LongArray_r	*busy_months;
	const struct BinaryArray_r	*busy_events;
	const struct LongArray_r	*tentative_months;
	const struct BinaryArray_r	*tentative_events;
	const struct LongArray_r	*oof_months;
	const struct BinaryArray_r	*oof_events;
	uint32_t			year;
	uint32_t			event_year;

	ECalComponent *comp;
	ECalComponentAttendee attendee;
	GSList *attendee_list = NULL;
	icalcomponent *icalcomp = NULL;
	icaltimetype start_time, end_time;
	icaltimezone *default_zone = NULL;

	if (!exchange_mapi_connection_get_public_folder (conn, &obj_store, mapi_error)) {
		return FALSE;
	}

	for ( l = users; l != NULL; l = g_list_next (l)) {
		ms = GetUserFreeBusyData (&obj_store, (const gchar *)l->data, &aRow);

		if (ms != MAPI_E_SUCCESS) {
			gchar *context = g_strconcat ("GetUserFreeBusyData for ", l->data, NULL);

			make_mapi_error (mapi_error, context, ms);

			g_free (context);

			return FALSE;
		}

		/* Step 2. Dump properties */
		publish_start = (const uint32_t *) find_SPropValue_data(&aRow, PR_FREEBUSY_START_RANGE);
		busy_months = (const struct LongArray_r *) find_SPropValue_data(&aRow, PR_FREEBUSY_BUSY_MONTHS);
		busy_events = (const struct BinaryArray_r *) find_SPropValue_data(&aRow, PR_FREEBUSY_BUSY_EVENTS);
		tentative_months = (const struct LongArray_r *) find_SPropValue_data(&aRow, PR_FREEBUSY_TENTATIVE_MONTHS);
		tentative_events = (const struct BinaryArray_r *) find_SPropValue_data(&aRow, PR_FREEBUSY_TENTATIVE_EVENTS);
		oof_months = (const struct LongArray_r *) find_SPropValue_data(&aRow, PR_FREEBUSY_OOF_MONTHS);
		oof_events = (const struct BinaryArray_r *) find_SPropValue_data(&aRow, PR_FREEBUSY_OOF_EVENTS);

		year = GetFreeBusyYear(publish_start);

		comp = e_cal_component_new ();
		e_cal_component_set_new_vtype (comp, E_CAL_COMPONENT_FREEBUSY);
		e_cal_component_commit_sequence (comp);
		icalcomp = e_cal_component_get_icalcomponent (comp);

		start_time = icaltime_from_timet_with_zone (start, 0, default_zone ? default_zone : NULL);
		end_time = icaltime_from_timet_with_zone (end, 0, default_zone ? default_zone : NULL);
		icalcomponent_set_dtstart (icalcomp, start_time);
		icalcomponent_set_dtend (icalcomp, end_time);

		memset (&attendee, 0, sizeof (ECalComponentAttendee));
		if (l->data)
			attendee.value = l->data;

		attendee.cutype = ICAL_CUTYPE_INDIVIDUAL;
		attendee.role = ICAL_ROLE_REQPARTICIPANT;
		attendee.status = ICAL_PARTSTAT_NEEDSACTION;

		attendee_list = g_slist_append (attendee_list, &attendee);

		e_cal_component_set_attendee_list (comp, attendee_list);
		g_slist_free (attendee_list);

		if (busy_months && ((*(const uint32_t *) busy_months) != MAPI_E_NOT_FOUND) &&
		    busy_events && ((*(const uint32_t *) busy_events) != MAPI_E_NOT_FOUND)) {
			for (i = 0; i < busy_months->cValues; i++) {
				event_year = mapidump_freebusy_year(busy_months->lpl[i], year);
				populate_freebusy_data (&busy_events->lpbin[i], busy_months->lpl[i], event_year, freebusy, "Busy", comp);
			}
		}

		if (tentative_months && ((*(const uint32_t *) tentative_months) != MAPI_E_NOT_FOUND) &&
		    tentative_events && ((*(const uint32_t *) tentative_events) != MAPI_E_NOT_FOUND)) {
			for (i = 0; i < tentative_months->cValues; i++) {
				event_year = mapidump_freebusy_year(tentative_months->lpl[i], year);
				populate_freebusy_data (&tentative_events->lpbin[i], tentative_months->lpl[i], event_year, freebusy, "Tentative", comp);
			}
		}

		if (oof_months && ((*(const uint32_t *) oof_months) != MAPI_E_NOT_FOUND) &&
		    oof_events && ((*(const uint32_t *) oof_events) != MAPI_E_NOT_FOUND)) {
			for (i = 0; i < oof_months->cValues; i++) {
				event_year = mapidump_freebusy_year(oof_months->lpl[i], year);
				populate_freebusy_data (&oof_events->lpbin[i], oof_months->lpl[i], event_year, freebusy, "OutOfOffice", comp);
			}
		}

		e_cal_component_commit_sequence (comp);
		*freebusy = g_list_append (*freebusy, e_cal_component_get_as_string (comp));
		g_object_unref (comp);
		MAPIFreeBuffer(aRow.lpProps);
	}

	return TRUE;
}

/* beware, the 'data' pointer is an integer of the event kind */
gboolean
exchange_mapi_cal_utils_get_props_cb (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
{
	static const uint32_t cal_GetPropsList[] = {
		PR_FID,
		PR_MID,

		PR_SUBJECT_UNICODE,
		PR_NORMALIZED_SUBJECT_UNICODE,
		PR_CONVERSATION_TOPIC_UNICODE,
		PR_BODY,
		PR_BODY_UNICODE,

		PR_CREATION_TIME,
		PR_LAST_MODIFICATION_TIME,
		PR_PRIORITY,
		PR_SENSITIVITY,
		PR_START_DATE,
		PR_END_DATE,
		PR_RESPONSE_REQUESTED,
		PR_OWNER_APPT_ID,
		PR_PROCESSED,
		PR_MSG_EDITOR_FORMAT,

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

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	if (!exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, cal_GetPropsList, G_N_ELEMENTS (cal_GetPropsList)))
		return FALSE;

	return exchange_mapi_cal_utils_add_named_ids (conn, fid, mem_ctx, props, GPOINTER_TO_INT (data));
}

gchar *
exchange_mapi_cal_utils_get_icomp_x_prop (icalcomponent *comp, const gchar *key)
{
	icalproperty *xprop;

	/* Find the old one first */
	xprop = icalcomponent_get_first_property (comp, ICAL_X_PROPERTY);

	while (xprop) {
		const gchar *str = icalproperty_get_x_name (xprop);

		if (str && !strcmp (str, key)) {
			break;
		}

		xprop = icalcomponent_get_next_property (comp, ICAL_X_PROPERTY);
	}

	if (xprop)
		return icalproperty_get_value_as_string_r (xprop);

	return NULL;
}

