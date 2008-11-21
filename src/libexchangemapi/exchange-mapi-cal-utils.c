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

#include <glib/gstdio.h>
#include <fcntl.h>
#include <libecal/e-cal-util.h>
#include "exchange-mapi-cal-utils.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define d(x) 

static void appt_build_name_id (struct mapi_nameid *nameid);
static void task_build_name_id (struct mapi_nameid *nameid);
static void note_build_name_id (struct mapi_nameid *nameid);

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
		case ICAL_ROLE_OPTPARTICIPANT 	: return olCC;
		case ICAL_ROLE_CHAIR 		:
		case ICAL_ROLE_REQPARTICIPANT 	:
		case ICAL_ROLE_NONPARTICIPANT 	: 
		default 			: return olTo;
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
		default 		 : return ICAL_PARTSTAT_NEEDSACTION;
	}
}

static uint32_t 
get_trackstatus_from_partstat (icalparameter_partstat partstat)
{
	switch (partstat) {
		case ICAL_PARTSTAT_ACCEPTED 	: return olResponseAccepted;
		case ICAL_PARTSTAT_TENTATIVE 	: return olResponseTentative;
		case ICAL_PARTSTAT_DECLINED 	: return olResponseDeclined;
		default 			: return olResponseNone;
	}
}

static icalproperty_transp
get_transp_from_prop (uint32_t prop) 
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
		case olFree 		:
		case olTentative 	: return ICAL_TRANSP_TRANSPARENT;
		case olBusy 		:
		case olOutOfOffice 	:
		default 		: return ICAL_TRANSP_OPAQUE;
	}
}

static uint32_t 
get_prop_from_transp (icalproperty_transp transp)
{
	/* FIXME: is this mapping correct ? */
	switch (transp) {
		case ICAL_TRANSP_TRANSPARENT 		:
		case ICAL_TRANSP_TRANSPARENTNOCONFLICT 	: return olFree; 
		case ICAL_TRANSP_OPAQUE 		: 
		case ICAL_TRANSP_OPAQUENOCONFLICT 	:
		default 				: return olBusy;
	}
}

static icalproperty_status
get_taskstatus_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
		case olTaskComplete 	: return ICAL_STATUS_COMPLETED;
		case olTaskWaiting 	:
		case olTaskInProgress 	: return ICAL_STATUS_INPROCESS;
		case olTaskDeferred 	: return ICAL_STATUS_CANCELLED;
		case olTaskNotStarted 	: 
		default 		: return ICAL_STATUS_NEEDSACTION;
	}
}

static uint32_t
get_prop_from_taskstatus (icalproperty_status status)
{
	/* FIXME: is this mapping correct ? */
	switch (status) {
		case ICAL_STATUS_INPROCESS 	: return olTaskInProgress;
		case ICAL_STATUS_COMPLETED 	: return olTaskComplete;
		case ICAL_STATUS_CANCELLED 	: return olTaskDeferred;
		default 			: return olTaskNotStarted;
	}
}

static icalproperty_class
get_class_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
		case olPersonal 	:
		case olPrivate 		: return ICAL_CLASS_PRIVATE;
		case olConfidential 	: return ICAL_CLASS_CONFIDENTIAL;
		case olNormal 		: 
		default 		: return ICAL_CLASS_PUBLIC;
	}
}

static uint32_t 
get_prop_from_class (icalproperty_class class)
{
	/* FIXME: is this mapping correct ? */
	switch (class) {
		case ICAL_CLASS_PRIVATE 	: return olPrivate;
		case ICAL_CLASS_CONFIDENTIAL 	: return olConfidential;
		default 			: return olNormal;
	}
}

static int
get_priority_from_prop (uint32_t prop)
{
	switch (prop) {
		case PRIORITY_LOW 	: return 7;
		case PRIORITY_HIGH 	: return 1;
		case PRIORITY_NORMAL 	: 
		default 		: return 5;
	}
}

static uint32_t
get_prio_prop_from_priority (int priority)
{
	if (priority > 0 && priority <= 4)
		return PRIORITY_HIGH;
	else if (priority > 5 && priority <= 9)
		return PRIORITY_LOW;
	else
		return PRIORITY_NORMAL;
}

static uint32_t
get_imp_prop_from_priority (int priority)
{
	if (priority > 0 && priority <= 4)
		return IMPORTANCE_HIGH;
	else if (priority > 5 && priority <= 9)
		return IMPORTANCE_LOW;
	else
		return IMPORTANCE_NORMAL;
}

void
exchange_mapi_cal_util_fetch_attachments (ECalComponent *comp, GSList **attach_list, const char *local_store_uri)
{
	GSList *comp_attach_list = NULL, *new_attach_list = NULL;
	GSList *l;
	const char *uid;

	e_cal_component_get_attachment_list (comp, &comp_attach_list);
	e_cal_component_get_uid (comp, &uid);

	for (l = comp_attach_list; l ; l = l->next) {
		gchar *sfname_uri = (gchar *) l->data;
		gchar *sfname = NULL, *filename = NULL;
		GMappedFile *mapped_file;
		GError *error = NULL;

		sfname = g_filename_from_uri (sfname_uri, NULL, NULL);
		mapped_file = g_mapped_file_new (sfname, FALSE, &error);
		filename = g_path_get_basename (sfname);

		if (mapped_file && g_str_has_prefix (filename, uid)) {
			ExchangeMAPIAttachment *attach_item;
			ExchangeMAPIStream *stream; 
			gchar *attach = g_mapped_file_get_contents (mapped_file);
			guint filelength = g_mapped_file_get_length (mapped_file);
			const gchar *split_name = (filename + strlen (uid) + strlen ("-"));
			uint32_t flag; 

			new_attach_list = g_slist_append (new_attach_list, g_strdup (sfname_uri));

			attach_item = g_new0 (ExchangeMAPIAttachment, 1);

			attach_item->cValues = 4; 
			attach_item->lpProps = g_new0 (struct SPropValue, 4); 

			flag = ATTACH_BY_VALUE; 
			set_SPropValue_proptag(&(attach_item->lpProps[0]), PR_ATTACH_METHOD, (const void *) (&flag));

			/* MSDN Documentation: When the supplied offset is -1 (0xFFFFFFFF), the 
			 * attachment is not rendered using the PR_RENDERING_POSITION property. 
			 * All values other than -1 indicate the position within PR_BODY at which 
			 * the attachment is to be rendered. 
			 */
			flag = 0xFFFFFFFF;
			set_SPropValue_proptag(&(attach_item->lpProps[1]), PR_RENDERING_POSITION, (const void *) (&flag));

			set_SPropValue_proptag(&(attach_item->lpProps[2]), PR_ATTACH_FILENAME, (const void *) g_strdup(split_name));
			set_SPropValue_proptag(&(attach_item->lpProps[3]), PR_ATTACH_LONG_FILENAME, (const void *) g_strdup(split_name));

			stream = g_new0 (ExchangeMAPIStream, 1);
			stream->proptag = PR_ATTACH_DATA_BIN; 
			stream->value = g_byte_array_sized_new (filelength);
			stream->value = g_byte_array_append (stream->value, attach, filelength);
			attach_item->streams = g_slist_append (attach_item->streams, stream); 

			*attach_list = g_slist_append (*attach_list, attach_item);

			g_mapped_file_free (mapped_file);
		} else {
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
		const char *str = NULL;
		icalparameter *param;

		recipient = g_new0 (ExchangeMAPIRecipient, 1);

		if (!g_ascii_strncasecmp (org, "mailto:", 7)) 
			recipient->email_id = (org) + 7;
		else 
			recipient->email_id = (org);

		/* Required properties - set them always */
		recipient->in.req_lpProps = g_new0 (struct SPropValue, 5);
		recipient->in.req_cValues = 5;

		val = 0;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[0]), PR_SEND_INTERNET_ENCODING, (const void *)&val);

		val = RECIP_SENDABLE | RECIP_ORGANIZER;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[1]), PR_RECIPIENTS_FLAGS, (const void *)&val);

		val = olResponseNone;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[2]), PR_RECIPIENT_TRACKSTATUS, (const void *)&val);

		val = olTo;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[3]), PR_RECIPIENT_TYPE, (const void *) &val);

		param = icalproperty_get_first_parameter (org_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		if (!(str && *str)) 
			str = "";
		set_SPropValue_proptag (&(recipient->in.req_lpProps[4]), PR_RECIPIENT_DISPLAY_NAME, (const void *)(str));

		/* External recipient properties - set them only when the recipient is unresolved */
		recipient->in.ext_lpProps = g_new0 (struct SPropValue, 5);
		recipient->in.ext_cValues = 5;

		val = DT_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[0]), PR_DISPLAY_TYPE, (const void *)&val);
		val = MAPI_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[1]), PR_OBJECT_TYPE, (const void *)&val);
		str = "SMTP";
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[2]), PR_ADDRTYPE, (const void *)(str));
		str = recipient->email_id;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[3]), PR_SMTP_ADDRESS, (const void *)(str));

		param = icalproperty_get_first_parameter (org_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		if (!(str && *str)) 
			str = "";
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[4]), PR_DISPLAY_NAME, (const void *)(str));

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
		const char *str = NULL;
		icalparameter *param;

		recipient = g_new0 (ExchangeMAPIRecipient, 1);

		str = icalproperty_get_attendee (att_prop);
		if (!g_ascii_strncasecmp (str, "mailto:", 7)) 
			recipient->email_id = (str) + 7;
		else 
			recipient->email_id = (str);

		/* Required properties - set them always */
		recipient->in.req_lpProps = g_new0 (struct SPropValue, 5);
		recipient->in.req_cValues = 5;

		val = 0;
		set_SPropValue_proptag (&(recipient->in.req_lpProps[0]), PR_SEND_INTERNET_ENCODING, (const void *)&val);

		val = RECIP_SENDABLE | (!g_ascii_strcasecmp(str, org) ? RECIP_ORGANIZER : 0);
		set_SPropValue_proptag (&(recipient->in.req_lpProps[1]), PR_RECIPIENTS_FLAGS, (const void *)&val);

		param = icalproperty_get_first_parameter (att_prop, ICAL_PARTSTAT_PARAMETER);
		val = get_trackstatus_from_partstat (icalparameter_get_partstat(param));
		set_SPropValue_proptag (&(recipient->in.req_lpProps[2]), PR_RECIPIENT_TRACKSTATUS, (const void *)&val);

		param = icalproperty_get_first_parameter (att_prop, ICAL_ROLE_PARAMETER);
		val = get_type_from_role (icalparameter_get_role(param));
		set_SPropValue_proptag (&(recipient->in.req_lpProps[3]), PR_RECIPIENT_TYPE, (const void *) &val);

		param = icalproperty_get_first_parameter (att_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		if (!(str && *str)) 
			str = "";
		set_SPropValue_proptag (&(recipient->in.req_lpProps[4]), PR_RECIPIENT_DISPLAY_NAME, (const void *)(str));

		/* External recipient properties - set them only when the recipient is unresolved */
		recipient->in.ext_lpProps = g_new0 (struct SPropValue, 5);
		recipient->in.ext_cValues = 5;

		val = DT_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[0]), PR_DISPLAY_TYPE, (const void *)&val);
		val = MAPI_MAILUSER;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[1]), PR_OBJECT_TYPE, (const void *)&val);
		str = "SMTP";
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[2]), PR_ADDRTYPE, (const void *)(str));
		str = recipient->email_id;
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[3]), PR_SMTP_ADDRESS, (const void *)(str));

		param = icalproperty_get_first_parameter (att_prop, ICAL_CN_PARAMETER);
		str = icalparameter_get_cn (param);
		if (!(str && *str)) 
			str = "";
		set_SPropValue_proptag (&(recipient->in.ext_lpProps[4]), PR_DISPLAY_NAME, (const void *)(str));

		*recip_list = g_slist_append (*recip_list, recipient);

		att_prop = icalcomponent_get_next_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	}
}

static void
set_attachments_to_cal_component (ECalComponent *comp, GSList *attach_list, const char *local_store_uri)
{
	GSList *comp_attach_list = NULL, *l;
	const char *uid;

	g_return_if_fail (comp != NULL);

	e_cal_component_get_uid (comp, &uid);
	for (l = attach_list; l ; l = l->next) {
		ExchangeMAPIAttachment *attach_item = (ExchangeMAPIAttachment *) (l->data);
		ExchangeMAPIStream *stream; 
		gchar *attach_file_url, *filename; 
		const char *str, *attach;
		guint len;
		int fd = -1;

		stream = exchange_mapi_util_find_stream (attach_item->streams, PR_ATTACH_DATA_BIN);
		if (!stream)
			continue;

		attach = (const char *)stream->value->data;
		len = stream->value->len;

		str = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach_item->lpProps, PR_ATTACH_LONG_FILENAME);
		if (!(str && *str))
			str = (const char *) exchange_mapi_util_find_SPropVal_array_propval(attach_item->lpProps, PR_ATTACH_FILENAME);
		attach_file_url = g_strconcat (local_store_uri, G_DIR_SEPARATOR_S, uid, "-", str, NULL);
		filename = g_filename_from_uri (attach_file_url, NULL, NULL);

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
		const char *str;
		const uint32_t *flags; 

		if (recip->email_id)
			val = g_strdup_printf ("MAILTO:%s", recip->email_id);
		else 
			continue;

		flags = (const uint32_t *) get_SPropValue(recip->out.all_lpProps, PR_RECIPIENTS_FLAGS);

		if (flags && (*flags & RECIP_ORGANIZER)) {
			prop = icalproperty_new_organizer (val);

			/* CN */
			str = (const char *) exchange_mapi_util_find_SPropVal_array_propval(recip->out.all_lpProps, PR_RECIPIENT_DISPLAY_NAME);
			if (!str)
				str = (const char *) exchange_mapi_util_find_SPropVal_array_propval(recip->out.all_lpProps, PR_DISPLAY_NAME);
			if (str) {
				param = icalparameter_new_cn (str);
				icalproperty_add_parameter (prop, param);
			}
		} else {
			prop = icalproperty_new_attendee (val);

			/* CN */
			str = (const char *) exchange_mapi_util_find_SPropVal_array_propval(recip->out.all_lpProps, PR_RECIPIENT_DISPLAY_NAME);
			if (!str)
				str = (const char *) exchange_mapi_util_find_SPropVal_array_propval(recip->out.all_lpProps, PR_DISPLAY_NAME);
			if (str) {
				param = icalparameter_new_cn (str);
				icalproperty_add_parameter (prop, param);
			}
			/* RSVP */
			param = icalparameter_new_rsvp (rsvp ? ICAL_RSVP_TRUE : ICAL_RSVP_FALSE);
			icalproperty_add_parameter (prop, param);
			/* PARTSTAT */
			ui32 = (const uint32_t *) get_SPropValue(recip->out.all_lpProps, PR_RECIPIENT_TRACKSTATUS);
			if (ui32) {
				param = icalparameter_new_partstat (get_partstat_from_trackstatus (*ui32));
				icalproperty_add_parameter (prop, param);
			}
			/* ROLE */
			ui32 = (const uint32_t *) get_SPropValue(recip->out.all_lpProps, PR_RECIPIENT_TYPE);
			if (ui32) {
				param = icalparameter_new_role (get_role_from_type (*ui32));
				icalproperty_add_parameter (prop, param);
			}
#if 0
			/* CALENDAR USER TYPE */
			param = icalparameter_new_cutype ();
			icalproperty_add_parameter (prop, param);
#endif
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
exchange_mapi_cal_util_generate_globalobjectid (gboolean is_clean, const char *uid, struct SBinary *sb)
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
		ba = g_byte_array_append (ba, &flag32, sizeof (guint32));
	}

	/* creation time - may be all 0's  */
	flag32 = 0;
	ba = g_byte_array_append (ba, &flag32, sizeof (guint32));
	flag32 = 0;
	ba = g_byte_array_append (ba, &flag32, sizeof (guint32));

	/* RESERVED - should be all 0's  */
	flag32 = 0;
	ba = g_byte_array_append (ba, &flag32, sizeof (guint32));
	flag32 = 0;
	ba = g_byte_array_append (ba, &flag32, sizeof (guint32));

	/* FIXME: cleanup the UID first */

	/* We put Evolution's UID in base64 here */
	buf = g_base64_decode (uid, &len);
	if (len % 2 != 0)
		--len;
	flag32 = len;

	/* Size in bytes of the following data */
	ba = g_byte_array_append (ba, &flag32, sizeof (guint32));
	/* Data */
	ba = g_byte_array_append (ba, buf, flag32);
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
exchange_mapi_cal_util_mapi_props_to_comp (icalcomponent_kind kind, const gchar *mid, struct mapi_SPropValue_array *properties, 
					   GSList *streams, GSList *recipients, GSList *attachments, 
					   const char *local_store_uri, const icaltimezone *default_zone)
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

	subject = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_SUBJECT);
	if (!subject)
		subject = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_NORMALIZED_SUBJECT);
	if (!subject)
		subject = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_CONVERSATION_TOPIC);
	if (!subject)
		subject = ""; 

	body = (const gchar *)exchange_mapi_util_find_array_propval(properties, PR_BODY);
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
		const char *location = NULL;
		const gchar *dtstart_tz = NULL, *dtend_tz = NULL;
		ExchangeMAPIStream *stream;

		/* CleanGlobalObjectId */
		stream = exchange_mapi_util_find_stream (streams, PROP_TAG(PT_BINARY, 0x0023));
		if (stream) {
			gchar *value = id_to_string (stream->value);
			prop = icalproperty_new_x (value);
			icalproperty_set_x_name (prop, "X-EVOLUTION-MAPI-CLEAN-GLOBALID");
			icalcomponent_add_property (ical_comp, prop);
			g_free (value);
		}

		/* GlobalObjectId */
		stream = exchange_mapi_util_find_stream (streams, PROP_TAG(PT_BINARY, 0x0003));
		if (stream) {
			gchar *value = id_to_string (stream->value);
			prop = icalproperty_new_x (value);
			icalproperty_set_x_name (prop, "X-EVOLUTION-MAPI-GLOBALID");
			icalcomponent_add_property (ical_comp, prop);
			g_free (value);
		}

		/* AppointmentSequence */
		ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8201));
		if (ui32) {
			gchar *value = g_strdup_printf ("%d", *ui32);
			prop = icalproperty_new_x (value);
			icalproperty_set_x_name (prop, "X-EVOLUTION-MAPI-APPTSEQ");
			icalcomponent_add_property (ical_comp, prop);
			g_free (value);
		}

		location = (const char *)exchange_mapi_util_find_array_propval(properties, PROP_TAG(PT_STRING8, 0x8208));
		if (location && *location)
			icalcomponent_set_location (ical_comp, location);

		b = (const bool *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BOOLEAN, 0x8215));

		stream = exchange_mapi_util_find_stream (streams, PROP_TAG(PT_BINARY, 0x825E));
		if (stream) {
			gchar *buf = exchange_mapi_cal_util_bin_to_mapi_tz (stream->value);
			dtstart_tz = exchange_mapi_cal_tz_util_get_ical_equivalent (buf);
			g_free (buf);
		}

		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PROP_TAG(PT_SYSTIME, 0x820D)) == MAPI_E_SUCCESS) {
			icaltimezone *zone = dtstart_tz ? icaltimezone_get_builtin_timezone_from_tzid (dtstart_tz) : default_zone;
			prop = icalproperty_new_dtstart (icaltime_from_timet_with_zone (t.tv_sec, (b && *b), zone));
			icalproperty_add_parameter (prop, icalparameter_new_tzid(dtstart_tz));
			icalcomponent_add_property (ical_comp, prop);
		}

		stream = exchange_mapi_util_find_stream (streams, PROP_TAG(PT_BINARY, 0x825F));
		if (stream) {
			gchar *buf = exchange_mapi_cal_util_bin_to_mapi_tz (stream->value);
			dtend_tz = exchange_mapi_cal_tz_util_get_ical_equivalent (buf);
			g_free (buf);
		}

		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PROP_TAG(PT_SYSTIME, 0x820E)) == MAPI_E_SUCCESS) {
			icaltimezone *zone = dtend_tz ? icaltimezone_get_builtin_timezone_from_tzid (dtend_tz) : default_zone;
			prop = icalproperty_new_dtend (icaltime_from_timet_with_zone (t.tv_sec, (b && *b), zone));
			icalproperty_add_parameter (prop, icalparameter_new_tzid(dtend_tz));
			icalcomponent_add_property (ical_comp, prop);
		}

		ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8205));
		if (ui32) {
			prop = icalproperty_new_transp (get_transp_from_prop (*ui32));
			icalcomponent_add_property (ical_comp, prop);
		}

		if (recipients) {
			b = (const bool *)find_mapi_SPropValue_data(properties, PR_RESPONSE_REQUESTED);
			ical_attendees_from_props (ical_comp, recipients, (b && *b));
			if (icalcomponent_get_first_property (ical_comp, ICAL_ORGANIZER_PROPERTY) == NULL) {
				gchar *val;
//				const char *sender_name = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_NAME);
				const char *sender_email_type = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_ADDRTYPE);
				const char *sender_email = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_EMAIL_ADDRESS);
				const char *sent_name = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_NAME);
				const char *sent_email_type = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE);
				const char *sent_email = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS);

				if (!g_utf8_collate (sender_email_type, "EX"))
					sender_email = exchange_mapi_util_ex_to_smtp (sender_email);
				if (!g_utf8_collate (sent_email_type, "EX"))
					sent_email = exchange_mapi_util_ex_to_smtp (sent_email);

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
			}
		}

		b = (const bool *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BOOLEAN, 0x8223));
		if (b && *b) {
			stream = exchange_mapi_util_find_stream (streams, PROP_TAG(PT_BINARY, 0x8216));
			if (stream) {
				exchange_mapi_cal_util_bin_to_rrule (stream->value, comp);
			}
		} 

		b = (const bool *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BOOLEAN, 0x8503));
		if (b && *b) {
			struct timeval start, displaytime;

			if ((get_mapi_SPropValue_array_date_timeval (&start, properties, PROP_TAG(PT_SYSTIME, 0x8502)) == MAPI_E_SUCCESS) 
			 && (get_mapi_SPropValue_array_date_timeval (&displaytime, properties, PROP_TAG(PT_SYSTIME, 0x8560)) == MAPI_E_SUCCESS)) {
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
		const double *complete = 0;

		/* NOTE: Exchange tasks are DATE values, not DATE-TIME values, but maybe someday, we could expect Exchange to support it ;) */
		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PROP_TAG(PT_SYSTIME, 0x8104)) == MAPI_E_SUCCESS)
			icalcomponent_set_dtstart (ical_comp, icaltime_from_timet_with_zone (t.tv_sec, 1, default_zone));
		if (get_mapi_SPropValue_array_date_timeval (&t, properties, PROP_TAG(PT_SYSTIME, 0x8105)) == MAPI_E_SUCCESS)
			icalcomponent_set_due (ical_comp, icaltime_from_timet_with_zone (t.tv_sec, 1, default_zone));

		ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8101));
		if (ui32) {
			icalcomponent_set_status (ical_comp, get_taskstatus_from_prop(*ui32));
			if (*ui32 == olTaskComplete 
			&& get_mapi_SPropValue_array_date_timeval (&t, properties, PROP_TAG(PT_SYSTIME, 0x810F)) == MAPI_E_SUCCESS) {
				prop = icalproperty_new_completed (icaltime_from_timet_with_zone (t.tv_sec, 1, default_zone));
				icalcomponent_add_property (ical_comp, prop);
			}
		}

		complete = (const double *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_DOUBLE, 0x8102));
		if (complete) {
			prop = icalproperty_new_percentcomplete ((int)(*complete * 100));
			icalcomponent_add_property (ical_comp, prop);
		}

		b = (const bool *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BOOLEAN, 0x8126));
		if (b && *b) {
			/* FIXME: Evolution does not support recurring tasks */
			g_warning ("Encountered a recurring task.");
		}

		b = (const bool *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BOOLEAN, 0x8503));
		if (b && *b) {
			struct timeval abs;

			if (get_mapi_SPropValue_array_date_timeval (&abs, properties, PROP_TAG(PT_SYSTIME, 0x8502)) == MAPI_E_SUCCESS) {
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

#define TEMP_ATTACH_STORE ".evolution/cache/tmp"

static void
change_partstat (ECalComponent *comp, const gchar *att, const gchar *sentby, icalparameter_partstat partstat)
{
	icalcomponent *icalcomp = e_cal_component_get_icalcomponent (comp);
	icalproperty *attendee; 
	gboolean found = FALSE;

	attendee = icalcomponent_get_first_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	while (attendee) {
		const char *value = icalproperty_get_attendee (attendee);
		if (!g_ascii_strcasecmp (value, att)) {
			icalparameter *param = icalparameter_new_partstat (partstat);
			icalproperty_set_parameter (attendee, param);
			if (g_ascii_strcasecmp(att, sentby)) {
				icalparameter *sentby_param = icalparameter_new_sentby (sentby);
				icalproperty_set_parameter (attendee, sentby_param);
			}
			found = TRUE;
			break;
		}
		attendee = icalcomponent_get_next_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	}

	if (found) {
		icalproperty *prop = icalproperty_new_x ("1");
		icalproperty_set_x_name (prop, "X-EVOLUTION-IS-REPLY");
		icalcomponent_add_property (icalcomp, prop);
	}

	e_cal_component_set_icalcomponent (comp, icalcomp);
}

static void
remove_other_attendees (ECalComponent *comp, const gchar *att)
{
	icalcomponent *icalcomp = e_cal_component_get_icalcomponent (comp);
	icalproperty *attendee; 

	attendee = icalcomponent_get_first_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	while (attendee) {
		const char *value = icalproperty_get_attendee (attendee);
		if (g_ascii_strcasecmp (value, att))
			icalcomponent_remove_property (icalcomp, attendee);

		attendee = icalcomponent_get_next_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	}

	e_cal_component_set_icalcomponent (comp, icalcomp);
}

static gboolean
fetch_server_data_cb (FetchItemsCallbackData *item_data, gpointer data) 
{
	struct mapi_SPropValue_array *properties = item_data->properties;
	const mapi_id_t fid = item_data->fid;
	const mapi_id_t mid = item_data->mid;
	GSList *streams = item_data->streams;
	GSList *recipients = item_data->recipients;
	GSList *attachments = item_data->attachments;

	icalcomponent_kind kind = ICAL_VEVENT_COMPONENT;
	gchar *filename = g_build_filename (g_get_home_dir (), TEMP_ATTACH_STORE, NULL);
	gchar *fileuri = g_filename_to_uri (filename, NULL, NULL);
	gchar *smid = exchange_mapi_util_mapi_id_to_string (mid);
	ECalComponent *comp = exchange_mapi_cal_util_mapi_props_to_comp (kind, smid, properties, streams, recipients, attachments, fileuri, NULL);
	struct cbdata *cbdata = (struct cbdata *)(data);
	const uint32_t *ui32;

	ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PR_OWNER_APPT_ID);
	cbdata->appt_id = ui32 ? *ui32 : 0;
	ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8201));
	cbdata->appt_seq = ui32 ? *ui32 : 0;
	cbdata->username = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_NAME);
	cbdata->useridtype = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE);
	cbdata->userid = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	cbdata->ownername = exchange_mapi_util_find_array_propval (properties, PR_SENDER_NAME);
	cbdata->owneridtype = exchange_mapi_util_find_array_propval (properties, PR_SENDER_ADDRTYPE);
	cbdata->ownerid = exchange_mapi_util_find_array_propval (properties, PR_SENDER_EMAIL_ADDRESS);

	cbdata->comp = comp; 

	g_free (smid);
	g_free (fileuri);
	g_free (filename);

	return TRUE;
}

static void
fetch_server_data (mapi_id_t mid, struct cbdata *cbd) 
{
	icalcomponent_kind kind = ICAL_VEVENT_COMPONENT;
	mapi_id_t fid;

	fid = exchange_mapi_get_default_folder_id (olFolderCalendar);

	exchange_mapi_connection_fetch_item (fid, mid, 
					cal_GetPropsList, G_N_ELEMENTS (cal_GetPropsList), 
					exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER (kind), 
					fetch_server_data_cb, cbd, 
					MAPI_OPTIONS_FETCH_RECIPIENTS | MAPI_OPTIONS_FETCH_GENERIC_STREAMS);

}

static ECalComponent * 
update_attendee_status (struct mapi_SPropValue_array *properties, mapi_id_t mid) 
{
	const gchar *att, *att_sentby, *addrtype;
	icalparameter_partstat partstat = ICAL_PARTSTAT_NONE;
	const gchar *state = (const gchar *) exchange_mapi_util_find_array_propval (properties, PR_MESSAGE_CLASS);
	struct cbdata cbdata; 
	gchar *matt, *matt_sentby;
	uint32_t cur_seq;
	const uint32_t *ui32;

	if (!(state && *state))
		return NULL;

	if (!g_ascii_strcasecmp (state, IPM_SCHEDULE_MEETING_RESP_POS))
		partstat = ICAL_PARTSTAT_ACCEPTED;
	else if (!g_ascii_strcasecmp (state, IPM_SCHEDULE_MEETING_RESP_TENT))
		partstat = ICAL_PARTSTAT_TENTATIVE;
	else if (!g_ascii_strcasecmp (state, IPM_SCHEDULE_MEETING_RESP_NEG))
		partstat = ICAL_PARTSTAT_DECLINED;
	else
		return NULL;

	fetch_server_data (mid, &cbdata);

	att = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	addrtype = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE);
	if (addrtype && !g_ascii_strcasecmp (addrtype, "EX"))
		att = exchange_mapi_util_ex_to_smtp (att);

	att_sentby = exchange_mapi_util_find_array_propval (properties, PR_SENDER_EMAIL_ADDRESS);
	addrtype = exchange_mapi_util_find_array_propval (properties, PR_SENDER_ADDRTYPE);
	if (addrtype && !g_ascii_strcasecmp (addrtype, "EX"))
		att_sentby = exchange_mapi_util_ex_to_smtp (att_sentby);

	matt = g_strdup_printf ("MAILTO:%s", att);
	matt_sentby = g_strdup_printf ("MAILTO:%s", att_sentby);

	change_partstat (cbdata.comp, matt, matt_sentby, partstat);

	ui32 = (const uint32_t *) find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8201));
	cur_seq = ui32 ? *ui32 : 0;

	if (cbdata.appt_seq == cur_seq) {

/* 
 * The itip-formatter provides an option to update the attendee's status.
 * Hence, we need not update the server straight away. 
 */
#if 0
		gchar *filename = g_build_filename (g_get_home_dir (), TEMP_ATTACH_STORE, NULL);
		gchar *fileuri = g_filename_to_uri (filename, NULL, NULL);
		GSList *attachments = NULL, *recipients = NULL, *streams = NULL;

		if (e_cal_component_has_attachments (cbdata.comp))
			exchange_mapi_cal_util_fetch_attachments (cbdata.comp, &attachments, fileuri);

		if (e_cal_component_has_attendees (cbdata.comp))
			exchange_mapi_cal_util_fetch_recipients (cbdata.comp, &recipients);

		cbdata.meeting_type = (recipients != NULL) ? MEETING_OBJECT : NOT_A_MEETING;
		cbdata.resp = (recipients != NULL) ? olResponseOrganized : olResponseNone;
		cbdata.msgflags = MSGFLAG_READ;
		cbdata.is_modify = TRUE;
		cbdata.cleanglobalid = (const struct SBinary *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BINARY, 0x0023));
		cbdata.globalid = (const struct SBinary *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BINARY, 0x0003));

		status = exchange_mapi_modify_item (olFolderCalendar, fid, mid, 
				exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER (kind), 
				exchange_mapi_cal_util_build_props, &cbdata, 
				recipients, attachments, streams, MAPI_OPTIONS_DONT_SUBMIT);
		g_free (cbdata.props);

		exchange_mapi_util_free_recipient_list (&recipients);
		exchange_mapi_util_free_attachment_list (&attachments);
		g_free (fileuri);
		g_free (filename);
#endif 

		/* remove the other attendees so not to confuse itip-formatter */
		remove_other_attendees (cbdata.comp, matt);
	} else { 
		g_object_unref (cbdata.comp);
		cbdata.comp = NULL;
	}

	g_free (matt);
	g_free (matt_sentby);

	return cbdata.comp;
}

static void 
update_server_object (struct mapi_SPropValue_array *properties, GSList *attachments, ECalComponent *comp, mapi_id_t *mid)
{
	const uint32_t *ui32 = NULL;
	uint32_t cur_seq;
	mapi_id_t fid;
	gboolean create_new = TRUE;

	fid = exchange_mapi_get_default_folder_id (olFolderCalendar);

	ui32 = (const uint32_t *) find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8201));
	cur_seq = ui32 ? *ui32 : 0;

	if (*mid) {
		struct cbdata server_cbd;
		fetch_server_data (*mid, &server_cbd);

		if (cur_seq > server_cbd.appt_seq) {
			struct id_list idlist; 
			GSList *ids = NULL;

			idlist.id = *mid;
			ids = g_slist_append (ids, &idlist);

			exchange_mapi_remove_items (olFolderCalendar, fid, ids);
			g_slist_free (ids);
		} else 
			create_new = FALSE;
	}

	if (create_new) {
		struct cbdata cbdata;
		GSList *myrecipients = NULL;
		GSList *myattachments = NULL;
		icalcomponent_kind kind = icalcomponent_isa (e_cal_component_get_icalcomponent(comp));

		cbdata.comp = comp;
		cbdata.username = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_NAME);
		cbdata.useridtype = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_ADDRTYPE);
		cbdata.userid = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENDER_EMAIL_ADDRESS);
		cbdata.ownername = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_NAME);
		cbdata.owneridtype = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE);
		cbdata.ownerid = (const char *) exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS);
		cbdata.is_modify = FALSE;
		cbdata.msgflags = MSGFLAG_READ;
		cbdata.meeting_type = MEETING_REQUEST_RCVD;
		cbdata.resp = olResponseNone;
		cbdata.appt_seq = (*(const uint32_t *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8201)));
		cbdata.appt_id = (*(const uint32_t *)find_mapi_SPropValue_data(properties, PR_OWNER_APPT_ID));
		cbdata.globalid = (const struct SBinary *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BINARY, 0x0003));
		cbdata.cleanglobalid = (const struct SBinary *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BINARY, 0x0023));

		exchange_mapi_cal_util_fetch_recipients (comp, &myrecipients);
		myattachments = attachments;
		*mid = exchange_mapi_create_item (olFolderCalendar, 0, 
					exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER(kind),
					exchange_mapi_cal_util_build_props, &cbdata, 
					myrecipients, myattachments, NULL, MAPI_OPTIONS_DONT_SUBMIT);
		g_free (cbdata.props);
		exchange_mapi_util_free_recipient_list (&myrecipients);
	}
}

static void
check_server_for_object (struct mapi_SPropValue_array *properties, mapi_id_t *mid)
{
	struct mapi_SRestriction res;
	struct SPropValue sprop;
	const struct SBinary *sb;
	uint32_t proptag = 0x0;
	struct SPropTagArray *array;
	GSList *ids = NULL, *l;
	mapi_id_t fid;

	*mid = 0;

	fid = exchange_mapi_get_default_folder_id (olFolderCalendar);

	array = exchange_mapi_util_resolve_named_prop (olFolderCalendar, fid, 0x0023, PSETID_Meeting);
	proptag = array->aulPropTag[0];

	res.rt = RES_PROPERTY;
	res.res.resProperty.relop = RELOP_EQ;
	res.res.resProperty.ulPropTag = proptag;

	sb = (const struct SBinary *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BINARY, 0x0023));

	set_SPropValue_proptag (&sprop, proptag, (const void *) sb);
	cast_mapi_SPropValue (&(res.res.resProperty.lpProp), &sprop);

	ids = exchange_mapi_util_check_restriction (fid, &res);

	if (ids && g_slist_length(ids) == 1) {
		struct id_list *idlist = (struct id_list *)(ids->data);
		*mid = idlist->id;
	} else 
	/* FIXME: what to do here? */
	;

	for (l = ids; l; l = l->next)
		g_free(l->data);
	g_slist_free(l);
}

gchar *
exchange_mapi_cal_util_camel_helper (struct mapi_SPropValue_array *properties, 
				   GSList *streams, GSList *recipients, GSList *attachments)
{
	ECalComponent *comp = NULL;
	icalcomponent_kind kind = ICAL_NO_COMPONENT;
	icalproperty_method method = ICAL_METHOD_NONE;
	const char *msg_class = NULL;
	mapi_id_t mid = 0;
	icalcomponent *icalcomp = NULL;
	gchar *str = NULL, *smid = NULL, *tmp, *filename, *fileuri;

	msg_class = (const char *) exchange_mapi_util_find_array_propval (properties, PR_MESSAGE_CLASS);
	g_return_val_if_fail (msg_class && *msg_class, NULL);
	if (!g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_REQUEST)) {
		method = ICAL_METHOD_REQUEST;
		kind = ICAL_VEVENT_COMPONENT;
	} else if (!g_ascii_strcasecmp (msg_class, IPM_SCHEDULE_MEETING_CANCELED)) {
		method = ICAL_METHOD_CANCEL;
		kind = ICAL_VEVENT_COMPONENT;
	} else if (g_str_has_prefix (msg_class, IPM_SCHEDULE_MEETING_RESP_PREFIX)) {
		method = ICAL_METHOD_REPLY;
		kind = ICAL_VEVENT_COMPONENT;
	} else
		return (g_strdup (""));

	filename = g_build_filename (g_get_home_dir (), TEMP_ATTACH_STORE, NULL);
	fileuri = g_filename_to_uri (filename, NULL, NULL);

	check_server_for_object (properties, &mid);

	if (method == ICAL_METHOD_REPLY) {
		if (mid) { 
	 		comp = update_attendee_status (properties, mid);
			set_attachments_to_cal_component (comp, attachments, fileuri);
		} 
	} else if (method == ICAL_METHOD_CANCEL) {
		if (mid) {
			struct cbdata server_cbd; 
			fetch_server_data (mid, &server_cbd);
			comp = server_cbd.comp;
			set_attachments_to_cal_component (comp, attachments, fileuri);
		}
	} else if (method == ICAL_METHOD_REQUEST) { 
		if (mid)
			smid = exchange_mapi_util_mapi_id_to_string (mid);
		else 
			smid = e_cal_component_gen_uid();

		comp = exchange_mapi_cal_util_mapi_props_to_comp (kind, smid, 
							properties, streams, recipients, 
							NULL, NULL, NULL);
		set_attachments_to_cal_component (comp, attachments, fileuri);

		update_server_object (properties, attachments, comp, &mid);

		tmp = exchange_mapi_util_mapi_id_to_string (mid);
		e_cal_component_set_uid (comp, tmp);
		g_free (tmp);
		g_free (smid);
	}

	g_free (fileuri);
	g_free (filename);

	icalcomp = e_cal_util_new_top_level ();
	icalcomponent_set_method (icalcomp, method);
	if (comp)
		icalcomponent_add_component (icalcomp, 
			icalcomponent_new_clone(e_cal_component_get_icalcomponent(comp)));
	str = icalcomponent_as_ical_string (icalcomp);
	icalcomponent_free (icalcomp);
	if (comp)
		g_object_unref (comp);

	return str;
}


#define COMMON_NAMED_PROPS_N 9

typedef enum 
{
	I_COMMON_REMMINS = 0 , 
	I_COMMON_REMTIME , 
	I_COMMON_REMSET , 
	I_COMMON_ISPRIVATE , 
	I_COMMON_SIDEEFFECTS , 
	I_COMMON_START , 
	I_COMMON_END , 
	I_COMMON_TASKMODE , 
	I_COMMON_REMNEXTTIME 
} CommonNamedPropsIndex;

gboolean
exchange_mapi_cal_util_build_name_id (struct mapi_nameid *nameid, gpointer data)
{
	icalcomponent_kind kind = GPOINTER_TO_INT (data);

	/* NOTE: Avoid using mapi_nameid_OOM_add because: 
	 * a) its inefficient (uses strcmp) 
	 * b) names may vary in different server/libmapi versions 
	 */

	mapi_nameid_lid_add(nameid, 0x8501, PSETID_Common); 	// PT_LONG - ReminderMinutesBeforeStart
	mapi_nameid_lid_add(nameid, 0x8502, PSETID_Common); 	// PT_SYSTIME - ReminderTime
	mapi_nameid_lid_add(nameid, 0x8503, PSETID_Common); 	// PT_BOOLEAN - ReminderSet
	mapi_nameid_lid_add(nameid, 0x8506, PSETID_Common); 	// PT_BOOLEAN - Private
	mapi_nameid_lid_add(nameid, 0x8510, PSETID_Common); 	// PT_LONG - (context menu flags)
	mapi_nameid_lid_add(nameid, 0x8516, PSETID_Common); 	// PT_SYSTIME - CommonStart
	mapi_nameid_lid_add(nameid, 0x8517, PSETID_Common); 	// PT_SYSTIME - CommonEnd
	mapi_nameid_lid_add(nameid, 0x8518, PSETID_Common); 	// PT_LONG - TaskMode
	mapi_nameid_lid_add(nameid, 0x8560, PSETID_Common); 	// PT_SYSTIME - ReminderNextTime

	if (kind == ICAL_VEVENT_COMPONENT) 
		appt_build_name_id (nameid);
	else if (kind == ICAL_VTODO_COMPONENT)
		task_build_name_id (nameid);
	else if (kind == ICAL_VJOURNAL_COMPONENT)
		note_build_name_id (nameid);

	return TRUE;
}

/**
 * NOTE: The enumerations '(Appt/Task/Note)NamedPropsIndex' have been defined 
 * only to make life a little easier for developers. Here's the logic 
 * behind the definition:
     1) The first element is initialized with 'COMMON_NAMED_PROPS_N' : When 
	adding named props, we add the common named props first and then the 
	specific named props. So.. the index of the first specific 
	named property = COMMON_NAMED_PROPS_N
     2) The order in the enumeration 'must' be the same as that in the routine 
	which adds the specific named props - (appt/task/note)_build_name_id
     3) If a specific named prop is added/deleted, an index needs to
	be created/deleted at the correct position. [Don't forget to update 
	(APPT/TASK/NOTE)_NAMED_PROPS_N]. 

 * To summarize the pros: 
     1) Addition/deletion of a common-named-prop would not affect the indexes 
	of the specific named props once COMMON_NAMED_PROPS_N is updated. 
     2) Values of named props can be added in any order. 
 */


#define APPT_NAMED_PROPS_N  29
#define DEFAULT_APPT_REMINDER_MINS 15

typedef enum 
{
	I_APPT_SEQ = COMMON_NAMED_PROPS_N , 
	I_APPT_BUSYSTATUS , 
	I_APPT_LOCATION , 
	I_APPT_START , 
	I_APPT_END , 
	I_APPT_DURATION , 
	I_APPT_ALLDAY , 
	I_APPT_RECURBLOB , 
	I_APPT_STATEFLAGS , 
	I_APPT_RESPONSESTATUS , 
	I_APPT_RECURRING , 
	I_APPT_INTENDEDBUSY , 
	I_APPT_RECURBASE , 
	I_APPT_INVITED , 
	I_APPT_RECURTYPE , 
	I_APPT_CLIPSTART , 
	I_APPT_CLIPEND , 
	I_APPT_AUTOLOCATION , 
	I_APPT_ISCOUNTERPROPOSAL , 
	I_APPT_NOTALLOWPROPOSE , 
	I_APPT_STARTTZBLOB , 
	I_APPT_ENDTZBLOB , 

	I_MEET_WHERE , 
	I_MEET_GUID , 
	I_MEET_ISRECURRING , 
	I_MEET_ISEXCEPTION , 
	I_MEET_CLEANGUID , 
	I_MEET_APPTMSGCLASS , 
	I_MEET_TYPE

//	I_APPT_SENDASICAL , 
//	I_APPT_SEQTIME , 
//	I_APPT_LABEL , 
//	I_APPT_RECURPATTERN , 
//	I_APPT_DISPTZ , 
//	I_APPT_ALLATTENDEES , 
//	I_APPT_TOATTENDEES , 
//	I_APPT_CCATTENDEES , 
} ApptNamedPropsIndex;

static void 
appt_build_name_id (struct mapi_nameid *nameid)
{
	mapi_nameid_lid_add(nameid, 0x8201, PSETID_Appointment); 	// PT_LONG - ApptSequence
	mapi_nameid_lid_add(nameid, 0x8205, PSETID_Appointment); 	// PT_LONG - BusyStatus
	mapi_nameid_lid_add(nameid, 0x8208, PSETID_Appointment); 	// PT_UNICODE - Location
	mapi_nameid_lid_add(nameid, 0x820D, PSETID_Appointment); 	// PT_SYSTIME - Start/ApptStartWhole
	mapi_nameid_lid_add(nameid, 0x820E, PSETID_Appointment); 	// PT_SYSTIME - End/ApptEndWhole
	mapi_nameid_lid_add(nameid, 0x8213, PSETID_Appointment); 	// PT_LONG - Duration/ApptDuration
	mapi_nameid_lid_add(nameid, 0x8215, PSETID_Appointment); 	// PT_BOOLEAN - AllDayEvent (also called ApptSubType)
	mapi_nameid_lid_add(nameid, 0x8216, PSETID_Appointment); 	// PT_BINARY - (recurrence blob)
	mapi_nameid_lid_add(nameid, 0x8217, PSETID_Appointment); 	// PT_LONG - ApptStateFlags
	mapi_nameid_lid_add(nameid, 0x8218, PSETID_Appointment); 	// PT_LONG - ResponseStatus
	mapi_nameid_lid_add(nameid, 0x8223, PSETID_Appointment); 	// PT_BOOLEAN - Recurring
	mapi_nameid_lid_add(nameid, 0x8224, PSETID_Appointment); 	// PT_LONG - IntendedBusyStatus
	mapi_nameid_lid_add(nameid, 0x8228, PSETID_Appointment); 	// PT_SYSTIME - RecurrenceBase
	mapi_nameid_lid_add(nameid, 0x8229, PSETID_Appointment); 	// PT_BOOLEAN - FInvited
	mapi_nameid_lid_add(nameid, 0x8231, PSETID_Appointment); 	// PT_LONG - RecurrenceType
	mapi_nameid_lid_add(nameid, 0x8235, PSETID_Appointment); 	// PT_SYSTIME - (dtstart)(for recurring events UTC 12 AM of day of start)
	mapi_nameid_lid_add(nameid, 0x8236, PSETID_Appointment); 	// PT_SYSTIME - (dtend)(for recurring events UTC 12 AM of day of end)
	mapi_nameid_lid_add(nameid, 0x823A, PSETID_Appointment); 	// PT_BOOLEAN - AutoFillLocation
	mapi_nameid_lid_add(nameid, 0x8257, PSETID_Appointment); 	// PT_BOOLEAN - ApptCounterProposal
	mapi_nameid_lid_add(nameid, 0x825A, PSETID_Appointment); 	// PT_BOOLEAN - ApptNotAllowPropose
	mapi_nameid_lid_add(nameid, 0x825E, PSETID_Appointment); 	// PT_BINARY - (timezone for dtstart)
	mapi_nameid_lid_add(nameid, 0x825F, PSETID_Appointment); 	// PT_BINARY - (timezone for dtend)

	mapi_nameid_lid_add(nameid, 0x0002, PSETID_Meeting); 		// PT_UNICODE - Where
	mapi_nameid_lid_add(nameid, 0x0003, PSETID_Meeting); 		// PT_BINARY - GlobalObjectId
	mapi_nameid_lid_add(nameid, 0x0005, PSETID_Meeting); 		// PT_BOOLEAN - IsRecurring
	mapi_nameid_lid_add(nameid, 0x000A, PSETID_Meeting); 		// PT_BOOLEAN - IsException 
	mapi_nameid_lid_add(nameid, 0x0023, PSETID_Meeting); 		// PT_BINARY - CleanGlobalObjectId
	mapi_nameid_lid_add(nameid, 0x0024, PSETID_Meeting); 		// PT_STRING8 - AppointmentMessageClass 
	mapi_nameid_lid_add(nameid, 0x0026, PSETID_Meeting); 		// PT_LONG - MeetingType

	/* These probably would never be used from Evolution */
//	mapi_nameid_lid_add(nameid, 0x8200, PSETID_Appointment); 	// PT_BOOLEAN - SendAsICAL
//	mapi_nameid_lid_add(nameid, 0x8202, PSETID_Appointment); 	// PT_SYSTIME - ApptSequenceTime
//	mapi_nameid_lid_add(nameid, 0x8214, PSETID_Appointment); 	// PT_LONG - Label
//	mapi_nameid_lid_add(nameid, 0x8232, PSETID_Appointment); 	// PT_STRING8 - RecurrencePattern
//	mapi_nameid_lid_add(nameid, 0x8234, PSETID_Appointment); 	// PT_STRING8 - display TimeZone
//	mapi_nameid_lid_add(nameid, 0x8238, PSETID_Appointment); 	// PT_STRING8 - AllAttendees
//	mapi_nameid_lid_add(nameid, 0x823B, PSETID_Appointment); 	// PT_STRING8 - ToAttendeesString (dupe PR_DISPLAY_TO)
//	mapi_nameid_lid_add(nameid, 0x823C, PSETID_Appointment); 	// PT_STRING8 - CCAttendeesString (dupe PR_DISPLAY_CC)
}

#define TASK_NAMED_PROPS_N 13
#define DEFAULT_TASK_REMINDER_MINS 1080

typedef enum 
{
	I_TASK_STATUS = COMMON_NAMED_PROPS_N , 
	I_TASK_PERCENT , 
	I_TASK_ISTEAMTASK , 
	I_TASK_START , 
	I_TASK_DUE , 
	I_TASK_COMPLETED , 
//	I_TASK_RECURBLOB , 
	I_TASK_ISCOMPLETE , 
	I_TASK_OWNER , 
	I_TASK_DELEGATOR , 
	I_TASK_ISRECURRING , 
	I_TASK_ROLE , 
	I_TASK_OWNERSHIP , 
	I_TASK_DELEGATIONSTATE , 
//	I_TASK_ACTUALWORK , 
//	I_TASK_TOTALWORK 
} TaskNamedPropsIndex;

static void 
task_build_name_id (struct mapi_nameid *nameid)
{
	mapi_nameid_lid_add(nameid, 0x8101, PSETID_Task); 	// PT_LONG - Status
	mapi_nameid_lid_add(nameid, 0x8102, PSETID_Task); 	// PT_DOUBLE - PercentComplete
	mapi_nameid_lid_add(nameid, 0x8103, PSETID_Task); 	// PT_BOOLEAN - TeamTask
	mapi_nameid_lid_add(nameid, 0x8104, PSETID_Task); 	// PT_SYSTIME - StartDate/TaskStartDate
	mapi_nameid_lid_add(nameid, 0x8105, PSETID_Task); 	// PT_SYSTIME - DueDate/TaskDueDate
	mapi_nameid_lid_add(nameid, 0x810F, PSETID_Task); 	// PT_SYSTIME - DateCompleted
//	mapi_nameid_lid_add(nameid, 0x8116, PSETID_Task); 	// PT_BINARY - (recurrence blob)
	mapi_nameid_lid_add(nameid, 0x811C, PSETID_Task); 	// PT_BOOLEAN - Complete
	mapi_nameid_lid_add(nameid, 0x811F, PSETID_Task); 	// PT_STRING8 - Owner
	mapi_nameid_lid_add(nameid, 0x8121, PSETID_Task); 	// PT_STRING8 - Delegator
	mapi_nameid_lid_add(nameid, 0x8126, PSETID_Task); 	// PT_BOOLEAN - IsRecurring/TaskFRecur
	mapi_nameid_lid_add(nameid, 0x8127, PSETID_Task); 	// PT_STRING8 - Role
	mapi_nameid_lid_add(nameid, 0x8129, PSETID_Task); 	// PT_LONG - Ownership
	mapi_nameid_lid_add(nameid, 0x812A, PSETID_Task); 	// PT_LONG - DelegationState

	/* These probably would never be used from Evolution */
//	mapi_nameid_lid_add(nameid, 0x8110, PSETID_Task); 	// PT_LONG - ActualWork/TaskActualEffort
//	mapi_nameid_lid_add(nameid, 0x8111, PSETID_Task); 	// PT_LONG - TotalWork/TaskEstimatedEffort
}


#define NOTE_NAMED_PROPS_N 3

typedef enum 
{
	I_NOTE_COLOR = COMMON_NAMED_PROPS_N , 
	I_NOTE_WIDTH , 
	I_NOTE_HEIGHT
} NoteNamedPropsIndex;

static void 
note_build_name_id (struct mapi_nameid *nameid)
{
	mapi_nameid_lid_add(nameid, 0x8B00, PSETID_Note); 	// PT_LONG - Color
	mapi_nameid_lid_add(nameid, 0x8B02, PSETID_Note); 	// PT_LONG - Width
	mapi_nameid_lid_add(nameid, 0x8B03, PSETID_Note); 	// PT_LONG - Height
}

#define MINUTES_IN_HOUR 60
#define SECS_IN_MINUTE 60

/** 
 * NOTE: When a new regular property (PR_***) is added, 'REGULAR_PROPS_N' 
 * should be updated. 
 */
#define REGULAR_PROPS_N    22

int
exchange_mapi_cal_util_build_props (struct SPropValue **value, struct SPropTagArray *proptag_array, gpointer data)
{
	struct cbdata *cbdata = (struct cbdata *) data;
	ECalComponent *comp = cbdata->comp;
	icalcomponent *ical_comp = e_cal_component_get_icalcomponent (comp);
	icalcomponent_kind  kind = icalcomponent_isa (ical_comp);
	struct SPropValue *props = NULL;
	int i=0;
	uint32_t flag32;
	bool b;
	icalproperty *prop;
	struct icaltimetype dtstart, dtend, utc_dtstart, utc_dtend;
	const icaltimezone *utc_zone;
	const char *dtstart_tzid, *dtend_tzid, *text = NULL;
	struct timeval t;

	flag32 = REGULAR_PROPS_N + COMMON_NAMED_PROPS_N;
	switch (kind) {
		case ICAL_VEVENT_COMPONENT:
			flag32 += APPT_NAMED_PROPS_N;
			break;
		case ICAL_VTODO_COMPONENT:
			flag32 += TASK_NAMED_PROPS_N;
			break;
		case ICAL_VJOURNAL_COMPONENT:
			flag32 += NOTE_NAMED_PROPS_N;
			break;
		default:
			return 0;
	} 

	d(g_debug ("Allocating space for %d props ", flag32));
	props = g_new0 (struct SPropValue, flag32);

	/* PR_MESSAGE_CLASS needs to be set appropriately */					/* propcount++ */

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

	dtstart_tzid = icaltime_get_tzid (dtstart);
	dtend_tzid = icaltime_get_tzid (dtend);

	utc_dtstart = icaltime_convert_to_zone (dtstart, utc_zone);
	utc_dtend = icaltime_convert_to_zone (dtend, utc_zone);

	text = icalcomponent_get_summary (ical_comp);
	if (!(text && *text)) 
		text = "";
	set_SPropValue_proptag(&props[i++], PR_SUBJECT, 					/* propcount++ */ 
					(const void *) text);
	set_SPropValue_proptag(&props[i++], PR_NORMALIZED_SUBJECT, 				/* propcount++ */ 
					(const void *) text);
	if (cbdata->appt_seq == 0)
		set_SPropValue_proptag(&props[i++], PR_CONVERSATION_TOPIC, 			/* propcount++ */
						(const void *) text);
	text = NULL;

	/* we don't support HTML event/task/memo editor */
	flag32 = olEditorText;
	set_SPropValue_proptag(&props[i++], PR_MSG_EDITOR_FORMAT, &flag32); 			/* propcount++ */

	/* it'd be better to convert, then set it in unicode */
	text = icalcomponent_get_description (ical_comp);
	if (!(text && *text) || !g_utf8_validate (text, -1, NULL)) 
		text = "";
	set_SPropValue_proptag(&props[i++], PR_BODY, 						/* propcount++ */
					(const void *) text);
	text = NULL;

	/* Priority and Importance */
	prop = icalcomponent_get_first_property (ical_comp, ICAL_PRIORITY_PROPERTY);
	flag32 = prop ? get_prio_prop_from_priority (icalproperty_get_priority (prop)) : PRIORITY_NORMAL;
	set_SPropValue_proptag(&props[i++], PR_PRIORITY, (const void *) &flag32); 		/* propcount++ */
	flag32 = prop ? get_imp_prop_from_priority (icalproperty_get_priority (prop)) : IMPORTANCE_NORMAL;
	set_SPropValue_proptag(&props[i++], PR_IMPORTANCE, (const void *) &flag32); 		/* propcount++ */

	set_SPropValue_proptag(&props[i++], PR_SENT_REPRESENTING_NAME, 
		(const void *) cbdata->ownername); 						/* propcount++ */
	set_SPropValue_proptag(&props[i++], PR_SENT_REPRESENTING_ADDRTYPE, 
		(const void *) cbdata->owneridtype); 						/* propcount++ */
	set_SPropValue_proptag(&props[i++], PR_SENT_REPRESENTING_EMAIL_ADDRESS, 
		(const void *) cbdata->ownerid); 						/* propcount++ */
	set_SPropValue_proptag(&props[i++], PR_SENDER_NAME, 
		(const void *) cbdata->username); 						/* propcount++ */
	set_SPropValue_proptag(&props[i++], PR_SENDER_ADDRTYPE, 
		(const void *) cbdata->useridtype); 						/* propcount++ */
	set_SPropValue_proptag(&props[i++], PR_SENDER_EMAIL_ADDRESS, 
		(const void *) cbdata->userid); 						/* propcount++ */

	flag32 = cbdata->msgflags;
	set_SPropValue_proptag(&props[i++], PR_MESSAGE_FLAGS, (const void *) &flag32); 		/* propcount++ */

	flag32 = 0x0;
	b = e_cal_component_has_alarms (comp);
	if (b) {
		/* We know there would be only a single alarm of type:DISPLAY [static properties of the backend] */
		GList *alarm_uids = e_cal_component_get_alarm_uids (comp);
		ECalComponentAlarm *alarm = e_cal_component_get_alarm (comp, (const char *)(alarm_uids->data));
		ECalComponentAlarmAction action;
		e_cal_component_alarm_get_action (alarm, &action);
		if (action == E_CAL_COMPONENT_ALARM_DISPLAY) {
			ECalComponentAlarmTrigger trigger;
			e_cal_component_alarm_get_trigger (alarm, &trigger);
			int dur_int = 0; 
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
	set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_REMSET], (const void *) &b);
	set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_REMMINS], (const void *) &flag32);
	t.tv_sec = icaltime_as_timet (utc_dtstart);
	t.tv_usec = 0;
	set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_COMMON_REMTIME], &t);
	t.tv_sec = icaltime_as_timet (utc_dtstart) - (flag32 * SECS_IN_MINUTE);
	t.tv_usec = 0;
	/* ReminderNextTime: FIXME for recurrence */
	set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_COMMON_REMNEXTTIME], &t);

	/* Sensitivity, Private */
	flag32 = olNormal; 	/* default */
	b = 0; 			/* default */
	prop = icalcomponent_get_first_property (ical_comp, ICAL_CLASS_PROPERTY);
	if (prop) 
		flag32 = get_prop_from_class (icalproperty_get_class (prop));
	if (flag32 == olPrivate || flag32 == olConfidential)
		b = 1;
	set_SPropValue_proptag(&props[i++], PR_SENSITIVITY, (const void *) &flag32); 		/* propcount++ */
	set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_ISPRIVATE], (const void *) &b);

	t.tv_sec = icaltime_as_timet (utc_dtstart);
	t.tv_usec = 0;
	set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_COMMON_START], &t);
	set_SPropValue_proptag_date_timeval(&props[i++], PR_START_DATE, &t); 			/* propcount++ */

	t.tv_sec = icaltime_as_timet (utc_dtend);
	t.tv_usec = 0;
	set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_COMMON_END], &t);
	set_SPropValue_proptag_date_timeval(&props[i++], PR_END_DATE, &t); 			/* propcount++ */

	b = 1;
	set_SPropValue_proptag(&props[i++], PR_RESPONSE_REQUESTED, (const void *) &b); 		/* propcount++ */

	/* PR_OWNER_APPT_ID needs to be set in certain cases only */				/* propcount++ */
	/* PR_ICON_INDEX needs to be set appropriately */					/* propcount++ */

	b = 0;
	set_SPropValue_proptag(&props[i++], PR_RTF_IN_SYNC, (const void *) &b); 		/* propcount++ */

	if (kind == ICAL_VEVENT_COMPONENT) {
		const char *mapi_tzid;
		struct SBinary start_tz, end_tz; 

		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_APPTMSGCLASS], (const void *) IPM_APPOINTMENT);

		/* Busy Status */
		flag32 = olBusy; 	/* default */
		prop = icalcomponent_get_first_property (ical_comp, ICAL_TRANSP_PROPERTY);
		if (prop)
			flag32 = get_prop_from_transp (icalproperty_get_transp (prop));
		if (cbdata->meeting_type == MEETING_CANCEL)
			flag32 = olFree;
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_INTENDEDBUSY], (const void *) &flag32);

		if (cbdata->meeting_type == MEETING_REQUEST || cbdata->meeting_type == MEETING_REQUEST_RCVD) {
			flag32 = olTentative;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_BUSYSTATUS], (const void *) &flag32);
		} else if (cbdata->meeting_type == MEETING_CANCEL) {
			flag32 = olFree;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_BUSYSTATUS], (const void *) &flag32);
		} else 
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_BUSYSTATUS], (const void *) &flag32);

		/* Location */
		text = icalcomponent_get_location (ical_comp);
		if (!(text && *text)) 
			text = "";
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_LOCATION], (const void *) text);
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_WHERE], (const void *) text);
		text = NULL;
		/* Auto-Location is always FALSE - Evolution doesn't work that way */
		b = 0; 
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_AUTOLOCATION], (const void *) &b);

		/* Start */
		t.tv_sec = icaltime_as_timet (utc_dtstart);
		t.tv_usec = 0;
		set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_APPT_START], &t);
		/* FIXME: for recurrence */
		set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_APPT_CLIPSTART], &t);

		/* Start TZ */
		mapi_tzid = exchange_mapi_cal_tz_util_get_mapi_equivalent ((dtstart_tzid && *dtstart_tzid) ? dtstart_tzid : "UTC");
		if (mapi_tzid && *mapi_tzid) {
			exchange_mapi_cal_util_mapi_tz_to_bin (mapi_tzid, &start_tz);
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STARTTZBLOB], (const void *) &start_tz);
		}

		/* End */
		t.tv_sec = icaltime_as_timet (utc_dtend);
		t.tv_usec = 0;
		set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_APPT_END], &t);
		/* FIXME: for recurrence */
		set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_APPT_CLIPEND], &t);

		/* End TZ */
		mapi_tzid = exchange_mapi_cal_tz_util_get_mapi_equivalent ((dtend_tzid && *dtend_tzid) ? dtend_tzid : "UTC");
		if (mapi_tzid && *mapi_tzid) {
			exchange_mapi_cal_util_mapi_tz_to_bin (mapi_tzid, &end_tz);
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_ENDTZBLOB], (const void *) &end_tz);
		}

		/* Duration */
		flag32 = icaldurationtype_as_int (icaltime_subtract (dtend, dtstart));
		flag32 /= MINUTES_IN_HOUR;
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_DURATION], (const void *) &flag32);

		/* All-day event */
		b = (icaltime_is_date (dtstart) && icaltime_is_date (dtend));
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_ALLDAY], (const void *) &b);

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
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_RECURTYPE], (const void *) &flag32);

		flag32 = cbdata->appt_id;
		set_SPropValue_proptag(&props[i++], PR_OWNER_APPT_ID, (const void *) &flag32);

		flag32 = cbdata->appt_seq;
		set_SPropValue_proptag(&props[i++],  proptag_array->aulPropTag[I_APPT_SEQ], (const void *) &flag32);

		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_CLEANGUID], (const void *) cbdata->cleanglobalid);
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_GUID], (const void *) cbdata->globalid);

		flag32 = cbdata->resp;
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_RESPONSESTATUS], (const void *) &flag32);

		switch (cbdata->meeting_type) {
		case MEETING_OBJECT :
			set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet; 
			set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

			flag32 = 0x0171;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

			flag32 = asfMeeting;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STATEFLAGS], (const void *) &flag32);

			flag32 = mtgRequest; 
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_TYPE], (const void *) &flag32);

			b = 1;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_INVITED], (const void *) &b);

			break;
		case MEETING_OBJECT_RCVD :
			set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet; 
			set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

			flag32 = 0x0171;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

			flag32 = asfMeeting | asfReceived;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STATEFLAGS], (const void *) &flag32);

			flag32 = mtgRequest; 
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_TYPE], (const void *) &flag32);

			b = 1;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_INVITED], (const void *) &b);

			break;
		case MEETING_REQUEST :
			set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_SCHEDULE_MEETING_REQUEST);

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */
			set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

			flag32 = 0x1C61;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

			flag32 = asfMeeting | asfReceived;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STATEFLAGS], (const void *) &flag32);

			flag32 = (cbdata->appt_seq == 0) ? mtgRequest : mtgFull; 
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_TYPE], (const void *) &flag32);

			b = 1;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_INVITED], (const void *) &b);

			break;
		case MEETING_REQUEST_RCVD :
			set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet; 
			set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

			flag32 = 0x0171;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

			flag32 = asfMeeting | asfReceived;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STATEFLAGS], (const void *) &flag32);

			flag32 = mtgRequest; 
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_TYPE], (const void *) &flag32);

			b = 1;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_INVITED], (const void *) &b);

			break;
		case MEETING_CANCEL :
			set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_SCHEDULE_MEETING_CANCELED);

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */ 
			set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

			flag32 = 0x1C61;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

			flag32 = asfMeeting | asfReceived | asfCanceled;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STATEFLAGS], (const void *) &flag32);

			flag32 = mtgEmpty; 
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_TYPE], (const void *) &flag32);

			b = 1;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_INVITED], (const void *) &b);

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
			set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) text);
			text = NULL;

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */ 
			set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

			flag32 = 0x1C61;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

			flag32 = asfNone;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STATEFLAGS], (const void *) &flag32);

			flag32 = mtgEmpty; 
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_TYPE], (const void *) &flag32);

			break;
		case NOT_A_MEETING :
		default :
			set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurAppt : SingleAppt; 
			set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

			flag32 = 0x0171;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

			flag32 = 0;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_STATEFLAGS], (const void *) &flag32);

			b = 0;
			set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_INVITED], (const void *) &b);

			break;
		}

		b = e_cal_component_has_recurrences (comp);
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_RECURRING], (const void *) &b);
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_ISRECURRING], (const void *) &b);
		/* FIXME: Modified exceptions */
		b = e_cal_component_has_exceptions (comp) && FALSE; b = 0;
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_MEET_ISEXCEPTION], (const void *) &b);

		/* Counter Proposal for appointments : not supported */
		b = 1;
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_NOTALLOWPROPOSE], (const void *) &b);
		b = 0;
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_APPT_ISCOUNTERPROPOSAL], (const void *) &b);

	} else if (kind == ICAL_VTODO_COMPONENT) {
		double d;

		set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_TASK);

		/* Context menu flags */ /* FIXME: for assigned tasks */
		flag32 = 0x0110; 
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

		/* Status, Percent complete, IsComplete */
		flag32 = olTaskNotStarted; 	/* default */
		b = 0; 				/* default */
		d = 0.0;
		prop = icalcomponent_get_first_property (ical_comp, ICAL_PERCENTCOMPLETE_PROPERTY);
		if (prop)
			d = 0.01 * icalproperty_get_percentcomplete (prop);

		flag32 = get_prop_from_taskstatus (icalcomponent_get_status (ical_comp));
		if (flag32 == olTaskComplete) {
			b = 1;
			d = 1.0;
		}

		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_TASK_STATUS], (const void *) &flag32);

		/* FIXME: bug in LibMAPI - does not handle PT_DOUBLE in set_SPropValue() */
//		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_TASK_PERCENT], (const void *) &d); 
		props[i].ulPropTag = proptag_array->aulPropTag[I_TASK_PERCENT];
		props[i].dwAlignPad = 0x0;
		memcpy (&(props[i].value.dbl), &d, sizeof(double));
		i++; 

		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_TASK_ISCOMPLETE], (const void *) &b);

		/* Date completed */
		if (b) {
			struct icaltimetype completed;
			prop = icalcomponent_get_first_property (ical_comp, ICAL_COMPLETED_PROPERTY);
			completed = icalproperty_get_completed (prop);

			completed.hour = completed.minute = completed.second = 0; completed.is_date = completed.is_utc = 1;
			t.tv_sec = icaltime_as_timet (completed);
			t.tv_usec = 0;
			set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_TASK_COMPLETED], &t);
		}

		/* Start */
		dtstart.hour = dtstart.minute = dtstart.second = 0; dtstart.is_date = dtstart.is_utc = 1;
		t.tv_sec = icaltime_as_timet (dtstart);
		t.tv_usec = 0;
		if (!icaltime_is_null_time (dtstart))
			set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_TASK_START], &t);

		/* Due */
		dtend.hour = dtend.minute = dtend.second = 0; dtend.is_date = dtend.is_utc = 1;
		t.tv_sec = icaltime_as_timet (dtend);
		t.tv_usec = 0;
		if (!icaltime_is_null_time (dtend))
			set_SPropValue_proptag_date_timeval(&props[i++], proptag_array->aulPropTag[I_TASK_DUE], &t);

		/* FIXME: Evolution does not support recurring tasks */
		b = 0;
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_TASK_ISRECURRING], (const void *) &b);

	} else if (kind == ICAL_VJOURNAL_COMPONENT) {
		uint32_t color = olYellow; 

		set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *) IPM_STICKYNOTE);

		/* Context menu flags */
		flag32 = 0x0110; 
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_COMMON_SIDEEFFECTS], (const void *) &flag32);

		flag32 = 0x0300 + color; 
		set_SPropValue_proptag(&props[i++], PR_ICON_INDEX, (const void *) &flag32);

		flag32 = color; 
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_NOTE_COLOR], (const void *) &flag32);

		/* some random value */
		flag32 = 0x00FF; 
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_NOTE_WIDTH], (const void *) &flag32);

		/* some random value */
		flag32 = 0x00FF; 
		set_SPropValue_proptag(&props[i++], proptag_array->aulPropTag[I_NOTE_HEIGHT], (const void *) &flag32);
	}

	*value = props;
	/* Free this memory at the backends. */
	cbdata->props = props;

	d(g_debug ("Ended up setting %d props ", i));

	return i;
}

uint32_t
exchange_mapi_cal_util_get_new_appt_id (mapi_id_t fid)
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
			set_SPropValue_proptag (&sprop, PR_OWNER_APPT_ID, (const void *) &id);
			cast_mapi_SPropValue (&(res.res.resProperty.lpProp), &sprop);
			ids = exchange_mapi_util_check_restriction (fid, &res);
			if (ids) {
				GSList *l;
				for (l = ids; l; l = l->next)
					g_free (l->data);
			} else 
				found = TRUE;
		}
	};

	return id;
}

