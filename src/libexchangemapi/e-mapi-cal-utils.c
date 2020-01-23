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

#include "evolution-mapi-config.h"

#include <glib/gstdio.h>
#include <glib/gi18n-lib.h>
#include <libecal/libecal.h>
#include <libedataserver/libedataserver.h>

#include "e-mapi-mail-utils.h"
#include "e-mapi-cal-utils.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* This property changed names in openchange, try to support both */
#ifndef PidLidTaskAcceptanceState
	#define PidLidTaskAcceptanceState PidLidAcceptanceState
#endif

#define d(x) 

#define DEFAULT_APPT_REMINDER_MINS 15
#define DEFAULT_TASK_REMINDER_MINS 1080


static ICalParameterRole
get_role_from_type (OlMailRecipientType type)
{
	switch (type) {
	case olCC:
		return I_CAL_ROLE_OPTPARTICIPANT;
	case olOriginator:
	case olTo:
	case olBCC:
	default:
		return I_CAL_ROLE_REQPARTICIPANT;
	}
}

static OlMailRecipientType
get_type_from_role (ICalParameterRole role)
{
	switch (role) {
	case I_CAL_ROLE_OPTPARTICIPANT:
		return olCC;
	case I_CAL_ROLE_CHAIR:
	case I_CAL_ROLE_REQPARTICIPANT:
	case I_CAL_ROLE_NONPARTICIPANT:
	default:
		return olTo;
	}
}

static ICalParameterPartstat
get_partstat_from_trackstatus (uint32_t trackstatus)
{
	switch (trackstatus) {
	case olResponseOrganized:
	case olResponseAccepted:
		return I_CAL_PARTSTAT_ACCEPTED;
	case olResponseTentative:
		return I_CAL_PARTSTAT_TENTATIVE;
	case olResponseDeclined:
		return I_CAL_PARTSTAT_DECLINED;
	default:
		return I_CAL_PARTSTAT_NEEDSACTION;
	}
}

static uint32_t
get_trackstatus_from_partstat (ICalParameterPartstat partstat)
{
	switch (partstat) {
	case I_CAL_PARTSTAT_ACCEPTED:
		return olResponseAccepted;
	case I_CAL_PARTSTAT_TENTATIVE:
		return olResponseTentative;
	case I_CAL_PARTSTAT_DECLINED:
		return olResponseDeclined;
	default:
		return olResponseNone;
	}
}

static ICalPropertyTransp
get_transp_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
	case olFree:
	case olTentative:
		return I_CAL_TRANSP_TRANSPARENT;
	case olBusy:
	case olOutOfOffice:
	default:
		return I_CAL_TRANSP_OPAQUE;
	}
}

static uint32_t
get_prop_from_transp (ICalPropertyTransp transp)
{
	/* FIXME: is this mapping correct ? */
	switch (transp) {
	case I_CAL_TRANSP_TRANSPARENT:
	case I_CAL_TRANSP_TRANSPARENTNOCONFLICT:
		return olFree;
	case I_CAL_TRANSP_OPAQUE:
	case I_CAL_TRANSP_OPAQUENOCONFLICT:
	default:
		return olBusy;
	}
}

static ICalPropertyStatus
get_taskstatus_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
	case olTaskComplete:
		return I_CAL_STATUS_COMPLETED;
	case olTaskWaiting:
	case olTaskInProgress:
		return I_CAL_STATUS_INPROCESS;
	case olTaskDeferred:
		return I_CAL_STATUS_CANCELLED;
	case olTaskNotStarted:
	default:
		return I_CAL_STATUS_NEEDSACTION;
	}
}

static uint32_t
get_prop_from_taskstatus (ICalPropertyStatus status)
{
	/* FIXME: is this mapping correct ? */
	switch (status) {
	case I_CAL_STATUS_INPROCESS:
		return olTaskInProgress;
	case I_CAL_STATUS_COMPLETED:
		return olTaskComplete;
	case I_CAL_STATUS_CANCELLED:
		return olTaskDeferred;
	default:
		return olTaskNotStarted;
	}
}

static ICalProperty_Class
get_class_from_prop (uint32_t prop)
{
	/* FIXME: is this mapping correct ? */
	switch (prop) {
	case olPersonal:
	case olPrivate:
		return I_CAL_CLASS_PRIVATE;
	case olConfidential:
		return I_CAL_CLASS_CONFIDENTIAL;
	case olNormal:
	default:
		return I_CAL_CLASS_PUBLIC;
	}
}

static uint32_t
get_prop_from_class (ICalProperty_Class classif)
{
	/* FIXME: is this mapping correct ? */
	switch (classif) {
	case I_CAL_CLASS_PRIVATE:
		return olPrivate;
	case I_CAL_CLASS_CONFIDENTIAL:
		return olConfidential;
	default:
		return olNormal;
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

#define RECIP_SENDABLE  0x1
#define RECIP_ORGANIZER 0x2

static const uint8_t GID_START_SEQ[] = {
	0x04, 0x00, 0x00, 0x00, 0x82, 0x00, 0xe0, 0x00,
	0x74, 0xc5, 0xb7, 0x10, 0x1a, 0x82, 0xe0, 0x08
};

/* exception_replace_time is a value of PidLidExceptionReplaceTime; this is not used for 'clean' object ids.
   creation_time is a value of PR_CREATION_TIME
*/
void
e_mapi_cal_util_generate_globalobjectid (gboolean is_clean,
					 const gchar *uid,
					 const struct timeval *exception_replace_time,
					 const struct FILETIME *creation_time,
					 struct SBinary_short *sb)
{
	GByteArray *ba;
	guint32 val32;
	guchar *buf = NULL;
	gsize len;
	d(guint32 i);

	ba = g_byte_array_new ();

	ba = g_byte_array_append (ba, GID_START_SEQ, (sizeof (GID_START_SEQ) / sizeof (GID_START_SEQ[0])));

	val32 = 0;
	if (!is_clean && exception_replace_time) {
		ICalTime *itt = i_cal_time_new_from_timet_with_zone (exception_replace_time->tv_sec, 0, i_cal_timezone_get_utc_timezone ());

		val32 |= (i_cal_time_get_year (itt) & 0xFF00) << 16;
		val32 |= (i_cal_time_get_year (itt) & 0xFF) << 16;
		val32 |= (i_cal_time_get_month (itt) & 0xFF) << 8;
		val32 |= (i_cal_time_get_day (itt) & 0xFF);

		g_clear_object (&itt);
	}

	ba = g_byte_array_append (ba, (const guint8 *) &val32, sizeof (guint32));

	/* creation time */
	val32 = creation_time ? creation_time->dwLowDateTime : 0;
	ba = g_byte_array_append (ba, (const guint8 *) &val32, sizeof (guint32));
	val32 = creation_time ? creation_time->dwHighDateTime : 0;
	ba = g_byte_array_append (ba, (const guint8 *) &val32, sizeof (guint32));

	/* RESERVED - should be all 0's  */
	val32 = 0;
	ba = g_byte_array_append (ba, (const guint8 *) &val32, sizeof (guint32));
	val32 = 0;
	ba = g_byte_array_append (ba, (const guint8 *) &val32, sizeof (guint32));

	/* We put Evolution's UID in base64 here */
	buf = g_base64_decode (uid, &len);
	if (len % 2 != 0)
		--len;
	val32 = len;

	/* Size in bytes of the following data */
	ba = g_byte_array_append (ba, (const guint8 *) &val32, sizeof (guint32));
	/* Data */
	ba = g_byte_array_append (ba, (const guint8 *)buf, val32);
	g_free (buf);

	sb->lpb = ba->data;
	sb->cb = ba->len;

	d(g_message ("New GlobalObjectId.. Length: %d bytes.. Hex-data follows:", ba->len));
	d(for (i = 0; i < ba->len; i++)
		g_print("0x%02X ", ba->data[i]));

	g_byte_array_free (ba, FALSE);
}

/* returns complete globalid as base64 encoded string */
static gchar *
globalid_to_string (const guint8 *lpb,
		    guint32 cb)
{
	const guint8 *ptr;
	guint32 i, j;

	g_return_val_if_fail (lpb != NULL, NULL);

	/* MSDN docs: the globalID must have an even number of bytes */
	if ((cb) % 2 != 0)
		return NULL;

	ptr = lpb;

	/* starting seq - len = 16 bytes */
	for (i = 0, j = 0; i < cb && j < sizeof (GID_START_SEQ); i++, ptr++, j++) {
		if (*ptr != GID_START_SEQ[j])
			return NULL;
	}

	/* take complete global id */
	return g_base64_encode (lpb, cb);
}

/* retrieves timezone location from a timezone ID */
static const gchar *
get_tzid_location (const gchar *tzid,
		   struct cal_cbdata *cbdata)
{
	ICalTimezone *zone = NULL;

	if (!tzid || !*tzid || g_str_equal (tzid, "UTC"))
		return NULL;

	/* ask backend first, if any */
	if (cbdata && cbdata->get_timezone)
		zone = cbdata->get_timezone (cbdata->get_tz_data, tzid);

	if (!zone)
		zone = i_cal_timezone_get_builtin_timezone_from_tzid (tzid);

	/* the old TZID prefix used in previous versions of evolution-mapi */
	#define OLD_TZID_PREFIX "/softwarestudio.org/Tzfile/"

	if (!zone && g_str_has_prefix (tzid, OLD_TZID_PREFIX))
		zone = i_cal_timezone_get_builtin_timezone (tzid + strlen (OLD_TZID_PREFIX));

	#undef OLD_TZID_PREFIX

	if (!zone)
		return NULL;

	return i_cal_timezone_get_location (zone);
}

#define MINUTES_IN_HOUR 60
#define SECS_IN_MINUTE 60

static gboolean
emcu_build_restriction (EMapiConnection *conn,
			TALLOC_CTX *mem_ctx,
			struct mapi_SRestriction **restrictions,
			gpointer user_data,
			GCancellable *cancellable,
			GError **perror)
{
	struct mapi_SRestriction *restriction;
	struct SPropValue sprop;
	uint32_t *id = user_data;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (restrictions != NULL, FALSE);
	g_return_val_if_fail (id != NULL, FALSE);

	restriction = talloc_zero (mem_ctx, struct mapi_SRestriction);
	g_return_val_if_fail (restriction != NULL, FALSE);

	restriction->rt = RES_PROPERTY;
	restriction->res.resProperty.relop = RELOP_EQ;
	restriction->res.resProperty.ulPropTag = PR_OWNER_APPT_ID;

	set_SPropValue_proptag (&sprop, PR_OWNER_APPT_ID, id);
	cast_mapi_SPropValue (mem_ctx, &(restriction->res.resProperty.lpProp), &sprop);

	*restrictions = restriction;

	return TRUE;
}

static gboolean
emcu_check_id_exists_cb (EMapiConnection *conn,
			 TALLOC_CTX *mem_ctx,
			 const ListObjectsData *object_data,
			 guint32 obj_index,
			 guint32 obj_total,
			 gpointer user_data,
			 GCancellable *cancellable,
			 GError **perror)
{
	gboolean *unused = user_data;

	g_return_val_if_fail (unused != NULL, FALSE);

	*unused = FALSE;

	return FALSE;
}

uint32_t
e_mapi_cal_util_get_new_appt_id (EMapiConnection *conn, mapi_id_t fid)
{
	uint32_t id;
	gboolean unused = FALSE;
	mapi_object_t obj_folder;

	if (!e_mapi_connection_open_personal_folder (conn, fid, &obj_folder, NULL, NULL))
		return g_random_int ();

	while (!unused) {
		id = g_random_int ();
		if (id) {
			unused = TRUE;
			if (!e_mapi_connection_list_objects (conn, &obj_folder, emcu_build_restriction, &id, emcu_check_id_exists_cb, &unused, NULL, NULL))
				break;
		}
	}

	e_mapi_connection_close_folder (conn, &obj_folder, NULL, NULL);

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
populate_freebusy_data (struct Binary_r *bin,
			uint32_t month,
			uint32_t year,
			GSList **freebusy,
			const gchar *accept_type,
			ECalComponent *comp)
{
	uint16_t	event_start;
	uint16_t	event_end;
	uint32_t	i;
	uint32_t	day;
	const gchar	*month_name;
	uint32_t	minutes;
	uint32_t	real_month;
	gchar *date_string = NULL;
	gchar *start = NULL, *end = NULL;
	time_t start_date, end_date;
	ICalComponent *icomp = NULL;

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

		if (event_start <= event_end) {
			ICalPeriod *period;
			ICalProperty *prop;
			ICalTime *itt;

			day = 1;
			minutes = 0;
			real_month = month - (year * 16);

			date_string = g_strdup_printf ("%.2u-%.2u-%.2u", year, real_month, day);
			start = g_strdup_printf ("%sT%.2u:%.2u:00Z", date_string, 0, minutes);
			g_free (date_string);

			date_string = g_strdup_printf ("%.2u-%.2u-%.2u", year, real_month, day);
			end = g_strdup_printf ("%sT%.2u:%.2u:00Z", date_string, 0, minutes);
			g_free (date_string);

			start_date = mapi_get_date_from_string (start) + (60 * event_start);
			end_date = mapi_get_date_from_string (end) + (60 * event_end);

			period = i_cal_period_new_null_period ();

			itt = i_cal_time_new_from_timet_with_zone (start_date, 0, i_cal_timezone_get_utc_timezone ());
			i_cal_period_set_start (period, itt);
			g_clear_object (&itt);

			itt = i_cal_time_new_from_timet_with_zone (end_date, 0, i_cal_timezone_get_utc_timezone ());
			i_cal_period_set_end (period, itt);
			g_clear_object (&itt);

			icomp = e_cal_component_get_icalcomponent (comp);
			prop = i_cal_property_new_freebusy (period);

			if (!strcmp (accept_type, "Busy"))
				i_cal_property_set_parameter_from_string (prop, "FBTYPE", "BUSY");
			else if (!strcmp (accept_type, "Tentative"))
				i_cal_property_set_parameter_from_string (prop, "FBTYPE", "BUSY-TENTATIVE");
			else if (!strcmp (accept_type, "OutOfOffice"))
				i_cal_property_set_parameter_from_string (prop, "FBTYPE", "BUSY-UNAVAILABLE");

			i_cal_component_take_property (icomp, prop);

			g_clear_object (&period);
			g_free (start);
			g_free (end);
		}
	}
}

gboolean
e_mapi_cal_utils_get_free_busy_data (EMapiConnection *conn,
				     const GSList *users,
				     time_t start,
				     time_t end,
				     GSList **freebusy,
				     GCancellable *cancellable,
				     GError **mapi_error)
{
	struct SRow		aRow;
	enum MAPISTATUS		ms;
	uint32_t		i;
	mapi_object_t           obj_folder;
	const GSList *link;

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
	ECalComponentAttendee *attendee;
	GSList *attendees;
	ICalComponent *icomp = NULL;
	ICalTime *starttt, *endtt;

	*freebusy = NULL;

	mapi_object_init (&obj_folder);

	if (!e_mapi_connection_get_public_folder (conn, &obj_folder, cancellable, mapi_error)) {
		mapi_object_release (&obj_folder);
		return FALSE;
	}

	for (link = users; link; link = g_slist_next (link)) {
		ms = GetUserFreeBusyData (&obj_folder, (const gchar *) link->data, &aRow);

		if (ms != MAPI_E_SUCCESS) {
			gchar *context = g_strconcat ("GetUserFreeBusyData for ", link->data, NULL);

			make_mapi_error (mapi_error, context, ms);

			g_free (context);

			mapi_object_release (&obj_folder);

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
		icomp = e_cal_component_get_icalcomponent (comp);

		starttt = i_cal_time_new_from_timet_with_zone (start, 0, NULL);
		endtt = i_cal_time_new_from_timet_with_zone (end, 0, NULL);
		i_cal_component_set_dtstart (icomp, starttt);
		i_cal_component_set_dtend (icomp, endtt);
		g_clear_object (&starttt);
		g_clear_object (&endtt);

		attendee = e_cal_component_attendee_new ();
		if (link->data) {
			if (g_ascii_strncasecmp (link->data, "mailto:", 7) != 0) {
				gchar *mailto;

				mailto = g_strconcat ("mailto:", link->data, NULL);
				e_cal_component_attendee_set_value (attendee, mailto);
				g_free (mailto);
			} else {
				e_cal_component_attendee_set_value (attendee, link->data);
			}
		}

		e_cal_component_attendee_set_cutype (attendee, I_CAL_CUTYPE_INDIVIDUAL);
		e_cal_component_attendee_set_role (attendee, I_CAL_ROLE_REQPARTICIPANT);
		e_cal_component_attendee_set_partstat (attendee, I_CAL_PARTSTAT_NEEDSACTION);

		attendees = g_slist_append (NULL, attendee);

		e_cal_component_set_attendees (comp, attendees);
		g_slist_free_full (attendees, e_cal_component_attendee_free);

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
		*freebusy = g_slist_append (*freebusy, e_cal_component_get_as_string (comp));
		g_object_unref (comp);
		talloc_free (aRow.lpProps);
	}

	mapi_object_release (&obj_folder);

	return TRUE;
}

static void
populate_ical_attendees (EMapiConnection *conn,
			 EMapiRecipient *recipients,
			 ICalComponent *icomp,
			 gboolean rsvp)
{
	const uint32_t name_proptags[] = {
		PROP_TAG (PT_UNICODE, 0x6001), /* PidTagNickname for Recipients table */
		PidTagNickname,
		PidTagRecipientDisplayName,
		PidTagDisplayName,
		PidTagAddressBookDisplayNamePrintable
	};

	const uint32_t email_proptags[] = {
		PidTagSmtpAddress
	};

	EMapiRecipient *recipient;

	g_return_if_fail (conn != NULL);
	g_return_if_fail (icomp != NULL);

	for (recipient = recipients; recipient; recipient = recipient->next) {
		gchar *name = NULL, *email = NULL, *icalemail;
		ICalProperty *prop;
		ICalParameter *param;
		const uint32_t *ui32;
		const uint32_t *flags;

		e_mapi_mail_utils_decode_email_address (conn, &recipient->properties,
					name_proptags, G_N_ELEMENTS (name_proptags),
					email_proptags, G_N_ELEMENTS (email_proptags),
					PidTagAddressType, PidTagEmailAddress,
					&name, &email);

		if (!email) {
			g_free (name);
			g_debug ("%s: Skipping event recipient without email", G_STRFUNC);
			continue;
		}

		icalemail = g_strconcat ("mailto:", email, NULL);

		flags = e_mapi_util_find_array_propval (&recipient->properties, PidTagRecipientFlags);

		if (flags && (*flags & RECIP_ORGANIZER)) {
			prop = i_cal_property_new_organizer (icalemail);

			/* CN */
			if (name && *name) {
				param = i_cal_parameter_new_cn (name);
				i_cal_property_take_parameter (prop, param);
			}
		} else {
			prop = i_cal_property_new_attendee (icalemail);

			/* CN */
			if (name && *name) {
				param = i_cal_parameter_new_cn (name);
				i_cal_property_take_parameter (prop, param);
			}

			/* RSVP */
			param = i_cal_parameter_new_rsvp (rsvp ? I_CAL_RSVP_TRUE : I_CAL_RSVP_FALSE);
			i_cal_property_take_parameter (prop, param);

			/* PARTSTAT */
			ui32 = e_mapi_util_find_array_propval (&recipient->properties, PidTagRecipientTrackStatus);
			param = i_cal_parameter_new_partstat (get_partstat_from_trackstatus (ui32 ? *ui32 : olResponseNone));
			i_cal_property_take_parameter (prop, param);

			/* ROLE */
			ui32 = e_mapi_util_find_array_propval (&recipient->properties, PidTagRecipientType);
			param = i_cal_parameter_new_role (get_role_from_type (ui32 ? *ui32 : olTo));
			i_cal_property_take_parameter (prop, param);

			/* CALENDAR USER TYPE */
			param = NULL;
			if (ui32 && *ui32 == 0x03)
				param = i_cal_parameter_new_cutype (I_CAL_CUTYPE_RESOURCE);
			if (!param)
				param = i_cal_parameter_new_cutype (I_CAL_CUTYPE_INDIVIDUAL);

			i_cal_property_take_parameter (prop, param);
		}

		i_cal_component_take_property (icomp, prop);

		g_free (icalemail);
		g_free (email);
		g_free (name);
	}
}

static void
set_attachments_to_comp (EMapiConnection *conn,
			 EMapiAttachment *attachments,
			 ECalComponent *comp)
{
	EMapiAttachment *attach;
	ICalComponent *icomp;

	g_return_if_fail (comp != NULL);

	if (!attachments)
		return;

	icomp = e_cal_component_get_icalcomponent (comp);
	g_return_if_fail (icomp != NULL);

	for (attach = attachments; attach; attach = attach->next) {
		uint64_t data_cb = 0;
		const uint8_t *data_lpb = NULL;
		const gchar *filename;
		ICalAttach *new_attach;
		ICalParameter *param;
		gchar *base64;
		ICalProperty *prop;

		if (!e_mapi_attachment_get_bin_prop (attach, PidTagAttachDataBinary, &data_cb, &data_lpb)) {
			g_debug ("%s: Skipping calendar attachment without data", G_STRFUNC);
			continue;
		}

		filename = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachLongFilename);
		if (!filename || !*filename)
			filename = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachFilename);

		base64 = g_base64_encode ((const guchar *) data_lpb, data_cb);
		new_attach = i_cal_attach_new_from_data (base64, (GFunc) g_free, NULL);

		prop = i_cal_property_new_attach (new_attach);
		g_object_unref (new_attach);

		param = i_cal_parameter_new_value (I_CAL_VALUE_BINARY);
		i_cal_property_take_parameter (prop, param);

		param = i_cal_parameter_new_encoding (I_CAL_ENCODING_BASE64);
		i_cal_property_take_parameter (prop, param);

		if (filename && *filename) {
			param = i_cal_parameter_new_filename (filename);
			i_cal_property_take_parameter (prop, param);
		}

		i_cal_component_take_property (icomp, prop);
	}
}

ECalComponent *
e_mapi_cal_util_object_to_comp (EMapiConnection *conn,
				EMapiObject *object,
				ICalComponentKind kind,
				gboolean is_reply,
				const gchar *use_uid,
				GSList **detached_components)
{
	ECalComponent *comp = NULL;
	struct timeval t;
	const gchar *str;
	const struct mapi_SLPSTRArrayW *categories_array;
	const struct SBinary_short *bin;
	const uint32_t *ui32;
	const uint8_t *b;
	ICalComponent *icomp;
	ICalProperty *prop = NULL;
	ICalParameter *param = NULL;
	ICalTimezone *utc_zone;
	ICalTime *itt;

	g_return_val_if_fail (conn != NULL, NULL);
	g_return_val_if_fail (object != NULL, NULL);
	g_return_val_if_fail (use_uid != NULL, NULL);

	if (e_mapi_debug_is_enabled ()) {
		printf ("%s:\n", G_STRFUNC);
		e_mapi_debug_dump_object (object, TRUE, 3);
	}

	switch (kind) {
		case I_CAL_VEVENT_COMPONENT:
		case I_CAL_VTODO_COMPONENT:
		case I_CAL_VJOURNAL_COMPONENT:
			icomp = i_cal_component_new (kind);
			comp = e_cal_component_new_from_icalcomponent (icomp);
			if (!comp) {
				return NULL;
			}
			e_cal_component_set_uid (comp, use_uid);
			break;
		default:
			return NULL;
	}

	utc_zone = i_cal_timezone_get_utc_timezone ();

	str = e_mapi_util_find_array_propval (&object->properties, PidTagSubject);
	str = str ? str : e_mapi_util_find_array_propval (&object->properties, PidTagNormalizedSubject);
	str = str ? str : e_mapi_util_find_array_propval (&object->properties, PidTagConversationTopic);
	str = str ? str : "";
	i_cal_component_set_summary (icomp, str);

	ui32 = e_mapi_util_find_array_propval (&object->properties, PidTagInternetCodepage);
	if (e_mapi_object_contains_prop (object, PidTagBody)) {
		uint64_t text_cb = 0;
		const uint8_t *text_lpb = NULL;
		gchar *utf8_str = NULL;
		uint32_t proptag;

		proptag = e_mapi_util_find_array_proptag (&object->properties, PidTagBody);
		if (!proptag) {
			EMapiStreamedProp *stream = e_mapi_object_get_streamed (object, PidTagBody);
			if (stream)
				proptag = stream->proptag;
			else
				proptag = PidTagBody;
		}

		if (e_mapi_object_get_bin_prop (object, proptag, &text_cb, &text_lpb)) {
			if (e_mapi_utils_ensure_utf8_string (proptag, ui32, text_lpb, text_cb, &utf8_str))
				str = utf8_str;
			else if (text_lpb [text_cb] != 0) {
				utf8_str = g_strndup ((const gchar *) text_lpb, text_cb);
				str = utf8_str;
			}
		} else {
			str = "";
		}

		i_cal_component_set_description (icomp, str);

		g_free (utf8_str);
	} else {
		uint64_t html_cb = 0;
		const uint8_t *html_lpb = NULL;

		if (e_mapi_object_get_bin_prop (object, PidTagHtml, &html_cb, &html_lpb)) {
			gchar *utf8_str = NULL;

			if (e_mapi_utils_ensure_utf8_string (PidTagHtml, ui32, html_lpb, html_cb, &utf8_str))
				i_cal_component_set_description (icomp, utf8_str);

			g_free (utf8_str);
		}
	}

	/* set dtstamp - in UTC */
	if (e_mapi_util_find_array_datetime_propval (&t, &object->properties, PidTagCreationTime) == MAPI_E_SUCCESS) {
		itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, 0, utc_zone);
		i_cal_component_set_dtstamp (icomp, itt);

		prop = i_cal_property_new_created (itt);
		i_cal_component_take_property (icomp, prop);

		g_clear_object (&itt);
	} else {
		/* created - in UTC */
		itt = i_cal_time_new_current_with_zone (utc_zone);
		prop = i_cal_property_new_created (itt);
		i_cal_component_take_property (icomp, prop);
		g_clear_object (&itt);
	}

	/* last modified - in UTC */
	if (get_mapi_SPropValue_array_date_timeval (&t, &object->properties, PidTagLastModificationTime) == MAPI_E_SUCCESS) {
		itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, 0, utc_zone);
		prop = i_cal_property_new_lastmodified (itt);
		i_cal_component_take_property (icomp, prop);
		g_clear_object (&itt);
	}

	categories_array = e_mapi_util_find_array_propval (&object->properties, PidNameKeywords);
	if (categories_array) {
		GSList *categories = NULL;
		gint ii;

		for (ii = 0; ii < categories_array->cValues; ii++) {
			const gchar *category = categories_array->strings[ii].lppszW;

			if (!category || !*category)
				continue;

			categories = g_slist_prepend (categories, (gpointer) category);
		}

		categories = g_slist_reverse (categories);

		e_cal_component_set_categories_list (comp, categories);

		g_slist_free (categories);
	}

	if (i_cal_component_isa (icomp) == I_CAL_VEVENT_COMPONENT) {
		const gchar *location = NULL;
		const gchar *dtstart_tz_location = NULL, *dtend_tz_location = NULL;
		gboolean all_day;

		/* GlobalObjectId */
		bin = e_mapi_util_find_array_propval (&object->properties, PidLidGlobalObjectId);
		if (bin) {
			gchar *value = globalid_to_string (bin->lpb, bin->cb);
			e_cal_util_component_set_x_property (icomp, "X-EVOLUTION-MAPI-GLOBALID", value);
			if (value && *value) {
				e_cal_component_set_uid (comp, value);

				if (!g_str_equal (value, use_uid))
					e_cal_util_component_set_x_property (icomp, "X-EVOLUTION-MAPI-MID", use_uid);
			}

			g_free (value);
		}

		ui32 = e_mapi_util_find_array_propval (&object->properties, PidTagOwnerAppointmentId);
		if (ui32) {
			gchar *value = e_mapi_util_mapi_id_to_string ((mapi_id_t) (*ui32));

			e_cal_util_component_set_x_property (icomp, "X-EVOLUTION-MAPI-OWNER-APPT-ID", value);

			g_free (value);
		}

		/* AppointmentSequence */
		ui32 = e_mapi_util_find_array_propval (&object->properties, PidLidAppointmentSequence);
		if (ui32) {
			gchar *value = g_strdup_printf ("%d", *ui32);

			e_cal_util_component_set_x_property (icomp, "X-EVOLUTION-MAPI-APPTSEQ", value);

			g_free (value);
		}

		location = e_mapi_util_find_array_propval (&object->properties, PidLidLocation);
		if (location && *location)
			i_cal_component_set_location (icomp, location);

		b = e_mapi_util_find_array_propval (&object->properties, PidLidAppointmentSubType);
		all_day = b && *b;

		bin = e_mapi_util_find_array_propval (&object->properties, PidLidAppointmentTimeZoneDefinitionStartDisplay);
		if (bin) {
			gchar *buf = e_mapi_cal_util_bin_to_mapi_tz (bin->lpb, bin->cb);
			dtstart_tz_location = e_mapi_cal_tz_util_get_ical_equivalent (buf);
			g_free (buf);
		}

		if (!dtstart_tz_location) {
			bin = e_mapi_util_find_array_propval (&object->properties, PidLidTimeZoneStruct);
			if (bin)
				dtstart_tz_location = e_mapi_cal_tz_util_ical_from_zone_struct (bin->lpb, bin->cb);
		}

		if (e_mapi_util_find_array_datetime_propval (&t, &object->properties, PidLidAppointmentStartWhole) == MAPI_E_SUCCESS) {
			ICalTimezone *zone = dtstart_tz_location ? i_cal_timezone_get_builtin_timezone (dtstart_tz_location) : utc_zone;

			itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, all_day, zone);
			i_cal_time_set_timezone (itt, zone);
			prop = i_cal_property_new_dtstart (itt);
			if (!all_day && zone && i_cal_timezone_get_tzid (zone)) {
				i_cal_property_take_parameter (prop, i_cal_parameter_new_tzid (i_cal_timezone_get_tzid (zone)));
			}

			i_cal_component_take_property (icomp, prop);

			g_clear_object (&itt);
		}

		bin = e_mapi_util_find_array_propval (&object->properties, PidLidAppointmentTimeZoneDefinitionEndDisplay);
		if (bin) {
			gchar *buf = e_mapi_cal_util_bin_to_mapi_tz (bin->lpb, bin->cb);
			dtend_tz_location = e_mapi_cal_tz_util_get_ical_equivalent (buf);
			g_free (buf);
		}

		if (!dtend_tz_location) {
			bin = e_mapi_util_find_array_propval (&object->properties, PidLidTimeZoneStruct);
			if (bin)
				dtend_tz_location = e_mapi_cal_tz_util_ical_from_zone_struct (bin->lpb, bin->cb);
		}

		if (e_mapi_util_find_array_datetime_propval (&t, &object->properties, PidLidAppointmentEndWhole) == MAPI_E_SUCCESS) {
			ICalTimezone *zone;

			if (!dtend_tz_location)
				dtend_tz_location = dtstart_tz_location;

			zone = dtend_tz_location ? i_cal_timezone_get_builtin_timezone (dtend_tz_location) : utc_zone;
			itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, all_day, zone);
			i_cal_time_set_timezone (itt, zone);
			prop = i_cal_property_new_dtend (itt);
			if (!all_day && zone && i_cal_timezone_get_tzid (zone)) {
				i_cal_property_take_parameter (prop, i_cal_parameter_new_tzid (i_cal_timezone_get_tzid (zone)));
			}

			i_cal_component_take_property (icomp, prop);
		}

		ui32 = e_mapi_util_find_array_propval (&object->properties, PidLidBusyStatus);
		if (ui32) {
			prop = i_cal_property_new_transp (get_transp_from_prop (*ui32));
			i_cal_component_take_property (icomp, prop);
		}

		if (object->recipients) {
			gchar *name = NULL, *email = NULL;
			gchar *val;

			b = e_mapi_util_find_array_propval (&object->properties, PidTagResponseRequested);
			populate_ical_attendees (conn, object->recipients, icomp, (b && *b));
			if (is_reply) {
				if (!e_cal_util_component_has_property (icomp, I_CAL_ORGANIZER_PROPERTY)) {
					name = NULL;
					email = NULL;

					e_mapi_mail_utils_decode_email_address1	(conn, &object->properties,
						PidTagReceivedRepresentingName,
						PidTagReceivedRepresentingEmailAddress,
						PidTagReceivedRepresentingAddressType,
						&name, &email);

					if (email) {
						val = g_strdup_printf ("mailto:%s", email);
						prop = i_cal_property_new_organizer (val);
						g_free (val);

						if (name && g_strcmp0 (name, email) != 0) {
							/* CN */
							param = i_cal_parameter_new_cn (name);
							i_cal_property_take_parameter (prop, param);
						}

						i_cal_component_take_property (icomp, prop);
					}

					g_free (name);
					g_free (email);
				}

				if (!e_cal_util_component_has_property (icomp, I_CAL_ATTENDEE_PROPERTY)) {
					name = NULL;
					email = NULL;

					e_mapi_mail_utils_decode_email_address1	(conn, &object->properties,
						PidTagSentRepresentingName,
						PidTagSentRepresentingEmailAddress,
						PidTagSentRepresentingAddressType,
						&name, &email);

					if (email) {
						val = g_strdup_printf ("mailto:%s", email);
						prop = i_cal_property_new_attendee (val);
						g_free (val);

						if (name && g_strcmp0 (name, email) != 0) {
							/* CN */
							param = i_cal_parameter_new_cn (name);
							i_cal_property_take_parameter (prop, param);
						}

						ui32 = e_mapi_util_find_array_propval (&object->properties, PidLidResponseStatus);
						param = i_cal_parameter_new_partstat (get_partstat_from_trackstatus (ui32 ? *ui32 : olResponseNone));
						i_cal_property_take_parameter (prop, param);

						i_cal_component_take_property (icomp, prop);
					}

					g_free (name);
					g_free (email);
				}
			} else if (!e_cal_util_component_has_property (icomp, I_CAL_ORGANIZER_PROPERTY)) {
				gchar *sent_name = NULL, *sent_email = NULL;

				name = NULL;
				email = NULL;

				e_mapi_mail_utils_decode_email_address1	(conn, &object->properties,
					PidTagSenderName,
					PidTagSenderEmailAddress,
					PidTagSenderAddressType,
					&name, &email);

				e_mapi_mail_utils_decode_email_address1	(conn, &object->properties,
					PidTagSentRepresentingName,
					PidTagSentRepresentingEmailAddress,
					PidTagSentRepresentingAddressType,
					&sent_name, &sent_email);

				if (sent_email) {
					val = g_strdup_printf ("mailto:%s", sent_email);
					prop = i_cal_property_new_organizer (val);
					g_free (val);

					if (sent_name && g_strcmp0 (sent_name, sent_email) != 0) {
						/* CN */
						param = i_cal_parameter_new_cn (sent_name);
						i_cal_property_take_parameter (prop, param);
					}

					/* SENTBY */
					if (email && g_utf8_collate (sent_email, email)) {
						val = g_strdup_printf ("mailto:%s", email);
						param = i_cal_parameter_new_sentby (val);
						i_cal_property_take_parameter (prop, param);
						g_free (val);
					}

					i_cal_component_take_property (icomp, prop);
				}


				g_free (name);
				g_free (email);
				g_free (sent_name);
				g_free (sent_email);
			}
		}

		b = e_mapi_util_find_array_propval (&object->properties, PidLidRecurring);
		if (b && *b) {
			bin = e_mapi_util_find_array_propval (&object->properties, PidLidAppointmentRecur);
			if (bin) {
				ICalTimezone *recur_zone;
				const gchar *recur_tz_location;

				recur_tz_location = e_mapi_util_find_array_propval (&object->properties, PidLidTimeZoneDescription);
				if (recur_tz_location)
					recur_tz_location = e_mapi_cal_tz_util_get_ical_equivalent (recur_tz_location);
				recur_zone = recur_tz_location ? i_cal_timezone_get_builtin_timezone (recur_tz_location) : utc_zone;

				e_mapi_cal_util_bin_to_rrule (bin->lpb, bin->cb, comp, detached_components, recur_zone);
			}
		}

		b = e_mapi_util_find_array_propval (&object->properties, PidLidReminderSet);
		if (b && *b) {
			struct timeval start, displaytime;

			if ((e_mapi_util_find_array_datetime_propval (&start, &object->properties, PidLidReminderTime) == MAPI_E_SUCCESS)
			 && (e_mapi_util_find_array_datetime_propval (&displaytime, &object->properties, PidLidReminderSignalTime) == MAPI_E_SUCCESS)) {
				ECalComponentAlarm *e_alarm = e_cal_component_alarm_new ();
				ECalComponentAlarmTrigger *trigger;
				ICalDuration *duration;
				ICalTime *itt1, *itt2;

				itt1 = i_cal_time_new_from_timet_with_zone (displaytime.tv_sec, 0, NULL);
				itt2 = i_cal_time_new_from_timet_with_zone (start.tv_sec, 0, NULL);
				duration = i_cal_time_subtract (itt1, itt2);
				g_clear_object (&itt1);
				g_clear_object (&itt2);

				trigger = e_cal_component_alarm_trigger_new_relative (E_CAL_COMPONENT_ALARM_TRIGGER_RELATIVE_START, duration);

				e_cal_component_alarm_set_action (e_alarm, E_CAL_COMPONENT_ALARM_DISPLAY);
				e_cal_component_alarm_take_trigger (e_alarm, trigger);

				e_cal_component_add_alarm (comp, e_alarm);
				e_cal_component_alarm_free (e_alarm);
				g_clear_object (&duration);
			}
		} else
			e_cal_component_remove_all_alarms (comp);

	} else if (i_cal_component_isa (icomp) == I_CAL_VTODO_COMPONENT) {
		const double *complete = NULL;
		const uint64_t *status = NULL;

		/* NOTE: Exchange tasks are DATE values, not DATE-TIME values, but maybe someday, we could expect Exchange to support it;) */
		if (e_mapi_util_find_array_datetime_propval (&t, &object->properties, PidLidTaskStartDate) == MAPI_E_SUCCESS) {
			itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, 1, utc_zone);
			i_cal_component_set_dtstart (icomp, itt);
			g_clear_object (&itt);
		}

		if (e_mapi_util_find_array_datetime_propval (&t, &object->properties, PidLidTaskDueDate) == MAPI_E_SUCCESS) {
			itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, 1, utc_zone);
			i_cal_component_set_due (icomp, itt);
			g_clear_object (&itt);
		}

		status = e_mapi_util_find_array_propval (&object->properties, PidLidTaskStatus);
		if (status) {
			i_cal_component_set_status (icomp, get_taskstatus_from_prop (*status));
			if (*status == olTaskComplete
			    && e_mapi_util_find_array_datetime_propval (&t, &object->properties, PidLidTaskDateCompleted) == MAPI_E_SUCCESS) {
				itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, 0, utc_zone);
				prop = i_cal_property_new_completed (itt);
				i_cal_component_take_property (icomp, prop);
				g_clear_object (&itt);
			}
		}

		complete = e_mapi_util_find_array_propval (&object->properties, PidLidPercentComplete);
		if (complete) {
			prop = i_cal_property_new_percentcomplete ((gint) ((*complete) * 100 + 1e-9));
			i_cal_component_take_property (icomp, prop);
		}

		b = e_mapi_util_find_array_propval (&object->properties, PidLidTaskFRecurring);
		if (b && *b) {
			g_debug ("%s: Evolution does not support recurring tasks.", G_STRFUNC);
		}

		b = e_mapi_util_find_array_propval (&object->properties, PidLidReminderSet);
		if (b && *b) {
			struct timeval abs;

			if (e_mapi_util_find_array_datetime_propval (&abs, &object->properties, PidLidReminderTime) == MAPI_E_SUCCESS) {
				ECalComponentAlarm *e_alarm = e_cal_component_alarm_new ();
				ECalComponentAlarmTrigger *trigger;
				ICalTime *abs_time;

				abs_time = i_cal_time_new_from_timet_with_zone (abs.tv_sec, 0, utc_zone);
				trigger = e_cal_component_alarm_trigger_new_absolute (abs_time);
				g_clear_object (&abs_time);

				e_cal_component_alarm_set_action (e_alarm, E_CAL_COMPONENT_ALARM_DISPLAY);
				e_cal_component_alarm_take_trigger (e_alarm, trigger);

				e_cal_component_add_alarm (comp, e_alarm);
				e_cal_component_alarm_free (e_alarm);
			}
		} else
			e_cal_component_remove_all_alarms (comp);

	} else if (i_cal_component_isa (icomp) == I_CAL_VJOURNAL_COMPONENT) {
		if (e_mapi_util_find_array_datetime_propval (&t, &object->properties, PidTagLastModificationTime) == MAPI_E_SUCCESS) {
			itt = i_cal_time_new_from_timet_with_zone (t.tv_sec, 1, utc_zone);
			i_cal_component_set_dtstart (icomp, itt);
			g_clear_object (&itt);
		}
	}

	if (i_cal_component_isa (icomp) == I_CAL_VEVENT_COMPONENT ||
	    i_cal_component_isa (icomp) == I_CAL_VTODO_COMPONENT) {
		/* priority */
		ui32 = e_mapi_util_find_array_propval (&object->properties, PidTagPriority);
		if (ui32) {
			prop = i_cal_property_new_priority (get_priority_from_prop (*ui32));
			i_cal_component_take_property (icomp, prop);
		}
	}

	/* classification */
	ui32 = e_mapi_util_find_array_propval (&object->properties, PidTagSensitivity);
	if (ui32) {
		prop = i_cal_property_new_class (get_class_from_prop (*ui32));
		i_cal_component_take_property (icomp, prop);
	}

	set_attachments_to_comp (conn, object->attachments, comp);

	return comp;
}

static void
e_mapi_cal_utils_add_organizer (EMapiObject *object,
				ECalComponent *comp)
{
	ICalComponent *icomp;
	ICalProperty *org_prop = NULL;
	const gchar *org = NULL;

	g_return_if_fail (object != NULL);
	g_return_if_fail (comp != NULL);

	icomp = e_cal_component_get_icalcomponent (comp);
	org_prop = i_cal_component_get_first_property (icomp, I_CAL_ORGANIZER_PROPERTY);
	org = i_cal_property_get_organizer (org_prop);
	if (org && *org) {
		EMapiRecipient *recipient;
		uint32_t ui32 = 0;
		const gchar *str = NULL, *email;
		ICalParameter *param;

		recipient = e_mapi_recipient_new (object);
		e_mapi_object_add_recipient (object, recipient);

		#define set_value(pt,vl) {								\
			if (!e_mapi_utils_add_property (&recipient->properties, pt, vl, recipient)) {	\
				g_warning ("%s: Failed to set property 0x%x", G_STRFUNC, pt);		\
													\
				return;									\
			}										\
		}

		if (g_ascii_strncasecmp (org, "mailto:", 7) == 0)
			email = org + 7;
		else
			email = org;

		set_value (PidTagAddressType, "SMTP");
		set_value (PidTagEmailAddress, email);

		set_value (PidTagSmtpAddress, email);

		ui32 = 0;
		set_value (PidTagSendInternetEncoding, &ui32);

		ui32 = RECIP_SENDABLE | RECIP_ORGANIZER;
		set_value (PidTagRecipientFlags, &ui32);

		ui32 = olResponseNone;
		set_value (PidTagRecipientTrackStatus, &ui32);

		ui32 = olTo;
		set_value (PidTagRecipientType, &ui32);

		param = i_cal_property_get_first_parameter (org_prop, I_CAL_CN_PARAMETER);
		str = param ? i_cal_parameter_get_cn (param) : NULL;
		str = (str && *str) ? str : email;
		set_value (PidTagRecipientDisplayName, str);
		set_value (PidTagDisplayName, str);
		g_clear_object (&param);

		ui32 = DT_MAILUSER;
		set_value (PidTagDisplayType, &ui32);

		ui32 = MAPI_MAILUSER;
		set_value (PidTagObjectType, &ui32);

		#undef set_value
	}

	g_clear_object (&org_prop);
}

static void
e_mapi_cal_utils_add_recipients (EMapiObject *object,
				 ECalComponent *comp)
{
	ICalComponent *icomp;
	ICalProperty *org_prop = NULL, *att_prop = NULL;
	const gchar *org = NULL;

	g_return_if_fail (object != NULL);
	g_return_if_fail (comp != NULL);

	if (!e_cal_component_has_attendees (comp))
		return;

	icomp = e_cal_component_get_icalcomponent (comp);
	org_prop = i_cal_component_get_first_property (icomp, I_CAL_ORGANIZER_PROPERTY);
	org = org_prop ? i_cal_property_get_organizer (org_prop) : NULL;
	if (!org)
		org = "";

	for (att_prop = i_cal_component_get_first_property (icomp, I_CAL_ATTENDEE_PROPERTY);
	     att_prop;
	     g_object_unref (att_prop), att_prop = i_cal_component_get_next_property (icomp, I_CAL_ATTENDEE_PROPERTY)) {
		EMapiRecipient *recipient;
		uint32_t ui32 = 0;
		const gchar *str = NULL, *email;
		ICalParameter *param;

		str = i_cal_property_get_attendee (att_prop);
		if (!str || g_ascii_strcasecmp (str, org) == 0)
			continue;

		recipient = e_mapi_recipient_new (object);
		e_mapi_object_add_recipient (object, recipient);

		#define set_value(pt,vl) {								\
			if (!e_mapi_utils_add_property (&recipient->properties, pt, vl, recipient)) {	\
				g_warning ("%s: Failed to set property 0x%x", G_STRFUNC, pt);		\
													\
				return;									\
			}										\
		}

		if (g_ascii_strncasecmp (str, "mailto:", 7) == 0)
			email = str + 7;
		else
			email = str;

		set_value (PidTagAddressType, "SMTP");
		set_value (PidTagEmailAddress, email);
		set_value (PidTagSmtpAddress, email);

		ui32 = 0;
		set_value (PidTagSendInternetEncoding, &ui32);

		ui32 = RECIP_SENDABLE | (g_ascii_strcasecmp (str, org) == 0 ? RECIP_ORGANIZER : 0);
		set_value (PidTagRecipientFlags, &ui32);

		param = i_cal_property_get_first_parameter (att_prop, I_CAL_PARTSTAT_PARAMETER);
		ui32 = get_trackstatus_from_partstat (param ? i_cal_parameter_get_partstat (param) : I_CAL_PARTSTAT_ACCEPTED);
		set_value (PidTagRecipientTrackStatus, &ui32);
		g_clear_object (&param);

		param = i_cal_property_get_first_parameter (att_prop, I_CAL_ROLE_PARAMETER);
		ui32 = get_type_from_role (param ? i_cal_parameter_get_role (param) : I_CAL_ROLE_NONE);
		set_value (PidTagRecipientType, &ui32);
		g_clear_object (&param);

		param = i_cal_property_get_first_parameter (att_prop, I_CAL_CN_PARAMETER);
		str = param ? i_cal_parameter_get_cn (param) : NULL;
		str = (str && *str) ? str : email;
		set_value (PidTagRecipientDisplayName, str);
		set_value (PidTagDisplayName, str);
		g_clear_object (&param);

		ui32 = DT_MAILUSER;
		set_value (PidTagDisplayType, &ui32);

		ui32 = MAPI_MAILUSER;
		set_value (PidTagObjectType, &ui32);

		#undef set_value
	}

	g_clear_object (&org_prop);
}

static void
e_mapi_cal_utils_add_attachments (EMapiObject *object,
				  ECalComponent *comp)
{
	ICalComponent *icomp;
	ICalProperty *prop;
	const gchar *uid;
	gchar *safeuid;

	g_return_if_fail (object != NULL);
	g_return_if_fail (comp != NULL);

	if (!e_cal_component_has_attachments (comp))
		return;

	uid = e_cal_component_get_uid (comp);
	icomp = e_cal_component_get_icalcomponent (comp);

	safeuid = g_strdup (uid);
	e_filename_make_safe (safeuid);
	g_return_if_fail (safeuid != NULL);

	for (prop = i_cal_component_get_first_property (icomp, I_CAL_ATTACH_PROPERTY);
	     prop;
	     g_object_unref (prop), prop = i_cal_component_get_next_property (icomp, I_CAL_ATTACH_PROPERTY)) {
		ICalAttach *attach = i_cal_property_get_attach (prop);
		ICalParameter *param;
		const gchar *sfname_uri, *stored_filename;
		gchar *sfname = NULL, *filename = NULL;
		GMappedFile *mapped_file;
		GError *error = NULL;

		if (!I_CAL_IS_ATTACH (attach))
			continue;

		#define set_value(pt,vl) {								\
			if (!e_mapi_utils_add_property (&attachment->properties, pt, vl, attachment)) {	\
				g_warning ("%s: Failed to set property 0x%x", G_STRFUNC, pt);		\
													\
				return;									\
			}										\
		}

		param = i_cal_property_get_first_parameter (prop, I_CAL_FILENAME_PARAMETER);
		stored_filename = param ? i_cal_parameter_get_filename (param) : NULL;
		if (stored_filename && !*stored_filename)
			stored_filename = NULL;

		if (i_cal_attach_get_is_url (attach)) {
			sfname_uri = i_cal_attach_get_url (attach);

			sfname = g_filename_from_uri (sfname_uri, NULL, NULL);
			mapped_file = g_mapped_file_new (sfname, FALSE, &error);
			filename = g_path_get_basename (sfname);

			if (mapped_file) {
				EMapiAttachment *attachment;
				guint8 *attach = (guint8 *) g_mapped_file_get_contents (mapped_file);
				guint filelength = g_mapped_file_get_length (mapped_file);
				const gchar *split_name;
				uint32_t ui32;
				uint64_t data_cb;
				uint8_t *data_lpb;

				if (g_str_has_prefix (filename, safeuid)) {
					split_name = (filename + strlen (safeuid) + strlen ("-"));
				} else {
					split_name = filename;
				}

				attachment = e_mapi_attachment_new (object);
				e_mapi_object_add_attachment (object, attachment);

				ui32 = ATTACH_BY_VALUE;
				set_value (PidTagAttachMethod, &ui32);

				/* MSDN Documentation: When the supplied offset is -1 (0xFFFFFFFF), the
				 * attachment is not rendered using the PR_RENDERING_POSITION property.
				 * All values other than -1 indicate the position within PR_BODY at which
				 * the attachment is to be rendered.
				 */
				ui32 = -1;
				set_value (PidTagRenderingPosition, &ui32);

				set_value (PidTagAttachFilename, stored_filename ? stored_filename : split_name);
				set_value (PidTagAttachLongFilename, stored_filename ? stored_filename : split_name);

				data_cb = filelength;
				data_lpb = talloc_memdup (attachment, attach, data_cb);
				e_mapi_attachment_add_streamed (attachment, PidTagAttachDataBinary, data_cb, data_lpb);

#if GLIB_CHECK_VERSION(2,21,3)
				g_mapped_file_unref (mapped_file);
#else
				g_mapped_file_free (mapped_file);
#endif
			} else if (error) {
				e_mapi_debug_print ("Could not map %s: %s \n", sfname_uri, error->message);
				g_error_free (error);
			}

			g_free (filename);
		} else {
			EMapiAttachment *attachment;
			gsize len = -1;
			guchar *decoded = NULL;
			const gchar *content;
			uint32_t ui32;
			uint64_t data_cb;
			uint8_t *data_lpb;

			content = (const gchar *) i_cal_attach_get_data (attach);
			decoded = g_base64_decode (content, &len);

			attachment = e_mapi_attachment_new (object);
			e_mapi_object_add_attachment (object, attachment);

			ui32 = ATTACH_BY_VALUE;
			set_value (PidTagAttachMethod, &ui32);

			/* MSDN Documentation: When the supplied offset is -1 (0xFFFFFFFF), the
			 * attachment is not rendered using the PR_RENDERING_POSITION property.
			 * All values other than -1 indicate the position within PR_BODY at which
			 * the attachment is to be rendered.
			 */
			ui32 = -1;
			set_value (PidTagRenderingPosition, &ui32);

			if (stored_filename) {
				set_value (PidTagAttachFilename, stored_filename);
				set_value (PidTagAttachLongFilename, stored_filename);
			}

			data_cb = len;
			data_lpb = talloc_memdup (attachment, decoded, data_cb);
			e_mapi_attachment_add_streamed (attachment, PidTagAttachDataBinary, data_cb, data_lpb);

			g_free (decoded);
		}

		#undef set_value

		g_clear_object (&param);
	}

	g_free (safeuid);
}

gboolean
e_mapi_cal_utils_comp_to_object (EMapiConnection *conn,
				 TALLOC_CTX *mem_ctx,
				 EMapiObject **pobject, /* out */
				 gpointer user_data,
				 GCancellable *cancellable,
				 GError **perror)
{
	struct cal_cbdata *cbdata = (struct cal_cbdata *) user_data;
	ECalComponent *comp;
	ICalComponent *icomp;
	ICalComponentKind kind;
	uint32_t flag32;
	uint8_t b;
	ICalProperty *prop;
	ICalTime *dtstart, *dtend, *utc_dtstart, *utc_dtend, *all_day_dtstart = NULL, *all_day_dtend = NULL;
	ICalTimezone *utc_zone;
	const gchar *dtstart_tz_location, *dtend_tz_location, *text = NULL;
	time_t tt;
	gboolean is_all_day;
	GSList *categories = NULL;
	EMapiObject *object;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (cbdata != NULL, FALSE);
	g_return_val_if_fail (pobject != NULL, FALSE);

	switch (cbdata->kind) {
		case I_CAL_VEVENT_COMPONENT:
		case I_CAL_VTODO_COMPONENT:
		case I_CAL_VJOURNAL_COMPONENT:
			break;
		default:
			return FALSE;
	}

	comp = cbdata->comp;
	icomp = e_cal_component_get_icalcomponent (comp);
	kind = i_cal_component_isa (icomp);
	g_return_val_if_fail (kind == cbdata->kind, FALSE);

	object = e_mapi_object_new (mem_ctx);
	*pobject = object;

	#define set_value(hex, val) G_STMT_START { \
		if (!e_mapi_utils_add_property (&object->properties, hex, val, object)) \
			return FALSE;	\
		} G_STMT_END

	#define set_timet_value(hex, dtval) G_STMT_START {		\
		struct FILETIME	filetime;				\
									\
		e_mapi_util_time_t_to_filetime (dtval, &filetime); 	\
		set_value (hex, &filetime); 				\
		} G_STMT_END

	utc_zone = i_cal_timezone_get_utc_timezone ();

	dtstart = i_cal_component_get_dtstart (icomp);

	/* For VEVENTs */
	if (e_cal_util_component_has_property (icomp, I_CAL_DTEND_PROPERTY))
		dtend = i_cal_component_get_dtend (icomp);
	/* For VTODOs */
	else if (e_cal_util_component_has_property (icomp, I_CAL_DUE_PROPERTY) != 0)
		dtend = i_cal_component_get_due (icomp);
	else
		dtend = i_cal_component_get_dtstart (icomp);

	dtstart_tz_location = get_tzid_location (i_cal_time_get_tzid (dtstart), cbdata);
	dtend_tz_location = get_tzid_location (i_cal_time_get_tzid (dtend), cbdata);

	is_all_day = kind == I_CAL_VEVENT_COMPONENT && i_cal_time_is_date (dtstart) && i_cal_time_is_date (dtend);
	if (is_all_day) {
		const gchar *def_location;
		ICalTimezone *use_zone = NULL;

		/* all-day events expect times not in UTC but in local time;
		   if this differs from the server timezone, then the event
		   is shown spread among (two) days */
		def_location = get_tzid_location ("*default-zone*", cbdata);
		if (def_location && *def_location)
			use_zone = i_cal_timezone_get_builtin_timezone (def_location);

		if (!use_zone)
			use_zone = utc_zone;

		i_cal_time_set_is_date (dtstart, FALSE);
		i_cal_time_set_time (dtstart, 0, 0, 0);
		all_day_dtstart = i_cal_time_convert_to_zone (dtstart, use_zone);
		i_cal_time_set_is_date (dtstart, TRUE);
		all_day_dtstart = i_cal_time_convert_to_zone (all_day_dtstart, utc_zone);

		i_cal_time_set_is_date (dtend, FALSE);
		i_cal_time_set_time (dtend, 0, 0, 0);
		all_day_dtend = i_cal_time_convert_to_zone (dtend, use_zone);
		i_cal_time_set_is_date (dtend, TRUE);
		all_day_dtend = i_cal_time_convert_to_zone (all_day_dtend, utc_zone);
	}

	utc_dtstart = i_cal_time_convert_to_zone (dtstart, utc_zone);
	utc_dtend = i_cal_time_convert_to_zone (dtend, utc_zone);

	text = i_cal_component_get_summary (icomp);
	if (!(text && *text))
		text = "";
	set_value (PidTagSubject, text);
	set_value (PidTagNormalizedSubject, text);
	if (cbdata->appt_seq == 0)
		set_value (PidTagConversationTopic, text);
	text = NULL;

	/* we don't support HTML event/task/memo editor */
	flag32 = olEditorText;
	set_value (PidTagMessageEditorFormat, &flag32);

	/* it'd be better to convert, then set it in unicode */
	text = i_cal_component_get_description (icomp);
	if (!(text && *text) || !g_utf8_validate (text, -1, NULL))
		text = "";
	set_value (PidTagBody, text);
	text = NULL;

	categories = e_cal_component_get_categories_list (comp);
	if (categories) {
		gint ii;
		GSList *c;
		struct StringArrayW_r categories_array;

		categories_array.cValues = g_slist_length (categories);
		categories_array.lppszW = (const char **) talloc_zero_array (mem_ctx, gchar *, categories_array.cValues);

		for (c = categories, ii = 0; c; c = c->next, ii++) {
			const gchar *category = c->data;

			if (!category || !*category) {
				ii--;
				categories_array.cValues--;
				continue;
			}

			categories_array.lppszW[ii] = talloc_strdup (mem_ctx, category);
		}

		set_value (PidNameKeywords, &categories_array);

		g_slist_free_full (categories, g_free);
	}

	/* Priority and Importance */
	prop = i_cal_component_get_first_property (icomp, I_CAL_PRIORITY_PROPERTY);
	flag32 = prop ? get_prio_prop_from_priority (i_cal_property_get_priority (prop)) : PRIORITY_NORMAL;
	set_value (PidTagPriority, &flag32);
	flag32 = prop ? get_imp_prop_from_priority (i_cal_property_get_priority (prop)) : IMPORTANCE_NORMAL;
	set_value (PidTagImportance, &flag32);
	g_clear_object (&prop);

	if (cbdata->ownername && cbdata->owneridtype && cbdata->ownerid) {
		set_value (PidTagSentRepresentingName, cbdata->ownername);
		set_value (PidTagSentRepresentingAddressType, cbdata->owneridtype);
		set_value (PidTagSentRepresentingEmailAddress, cbdata->ownerid);
	}

	if (cbdata->username && cbdata->useridtype && cbdata->userid) {
		set_value (PidTagSenderName, cbdata->username);
		set_value (PidTagSenderAddressType, cbdata->useridtype);
		set_value (PidTagSenderEmailAddress, cbdata->userid);
	}

	flag32 = cbdata->msgflags;
	set_value (PidTagMessageFlags, &flag32);

	flag32 = 0x0;
	b = e_cal_component_has_alarms (comp);
	if (b) {
		/* We know there would be only a single alarm of type:DISPLAY [static properties of the backend] */
		GSList *alarm_uids = e_cal_component_get_alarm_uids (comp);
		ECalComponentAlarm *alarm = e_cal_component_get_alarm (comp, (const gchar *)(alarm_uids->data));
		ECalComponentAlarmAction action;

		action = e_cal_component_alarm_get_action (alarm);
		if (action == E_CAL_COMPONENT_ALARM_DISPLAY) {
			ECalComponentAlarmTrigger *trigger;
			gint dur_int = 0;

			trigger = e_cal_component_alarm_get_trigger (alarm);
			switch (e_cal_component_alarm_trigger_get_kind (trigger)) {
			case E_CAL_COMPONENT_ALARM_TRIGGER_RELATIVE_START:
				dur_int = (i_cal_duration_as_int (e_cal_component_alarm_trigger_get_duration (trigger))) / SECS_IN_MINUTE;
				/* we cannot set an alarm to popup after the start of an appointment on Exchange */
				flag32 = (dur_int < 0) ? -(dur_int) : 0;
				break;
			default :
				break;
			}
		}
		e_cal_component_alarm_free (alarm);
		g_slist_free_full (alarm_uids, g_free);
	}
	if (!flag32)
		switch (kind) {
			case I_CAL_VEVENT_COMPONENT:
				flag32 = DEFAULT_APPT_REMINDER_MINS;
				break;
			case I_CAL_VTODO_COMPONENT:
				flag32 = DEFAULT_TASK_REMINDER_MINS;
				break;
			default:
				break;
		}
	set_value (PidLidReminderSet, &b);
	set_value (PidLidReminderDelta, &flag32);
	tt = i_cal_time_as_timet (utc_dtstart);
	set_timet_value (PidLidReminderTime, tt);
	tt = i_cal_time_as_timet (utc_dtstart) - (flag32 * SECS_IN_MINUTE);
	/* ReminderNextTime: FIXME for recurrence */
	set_timet_value (PidLidReminderSignalTime, tt);

	/* Sensitivity, Private */
	flag32 = olNormal;	/* default */
	b = 0;			/* default */
	prop = i_cal_component_get_first_property (icomp, I_CAL_CLASS_PROPERTY);
	if (prop)
		flag32 = get_prop_from_class (i_cal_property_get_class (prop));
	if (flag32 == olPrivate || flag32 == olConfidential)
		b = 1;
	set_value (PidTagSensitivity, &flag32);
	set_value (PidLidPrivate, &b);
	g_clear_object (&prop);

	tt = i_cal_time_as_timet (is_all_day ? all_day_dtstart : utc_dtstart);
	set_timet_value (PidLidCommonStart, tt);
	set_timet_value (PidTagStartDate, tt);

	tt = i_cal_time_as_timet (is_all_day ? all_day_dtend : utc_dtend);
	set_timet_value (PidLidCommonEnd, tt);
	set_timet_value (PidTagEndDate, tt);

	b = 1;
	set_value (PidTagResponseRequested, &b);

	/* PR_OWNER_APPT_ID needs to be set in certain cases only */
	/* PR_ICON_INDEX needs to be set appropriately */

	b = 0;
	set_value (PidTagRtfInSync, &b);

	if (kind == I_CAL_VEVENT_COMPONENT) {
		const gchar *mapi_tzid;
		struct SBinary_short start_tz, end_tz;
		ICalDuration *duration;
		ICalTime *itt;

		set_value (PidLidAppointmentMessageClass, IPM_APPOINTMENT);

		/* Busy Status */
		flag32 = olBusy;
		prop = i_cal_component_get_first_property (icomp, I_CAL_TRANSP_PROPERTY);
		if (prop)
			flag32 = get_prop_from_transp (i_cal_property_get_transp (prop));
		if (cbdata->meeting_type == MEETING_CANCEL)
			flag32 = olFree;
		set_value (PidLidIntendedBusyStatus, &flag32);

		if (cbdata->meeting_type == MEETING_REQUEST || cbdata->meeting_type == MEETING_REQUEST_RCVD) {
			flag32 = olTentative;
			set_value (PidLidBusyStatus, &flag32);
		} else if (cbdata->meeting_type == MEETING_CANCEL) {
			flag32 = olFree;
			set_value (PidLidBusyStatus, &flag32);
		} else
			set_value (PidLidBusyStatus, &flag32);
		g_clear_object (&prop);

		/* Location */
		text = i_cal_component_get_location (icomp);
		if (!(text && *text))
			text = "";
		set_value (PidLidLocation, text);
		set_value (PidLidWhere, text);
		text = NULL;
		/* Auto-Location is always FALSE - Evolution doesn't work that way */
		b = 0;
		set_value (PidLidAutoFillLocation, &b);

		/* All-day event */
		b = is_all_day ? 1 : 0;
		set_value (PidLidAppointmentSubType, &b);

		/* Start */
		tt = i_cal_time_as_timet (is_all_day ? all_day_dtstart : utc_dtstart);
		set_timet_value (PidLidAppointmentStartWhole, tt);
		/* FIXME: for recurrence */
		set_timet_value (PidLidClipStart, tt);

		/* Start TZ */
		mapi_tzid = e_mapi_cal_tz_util_get_mapi_equivalent ((dtstart_tz_location && *dtstart_tz_location) ? dtstart_tz_location : "UTC");
		if (mapi_tzid && *mapi_tzid) {
			e_mapi_cal_util_mapi_tz_to_bin (mapi_tzid, &start_tz, object, FALSE);
			set_value (PidLidAppointmentTimeZoneDefinitionStartDisplay, &start_tz);

			if (e_cal_component_has_recurrences (comp)) {
				struct SBinary_short recur_tz;

				e_mapi_cal_util_mapi_tz_to_bin (mapi_tzid, &recur_tz, object, TRUE);
				set_value (PidLidAppointmentTimeZoneDefinitionRecur, &recur_tz);
			}
		}
		set_value (PidLidTimeZoneDescription, mapi_tzid ? mapi_tzid : "");

		/* End */
		tt = i_cal_time_as_timet (is_all_day ? all_day_dtend : utc_dtend);
		set_timet_value (PidLidAppointmentEndWhole, tt);
		/* FIXME: for recurrence */
		set_timet_value (PidLidClipEnd, tt);

		/* End TZ */
		mapi_tzid = e_mapi_cal_tz_util_get_mapi_equivalent ((dtend_tz_location && *dtend_tz_location) ? dtend_tz_location : "UTC");
		if (mapi_tzid && *mapi_tzid) {
			e_mapi_cal_util_mapi_tz_to_bin (mapi_tzid, &end_tz, object, FALSE);
			set_value (PidLidAppointmentTimeZoneDefinitionEndDisplay, &end_tz);
		}

		/* Recurrences also need to have this rather arbitrary index set
		   to properly determine SDT/DST and appear in OWA (Bug #629057). */
		if (e_cal_component_has_recurrences (comp)) {
			uint64_t pltz;
			ICalTimezone *ictz;
			const gchar *zone_location = dtstart_tz_location;

			if (!zone_location)
				zone_location = get_tzid_location ("*default-zone*", cbdata);

			ictz = i_cal_timezone_get_builtin_timezone (zone_location);
			pltz = e_mapi_cal_util_mapi_tz_pidlidtimezone (ictz);
			set_value (PidLidTimeZone, &pltz);
		}

		/* Duration */
		duration = i_cal_time_subtract (dtend, dtstart);
		flag32 = i_cal_duration_as_int (duration);
		flag32 /= MINUTES_IN_HOUR;
		set_value (PidLidAppointmentDuration, &flag32);
		g_clear_object (&duration);

		if (e_cal_component_has_recurrences (comp)) {
			GSList *rrule_list = NULL;
			ICalRecurrence *rt = NULL;

			rrule_list = e_cal_component_get_rrules (comp);
			rt = rrule_list->data;

			if (i_cal_recurrence_get_freq (rt) == I_CAL_DAILY_RECURRENCE)
				flag32 = rectypeDaily;
			else if (i_cal_recurrence_get_freq (rt) == I_CAL_WEEKLY_RECURRENCE)
				flag32 = rectypeWeekly;
			else if (i_cal_recurrence_get_freq (rt) == I_CAL_MONTHLY_RECURRENCE)
				flag32 = rectypeMonthly;
			else if (i_cal_recurrence_get_freq (rt) == I_CAL_YEARLY_RECURRENCE)
				flag32 = rectypeYearly;
			else
				flag32 = rectypeNone;

			g_slist_free_full (rrule_list, g_object_unref);
		} else
			flag32 = rectypeNone;
		set_value (PidLidRecurrenceType, &flag32);

		flag32 = cbdata->appt_id;
		if (!flag32) {
			gchar *propval;

			propval = e_cal_util_component_dup_x_property (e_cal_component_get_icalcomponent (comp), "X-EVOLUTION-MAPI-OWNER-APPT-ID");
			if (propval && *propval) {
				mapi_id_t as_id = 0;

				if (e_mapi_util_mapi_id_from_string (propval, &as_id))
					flag32 = (uint32_t) as_id;
			}

			g_free (propval);
		}
		set_value (PidTagOwnerAppointmentId, &flag32);

		flag32 = cbdata->appt_seq;
		set_value (PidLidAppointmentSequence, &flag32);

		if (cbdata->cleanglobalid) {
			struct Binary_r bin;
			bin.cb = cbdata->cleanglobalid->cb;
			bin.lpb = cbdata->cleanglobalid->lpb;

			set_value (PidLidCleanGlobalObjectId, &bin);
		}

		if (cbdata->globalid) {
			struct Binary_r bin;
			bin.cb = cbdata->globalid->cb;
			bin.lpb = cbdata->globalid->lpb;

			set_value (PidLidGlobalObjectId, &bin);
		}

		flag32 = cbdata->resp;
		set_value (PidLidResponseStatus, &flag32);

		switch (cbdata->meeting_type) {
		case MEETING_OBJECT :
			set_value (PidTagMessageClass, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet;
			set_value (PidTagIconIndex, &flag32);

			flag32 = 0x0171;
			set_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting;
			set_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgRequest;
			set_value (PidLidMeetingType, &flag32);

			b = 1;
			set_value (PidLidFInvited, &b);

			break;
		case MEETING_OBJECT_RCVD :
			set_value (PidTagMessageClass, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet;
			set_value (PidTagIconIndex, (gconstpointer ) &flag32);

			flag32 = 0x0171;
			set_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived;
			set_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgRequest;
			set_value (PidLidMeetingType, &flag32);

			b = 1;
			set_value (PidLidFInvited, &b);

			break;
		case MEETING_REQUEST :
			set_value (PidTagMessageClass, IPM_SCHEDULE_MEETING_REQUEST);

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */
			set_value (PidTagIconIndex, &flag32);

			flag32 = 0x1C61;
			set_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived;
			set_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = (cbdata->appt_seq == 0) ? mtgRequest : mtgFull;
			set_value (PidLidMeetingType, &flag32);

			b = 1;
			set_value (PidLidFInvited, &b);

			itt = i_cal_time_new_current_with_zone (utc_zone);
			tt = i_cal_time_as_timet (itt);
			set_timet_value (PidLidAttendeeCriticalChange, tt);
			g_clear_object (&itt);

			break;
		case MEETING_REQUEST_RCVD :
			set_value (PidTagMessageClass, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurMeet : SingleMeet;
			set_value (PidTagIconIndex, &flag32);

			flag32 = 0x0171;
			set_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived;
			set_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgRequest;
			set_value (PidLidMeetingType, &flag32);

			b = 1;
			set_value (PidLidFInvited, &b);

			break;
		case MEETING_CANCEL :
			set_value (PidTagMessageClass, IPM_SCHEDULE_MEETING_CANCELED);

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */
			set_value (PidTagIconIndex, &flag32);

			flag32 = 0x1C61;
			set_value (PidLidSideEffects, &flag32);

			flag32 = asfMeeting | asfReceived | asfCanceled;
			set_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgEmpty;
			set_value (PidLidMeetingType, &flag32);

			b = 1;
			set_value (PidLidFInvited, &b);

			break;
		case MEETING_RESPONSE :
			#define prefix_subject(prefix) {					\
				const gchar *summary;						\
												\
				summary = i_cal_component_get_summary (icomp);			\
				if (!(summary && *summary))					\
					summary = "";						\
												\
				summary = talloc_asprintf (mem_ctx, "%s %s", prefix, summary);	\
												\
				set_value (PidTagSubject, summary);				\
				set_value (PidTagNormalizedSubject, summary);			\
				if (cbdata->appt_seq == 0)					\
					set_value (PidTagConversationTopic, summary);		\
			}
			if (cbdata->resp == olResponseAccepted) {
				/* Translators: This is a meeting response prefix which will be shown in a message Subject */
				prefix_subject (C_("MeetingResp", "Accepted:"));
				text = IPM_SCHEDULE_MEETING_RESP_POS;
				flag32 = 1 << 5; /* ciRespondedAccept */
			} else if (cbdata->resp == olResponseTentative) {
				/* Translators: This is a meeting response prefix which will be shown in a message Subject */
				prefix_subject (C_("MeetingResp", "Tentative:"));
				text = IPM_SCHEDULE_MEETING_RESP_TENT;
				flag32 = 1 << 4; /* ciRespondedTentative */
			} else if (cbdata->resp == olResponseDeclined) {
				/* Translators: This is a meeting response prefix which will be shown in a message Subject */
				prefix_subject (C_("MeetingResp", "Declined:"));
				text = IPM_SCHEDULE_MEETING_RESP_NEG;
				flag32 = 1 << 6; /* ciRespondedDecline */
			} else {
				text = "";
				flag32 = 1 << 11; /* ciCanceled */
			}
			#undef prefix_subject
			set_value (PidTagMessageClass, text);
			text = NULL;

			set_value (PidLidClientIntent, &flag32);

			flag32 = 0xFFFFFFFF;  /* no idea why this has to be -1, but that's what the docs say */
			set_value (PidTagIconIndex, &flag32);

			flag32 = 0x1C61;
			set_value (PidLidSideEffects, &flag32);

			flag32 = asfNone;
			set_value (PidLidAppointmentStateFlags, &flag32);

			flag32 = mtgEmpty;
			set_value (PidLidMeetingType, &flag32);

			itt = i_cal_time_new_current_with_zone (utc_zone);
			tt = i_cal_time_as_timet (itt);
			set_timet_value (PidLidAppointmentReplyTime, tt);
			g_clear_object (&itt);

			break;
		case NOT_A_MEETING :
		default :
			set_value (PidTagMessageClass, IPM_APPOINTMENT);

			flag32 = e_cal_component_has_recurrences (comp) ? RecurAppt : SingleAppt;
			set_value (PidTagIconIndex, &flag32);

			flag32 = 0x0171;
			set_value (PidLidSideEffects, &flag32);

			flag32 = 0;
			set_value (PidLidAppointmentStateFlags, &flag32);

			b = 0;
			set_value (PidLidFInvited, &b);

			break;
		}

		b = e_cal_component_has_recurrences (comp);
		set_value (PidLidRecurring, &b);
		set_value (PidLidIsRecurring, &b);

		if (b) {
			struct SBinary_short recur_bin;

			if (e_mapi_cal_util_rrule_to_bin (comp, &recur_bin, object)) {
				set_value (PidLidAppointmentRecur, &recur_bin);
			}
		}

		/* FIXME: Modified exceptions */
		b = e_cal_component_has_exceptions (comp) && FALSE; b = 0;
		set_value (PidLidIsException, &b);

		/* Counter Proposal for appointments : not supported */
		b = 1;
		set_value (PidLidAppointmentNotAllowPropose, &b);
		b = 0;
		set_value (PidLidAppointmentCounterProposal, &b);

	} else if (kind == I_CAL_VTODO_COMPONENT) {
		gdouble d;

		set_value (PidTagMessageClass, IPM_TASK);

		/* Context menu flags */ /* FIXME: for assigned tasks */
		flag32 = 0x0110;
		set_value (PidLidSideEffects, &flag32);

		/* Status, Percent complete, IsComplete */
		flag32 = olTaskNotStarted;	/* default */
		b = 0;				/* default */
		d = 0.0;
		prop = i_cal_component_get_first_property (icomp, I_CAL_PERCENTCOMPLETE_PROPERTY);
		if (prop)
			d = 0.01 * i_cal_property_get_percentcomplete (prop);
		g_clear_object (&prop);

		flag32 = get_prop_from_taskstatus (i_cal_component_get_status (icomp));
		if (flag32 == olTaskComplete) {
			b = 1;
			d = 1.0;
		}

		set_value (PidLidTaskStatus, &flag32);
		set_value (PidLidPercentComplete, &d);
		set_value (PidLidTaskComplete, &b);

		/* Date completed */
		if (b) {
			ICalTime *completed;

			prop = i_cal_component_get_first_property (icomp, I_CAL_COMPLETED_PROPERTY);
			if (prop) {
				completed = i_cal_property_get_completed (prop);

				i_cal_time_set_time (completed, 0, 0, 0);
				i_cal_time_set_is_date (completed, TRUE);
				i_cal_time_set_timezone (completed, utc_zone);

				tt = i_cal_time_as_timet (completed);
				set_timet_value (PidLidTaskDateCompleted, tt);
				g_clear_object (&completed);
			}
		}

		/* Start */
		i_cal_time_set_time (dtstart, 0, 0, 0);
		i_cal_time_set_is_date (dtstart, TRUE);
		i_cal_time_set_timezone (dtstart, utc_zone);

		tt = i_cal_time_as_timet (dtstart);
		if (!i_cal_time_is_null_time (dtstart)) {
			set_timet_value (PidLidTaskStartDate, tt);
		}

		/* Due */
		i_cal_time_set_time (dtend, 0, 0, 0);
		i_cal_time_set_is_date (dtend, TRUE);
		i_cal_time_set_timezone (dtend, utc_zone);

		tt = i_cal_time_as_timet (dtend);
		if (!i_cal_time_is_null_time (dtend)) {
			set_timet_value (PidLidTaskDueDate, tt);
		}

		/* FIXME: Evolution does not support recurring tasks */
		b = 0;
		set_value (PidLidTaskFRecurring, &b);

	} else if (kind == I_CAL_VJOURNAL_COMPONENT) {
		uint32_t color = olYellow;

		set_value (PidTagMessageClass, IPM_STICKYNOTE);

		/* Context menu flags */
		flag32 = 0x0110;
		set_value (PidLidSideEffects, &flag32);

		flag32 = 0x0300 + color;
		set_value (PidTagIconIndex, &flag32);

		flag32 = color;
		set_value (PidLidNoteColor, &flag32);

		/* some random value */
		flag32 = 0x00FF;
		set_value (PidLidNoteWidth, &flag32);

		/* some random value */
		flag32 = 0x00FF;
		set_value (PidLidNoteHeight, &flag32);
	}

	#undef set_value
	#undef set_timet_value

	if (cbdata->meeting_type == MEETING_RESPONSE || cbdata->meeting_type == NOT_A_MEETING)
		e_mapi_cal_utils_add_organizer (object, comp);
	else
		e_mapi_cal_utils_add_recipients (object, comp);

	e_mapi_cal_utils_add_attachments (object, comp);

	if (e_mapi_debug_is_enabled ()) {
		printf ("%s:\n", G_STRFUNC);
		e_mapi_debug_dump_object (object, TRUE, 3);
	}

	g_clear_object (&dtstart);
	g_clear_object (&dtend);
	g_clear_object (&utc_dtstart);
	g_clear_object (&utc_dtend);
	g_clear_object (&all_day_dtstart);
	g_clear_object (&all_day_dtend);

	return TRUE;
}
