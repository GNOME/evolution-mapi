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

#include "exchange-mapi-cal-recur-utils.h"
#include <libecal/e-cal-util.h>

/* Reader/Writer versions */
#define READER_VERSION	0x3004
#define WRITER_VERSION	0x3004
#define READER_VERSION2 0x3006
#define WRITER_VERSION2 0x3009

#if 0
struct ChangeHighlight {
	uint32_t Size;
	uint32_t Value;
	uint32_t Reserved;
};

struct ExtendedException {
	struct ChangeHighlight ch;
	uint32_t ReservedEE1Size;
	uint32_t ReservedEE1;
	uint32_t StartDateTime;
	uint32_t EndDateTime;
	uint32_t OrigStartDate;
	uint16_t WideCharSubjectLength;
	gchar *WideCharSubject;
	uint16_t WideCharLocationLength;
	gchar *WideCharLocation;
	uint32_t ReservedEE2Size;
	uint32_t ReservedEE2;
};

struct ExceptionInfo {
	uint32_t StartDateTime;
	uint32_t EndDateTime;
	uint32_t OrigStartDate;
	uint16_t OverrideFlags;
	uint16_t SubjectLength;
	uint16_t SubjectLength2;
	gchar *Subject;
	uint32_t MeetingType;
	uint32_t ReminderDelta;
	uint32_t ReminderSet;
	uint16_t LocationLength;
	uint16_t LocationLength2;
	gchar *Location;
	uint32_t BusyStatus;
	uint32_t Attachment;
	uint32_t SubType;
	uint32_t AppointmentColor;
};
#endif

/* Override flags defining what fields might be found in ExceptionInfo */
#define ARO_SUBJECT 0x0001
#define ARO_MEETINGTYPE 0x0002
#define ARO_REMINDERDELTA 0x0004
#define ARO_REMINDER 0x0008
#define ARO_LOCATION 0x0010
#define ARO_BUSYSTATUS 0x0020
#define ARO_ATTACHMENT 0x0040
#define ARO_SUBTYPE 0x0080
#define ARO_APPTCOLOR 0x0100
#define ARO_EXCEPTIONAL_BODY 0x0200

static icalrecurrencetype_weekday
get_ical_weekstart (uint32_t fdow)
{
	switch (fdow) {
		case FirstDOW_Sunday	: return ICAL_SUNDAY_WEEKDAY;
		case FirstDOW_Monday	: return ICAL_MONDAY_WEEKDAY;
		case FirstDOW_Tuesday	: return ICAL_TUESDAY_WEEKDAY;
		case FirstDOW_Wednesday : return ICAL_WEDNESDAY_WEEKDAY;
		case FirstDOW_Thursday	: return ICAL_THURSDAY_WEEKDAY;
		case FirstDOW_Friday	: return ICAL_FRIDAY_WEEKDAY;
		case FirstDOW_Saturday	: return ICAL_SATURDAY_WEEKDAY;
		default			: return ICAL_SUNDAY_WEEKDAY;
	}
}

static uint32_t
get_mapi_weekstart (icalrecurrencetype_weekday weekstart)
{
	switch (weekstart) {
		case ICAL_SUNDAY_WEEKDAY   : return FirstDOW_Sunday;
		case ICAL_MONDAY_WEEKDAY   : return FirstDOW_Monday;
		case ICAL_TUESDAY_WEEKDAY  : return FirstDOW_Tuesday;
		case ICAL_WEDNESDAY_WEEKDAY: return FirstDOW_Wednesday;
		case ICAL_THURSDAY_WEEKDAY : return FirstDOW_Thursday;
		case ICAL_FRIDAY_WEEKDAY   : return FirstDOW_Friday;
		case ICAL_SATURDAY_WEEKDAY : return FirstDOW_Saturday;
		default			   : return FirstDOW_Sunday;
	}
}

static uint32_t
get_mapi_day (icalrecurrencetype_weekday someday)
{
	switch (someday) {
		case ICAL_SUNDAY_WEEKDAY   : return olSunday;
		case ICAL_MONDAY_WEEKDAY   : return olMonday;
		case ICAL_TUESDAY_WEEKDAY  : return olTuesday;
		case ICAL_WEDNESDAY_WEEKDAY: return olWednesday;
		case ICAL_THURSDAY_WEEKDAY : return olThursday;
		case ICAL_FRIDAY_WEEKDAY   : return olFriday;
		case ICAL_SATURDAY_WEEKDAY : return olSaturday;
		default			   : return 0;
	}
}

static int32_t
get_ical_pos (uint32_t pos)
{
	switch (pos) {
		case RecurrenceN_First	: return 1;
		case RecurrenceN_Second : return 2;
		case RecurrenceN_Third	: return 3;
		case RecurrenceN_Fourth : return 4;
		case RecurrenceN_Last	: return (-1);
		default			: return 0;
	}
}

static uint32_t
get_mapi_pos (int32_t pos)
{
	switch (pos) {
		case 1	: return RecurrenceN_First;
		case 2	: return RecurrenceN_Second;
		case 3	: return RecurrenceN_Third;
		case 4	: return RecurrenceN_Fourth;
		case -1 : return RecurrenceN_Last;
		default : return 0;
	}
}

#define cFileTimeUnitsPerSecond 10000000

#if 0
static void
convert_recurrence_minutes_to_date (uint32_t minutes, struct FILETIME *ft)
{
	NTTIME nt;

	nt = (NTTIME) minutes * (60 * cFileTimeUnitsPerSecond);

	ft->dwLowDateTime = (uint32_t)((nt << 32) >> 32);
	ft->dwHighDateTime = (uint32_t)(nt >> 32);
}

static uint32_t
convert_date_to_recurrence_minutes (const struct FILETIME *ft)
{
	NTTIME minutes;

	minutes = ft->dwHighDateTime;
	minutes = minutes << 32;
	minutes |= ft->dwLowDateTime;

	minutes = minutes / (60 * cFileTimeUnitsPerSecond);

	return (uint32_t)(minutes);
}

static time_t
convert_filetime_to_timet (const struct FILETIME *ft)
{
	NTTIME time;

	time = ft->dwHighDateTime;
	time = time << 32;
	time |= ft->dwLowDateTime;

	return nt_time_to_unix (time);
}

static void
convert_timet_to_filetime (time_t t, struct FILETIME *ft)
{
	NTTIME nt;

	unix_to_nt_time (&nt, t);

	ft->dwLowDateTime = (uint32_t)((nt << 32) >> 32);
	ft->dwHighDateTime = (uint32_t)(nt >> 32);
}
#endif

static time_t
convert_recurrence_minutes_to_timet (uint32_t minutes)
{
	NTTIME nt;

	nt = (NTTIME) minutes * (60 * cFileTimeUnitsPerSecond);

	return nt_time_to_unix (nt);
}

static uint32_t
convert_timet_to_recurrence_minutes (time_t t)
{
	NTTIME minutes;

	unix_to_nt_time (&minutes, t);

	minutes = minutes / (60 * cFileTimeUnitsPerSecond);

	return (uint32_t)(minutes);
}

static gboolean
check_calendar_type (guint16 type)
{
	/* Calendar Type - We support Gregorian only. */
	if (type == CAL_DEFAULT || type == CAL_GREGORIAN)
		return TRUE;
	else {
		g_warning ("Calendar type = 0x%04X - Evolution does not handle such calendar types.", type);
		return FALSE;
	}
}

gboolean
exchange_mapi_cal_util_bin_to_rrule (GByteArray *ba, ECalComponent *comp, GSList **extra_detached, icaltimezone *recur_zone)
{
	struct icalrecurrencetype rt;
	guint16 flag16;
	guint32 flag32, writer_version;
	guint8 *ptr = ba->data;
	gint i;
	GSList *exdate_list = NULL;
	gboolean repeats_until_date = FALSE;

	icalrecurrencetype_clear (&rt);

	/* Reader version */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	if (READER_VERSION != flag16)
		return FALSE;

	/* Writer version */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	if (WRITER_VERSION != flag16)
		return FALSE;

	/* FREQUENCY */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	if (flag16 == RecurFrequency_Daily) {
		rt.freq = ICAL_DAILY_RECURRENCE;

		flag16 = *((guint16 *)ptr);
		ptr += sizeof (guint16);
		if (flag16 == PatternType_Day) {
			/* Daily every N days */

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

			/* FirstDateTime (some crappy mod here) */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* INTERVAL */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			rt.interval = (short) (flag32 / (24 * 60));

			/* some constant 0 for the stuff we handle */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32)
				return FALSE;

		} else if (flag16 == PatternType_Week) {
			/* Daily every weekday */

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

	/* NOTE: Evolution does not handle daily-every-weekday any different
	 * from a weekly recurrence.
	 */
			rt.freq = ICAL_WEEKLY_RECURRENCE;

			/* FirstDateTime (some crappy mod here) */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* INTERVAL */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			rt.interval = (short) (flag32);

			/* some constant 0 for the stuff we handle */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32)
				return FALSE;

			/* BITMASK */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			i = 0;
			if (flag32 & olSunday)
				rt.by_day[i++] = ICAL_SUNDAY_WEEKDAY;
			if (flag32 & olMonday)
				rt.by_day[i++] = ICAL_MONDAY_WEEKDAY;
			if (flag32 & olTuesday)
				rt.by_day[i++] = ICAL_TUESDAY_WEEKDAY;
			if (flag32 & olWednesday)
				rt.by_day[i++] = ICAL_WEDNESDAY_WEEKDAY;
			if (flag32 & olThursday)
				rt.by_day[i++] = ICAL_THURSDAY_WEEKDAY;
			if (flag32 & olFriday)
				rt.by_day[i++] = ICAL_FRIDAY_WEEKDAY;
			if (flag32 & olSaturday)
				rt.by_day[i++] = ICAL_SATURDAY_WEEKDAY;
		}

	} else if (flag16 == RecurFrequency_Weekly) {
		rt.freq = ICAL_WEEKLY_RECURRENCE;

		flag16 = *((guint16 *)ptr);
		ptr += sizeof (guint16);
		if (flag16 == PatternType_Week) {
			/* weekly every N weeks (for all events and non-regenerating tasks) */

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

			/* FirstDateTime (some crappy mod here) */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* INTERVAL */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			rt.interval = (short) (flag32);

			/* some constant 0 */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32)
				return FALSE;

			/* BITMASK */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			i = 0;
			if (flag32 & olSunday)
				rt.by_day[i++] = ICAL_SUNDAY_WEEKDAY;
			if (flag32 & olMonday)
				rt.by_day[i++] = ICAL_MONDAY_WEEKDAY;
			if (flag32 & olTuesday)
				rt.by_day[i++] = ICAL_TUESDAY_WEEKDAY;
			if (flag32 & olWednesday)
				rt.by_day[i++] = ICAL_WEDNESDAY_WEEKDAY;
			if (flag32 & olThursday)
				rt.by_day[i++] = ICAL_THURSDAY_WEEKDAY;
			if (flag32 & olFriday)
				rt.by_day[i++] = ICAL_FRIDAY_WEEKDAY;
			if (flag32 & olSaturday)
				rt.by_day[i++] = ICAL_SATURDAY_WEEKDAY;

		} else if (flag16 == 0x0) {
			/* weekly every N weeks (for all regenerating tasks) */

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

			/* FIXME: we don't handle regenerating tasks */
			g_warning ("Evolution does not handle recurring tasks.");
			return FALSE;
		}

	} else if (flag16 == RecurFrequency_Monthly) {
		rt.freq = ICAL_MONTHLY_RECURRENCE;

		flag16 = *((guint16 *)ptr);
		ptr += sizeof (guint16);
		if (flag16 == PatternType_Month || flag16 == PatternType_MonthEnd) {
			guint16 pattern = flag16;
			/* Monthly every N months on day D or last day. */

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

			/* FirstDateTime (some crappy mod here) */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* INTERVAL */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			rt.interval = (short) (flag32);

			/* some constant 0 for the stuff we handle */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32)
				return FALSE;

			/* MONTH_DAY */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (pattern == PatternType_Month)
				rt.by_month_day[0] = (short) (flag32);
			else if (pattern == PatternType_MonthEnd)
				rt.by_month_day[0] = (short) (-1);

		} else if (flag16 == PatternType_MonthNth) {
			gboolean post_process = FALSE;
			guint32 mask = 0;
			/* Monthly every N months on the Xth Y */

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

			/* FirstDateTime (some crappy mod here) */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* INTERVAL */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			rt.interval = (short) (flag32);

			/* some constant 0 for the stuff we handle */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32)
				return FALSE;

			/* BITMASK */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32 == olSunday)
				rt.by_day[0] = ICAL_SUNDAY_WEEKDAY;
			else if (flag32 == olMonday)
				rt.by_day[0] = ICAL_MONDAY_WEEKDAY;
			else if (flag32 == olTuesday)
				rt.by_day[0] = ICAL_TUESDAY_WEEKDAY;
			else if (flag32 == olWednesday)
				rt.by_day[0] = ICAL_WEDNESDAY_WEEKDAY;
			else if (flag32 == olThursday)
				rt.by_day[0] = ICAL_THURSDAY_WEEKDAY;
			else if (flag32 == olFriday)
				rt.by_day[0] = ICAL_FRIDAY_WEEKDAY;
			else if (flag32 == olSaturday)
				rt.by_day[0] = ICAL_SATURDAY_WEEKDAY;
			else {
				post_process = TRUE;
				mask = flag32;
			}

			/* RecurrenceN */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (!post_process) {
				rt.by_set_pos[0] = get_ical_pos (flag32);
				if (rt.by_set_pos[0] == 0)
					return FALSE;
			} else {
				if (mask == (olSunday | olMonday | olTuesday | olWednesday | olThursday | olFriday | olSaturday)) {
					rt.by_month_day[0] = get_ical_pos (flag32);
					if (rt.by_month_day[0] == 0)
						return FALSE;
				} else {
				/* FIXME: Can we/LibICAL support any other types here? Namely, weekday and weekend-day */
					g_warning ("Encountered a recurrence type Evolution cannot handle. ");
					return FALSE;
				}
			}
		}

	} else if (flag16 == RecurFrequency_Yearly) {
		rt.freq = ICAL_YEARLY_RECURRENCE;

		flag16 = *((guint16 *)ptr);
		ptr += sizeof (guint16);
		if (flag16 == PatternType_Month) {
			/* Yearly on day D of month M */

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

			/* FirstDateTime (some crappy mod here) */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* INTERVAL */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			rt.interval = (short) (flag32 / 12);

			/* some constant 0 for the stuff we handle */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32)
				return FALSE;

			/* MONTH_DAY - but we don't need this */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

		} else if (flag16 == PatternType_MonthNth) {
			/* Yearly on the Xth Y of month M */

			g_warning ("Encountered a recurrence pattern Evolution cannot handle.");

			/* Calendar Type */
			flag16 = *((guint16 *)ptr);
			ptr += sizeof (guint16);
			if (!check_calendar_type (flag16))
				return FALSE;

			/* FirstDateTime (some crappy mod here) */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* INTERVAL */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			rt.interval = (short) (flag32 / 12);

			/* some constant 0 */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			if (flag32)
				return FALSE;

			/* BITMASK */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* RecurrenceN */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* TODO: Add support for this kinda recurrence in Evolution */
			return FALSE;
		}
	} else
		return FALSE;

	/* End Type - followed by Occurence count */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);
	if (flag32 == END_AFTER_DATE) {
		flag32 = *((guint32 *)ptr);
		ptr += sizeof (guint32);

		repeats_until_date = TRUE;
	} else if (flag32 == END_AFTER_N_OCCURRENCES) {
		flag32 = *((guint32 *)ptr);
		ptr += sizeof (guint32);

		rt.count = flag32;
	} else if (flag32 == END_NEVER_END) {
		flag32 = *((guint32 *)ptr);
		ptr += sizeof (guint32);
	}

	/* week_start */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);
	rt.week_start = get_ical_weekstart (flag32);

	/* number of exceptions */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);
	if (flag32) {
		for (i = 0; i < flag32; ++i) {
			uint32_t exdate;
			struct icaltimetype tt, *val;
			ECalComponentDateTime *dt = g_new0 (ECalComponentDateTime, 1);

			exdate = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			tt = icaltime_from_timet_with_zone (convert_recurrence_minutes_to_timet (exdate), 1, 0);

			val = g_new0(struct icaltimetype, 1);
			memcpy (val, &tt, sizeof(struct icaltimetype));

			dt->value = val;
			dt->tzid = g_strdup ("UTC");

			exdate_list = g_slist_append (exdate_list, dt);
		}
	}

	/* number of changed exceptions */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);
	/* For each changed exception, there will be a corresponding
          ExceptionInfo below.  So at present we don't need to do
          anything with the information here beyond skipping it */
	if (flag32)
		ptr += flag32 * sizeof (guint32);

	/* start date */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);

	/* end date */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);
	if (repeats_until_date) {
		rt.until = icaltime_from_timet_with_zone (convert_recurrence_minutes_to_timet (flag32), 1, 0);
	}

	/* some constant */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);
	if (flag32 != READER_VERSION2)
		return FALSE;

	/* some constant */
	writer_version = *((guint32 *)ptr);
	ptr += sizeof (guint32);
	/* It should be set, but not must. It can be, technically, any value.
	   Seen were 0x3006, 0x3008, 0x3009. It affects format of extended exception info
	if (writer_version != WRITER_VERSION2)
		return FALSE; */

	/* start time in mins */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);

	/* end time in mins */
	flag32 = *((guint32 *)ptr);
	ptr += sizeof (guint32);

	/* Set the recurrence */
	{
		GSList l;

		l.data = &rt;
		l.next = NULL;

		e_cal_component_set_rrule_list (comp, &l);
	}

	/* FIXME: this also has modified instances */
	e_cal_component_set_exdate_list (comp, exdate_list);

	/* modified exceptions, an ExceptionCount sized list of
	   ExceptionInfo instances */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	if (flag16 && extra_detached) {
		gint count = flag16;
		guint16 *overrideflags = g_new0 (guint16, count);
		ECalComponent **detached = g_new0 (ECalComponent *, count);
		uint32_t starttime, endtime, origtime;
		struct icaltimetype tt;
		ECalComponentDateTime edt;
		ECalComponentRange rid;

		e_cal_component_commit_sequence (comp);

		for (i = 0; i < count; i++) {
			/* ExceptionInfo.StartTime */
			starttime = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* ExceptionInfo.EndTime */
			endtime = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* ExceptionInfo.OriginalStartDate */
			origtime = *((guint32 *)ptr);
			ptr += sizeof (guint32);

			/* make a shallow clone of comp */
			detached[i] = e_cal_component_clone (comp);

			tt = icaltime_from_timet_with_zone (convert_recurrence_minutes_to_timet (origtime), 0, 0);
			rid.type = E_CAL_COMPONENT_RANGE_SINGLE;
			rid.datetime.value = &tt;
			rid.datetime.tzid = recur_zone ? icaltimezone_get_tzid (recur_zone) : "UTC";
			e_cal_component_set_recurid (detached[i], &rid);

			tt = icaltime_from_timet_with_zone (convert_recurrence_minutes_to_timet (starttime), 0, 0);
			edt.value = &tt;
			edt.tzid = recur_zone ? icaltimezone_get_tzid (recur_zone) : "UTC";
			e_cal_component_set_dtstart (detached[i], &edt);

			tt = icaltime_from_timet_with_zone (convert_recurrence_minutes_to_timet (endtime), 0, 0);
			edt.value = &tt;
			edt.tzid = recur_zone ? icaltimezone_get_tzid (recur_zone) : "UTC";
			e_cal_component_set_dtend (detached[i], &edt);

			e_cal_component_set_rdate_list (detached[i], NULL);
			e_cal_component_set_rrule_list (detached[i], NULL);
			e_cal_component_set_exdate_list (detached[i], NULL);
			e_cal_component_set_exrule_list (detached[i], NULL);

			/* continue parsing stuff we don't need, because we need to
			   get to the next ExceptionInfo object or back out to the
			   containing AppointmentRecurrencePattern object */

			/* ExceptionInfo.OverrideFlags */
			overrideflags[i] = *((guint16 *) ptr);
			ptr += sizeof (guint16);

			if (overrideflags[i] & ARO_SUBJECT) {
				ECalComponentText text = { 0 };
				gchar *str;

				/* ExceptionInfo.SubjectLength, ExceptionInfo.SubjectLength2
				   and ExceptionInfo.Subject */
				ptr += sizeof (guint16);
				flag16 = *(guint16 *)ptr; /* use SubjectLength2 */
				ptr += sizeof (guint16);
				/* note a discrepency in MS-OXOCAL here, which suggests that
				   Subject is actually 2 bytes */

				str = g_strndup ((const gchar *) ptr, flag16);
				text.value = str;
				e_cal_component_set_summary (detached[i], &text);
				g_free (str);

				ptr += flag16;
			}

			if (overrideflags[i] & ARO_MEETINGTYPE) {
				/* ExceptionInfo.MeetingType */
				ptr += sizeof (guint32);
			}

			if (overrideflags[i] & ARO_REMINDERDELTA) {
				/* ExceptionInfo.ReminderDelta */
				ptr += sizeof (guint32);
			}

			if (overrideflags[i] & ARO_REMINDER) {
				/* ExceptionInfo.ReminderSet */
				ptr += sizeof (guint32);
			}

			if (overrideflags[i] & ARO_LOCATION) {
				gchar *str;

				/* ExceptionInfo.LocationLength, ExceptionInfo.LocationLength2
				   and ExceptionInfo.Location */
				ptr += sizeof (guint16);
				flag16 = *(guint16 *) ptr; /* use LocationLength2 */
				ptr += sizeof (guint16);
				/* note a discrepency in MS-OXOCAL here, which suggests that
				   Location is actually 4 bytes */

				str = g_strndup ((const gchar *) ptr, flag16);
				e_cal_component_set_location (detached[i], str);
				g_free (str);

				ptr += flag16;
			}

			if (overrideflags[i] & ARO_BUSYSTATUS) {
				/* ExceptionInfo.BusyStatus */
				ptr += sizeof (guint32);
			}

			if (overrideflags[i] & ARO_ATTACHMENT) {
				/* ExceptionInfo.Attachment */
				ptr += sizeof (guint32);
			}

			if (overrideflags[i] & ARO_SUBTYPE) {
				/* ExceptionInfo.Subtype */
				ptr += sizeof (guint32);
			}

			if (overrideflags[i] & ARO_APPTCOLOR) {
				/* ExceptionInfo.AppointmentColor */
				ptr += sizeof (guint32);
			}
		}

		/* ExceptionInfo.ReservedBlock1Size */
		flag32 = *((guint32 *)ptr);
		ptr += sizeof (guint32);
		/* the size MUST be zero according to the doc, but... */
		ptr += flag32;

		/* ExtendedExceptionInfo */
		for (i = 0; i < count; i++) {
			/* conditionally parse the ChangeHighlight struct */
			if (writer_version >= 0x3009) {
				/* ChangeHighlightSize */
				flag32 = *((guint32 *)ptr);
				ptr += sizeof (guint32);
				/* again, the size MUST be zero according to the doc, but... */
				ptr += flag32;
			}

			if (!(overrideflags[i] & (ARO_SUBJECT | ARO_LOCATION)))
				continue;

			/* ReservedBlockEE1Size */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			/* again, the size MUST be zero according to the doc, but... */
			ptr += flag32;

			/* it's supposed to be 0 */

			/* StartTime */
			ptr += sizeof (guint32);

			/* EndTime */
			ptr += sizeof (guint32);

			/* OriginalStartDate */
			ptr += sizeof (guint32);

			if (overrideflags[i] & ARO_SUBJECT) {
				ECalComponentText text = { 0 };
				gchar *str;

				/* SubjectLength */
				flag16 = *(guint16 *)ptr;
				ptr += sizeof (guint16);

				str = g_convert ((const gchar *) ptr, flag16 * 2, "UTF-8", "UTF-16", NULL, NULL, NULL);
				text.value = str;
				e_cal_component_set_summary (detached[i], &text);
				g_free (str);

				ptr += flag16 * 2;
			}

			if (overrideflags[i] & ARO_LOCATION) {
				gchar *str;

				/* LocationLength */
				flag16 = *(guint16 *)ptr;
				ptr += sizeof (guint16);

				str = g_convert ((const gchar *) ptr, flag16 * 2, "UTF-8", "UTF-16", NULL, NULL, NULL);
				e_cal_component_set_location (detached[i], str);
				g_free (str);

				ptr += flag16 * 2;
			}

			/* ReservedBlockEE2Size */
			flag32 = *((guint32 *)ptr);
			ptr += sizeof (guint32);
			/* the size MUST be zero according to the doc, but... */
			ptr += flag32;
		}
		for (i = 0; i < count; i++) {
			*extra_detached = g_slist_append (*extra_detached, detached[i]);
		}
		g_free (overrideflags);
		g_free (detached);
	}

	/* in case anyone ever needs to traverse further, from this point ptr 
	   should be pointing at AppointmentRecurrencePattern.ReservedBlock1Size */
	return TRUE;
}

static guint32
compute_startdate (ECalComponent *comp)
{
	ECalComponentDateTime dtstart;
	guint32 flag32;

	e_cal_component_get_dtstart (comp, &dtstart);
	dtstart.value->hour = dtstart.value->minute = dtstart.value->second = 0;
	flag32 = convert_timet_to_recurrence_minutes (icaltime_as_timet_with_zone (*(dtstart.value), 0));

	e_cal_component_free_datetime (&dtstart);

	return flag32;
}

static guint32
compute_rdaily_firstdatetime (ECalComponent *comp, guint32 period)
{
	return (compute_startdate (comp) % period);
}

static guint32
compute_rweekly_firstdatetime (ECalComponent *comp, icalrecurrencetype_weekday week_start, guint32 period)
{
	ECalComponentDateTime dtstart;
	guint32 flag32;
	gint cur_weekday = 0, weekstart_weekday = 0, diff = 0;
	time_t t;

	e_cal_component_get_dtstart (comp, &dtstart);
	dtstart.value->hour = dtstart.value->minute = dtstart.value->second = 0;
	cur_weekday = icaltime_day_of_week (*(dtstart.value));
	t = icaltime_as_timet_with_zone (*(dtstart.value), 0);
	e_cal_component_free_datetime (&dtstart);

	switch (week_start) {
		case ICAL_SUNDAY_WEEKDAY	: weekstart_weekday = 1; break;
		case ICAL_MONDAY_WEEKDAY	: weekstart_weekday = 2; break;
		case ICAL_TUESDAY_WEEKDAY	: weekstart_weekday = 3; break;
		case ICAL_WEDNESDAY_WEEKDAY	: weekstart_weekday = 4; break;
		case ICAL_THURSDAY_WEEKDAY	: weekstart_weekday = 5; break;
		case ICAL_FRIDAY_WEEKDAY	: weekstart_weekday = 6; break;
		case ICAL_SATURDAY_WEEKDAY	: weekstart_weekday = 7; break;
		default				: weekstart_weekday = 1; break;
	};

	diff = cur_weekday - weekstart_weekday;

	if (diff == 0);
	else if (diff > 0)
		t -= (diff * 24 * 60 * 60);
	else if (diff < 0)
		t -= ((diff + 7) * 24 * 60 * 60);

	flag32 = convert_timet_to_recurrence_minutes (t);

	return (flag32 % period);
}

/* The most fucked up algorithm ever conceived by (..you know who..) */
static guint32
compute_rmonthly_firstdatetime (ECalComponent *comp, guint32 period)
{
	const guint8 dinm[] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	ECalComponentDateTime dtstart;
	guint32 flag32, monthindex, i;

	e_cal_component_get_dtstart (comp, &dtstart);
	monthindex = (guint32)((((guint64)(12) * (dtstart.value->year - 1601)) + (dtstart.value->month - 1)) % period);
	e_cal_component_free_datetime (&dtstart);

	for (flag32 = 0, i = 0; i < monthindex; ++i)
		flag32 += dinm[(i % 12) + 1] * 24 * 60;

	return flag32;
}

static guint32
calculate_no_of_occurrences (ECalComponent *comp, const struct icalrecurrencetype *rt)
{
	ECalComponentDateTime dtstart;
	icalrecur_iterator *iter;
	struct icaltimetype next;
	guint32 count = 1;

	e_cal_component_get_dtstart (comp, &dtstart);

	for (iter = icalrecur_iterator_new (*rt, *(dtstart.value)),
	     next = icalrecur_iterator_next(iter);
	     !icaltime_is_null_time(next);
	     next = icalrecur_iterator_next(iter))
		++count;

	icalrecur_iterator_free (iter);
	e_cal_component_free_datetime (&dtstart);

	return count;
}

static gint
compare_guint32 (gconstpointer a, gconstpointer b, gpointer user_data)
{
	return (*((guint32 *) a) - *((guint32 *) b));
}

GByteArray *
exchange_mapi_cal_util_rrule_to_bin (ECalComponent *comp, GSList *modified_comps)
{
	struct icalrecurrencetype *rt;
	guint16 flag16;
	guint32 flag32, end_type;
	gint i;
	GSList *rrule_list = NULL, *exdate_list = NULL;
	GByteArray *ba = NULL;

	if (!e_cal_component_has_recurrences (comp))
		return NULL;

	e_cal_component_get_rrule_list (comp, &rrule_list);
	e_cal_component_get_exdate_list (comp, &exdate_list);

	if (g_slist_length (rrule_list) != 1)
		goto cleanup;

	rt = (struct icalrecurrencetype *)(rrule_list->data);

	ba = g_byte_array_new ();

	/* Reader Version */
	flag16 = READER_VERSION;
	ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

	/* Writer Version */
	flag16 = WRITER_VERSION;
	ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

	if (rt->freq == ICAL_DAILY_RECURRENCE) {
		flag16 = RecurFrequency_Daily;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* Pattern Type - it would be PatternType_Day since we have only "Daily every N days"
		 * The other type would be parsed as a weekly recurrence.
		 */
		flag16 = PatternType_Day;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* Calendar Type */
		flag16 = CAL_DEFAULT;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* FirstDateTime */
		flag32 = compute_rdaily_firstdatetime (comp, (rt->interval * (60 * 24)));
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* INTERVAL */
		flag32 = (rt->interval * (60 * 24));
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* This would be 0 for the stuff we handle */
		flag32 = 0x0;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* No PatternTypeSpecific for PatternType_Day */

	} else if (rt->freq == ICAL_WEEKLY_RECURRENCE) {
		flag16 = RecurFrequency_Weekly;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* Pattern Type - it would be PatternType_Week since we don't support any other type. */
		flag16 = PatternType_Week;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* Calendar Type */
		flag16 = CAL_DEFAULT;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* FirstDateTime */
		flag32 = compute_rweekly_firstdatetime (comp, rt->week_start, (rt->interval * (60 * 24 * 7)));
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* INTERVAL */
		flag32 = rt->interval;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* This would be 0 for the stuff we handle */
		flag32 = 0x0;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* BITMASK */
		for (flag32 = 0x0, i = 0; i < ICAL_BY_DAY_SIZE; ++i) {
			if (rt->by_day[i] == ICAL_SUNDAY_WEEKDAY)
				flag32 |= olSunday;
			else if (rt->by_day[i] == ICAL_MONDAY_WEEKDAY)
				flag32 |= olMonday;
			else if (rt->by_day[i] == ICAL_TUESDAY_WEEKDAY)
				flag32 |= olTuesday;
			else if (rt->by_day[i] == ICAL_WEDNESDAY_WEEKDAY)
				flag32 |= olWednesday;
			else if (rt->by_day[i] == ICAL_THURSDAY_WEEKDAY)
				flag32 |= olThursday;
			else if (rt->by_day[i] == ICAL_FRIDAY_WEEKDAY)
				flag32 |= olFriday;
			else if (rt->by_day[i] == ICAL_SATURDAY_WEEKDAY)
				flag32 |= olSaturday;
			else
				break;
		}
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	} else if (rt->freq == ICAL_MONTHLY_RECURRENCE) {
		guint16 pattern = 0x0; guint32 mask = 0x0, flag = 0x0;

		flag16 = RecurFrequency_Monthly;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		if (rt->by_month_day[0] >= 1 && rt->by_month_day[0] <= 31) {
			pattern = PatternType_Month;
			flag = rt->by_month_day[0];
		} else if (rt->by_month_day[0] == -1) {
			pattern = PatternType_MonthNth;
			mask = (olSunday | olMonday | olTuesday | olWednesday | olThursday | olFriday | olSaturday);
			flag = RecurrenceN_Last;
		} else if (rt->by_day[0] >= ICAL_SUNDAY_WEEKDAY && rt->by_day[0] <= ICAL_SATURDAY_WEEKDAY) {
			pattern = PatternType_MonthNth;
			mask = get_mapi_day (rt->by_day[0]);
			flag = get_mapi_pos (rt->by_set_pos[0]);
		}

		/* Pattern Type */
		flag16 = pattern;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* Calendar Type */
		flag16 = CAL_DEFAULT;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* FirstDateTime */
		flag32 = compute_rmonthly_firstdatetime (comp, rt->interval);
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* INTERVAL */
		flag32 = rt->interval;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* This would be 0 for the stuff we handle */
		flag32 = 0x0;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		if (pattern == PatternType_Month) {
			flag32 = flag;
			ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

			if (!(flag))
				g_warning ("Possibly setting incorrect values in the stream. ");
		} else if (pattern == PatternType_MonthNth) {
			flag32 = mask;
			ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

			flag32 = flag;
			ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

			if (!(flag && mask))
				g_warning ("Possibly setting incorrect values in the stream. ");
		} else
			g_warning ("Possibly setting incorrect values in the stream. ");

	} else if (rt->freq == ICAL_YEARLY_RECURRENCE) {
		flag16 = RecurFrequency_Yearly;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* Pattern Type - it would be PatternType_Month since we don't support any other type. */
		flag16 = PatternType_Month;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* Calendar Type */
		flag16 = CAL_DEFAULT;
		ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

		/* FirstDateTime - uses the same function as monthly recurrence */
		flag32 = compute_rmonthly_firstdatetime (comp, 0xC);
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* INTERVAL - should be 12 for yearly recurrence */
		flag32 = 0xC;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* This would be 0 for the stuff we handle */
		flag32 = 0x0;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		/* MONTH_DAY */
		{
			ECalComponentDateTime dtstart;
			e_cal_component_get_dtstart (comp, &dtstart);
			flag32 = dtstart.value->day;
			e_cal_component_free_datetime (&dtstart);
		}
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	}

	/* End Type followed by Occurence count */
	if (!icaltime_is_null_time (rt->until)) {
		flag32 = END_AFTER_DATE;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		flag32 = calculate_no_of_occurrences (comp, rt);
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		end_type = END_AFTER_DATE;
	} else if (rt->count) {
		flag32 = END_AFTER_N_OCCURRENCES;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		flag32 = rt->count;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		end_type = END_AFTER_N_OCCURRENCES;
	} else {
		flag32 = END_NEVER_END;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		flag32 = 0x0;
		ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

		end_type = END_NEVER_END;
	}

	/* FirstDOW */
	flag32 = get_mapi_weekstart (rt->week_start);
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* DeletedInstances */
	flag32 = g_slist_length (exdate_list);
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));
	if (flag32) {
		GSList *l;
		guint32 *sorted_list = g_new0(guint32, flag32);
		/* FIXME: This should include modified dates */
		for (i = 0, l = exdate_list; l; ++i, l = l->next) {
			ECalComponentDateTime *dt = (ECalComponentDateTime *)(l->data);
			dt->value->hour = dt->value->minute = dt->value->second = 0;
			sorted_list[i] = convert_timet_to_recurrence_minutes (icaltime_as_timet_with_zone (*(dt->value), 0));
		}

		g_qsort_with_data (sorted_list, flag32, sizeof (guint32), compare_guint32, NULL);

		for (i = 0; i < flag32; ++i)
			ba = g_byte_array_append (ba, (const guint8 *)&(sorted_list[i]), sizeof (guint32));

		g_free (sorted_list);
	}

	/* FIXME: Add support for modified instances */
	/* ModifiedInstanceCount */
	flag32 = 0x0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));
	if (flag32) {
	}

	/* StartDate */
	flag32 = compute_startdate (comp);
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* EndDate */
	{
		if (end_type == END_NEVER_END)
			flag32 = 0x5AE980DF;
		else if (end_type == END_AFTER_N_OCCURRENCES) {
			ECalComponentDateTime dtstart;
			gchar *rrule_str = icalrecurrencetype_as_string_r (rt);
			time_t *array = g_new0 (time_t, rt->count);

			e_cal_component_get_dtstart (comp, &dtstart);
			dtstart.value->hour = dtstart.value->minute = dtstart.value->second = 0;

			icalrecur_expand_recurrence (rrule_str, icaltime_as_timet_with_zone (*(dtstart.value), 0), rt->count, array);

			flag32 = convert_timet_to_recurrence_minutes (array[(rt->count) - 1]);

			g_free (array);
			g_free (rrule_str);
			e_cal_component_free_datetime (&dtstart);
		} else if (end_type == END_AFTER_DATE) {
			struct icaltimetype until;
			memcpy (&until, &(rt->until), sizeof(struct icaltimetype));
			until.hour = until.minute = until.second = 0;
			flag32 = convert_timet_to_recurrence_minutes (icaltime_as_timet_with_zone (until, 0));
		} else
			flag32 = 0x0;
	}
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* Reader Version 2 */
	flag32 = READER_VERSION2;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* Writer Version 2 */
	flag32 = WRITER_VERSION2;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* StartTimeOffset */
	{
		ECalComponentDateTime dtstart;
		e_cal_component_get_dtstart (comp, &dtstart);
		flag32 = (dtstart.value->hour * 60) + dtstart.value->minute;
		e_cal_component_free_datetime (&dtstart);
	}
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* EndTimeOffset */
	{
		ECalComponentDateTime dtend;
		e_cal_component_get_dtend (comp, &dtend);
		flag32 = (dtend.value->hour * 60) + dtend.value->minute;
		e_cal_component_free_datetime (&dtend);
	}
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* FIXME: Add support for modified instances */
	/* ModifiedExceptionCount */
	flag16 = 0x0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

	/* FIXME: Add the ExceptionInfo here */

	/* Reserved Block 1 Size */
	flag32 = 0x0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

	/* FIXME: Add the ExtendedExceptionInfo here */

	/* Reserved Block 2 Size */
	flag32 = 0x0;
	ba = g_byte_array_append (ba, (const guint8 *)&flag32, sizeof (guint32));

cleanup:
	e_cal_component_free_exdate_list (exdate_list);
	e_cal_component_free_recur_list (rrule_list);

	g_print ("\n== ICAL to MAPI == The recurrence blob data is as follows:\n");
	for (i = 0; i < ba->len; ++i)
		g_print ("0x%02X ", ba->data[i]);
	g_print("\n== End of stream ==\n");

	return ba;
}

