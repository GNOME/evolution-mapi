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

#include <libecal/libecal.h>

#include "e-mapi-cal-utils.h"
#include "e-mapi-cal-recur-utils.h"

/* Reader/Writer versions */
#define READER_VERSION	0x3004
#define WRITER_VERSION	0x3004
#define READER_VERSION2 0x3006
#define WRITER_VERSION2 0x3009

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

/* Serialization helper: append len bytes from var to arr. */
#define GBA_APPEND(a, v, l) g_byte_array_append ((a), (guint8*)(v), (l))

/* Serialization helper: append the value of the variable to arr. */
#define GBA_APPEND_LVAL(a, v) GBA_APPEND ((a), (&v), (sizeof (v)))

/* Unserialization helper: read len bytes into buff from ba at offset off. */
#define GBA_MEMCPY_OFFSET(arr, off, buf, blen) \
	G_STMT_START { \
		g_return_val_if_fail ((off >= 0 && arr->len - off >= blen), FALSE); \
		memcpy (buf, arr->data + off, blen); \
		off += blen; \
	} G_STMT_END

/* Unserialization helper: dereference and increment pointer. */
#define GBA_DEREF_OFFSET(arr, off, lval, valtype) \
	G_STMT_START { \
		g_return_val_if_fail ((off >= 0 && arr->len - off >= sizeof (valtype)), FALSE); \
		lval = *((valtype*)(arr->data+off)); \
		off += sizeof (valtype); \
	} G_STMT_END

/** MS-OXOCAL 2.2.1.44.3 */
struct ema_ChangeHighlight {
	guint32 ChangeHighlightSize;
	guint32 ChangeHighlightValue;
	void *Reserved;
};

/** MS-OXOCAL 2.2.1.44.4 */
struct ema_ExtendedException {
	struct ema_ChangeHighlight ChangeHighlight;
	guint32 ReservedBlockEE1Size;
	void *ReservedBlockEE1;
	guint32 StartDateTime;
	guint32 EndDateTime;
	guint32 OriginalStartDate;
	guint16 WideCharSubjectLength;
	gchar *WideCharSubject;
	guint16 WideCharLocationLength;
	gchar *WideCharLocation;
	guint32 ReservedBlockEE2Size;
	void *ReservedBlockEE2;
};

/** MS-OXOCAL 2.2.1.44.2 */
struct ema_ExceptionInfo {
	guint32 StartDateTime;
	guint32 EndDateTime;
	guint32 OriginalStartDate;
	guint16 OverrideFlags;
	guint16 SubjectLength;
	guint16 SubjectLength2;
	gchar *Subject;
	guint32 MeetingType;
	guint32 ReminderDelta;
	guint32 ReminderSet;
	guint16 LocationLength;
	guint16 LocationLength2;
	gchar *Location;
	guint32 BusyStatus;
	guint32 Attachment;
	guint32 SubType;
	guint32 AppointmentColor;
};

/** MS-OXOCAL 2.2.1.44.1 */
struct ema_RecurrencePattern {
	guint16 ReaderVersion;
	guint16 WriterVersion;
	guint16 RecurFrequency;
	guint16 PatternType;
	guint16 CalendarType;
	guint32 FirstDateTime;
	guint32 Period;
	guint32 SlidingFlag;
	guint32 PatternTypeSpecific;
	guint32 N;
	guint32 EndType;
	guint32 OccurrenceCount;
	guint32 FirstDOW;
	guint32 DeletedInstanceCount;
	guint32 *DeletedInstanceDates;
	guint32 ModifiedInstanceCount;
	guint32 *ModifiedInstanceDates;
	guint32 StartDate;
	guint32 EndDate;
};

/** MS-OXOCAL 2.2.1.44.5 */
struct ema_AppointmentRecurrencePattern {
	struct ema_RecurrencePattern RecurrencePattern;
	guint32 ReaderVersion2;
	guint32 WriterVersion2;
	guint32 StartTimeOffset;
	guint32 EndTimeOffset;
	guint16 ExceptionCount;
	struct ema_ExceptionInfo *ExceptionInfo;
	guint32 ReservedBlock1Size;
	void *ReservedBlock1;
	struct ema_ExtendedException *ExtendedException;
	guint32 ReservedBlock2Size;
	void *ReservedBlock2;
};

/** Serialize a RecurrencePattern to the end of an existing GByteArray */
static void
rp_to_gba(const struct ema_RecurrencePattern *rp, GByteArray *gba)
{
	GBA_APPEND_LVAL (gba, rp->ReaderVersion);
	GBA_APPEND_LVAL (gba, rp->WriterVersion);
	GBA_APPEND_LVAL (gba, rp->RecurFrequency);
	GBA_APPEND_LVAL (gba, rp->PatternType);
	GBA_APPEND_LVAL (gba, rp->CalendarType);
	GBA_APPEND_LVAL (gba, rp->FirstDateTime);
	GBA_APPEND_LVAL (gba, rp->Period);
	GBA_APPEND_LVAL (gba, rp->SlidingFlag);

	if (rp->PatternType != PatternType_Day) {
		GBA_APPEND_LVAL (gba, rp->PatternTypeSpecific);
		if (rp->PatternType == PatternType_MonthNth) {
			GBA_APPEND_LVAL (gba, rp->N);
		}
	}

	GBA_APPEND_LVAL (gba, rp->EndType);
	GBA_APPEND_LVAL (gba, rp->OccurrenceCount);
	GBA_APPEND_LVAL (gba, rp->FirstDOW);
	GBA_APPEND_LVAL (gba, rp->DeletedInstanceCount);
	if ( rp->DeletedInstanceCount ) {
		GBA_APPEND (gba, rp->DeletedInstanceDates,
		            sizeof (guint32) * rp->DeletedInstanceCount);
	}
	GBA_APPEND_LVAL(gba, rp->ModifiedInstanceCount);
	if ( rp->ModifiedInstanceCount ) {
		GBA_APPEND (gba, rp->ModifiedInstanceDates,
		            sizeof (guint32) * rp->ModifiedInstanceCount);
	}
	GBA_APPEND_LVAL (gba, rp->StartDate);
	GBA_APPEND_LVAL (gba, rp->EndDate);
}

static void
ei_to_gba(const struct ema_ExceptionInfo *ei, GByteArray *gba)
{
	GBA_APPEND_LVAL (gba, ei->StartDateTime);
	GBA_APPEND_LVAL (gba, ei->EndDateTime);
	GBA_APPEND_LVAL (gba, ei->OriginalStartDate);
	GBA_APPEND_LVAL (gba, ei->OverrideFlags);
	if (ei->OverrideFlags&ARO_SUBJECT) {
		GBA_APPEND_LVAL (gba, ei->SubjectLength);
		GBA_APPEND_LVAL (gba, ei->SubjectLength2);
		GBA_APPEND (gba, ei->Subject, strlen (ei->Subject));
	}
	if (ei->OverrideFlags&ARO_MEETINGTYPE) {
		GBA_APPEND_LVAL (gba, ei->MeetingType);
	}
	if (ei->OverrideFlags&ARO_REMINDERDELTA) {
		GBA_APPEND_LVAL (gba, ei->ReminderDelta);
	}
	if (ei->OverrideFlags & ARO_REMINDER) {
		GBA_APPEND_LVAL (gba, ei->ReminderSet);
	}
	if (ei->OverrideFlags&ARO_LOCATION) {
		GBA_APPEND_LVAL (gba, ei->LocationLength);
		GBA_APPEND_LVAL (gba, ei->LocationLength2);
		GBA_APPEND (gba, ei->Location, strlen (ei->Location));
	}
	if (ei->OverrideFlags&ARO_BUSYSTATUS) {
		GBA_APPEND_LVAL (gba, ei->BusyStatus);
	}
	if (ei->OverrideFlags&ARO_ATTACHMENT) {
		GBA_APPEND_LVAL (gba, ei->Attachment);
	}
	if (ei->OverrideFlags&ARO_SUBTYPE) {
		GBA_APPEND_LVAL (gba, ei->SubType);
	}
	if (ei->OverrideFlags&ARO_APPTCOLOR) {
		GBA_APPEND_LVAL (gba, ei->AppointmentColor);
	}
}

static void
ee_to_gba(const struct ema_ExtendedException *ee,
          const struct ema_AppointmentRecurrencePattern *arp, int exnum,
          GByteArray *gba)
{
	if (arp->WriterVersion2 >= 0x3009) {
		GBA_APPEND_LVAL (gba, ee->ChangeHighlight.ChangeHighlightSize);
		if (ee->ChangeHighlight.ChangeHighlightSize >= sizeof (guint32)) {
			GBA_APPEND_LVAL (gba, ee->ChangeHighlight.ChangeHighlightValue);
			if (ee->ChangeHighlight.ChangeHighlightSize > sizeof (guint32)) {
				GBA_APPEND (gba, ee->ChangeHighlight.Reserved,
				            ee->ChangeHighlight.ChangeHighlightSize - sizeof (guint32));
			}
		}
	}

	GBA_APPEND_LVAL (gba, ee->ReservedBlockEE1Size);
	if (ee->ReservedBlockEE1Size) {
		GBA_APPEND (gba, ee->ReservedBlockEE1, ee->ReservedBlockEE1Size);
	}

	if (arp->ExceptionInfo[exnum].OverrideFlags&(ARO_SUBJECT|ARO_LOCATION)) {
		GBA_APPEND_LVAL (gba, ee->StartDateTime);
		GBA_APPEND_LVAL (gba, ee->EndDateTime);
		GBA_APPEND_LVAL (gba, ee->OriginalStartDate);

		if (arp->ExceptionInfo[exnum].OverrideFlags&ARO_SUBJECT) {
			GBA_APPEND_LVAL (gba, ee->WideCharSubjectLength);
			GBA_APPEND (gba, ee->WideCharSubject,
			            sizeof (guint16) * ee->WideCharSubjectLength);
		}

		if( arp->ExceptionInfo[exnum].OverrideFlags&ARO_LOCATION) {
			GBA_APPEND_LVAL(gba, ee->WideCharLocationLength);
			GBA_APPEND(gba, ee->WideCharLocation,
			           sizeof (guint16) * ee->WideCharLocationLength);
		}

		GBA_APPEND_LVAL (gba, ee->ReservedBlockEE2Size);
		if (ee->ReservedBlockEE2Size) {
			GBA_APPEND (gba, ee->ReservedBlockEE2,
			            ee->ReservedBlockEE2Size);
		}
	}
}

static void
arp_to_gba(const struct ema_AppointmentRecurrencePattern *arp, GByteArray *gba)
{
	int i;

	rp_to_gba (&arp->RecurrencePattern, gba);
	GBA_APPEND_LVAL (gba, arp->ReaderVersion2);
	GBA_APPEND_LVAL (gba, arp->WriterVersion2);
	GBA_APPEND_LVAL (gba, arp->StartTimeOffset);
	GBA_APPEND_LVAL (gba, arp->EndTimeOffset);
	GBA_APPEND_LVAL (gba, arp->ExceptionCount);
	for (i = 0; i < arp->ExceptionCount; ++i) {
		ei_to_gba (&arp->ExceptionInfo[i], gba);
	}
	GBA_APPEND_LVAL (gba, arp->ReservedBlock1Size);
	if (arp->ReservedBlock1Size) {
		GBA_APPEND (gba, arp->ReservedBlock1, arp->ReservedBlock1Size);
	}
	for (i = 0; i < arp->ExceptionCount; ++i) {
		ee_to_gba (&arp->ExtendedException[i], arp, i, gba);
	}
	GBA_APPEND_LVAL (gba, arp->ReservedBlock2Size);
	if (arp->ReservedBlock2Size) {
		GBA_APPEND (gba, arp->ReservedBlock2, arp->ReservedBlock2Size);
	}
}

static gboolean
gba_to_rp(const GByteArray *gba, ptrdiff_t *off,
	  struct ema_RecurrencePattern *rp)
{
	GBA_DEREF_OFFSET (gba, *off, rp->ReaderVersion, guint16);
	GBA_DEREF_OFFSET (gba, *off, rp->WriterVersion, guint16);
	GBA_DEREF_OFFSET (gba, *off, rp->RecurFrequency, guint16);
	GBA_DEREF_OFFSET (gba, *off, rp->PatternType, guint16);
	GBA_DEREF_OFFSET (gba, *off, rp->CalendarType, guint16);
	GBA_DEREF_OFFSET (gba, *off, rp->FirstDateTime, guint32);
	GBA_DEREF_OFFSET (gba, *off, rp->Period, guint32);
	GBA_DEREF_OFFSET (gba, *off, rp->SlidingFlag, guint32);

	if (rp->PatternType != PatternType_Day) {
		GBA_DEREF_OFFSET (gba, *off, rp->PatternTypeSpecific, guint32);
		if (rp->PatternType == PatternType_MonthNth) {
			GBA_DEREF_OFFSET (gba, *off, rp->N,
			                  guint32);
		}
	}

	GBA_DEREF_OFFSET (gba, *off, rp->EndType, guint32);
	GBA_DEREF_OFFSET (gba, *off, rp->OccurrenceCount, guint32);
	GBA_DEREF_OFFSET (gba, *off, rp->FirstDOW, guint32);

	GBA_DEREF_OFFSET (gba, *off, rp->DeletedInstanceCount, guint32);
	if (rp->DeletedInstanceCount) {
		rp->DeletedInstanceDates = g_new (guint32,
		                                  rp->DeletedInstanceCount);
		GBA_MEMCPY_OFFSET(gba, *off, rp->DeletedInstanceDates,
		                  sizeof (guint32) * rp->DeletedInstanceCount);
	}

	GBA_DEREF_OFFSET (gba, *off, rp->ModifiedInstanceCount, guint32);
	if (rp->ModifiedInstanceCount) {
		rp->ModifiedInstanceDates = g_new (guint32,
		                                   rp->ModifiedInstanceCount);
		GBA_MEMCPY_OFFSET (gba, *off, rp->ModifiedInstanceDates,
		                   sizeof (guint32) * rp->ModifiedInstanceCount);
	}

	GBA_DEREF_OFFSET(gba, *off, rp->StartDate, guint32);
	GBA_DEREF_OFFSET(gba, *off, rp->EndDate, guint32);

	return TRUE;
}

static gboolean
gba_to_ei(const GByteArray *gba, ptrdiff_t *off, struct ema_ExceptionInfo *ei)
{
	GBA_DEREF_OFFSET (gba, *off, ei->StartDateTime, guint32);
	GBA_DEREF_OFFSET (gba, *off, ei->EndDateTime, guint32);
	GBA_DEREF_OFFSET (gba, *off, ei->OriginalStartDate, guint32);
	GBA_DEREF_OFFSET (gba, *off, ei->OverrideFlags, guint16);

	if (ei->OverrideFlags&ARO_SUBJECT) {
		GBA_DEREF_OFFSET (gba, *off, ei->SubjectLength, guint16);
		GBA_DEREF_OFFSET (gba, *off, ei->SubjectLength2, guint16);
		ei->Subject = g_new0 (gchar, ei->SubjectLength2 + 1);
		GBA_MEMCPY_OFFSET (gba, *off, ei->Subject, ei->SubjectLength2);
	}

	if (ei->OverrideFlags&ARO_MEETINGTYPE) {
		GBA_DEREF_OFFSET (gba, *off, ei->MeetingType, guint32);
	}

	if (ei->OverrideFlags&ARO_REMINDERDELTA) {
		GBA_DEREF_OFFSET (gba, *off, ei->ReminderDelta, guint32);
	}

	if (ei->OverrideFlags & ARO_REMINDER) {
		GBA_DEREF_OFFSET (gba, *off, ei->ReminderSet, guint32);
	}

	if (ei->OverrideFlags&ARO_LOCATION) {
		GBA_DEREF_OFFSET (gba, *off, ei->LocationLength, guint16);
		GBA_DEREF_OFFSET (gba, *off, ei->LocationLength2, guint16);
		ei->Location = g_new0 (gchar, ei->LocationLength2 + 1);
		GBA_MEMCPY_OFFSET (gba, *off, ei->Location, ei->LocationLength2);
	}

	if (ei->OverrideFlags&ARO_BUSYSTATUS) {
		GBA_DEREF_OFFSET (gba, *off, ei->BusyStatus, guint32);
	}

	if (ei->OverrideFlags&ARO_ATTACHMENT) {
		GBA_DEREF_OFFSET (gba, *off, ei->Attachment, guint32);
	}

	if (ei->OverrideFlags&ARO_SUBTYPE) {
		GBA_DEREF_OFFSET (gba, *off, ei->SubType, guint32);
	}

	if (ei->OverrideFlags&ARO_APPTCOLOR) {
		GBA_DEREF_OFFSET (gba, *off, ei->AppointmentColor, guint32);
	}

	return TRUE;
}

static gboolean
gba_to_ee(const GByteArray *gba, ptrdiff_t *off,
          struct ema_ExtendedException *ee,
          struct ema_AppointmentRecurrencePattern *arp, int exnum)
{
	GBA_DEREF_OFFSET (gba, *off, ee->ChangeHighlight.ChangeHighlightSize,
	                  guint32);

	if (arp->WriterVersion2 >= 0x3009) {
		if (ee->ChangeHighlight.ChangeHighlightSize > 0) {
			int reserved_size = ee->ChangeHighlight.ChangeHighlightSize - sizeof (guint32);
			GBA_DEREF_OFFSET (gba, *off,
			                  ee->ChangeHighlight.ChangeHighlightValue,
			                  guint32);
			if (reserved_size > 0) {
				ee->ChangeHighlight.Reserved = g_new (gchar, reserved_size);
				GBA_MEMCPY_OFFSET (gba, *off,
				                   &ee->ChangeHighlight.Reserved,
				                   reserved_size);
			}
		}
	}

	GBA_DEREF_OFFSET (gba, *off, ee->ReservedBlockEE1Size, guint32);
	if (ee->ReservedBlockEE1Size) {
		ee->ReservedBlockEE1 = g_new (gchar, ee->ReservedBlockEE1Size);
		GBA_MEMCPY_OFFSET (gba, *off, ee->ReservedBlockEE1,
		                   ee->ReservedBlockEE1Size);
	}

	if (arp->ExceptionInfo[exnum].OverrideFlags&(ARO_SUBJECT|ARO_LOCATION)) {
		GBA_DEREF_OFFSET (gba, *off, ee->StartDateTime, guint32);
		GBA_DEREF_OFFSET (gba, *off, ee->EndDateTime, guint32);
		GBA_DEREF_OFFSET (gba, *off, ee->OriginalStartDate, guint32);

		if(arp->ExceptionInfo[exnum].OverrideFlags&ARO_SUBJECT) {
			GBA_DEREF_OFFSET (gba, *off, ee->WideCharSubjectLength,
			                  guint16);
			ee->WideCharSubject = g_new0(gchar,
			                             sizeof(guint16) * (ee->WideCharSubjectLength + 1));
			GBA_MEMCPY_OFFSET (gba, *off, ee->WideCharSubject,
			                   sizeof(guint16) * ee->WideCharSubjectLength);
		}

		if(arp->ExceptionInfo[exnum].OverrideFlags&ARO_LOCATION) {
			GBA_DEREF_OFFSET (gba, *off, ee->WideCharLocationLength,
			                  guint16);
			ee->WideCharLocation = g_new0 (gchar,
			                               sizeof(guint16) * (ee->WideCharLocationLength + 1));
			GBA_MEMCPY_OFFSET (gba, *off, ee->WideCharLocation,
			                   sizeof (guint16) * ee->WideCharLocationLength);
		}

		GBA_DEREF_OFFSET (gba, *off, ee->ReservedBlockEE2Size, guint32);
		if (ee->ReservedBlockEE2Size) {
			ee->ReservedBlockEE2 = g_new (gchar,
			                              ee->ReservedBlockEE2Size);
			GBA_MEMCPY_OFFSET (gba, *off, ee->ReservedBlockEE2,
			                   ee->ReservedBlockEE2Size);
		}
	}

	return TRUE;
}

static gboolean
gba_to_arp(const GByteArray *gba, ptrdiff_t *off,
           struct ema_AppointmentRecurrencePattern *arp) {
	int i;

	g_return_val_if_fail (gba_to_rp (gba, off, &arp->RecurrencePattern),
	                      FALSE);
	GBA_DEREF_OFFSET (gba, *off, arp->ReaderVersion2, guint32);
	GBA_DEREF_OFFSET (gba, *off, arp->WriterVersion2, guint32);
	GBA_DEREF_OFFSET (gba, *off, arp->StartTimeOffset, guint32);
	GBA_DEREF_OFFSET (gba, *off, arp->EndTimeOffset, guint32);

	GBA_DEREF_OFFSET (gba, *off, arp->ExceptionCount, guint16);
	if (arp->ExceptionCount) {
		arp->ExceptionInfo = g_new0 (struct ema_ExceptionInfo,
		                             arp->ExceptionCount);
		for (i = 0; i < arp->ExceptionCount; ++i) {
			g_return_val_if_fail (gba_to_ei (gba, off, &arp->ExceptionInfo[i]),
			                      FALSE);
		}
	}

	GBA_DEREF_OFFSET (gba, *off, arp->ReservedBlock1Size, guint32);
	if (arp->ReservedBlock1Size) {
		arp->ReservedBlock1 = g_new (gchar, arp->ReservedBlock1Size);
		GBA_MEMCPY_OFFSET (gba, *off, arp->ReservedBlock1,
		                   arp->ReservedBlock1Size);
	}

	if (arp->ExceptionCount) {
		arp->ExtendedException = g_new0 (struct ema_ExtendedException,
		                                 arp->ExceptionCount);
		for (i = 0; i < arp->ExceptionCount; ++i) {
			g_return_val_if_fail (gba_to_ee (gba, off, &arp->ExtendedException[i], arp, i),
			                      FALSE);
		}
	}

	GBA_DEREF_OFFSET (gba, *off, arp->ReservedBlock2Size, guint32);
	if (arp->ReservedBlock2Size) {
		arp->ReservedBlock2 = g_new (gchar, arp->ReservedBlock2Size);
		GBA_MEMCPY_OFFSET (gba, *off, arp->ReservedBlock2,
		                   arp->ReservedBlock2Size);
	}

	return TRUE;
}

static void
free_arp_contents(struct ema_AppointmentRecurrencePattern *arp)
{
	int i;

	if(arp) {
		if (arp->RecurrencePattern.DeletedInstanceDates)
			g_free (arp->RecurrencePattern.DeletedInstanceDates);
		if (arp->RecurrencePattern.ModifiedInstanceDates)
			g_free (arp->RecurrencePattern.ModifiedInstanceDates);
		if (arp->ExceptionInfo) {
			for (i = 0; i < arp->RecurrencePattern.ModifiedInstanceCount; ++i) {
				if (arp->ExceptionInfo[i].Subject)
					g_free (arp->ExceptionInfo[i].Subject);
				if (arp->ExceptionInfo[i].Location)
					g_free (arp->ExceptionInfo[i].Location);
			}
			g_free (arp->ExceptionInfo);
		}
		if (arp->ReservedBlock1) {
			g_free (arp->ReservedBlock1);
		}
		if (arp->ExtendedException) {
			for (i = 0; i < arp->RecurrencePattern.ModifiedInstanceCount; ++i) {
				if (arp->ExtendedException[i].ChangeHighlight.Reserved)
					g_free (arp->ExtendedException[i].ChangeHighlight.Reserved);
				if (arp->ExtendedException[i].ReservedBlockEE1)
					g_free (arp->ExtendedException[i].ReservedBlockEE1);
				if (arp->ExtendedException[i].WideCharSubject)
					g_free (arp->ExtendedException[i].WideCharSubject);
				if (arp->ExtendedException[i].WideCharLocation)
					g_free (arp->ExtendedException[i].WideCharLocation);
				if (arp->ExtendedException[i].ReservedBlockEE2)
					g_free (arp->ExtendedException[i].ReservedBlockEE2);
			}
			g_free (arp->ExtendedException);
		}
		if (arp->ReservedBlock2) {
			g_free (arp->ReservedBlock2);
		}
	}
}

static ICalRecurrenceWeekday
get_ical_weekstart (uint32_t fdow)
{
	switch (fdow) {
	case FirstDOW_Sunday:
		return I_CAL_SUNDAY_WEEKDAY;
	case FirstDOW_Monday:
		return I_CAL_MONDAY_WEEKDAY;
	case FirstDOW_Tuesday:
		return I_CAL_TUESDAY_WEEKDAY;
	case FirstDOW_Wednesday:
		return I_CAL_WEDNESDAY_WEEKDAY;
	case FirstDOW_Thursday:
		return I_CAL_THURSDAY_WEEKDAY;
	case FirstDOW_Friday:
		return I_CAL_FRIDAY_WEEKDAY;
	case FirstDOW_Saturday:
		return I_CAL_SATURDAY_WEEKDAY;
	default:
		return I_CAL_SUNDAY_WEEKDAY;
	}
}

static uint32_t
get_mapi_weekstart (ICalRecurrenceWeekday weekstart)
{
	switch (weekstart) {
	case I_CAL_SUNDAY_WEEKDAY:
		return FirstDOW_Sunday;
	case I_CAL_MONDAY_WEEKDAY:
		return FirstDOW_Monday;
	case I_CAL_TUESDAY_WEEKDAY:
		return FirstDOW_Tuesday;
	case I_CAL_WEDNESDAY_WEEKDAY:
		return FirstDOW_Wednesday;
	case I_CAL_THURSDAY_WEEKDAY:
		return FirstDOW_Thursday;
	case I_CAL_FRIDAY_WEEKDAY:
		return FirstDOW_Friday;
	case I_CAL_SATURDAY_WEEKDAY:
		return FirstDOW_Saturday;
	default:
		return FirstDOW_Sunday;
	}
}

static uint32_t
get_mapi_day (ICalRecurrenceWeekday someday)
{
	switch (someday) {
	case I_CAL_SUNDAY_WEEKDAY:
		return olSunday;
	case I_CAL_MONDAY_WEEKDAY:
		return olMonday;
	case I_CAL_TUESDAY_WEEKDAY:
		return olTuesday;
	case I_CAL_WEDNESDAY_WEEKDAY:
		return olWednesday;
	case I_CAL_THURSDAY_WEEKDAY:
		return olThursday;
	case I_CAL_FRIDAY_WEEKDAY:
		return olFriday;
	case I_CAL_SATURDAY_WEEKDAY:
		return olSaturday;
	default:
		return 0;
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
e_mapi_cal_util_bin_to_rrule (const guint8 *lpb,
			      guint32 cb,
			      ECalComponent *comp,
			      GSList **extra_detached,
			      ICalTimezone *recur_zone)
{
	ICalRecurrence *rt;
	struct ema_AppointmentRecurrencePattern arp;
	struct ema_RecurrencePattern *rp; /* Convenience pointer */
	gboolean success = FALSE, check_calendar = FALSE;
	gint i;
	ptrdiff_t off = 0;
	GSList *exdate_list = NULL;
	GByteArray fake_ba;

	if (e_mapi_debug_is_enabled ()) {
		e_mapi_debug_print ("Converting binary to RRULE:");
		e_mapi_debug_dump_bin (lpb, cb, 3);
		e_mapi_debug_print ("\n");
	}

	fake_ba.data = (guint8 *) lpb;
	fake_ba.len = cb;

	rt = i_cal_recurrence_new ();

	memset(&arp, 0, sizeof (struct ema_AppointmentRecurrencePattern));
	if (! gba_to_arp (&fake_ba, &off, &arp))
		goto cleanup;

	rp = &arp.RecurrencePattern;

	/* FREQUENCY */

	if (rp->RecurFrequency == RecurFrequency_Daily) {
		i_cal_recurrence_set_freq (rt, I_CAL_DAILY_RECURRENCE);

		if (rp->PatternType == PatternType_Day) {
			/* Daily every N days */

			check_calendar = TRUE;

			/* INTERVAL */
			i_cal_recurrence_set_interval (rt, (short) (rp->Period / (24 * 60)));
		} else if (rp->PatternType == PatternType_Week) {
			/* Daily every weekday */

			check_calendar = TRUE;

			/* NOTE: Evolution does not handle daily-every-weekday
			 * any different from a weekly recurrence.  */
			i_cal_recurrence_set_freq (rt, I_CAL_WEEKLY_RECURRENCE);

			/* INTERVAL */
			i_cal_recurrence_set_interval (rt, (short) (rp->Period));
		}
	} else if (rp->RecurFrequency == RecurFrequency_Weekly) {
		i_cal_recurrence_set_freq (rt, I_CAL_WEEKLY_RECURRENCE);

		if (rp->PatternType == PatternType_Week) {
			/* weekly every N weeks (for all events and non-regenerating tasks) */

			check_calendar = TRUE;

			/* INTERVAL */
			i_cal_recurrence_set_interval (rt, (short) (rp->Period));
		} else if (rp->PatternType == 0x0) {
			/* weekly every N weeks (for all regenerating tasks) */

			check_calendar = TRUE;

			/* FIXME: we don't handle regenerating tasks */
			g_warning ("Evolution does not handle recurring tasks.");
			goto cleanup;
		}

	} else if (rp->RecurFrequency == RecurFrequency_Monthly) {
		i_cal_recurrence_set_freq (rt, I_CAL_MONTHLY_RECURRENCE);

		if (rp->PatternType == PatternType_Month ||
		    rp->PatternType == PatternType_MonthEnd) {
			/* Monthly every N months on day D or last day. */

			check_calendar = TRUE;

			/* INTERVAL */
			i_cal_recurrence_set_interval (rt, (short) (rp->Period));

			/* MONTH_DAY */
			if (rp->PatternType == PatternType_Month)
				i_cal_recurrence_set_by_month_day (rt, 0, (short) (rp->PatternTypeSpecific));
			else if (rp->PatternType == PatternType_MonthEnd)
				i_cal_recurrence_set_by_month_day (rt, 0, (short) (-1));

		} else if (rp->PatternType == PatternType_MonthNth) {
			gboolean post_process = FALSE;
			/* Monthly every N months on the Xth Y */

			check_calendar = TRUE;

			/* INTERVAL */
			i_cal_recurrence_set_interval (rt, (short) (rp->Period));

			/* BITMASK */
			if (rp->PatternTypeSpecific == olSunday)
				i_cal_recurrence_set_by_day (rt, 0, I_CAL_SUNDAY_WEEKDAY);
			else if (rp->PatternTypeSpecific == olMonday)
				i_cal_recurrence_set_by_day (rt, 0, I_CAL_MONDAY_WEEKDAY);
			else if (rp->PatternTypeSpecific == olTuesday)
				i_cal_recurrence_set_by_day (rt, 0, I_CAL_TUESDAY_WEEKDAY);
			else if (rp->PatternTypeSpecific == olWednesday)
				i_cal_recurrence_set_by_day (rt, 0, I_CAL_WEDNESDAY_WEEKDAY);
			else if (rp->PatternTypeSpecific == olThursday)
				i_cal_recurrence_set_by_day (rt, 0, I_CAL_THURSDAY_WEEKDAY);
			else if (rp->PatternTypeSpecific == olFriday)
				i_cal_recurrence_set_by_day (rt, 0, I_CAL_FRIDAY_WEEKDAY);
			else if (rp->PatternTypeSpecific == olSaturday)
				i_cal_recurrence_set_by_day (rt, 0, I_CAL_SATURDAY_WEEKDAY);
			else {
				post_process = TRUE;
			}

			/* RecurrenceN */
			if (!post_process) {
				i_cal_recurrence_set_by_set_pos (rt, 0, get_ical_pos (rp->N));
				if (i_cal_recurrence_get_by_set_pos (rt, 0) == 0)
					goto cleanup;
			} else {
				if (rp->PatternTypeSpecific == (olSunday | olMonday | olTuesday | olWednesday | olThursday | olFriday | olSaturday)) {
					i_cal_recurrence_set_by_month_day (rt, 0, get_ical_pos (rp->N));
					if (i_cal_recurrence_get_by_month_day (rt, 0) == 0)
						goto cleanup;
				} else {
				/* FIXME: Can we/LibICAL support any other types here? Namely, weekday and weekend-day */
					g_warning ("Encountered a recurrence type Evolution cannot handle. ");
					goto cleanup;
				}
			}
		}

	} else if (rp->RecurFrequency == RecurFrequency_Yearly) {
		i_cal_recurrence_set_freq (rt, I_CAL_YEARLY_RECURRENCE);

		if (rp->PatternType == PatternType_Month) {
			/* Yearly on day D of month M */

			check_calendar = TRUE;

			/* INTERVAL */
			i_cal_recurrence_set_interval (rt, (short) (rp->Period / 12));

		} else if (rp->PatternType == PatternType_MonthNth) {
			/* Yearly on the Xth Y of month M */

			g_warning ("Encountered a recurrence pattern Evolution cannot handle.");

			/* TODO: Add support for this kinda recurrence in Evolution */
			goto cleanup;
		}
	} else
		goto cleanup;

	/* Process by_day<->PatternTypeSpecific bitmasks for events that can
	 * occur on multiple days in a recurrence */
	if ( (rp->RecurFrequency == RecurFrequency_Daily &&
              rp->PatternType == PatternType_Week) ||
	     (rp->RecurFrequency == RecurFrequency_Weekly &&
	      rp->PatternType == PatternType_Week) ) {
		i = 0;
		if (rp->PatternTypeSpecific & olSunday)
			i_cal_recurrence_set_by_day (rt, i++, I_CAL_SUNDAY_WEEKDAY);
		if (rp->PatternTypeSpecific & olMonday)
			i_cal_recurrence_set_by_day (rt, i++, I_CAL_MONDAY_WEEKDAY);
		if (rp->PatternTypeSpecific & olTuesday)
			i_cal_recurrence_set_by_day (rt, i++, I_CAL_TUESDAY_WEEKDAY);
		if (rp->PatternTypeSpecific & olWednesday)
			i_cal_recurrence_set_by_day (rt, i++, I_CAL_WEDNESDAY_WEEKDAY);
		if (rp->PatternTypeSpecific & olThursday)
			i_cal_recurrence_set_by_day (rt, i++, I_CAL_THURSDAY_WEEKDAY);
		if (rp->PatternTypeSpecific & olFriday)
			i_cal_recurrence_set_by_day (rt, i++, I_CAL_FRIDAY_WEEKDAY);
		if (rp->PatternTypeSpecific & olSaturday)
			i_cal_recurrence_set_by_day (rt, i++, I_CAL_SATURDAY_WEEKDAY);
	}

	/* Only some calendar types supported */
	if (check_calendar && !check_calendar_type (rp->CalendarType))
		goto cleanup;

	/* End Type - followed by Occurence count */
	if (rp->EndType == END_AFTER_N_OCCURRENCES) {
		i_cal_recurrence_set_count (rt, rp->OccurrenceCount);
	}

	/* week_start */
	i_cal_recurrence_set_week_start (rt, get_ical_weekstart (rp->FirstDOW));

	/* number of exceptions */
	if (rp->DeletedInstanceCount) {
		for (i = 0; i < rp->DeletedInstanceCount; ++i) {
			ICalTime *tt;
			time_t ictime = convert_recurrence_minutes_to_timet (rp->DeletedInstanceDates[i]);

			tt = i_cal_time_new_from_timet_with_zone (ictime, 1, NULL);

			exdate_list = g_slist_append (exdate_list, e_cal_component_datetime_new_take (tt, g_strdup ("UTC")));
		}
	}

	/* end date */
	if (rp->EndType == END_AFTER_DATE) {
		ICalTime *itt;

		time_t ict = convert_recurrence_minutes_to_timet (rp->EndDate);

		itt = i_cal_time_new_from_timet_with_zone (ict, 1, NULL);
		i_cal_recurrence_set_until (rt, itt);
		g_clear_object (&itt);
	}

	/* Set the recurrence */
	{
		GSList l;

		l.data = rt;
		l.next = NULL;

		e_cal_component_set_rrules (comp, &l);
		e_cal_component_set_exdates (comp, exdate_list);
	}

	g_slist_free_full (exdate_list, e_cal_component_datetime_free);
	g_clear_object (&rt);

	/* Modified exceptions */
	if (arp.ExceptionCount && extra_detached) {
		ECalComponent **detached = g_new0 (ECalComponent *,
		                                   arp.ExceptionCount);
		ICalTime *tt;
		ECalComponentDateTime *edt;
		ECalComponentRange *rid;

		e_cal_component_commit_sequence (comp);

		for (i = 0; i < arp.ExceptionCount; i++) {
			struct ema_ExceptionInfo *ei = &arp.ExceptionInfo[i];
			struct ema_ExtendedException *ee = &arp.ExtendedException[i];
			/* make a shallow clone of comp */
			detached[i] = e_cal_component_clone (comp);

			tt = i_cal_time_new_from_timet_with_zone (convert_recurrence_minutes_to_timet (ei->OriginalStartDate), 0, NULL);
			rid = e_cal_component_range_new_take (E_CAL_COMPONENT_RANGE_SINGLE,
				e_cal_component_datetime_new_take (tt, g_strdup (recur_zone ? i_cal_timezone_get_tzid (recur_zone) : "UTC")));
			e_cal_component_set_recurid (detached[i], rid);
			e_cal_component_range_free (rid);

			tt = i_cal_time_new_from_timet_with_zone (convert_recurrence_minutes_to_timet (ei->StartDateTime), 0, NULL);
			edt = e_cal_component_datetime_new_take (tt, g_strdup (recur_zone ? i_cal_timezone_get_tzid (recur_zone) : "UTC"));
			e_cal_component_set_dtstart (detached[i], edt);
			e_cal_component_datetime_free (edt);

			tt = i_cal_time_new_from_timet_with_zone (convert_recurrence_minutes_to_timet (ei->EndDateTime), 0, NULL);
			edt = e_cal_component_datetime_new_take (tt, g_strdup (recur_zone ? i_cal_timezone_get_tzid (recur_zone) : "UTC"));
			e_cal_component_set_dtend (detached[i], edt);
			e_cal_component_datetime_free (edt);

			e_cal_component_set_rdates (detached[i], NULL);
			e_cal_component_set_rrules (detached[i], NULL);
			e_cal_component_set_exdates (detached[i], NULL);
			e_cal_component_set_exrules (detached[i], NULL);

			if (ee->WideCharSubject) {
				ECalComponentText *txt;
				gchar *str;

				str = g_convert (ee->WideCharSubject,
				                 2 * ee->WideCharSubjectLength,
				                 "UTF-8", "UTF-16", NULL, NULL,
				                 NULL);
				txt = e_cal_component_text_new (str ? str : "", NULL);
				e_cal_component_set_summary (detached[i], txt);
				e_cal_component_text_free (txt);
				g_free (str);
			} else if (ei->Subject) {
				ECalComponentText *txt;

				txt = e_cal_component_text_new (ei->Subject, NULL);
				e_cal_component_set_summary (detached[i], txt);
				e_cal_component_text_free (txt);
			}

			/* FIXME: Handle MeetingType */
			/* FIXME: Handle ReminderDelta */
			/* FIXME: Handle Reminder */

			if (ee->WideCharLocation) {
				gchar *str;

				/* LocationLength */
				str = g_convert (ee->WideCharLocation,
				                 2 * ee->WideCharLocationLength,
				                 "UTF-8", "UTF-16", NULL, NULL,
				                 NULL);
				e_cal_component_set_location (detached[i], str);
				g_free (str);
			} else if (ei->Location) {
				e_cal_component_set_location (detached[i], ei->Location);
			}

			/* FIXME: Handle BusyStatus? */
			/* FIXME: Handle Attachment? */
			/* FIXME: Handle SubType? */
			/* FIXME: Handle AppointmentColor? */
			/* FIXME: do we do anything with ChangeHighlight? */

			*extra_detached = g_slist_append (*extra_detached,
			                                  detached[i]);
		}
		g_free (detached);
	}

	success = TRUE;
cleanup:
	free_arp_contents (&arp);
	return success;
}

static guint32
compute_startdate (ECalComponent *comp)
{
	ECalComponentDateTime *dtstart;
	ICalTime *itt;
	guint32 flag32;

	dtstart = e_cal_component_get_dtstart (comp);
	if (!dtstart)
		return 0;

	itt = e_cal_component_datetime_get_value (dtstart);
	i_cal_time_set_time (itt, 0, 0, 0);

	flag32 = convert_timet_to_recurrence_minutes (i_cal_time_as_timet_with_zone (itt, NULL));

	e_cal_component_datetime_free (dtstart);

	return flag32;
}

static guint32
compute_rdaily_firstdatetime (ECalComponent *comp,
			      guint32 period)
{
	return (compute_startdate (comp) % period);
}

static guint32
compute_rweekly_firstdatetime (ECalComponent *comp,
			       ICalRecurrenceWeekday week_start,
			       guint32 period)
{
	ECalComponentDateTime *dtstart;
	ICalTime *itt;
	guint32 flag32;
	gint cur_weekday = 0, weekstart_weekday = 0, diff = 0;
	time_t t;

	dtstart = e_cal_component_get_dtstart (comp);
	if (!dtstart)
		return 0;

	itt = e_cal_component_datetime_get_value (dtstart);
	i_cal_time_set_time (itt, 0, 0, 0);
	cur_weekday = i_cal_time_day_of_week (itt);
	t = i_cal_time_as_timet_with_zone (itt, NULL);
	e_cal_component_datetime_free (dtstart);

	switch (week_start) {
	case I_CAL_SUNDAY_WEEKDAY:
		weekstart_weekday = 1; break;
	case I_CAL_MONDAY_WEEKDAY:
		weekstart_weekday = 2; break;
	case I_CAL_TUESDAY_WEEKDAY:
		weekstart_weekday = 3; break;
	case I_CAL_WEDNESDAY_WEEKDAY:
		weekstart_weekday = 4; break;
	case I_CAL_THURSDAY_WEEKDAY:
		weekstart_weekday = 5; break;
	case I_CAL_FRIDAY_WEEKDAY:
		weekstart_weekday = 6; break;
	case I_CAL_SATURDAY_WEEKDAY:
		weekstart_weekday = 7; break;
	default:
		weekstart_weekday = 1; break;
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
compute_rmonthly_firstdatetime (ECalComponent *comp,
				guint32 period)
{
	const guint8 dinm[] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	ECalComponentDateTime *dtstart;
	ICalTime *itt;
	guint32 flag32, monthindex, i;

	dtstart = e_cal_component_get_dtstart (comp);
	if (!dtstart)
		return 0;
	itt = e_cal_component_datetime_get_value (dtstart);
	monthindex = (guint32)((((guint64)(12) * (i_cal_time_get_year (itt)- 1601)) + (i_cal_time_get_month (itt) - 1)) % period);
	e_cal_component_datetime_free (dtstart);

	for (flag32 = 0, i = 0; i < monthindex; ++i)
		flag32 += dinm[(i % 12) + 1] * 24 * 60;

	return flag32;
}

static guint32
calculate_no_of_occurrences (ECalComponent *comp,
			     ICalRecurrence *rt)
{
	ECalComponentDateTime *dtstart;
	ICalRecurIterator *iter;
	ICalTime *next, *prev = NULL;
	guint32 count = 1;

	dtstart = e_cal_component_get_dtstart (comp);
	if (!dtstart)
		return 1;

	iter = i_cal_recur_iterator_new (rt, e_cal_component_datetime_get_value (dtstart));
	if (iter) {
		for (next = i_cal_recur_iterator_next (iter);
		     next && !i_cal_time_is_null_time (next);
		     g_object_unref (next), next = i_cal_recur_iterator_next (iter)) {
			if (prev && !i_cal_time_is_null_time (prev) &&
			    i_cal_time_compare (next, prev) == 0)
				break;

			g_clear_object (&prev);
			prev = i_cal_time_clone (next);

			count++;
		}

		g_clear_object (&iter);
		g_clear_object (&prev);
		g_clear_object (&next);
	}

	e_cal_component_datetime_free (dtstart);

	return count;
}

static gint
compare_guint32 (gconstpointer a,
		 gconstpointer b,
		 gpointer user_data)
{
	return (*((guint32 *) a) - *((guint32 *) b));
}

gboolean
e_mapi_cal_util_rrule_to_bin (ECalComponent *comp,
			      struct SBinary_short *bin,
			      TALLOC_CTX *mem_ctx)
{
	ICalRecurrence *rt;
	ICalTime *until;
	gint i;
	GSList *rrule_list, *exdate_list;
	GByteArray *ba = NULL;
	struct ema_AppointmentRecurrencePattern arp;
	struct ema_RecurrencePattern *rp; /* Convenience ptr */

	g_return_val_if_fail (comp != NULL, FALSE);
	g_return_val_if_fail (bin != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);

	if (!e_cal_component_has_recurrences (comp))
		return FALSE;

	rrule_list = e_cal_component_get_rrules (comp);
	if (g_slist_length (rrule_list) != 1) {
		g_slist_free_full (rrule_list, g_object_unref);
		return FALSE;
	}

	exdate_list = e_cal_component_get_exdates (comp);

	rt = rrule_list->data;

	ba = g_byte_array_new ();
	memset (&arp, 0, sizeof (struct ema_AppointmentRecurrencePattern));
	rp = &arp.RecurrencePattern;

	/* Reader Version */
	rp->ReaderVersion = READER_VERSION;
	rp->WriterVersion = WRITER_VERSION;

	/* Calendar Type */
	rp->CalendarType = CAL_DEFAULT;

	if (i_cal_recurrence_get_freq (rt) == I_CAL_DAILY_RECURRENCE) {
		rp->RecurFrequency = RecurFrequency_Daily;

		/* Pattern Type - it would be PatternType_Day since we have
		 * only "Daily every N days". The other type would be
		 * parsed as a weekly recurrence. */
		rp->PatternType = PatternType_Day;

		/* FirstDateTime */
		rp->FirstDateTime = compute_rdaily_firstdatetime (comp, (i_cal_recurrence_get_interval (rt) * (60 * 24)));

		/* INTERVAL */
		rp->Period = (i_cal_recurrence_get_interval (rt) * (60 * 24));

		/* No PatternTypeSpecific for PatternType_Day */

	} else if (i_cal_recurrence_get_freq (rt) == I_CAL_WEEKLY_RECURRENCE) {
		rp->RecurFrequency = RecurFrequency_Weekly;

		/* Pattern Type - it would be PatternType_Week since we don't
		 * support any other type. */
		rp->PatternType = PatternType_Week;

		/* FirstDateTime */
		rp->FirstDateTime = compute_rweekly_firstdatetime (comp, i_cal_recurrence_get_week_start (rt), (i_cal_recurrence_get_interval (rt) * (60 * 24 * 7)));

		/* INTERVAL */
		rp->Period = i_cal_recurrence_get_interval (rt);

		/* BITMASK */
		for (i = 0; i < I_CAL_BY_DAY_SIZE; ++i) {
			if (i_cal_recurrence_get_by_day (rt, i) == I_CAL_SUNDAY_WEEKDAY)
				rp->PatternTypeSpecific |= olSunday;
			else if (i_cal_recurrence_get_by_day (rt, i) == I_CAL_MONDAY_WEEKDAY)
				rp->PatternTypeSpecific |= olMonday;
			else if (i_cal_recurrence_get_by_day (rt, i) == I_CAL_TUESDAY_WEEKDAY)
				rp->PatternTypeSpecific |= olTuesday;
			else if (i_cal_recurrence_get_by_day (rt, i) == I_CAL_WEDNESDAY_WEEKDAY)
				rp->PatternTypeSpecific |= olWednesday;
			else if (i_cal_recurrence_get_by_day (rt, i) == I_CAL_THURSDAY_WEEKDAY)
				rp->PatternTypeSpecific |= olThursday;
			else if (i_cal_recurrence_get_by_day (rt, i) == I_CAL_FRIDAY_WEEKDAY)
				rp->PatternTypeSpecific |= olFriday;
			else if (i_cal_recurrence_get_by_day (rt, i) == I_CAL_SATURDAY_WEEKDAY)
				rp->PatternTypeSpecific |= olSaturday;
			else
				break;
		}

	} else if (i_cal_recurrence_get_freq (rt) == I_CAL_MONTHLY_RECURRENCE) {
		guint16 pattern = 0x0; guint32 mask = 0x0, flag = 0x0;

		rp->RecurFrequency = RecurFrequency_Monthly;

		if (i_cal_recurrence_get_by_month_day (rt, 0) >= 1 && i_cal_recurrence_get_by_month_day (rt, 0) <= 31) {
			pattern = PatternType_Month;
			flag = i_cal_recurrence_get_by_month_day (rt, 0);
		} else if (i_cal_recurrence_get_by_month_day (rt, 0) == -1) {
			pattern = PatternType_MonthNth;
			mask = (olSunday | olMonday | olTuesday | olWednesday | olThursday | olFriday | olSaturday);
			flag = RecurrenceN_Last;
		} else if (i_cal_recurrence_get_by_day (rt, 0) >= I_CAL_SUNDAY_WEEKDAY && i_cal_recurrence_get_by_day (rt, 0) <= I_CAL_SATURDAY_WEEKDAY) {
			pattern = PatternType_MonthNth;
			mask = get_mapi_day (i_cal_recurrence_get_by_day (rt, 0));
			flag = get_mapi_pos (i_cal_recurrence_get_by_set_pos (rt, 0));
		}

		rp->PatternType = pattern;

		/* FirstDateTime */
		rp->FirstDateTime = compute_rmonthly_firstdatetime (comp, i_cal_recurrence_get_interval (rt));

		/* INTERVAL */
		rp->Period = i_cal_recurrence_get_interval (rt);

		if (pattern == PatternType_Month) {
			rp->N = flag;
		} else if (pattern == PatternType_MonthNth) {
			rp->PatternTypeSpecific = mask;
			rp->N = flag;
		}

		/* Warn for different cases where we might be sending
		 * untranslatable values */
		if ( (pattern == PatternType_Month && !(flag)) ||
		     (pattern == PatternType_MonthNth && !(flag && mask)) ||
		     (pattern != PatternType_Month && pattern != PatternType_MonthNth) ) {
			g_warning ("Possibly setting incorrect values in the stream. ");
		}

	} else if (i_cal_recurrence_get_freq (rt) == I_CAL_YEARLY_RECURRENCE) {
		rp->RecurFrequency = RecurFrequency_Yearly;

		/* Pattern Type - it would be PatternType_Month since we don't
		 * support any other type. */
		rp->PatternType = PatternType_Month;

		/* FirstDateTime - uses the same function as monthly
		 * recurrence */
		rp->FirstDateTime = compute_rmonthly_firstdatetime (comp, 0xC);

		/* INTERVAL - should be 12 for yearly recurrence */
		rp->Period = 0xC;

		/* MONTH_DAY */
		{
			ECalComponentDateTime *dtstart;
			dtstart = e_cal_component_get_dtstart (comp);
			rp->PatternTypeSpecific = (dtstart && e_cal_component_datetime_get_value (dtstart)) ?
				i_cal_time_get_day (e_cal_component_datetime_get_value (dtstart)) : 0;
			e_cal_component_datetime_free (dtstart);
		}
	}

	until = i_cal_recurrence_get_until (rt);

	/* End Type followed by Occurence count */
	if (until && !i_cal_time_is_null_time (until)) {
		rp->EndType = END_AFTER_DATE;
		rp->OccurrenceCount = calculate_no_of_occurrences (comp, rt);
	} else if (i_cal_recurrence_get_count (rt)) {
		rp->EndType = END_AFTER_N_OCCURRENCES;
		rp->OccurrenceCount = i_cal_recurrence_get_count (rt);
	} else {
		rp->EndType = END_NEVER_END;
	}

	g_clear_object (&until);

	/* FirstDOW */
	rp->FirstDOW = get_mapi_weekstart (i_cal_recurrence_get_week_start (rt));

	/* DeletedInstanceDates */
	rp->DeletedInstanceCount = g_slist_length (exdate_list);
	if (rp->DeletedInstanceCount) {
		GSList *l;
		ECalComponentDateTime *dt;
		rp->DeletedInstanceDates = g_new0(guint32,
		                              rp->DeletedInstanceCount);
		/* FIXME: This should include modified dates */
		for (i = 0, l = exdate_list; l; ++i, l = l->next) {
			ICalTime *itt;

			dt = l->data;

			itt = e_cal_component_datetime_get_value (dt);
			if (!itt)
				continue;

			i_cal_time_set_time (itt, 0, 0, 0);

			rp->DeletedInstanceDates[i] = convert_timet_to_recurrence_minutes (i_cal_time_as_timet_with_zone (itt, NULL));
		}

		g_qsort_with_data (rp->DeletedInstanceDates,
		                   rp->DeletedInstanceCount,
		                   sizeof (guint32), compare_guint32, NULL);
	}

	/* FIXME: Add support for modified instances
	 * (currently we send valid data saying no modified instances) */

	/* StartDate */
	rp->StartDate = compute_startdate (comp);

	/* EndDate */
	{
		if (rp->EndType == END_NEVER_END)
			/* FIXME: named prop here? */
			rp->EndDate = 0x5AE980DF;
		else if (rp->EndType == END_AFTER_N_OCCURRENCES) {
			ECalComponentDateTime *dtstart;
			ICalTime *itt;
			gchar *rrule_str = i_cal_recurrence_to_string (rt);
			GArray *array;

			dtstart = e_cal_component_get_dtstart (comp);
			itt = e_cal_component_datetime_get_value (dtstart);
			i_cal_time_set_time (itt, 0, 0, 0);

			array = i_cal_recur_expand_recurrence (rrule_str, i_cal_time_as_timet_with_zone (itt, NULL), i_cal_recurrence_get_count (rt));
			if (array) {
				rp->EndDate = convert_timet_to_recurrence_minutes (g_array_index (array, time_t, i_cal_recurrence_get_count (rt) - 1));
				g_array_unref (array);
			} else {
				g_warn_if_reached ();
			}

			g_free (rrule_str);
			e_cal_component_datetime_free (dtstart);
		} else if (rp->EndType == END_AFTER_DATE) {
			until = i_cal_recurrence_get_until (rt);
			i_cal_time_set_time (until, 0, 0, 0);

			rp->EndDate = convert_timet_to_recurrence_minutes (i_cal_time_as_timet_with_zone (until, NULL));
			g_clear_object (&until);
		}
	}

	/* Reader Version 2 */
	arp.ReaderVersion2 = READER_VERSION2;
	/* Writer Version 2 */
	arp.WriterVersion2 = WRITER_VERSION2;

	/* StartTimeOffset */
	{
		ECalComponentDateTime *dtstart;
		ICalTime *itt;

		dtstart = e_cal_component_get_dtstart (comp);
		itt = e_cal_component_datetime_get_value (dtstart);

		arp.StartTimeOffset = (i_cal_time_get_hour (itt) * 60) + i_cal_time_get_minute (itt);
		e_cal_component_datetime_free (dtstart);
	}

	/* EndTimeOffset */
	{
		ECalComponentDateTime *dtend;
		ICalTime *itt;

		dtend = e_cal_component_get_dtend (comp);
		itt = e_cal_component_datetime_get_value (dtend);
		arp.EndTimeOffset = (i_cal_time_get_hour (itt) * 60) + i_cal_time_get_minute (itt);
		e_cal_component_datetime_free (dtend);
	}

	/* FIXME: Add ExceptionInfo here */
	/* FIXME: Add the ExtendedExceptionInfo here */

	/* Reserved Block 2 Size */
	arp_to_gba (&arp, ba);

	free_arp_contents (&arp);
	g_slist_free_full (exdate_list, e_cal_component_datetime_free);
	g_slist_free_full (rrule_list, g_object_unref);

	/*g_print ("\n== ICAL to MAPI == The recurrence blob data is as follows:\n");
	for (i = 0; i < ba->len; ++i)
		g_print ("0x%02X ", ba->data[i]);
	g_print("\n== End of stream ==\n");*/

	bin->cb = ba->len;
	bin->lpb = talloc_memdup (mem_ctx, ba->data, ba->len);

	g_byte_array_free (ba, TRUE);

	return TRUE;
}
