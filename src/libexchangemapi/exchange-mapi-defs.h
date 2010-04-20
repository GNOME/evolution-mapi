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

/* Someday, all these definitions should be pushed in libmapi/mapidefs.h */
/* NOTE: Some of the enumerations are commented out since they conflict
 *       with libmapi/mapidefs.h */

#ifndef EXCHANGE_MAPI_DEFS_H
#define EXCHANGE_MAPI_DEFS_H

G_BEGIN_DECLS

/* GENERAL */
typedef enum {
    olSunday = 1,
    olMonday = 2,
    olTuesday = 4,
    olWednesday = 8,
    olThursday = 16,
    olFriday = 32,
    olSaturday = 64
} OlDaysOfWeek;

typedef enum {
    olNormal = 0,
    olPersonal = 1,
    olPrivate = 2,
    olConfidential = 3
} OlSensitivity;

typedef enum {
    olImportanceLow = 0,
    olImportanceNormal = 1,
    olImportanceHigh = 2
} OlImportance;

typedef enum {
    olOriginator = 0,
    olTo = 1,
    olCC = 2,
    olBCC = 3
} OlMailRecipientType;

typedef enum {
    SingleAppt = 0x0400 ,
    RecurAppt = 0x0401 ,
    SingleMeet = 0x0402 ,
    RecurMeet = 0x0403 ,
    MeetReq = 0x0404 ,
    RespAccept = 0x0405 ,
    RespDecline = 0x0406 ,
    RespTentAccept = 0x0407 ,
    MeetCancel = 0x0408 ,
    MeetInfoUpdate = 0x0409
} IconIndex;

#if 0
typedef enum {
    olEditorText = 1,
    olEditorHTML = 2,
    olEditorRTF = 3,
    olEditorWord = 4
} OlEditorType; /* PR_MESSAGE_EDITOR_FORMAT type */

typedef enum {
    olFolderDeletedItems = 3,
    olFolderOutbox = 4,
    olFolderSentMail = 5,
    olFolderInbox = 6,
    olFolderCalendar = 9,
    olFolderContacts = 10,
    olFolderJournal = 11,
    olFolderNotes = 12,
    olFolderTasks = 13,
    olFolderDrafts = 16,
    olPublicFoldersAllPublicFolders = 18,
    olFolderConflicts = 19,
    olFolderSyncIssues = 20,
    olFolderLocalFailures = 21,
    olFolderServerFailures = 22,
    olFolderJunk = 23,
    olFolderRssFeeds = 25,
    olFolderToDo = 28,
    olFolderManagedEmail = 29
} OlDefaultFolders;

#define	olFolderTopInformationStore	1
#define	olFolderCommonView		8
#define	olFolderFinder			24
#define	olFolderPublicRoot		25
#define	olFolderPublicIPMSubtree	26
#endif

/* APPOINTMENTS */
typedef enum {
    olFree = 0,
    olTentative = 1,
    olBusy = 2,
    olOutOfOffice = 3
} OlBusyStatus; /* Appointment flags with PR_APPOINTMENT_BUSY_STATUS */

typedef enum {
    olOrganizer = 0,
    olRequired = 1,
    olOptional = 2,
    olResource = 3
} OlMeetingRecipientType;

typedef enum {
    olMeetingTentative = 2,
    olMeetingAccepted = 3,
    olMeetingDeclined = 4
} OlMeetingResponse;

typedef enum {
    olResponseNone = 0,
    olResponseOrganized = 1,
    olResponseTentative = 2,
    olResponseAccepted = 3,
    olResponseDeclined = 4,
    olResponseNotResponded = 5
} OlResponseStatus;

typedef enum {
    mtgEmpty =		0x00000000,
    mtgRequest =	0x00000001,
    mtgFull =		0x00010000,
    mtgInfo =		0x00020000,
    mtgOutOfDate =	0x00080000,
    mtgDelegatorCopy =	0x00100000
} MeetingType;

typedef enum {
    olNonMeeting = 0,
    olMeeting = 1,
    olMeetingReceived = 3,
    olMeetingCanceled = 5
} OlMeetingStatus;

typedef enum {
    asfNone = 0,
    asfMeeting = 1,
    asfReceived = 2,
    asfCanceled = 4
} AppointmentStateFlags;

typedef enum {
    olNetMeeting = 0,
    olNetShow = 1,
    olChat = 2
} OlNetMeetingType;

/* TASKS */
typedef enum {
    olTaskNotDelegated = 0,
    olTaskDelegationUnknown = 1,
    olTaskDelegationAccepted = 2,
    olTaskDelegationDeclined = 3
} OlTaskDelegationState;

typedef enum {
    olUpdate = 2,
    olFinalStatus = 3
} OlTaskRecipientType;

typedef enum {
    olTaskSimple = 0,
    olTaskAssign = 1,
    olTaskAccept = 2,
    olTaskDecline = 3
} OlTaskResponse;

#if 0
typedef enum {
    olNewTask = 0,
    olDelegatedTask = 1,
    olOwnTask = 2
} OlTaskOwnership;

typedef enum {
    olTaskNotStarted = 0,
    olTaskInProgress = 1,
    olTaskComplete = 2,
    olTaskWaiting = 3,
    olTaskDeferred = 4
} OlTaskStatus;
#endif

/* NOTES */
#if 0
typedef enum {
    olBlue = 0,
    olGreen = 1,
    olPink = 2,
    olYellow = 3,
    olWhite = 4
} OlNoteColor;
#endif

/* RECURRENCE (APPOINTMENTS/MEETINGS/TASKS) */
typedef enum {
    rectypeNone = 0,
    rectypeDaily = 1,
    rectypeWeekly = 2,
    rectypeMonthly = 3,
    rectypeYearly = 4
} OlRecurrenceType;

typedef enum {
    olApptNotRecurring = 0,
    olApptMaster = 1,
    olApptOccurrence = 2,
    olApptException = 3
} OlRecurrenceState;

#if 0
typedef enum {
    olRecursDaily = 0,
    olRecursWeekly = 1,
    olRecursMonthly = 2,
    olRecursMonthNth = 3,
    olRecursYearly = 5,
    olRecursYearNth = 6
} OlRecurrencePatternType;
#endif

#define IPM_CONTACT				"IPM.Contact"
#define IPM_DISTLIST				"IPM.DistList"
#define IPM_APPOINTMENT				"IPM.Appointment"
#define IPM_SCHEDULE_MEETING_PREFIX		"IPM.Schedule.Meeting."
#define IPM_SCHEDULE_MEETING_REQUEST		"IPM.Schedule.Meeting.Request"
#define IPM_SCHEDULE_MEETING_CANCELED		"IPM.Schedule.Meeting.Canceled"
#define IPM_SCHEDULE_MEETING_RESP_PREFIX	"IPM.Schedule.Meeting.Resp."
#define IPM_SCHEDULE_MEETING_RESP_POS		"IPM.Schedule.Meeting.Resp.Pos"
#define IPM_SCHEDULE_MEETING_RESP_TENT		"IPM.Schedule.Meeting.Resp.Tent"
#define IPM_SCHEDULE_MEETING_RESP_NEG		"IPM.Schedule.Meeting.Resp.Neg"
#define IPM_TASK				"IPM.Task"
#define IPM_STICKYNOTE				"IPM.StickyNote"

G_END_DECLS

#endif
