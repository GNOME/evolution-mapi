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

#ifndef EXCHANGE_MAPI_CAL_UTILS_H
#define EXCHANGE_MAPI_CAL_UTILS_H

#include <libecal/e-cal-component.h>

#include "exchange-mapi-connection.h"
#include "exchange-mapi-defs.h"
#include "exchange-mapi-utils.h"

#include "exchange-mapi-cal-tz-utils.h"
#include "exchange-mapi-cal-recur-utils.h"

G_BEGIN_DECLS

typedef enum {
	NOT_A_MEETING 		= (1 << 0), 
	MEETING_OBJECT 		= (1 << 1), 
	MEETING_OBJECT_SENT 	= (1 << 2), 
	MEETING_OBJECT_RCVD 	= (1 << 3), 
	MEETING_REQUEST 	= (1 << 4), 
	MEETING_REQUEST_RCVD 	= (1 << 5), 
	MEETING_RESPONSE 	= (1 << 6), 
	MEETING_RESPONSE_RCVD 	= (1 << 7), 
	MEETING_CANCEL 		= (1 << 8), 
	MEETING_CANCEL_RCVD 	= (1 << 9) 
} MAPIMeetingOptions;

struct cbdata { 
	ECalComponent *comp;
	struct SPropValue *props;
	gboolean is_modify;

	/* These are appt specific data */ 
	MAPIMeetingOptions meeting_type;
	uint32_t appt_id;
	uint32_t appt_seq;
	const struct Binary_r *globalid;
	const struct Binary_r *cleanglobalid;

	uint32_t msgflags;
	OlResponseStatus resp; 
	const char *username;
	const char *useridtype;
	const char *userid;
	const char *ownername;
	const char *owneridtype;
	const char *ownerid;

	/* custom callback to get timezone from a backend */
	gpointer get_tz_data;
	icaltimezone * (*get_timezone)(gpointer get_tz_data, const gchar *tzid);
};

void
exchange_mapi_cal_util_fetch_organizer (ECalComponent *comp, GSList **recip_list);
void
exchange_mapi_cal_util_fetch_recipients (ECalComponent *comp, GSList **recip_list);
void
exchange_mapi_cal_util_fetch_attachments (ECalComponent *comp, GSList **attach_list, const char *local_store_uri);

ECalComponent *
exchange_mapi_cal_util_mapi_props_to_comp (icalcomponent_kind kind, const gchar *mid, struct mapi_SPropValue_array *properties, 
					   GSList *streams, GSList *recipients, GSList *attachments, 
					   const char *local_store_uri, const icaltimezone *default_zone);
gboolean
exchange_mapi_cal_util_build_name_id (struct mapi_nameid *nameid, gpointer data);

int
exchange_mapi_cal_util_build_props (struct SPropValue **value, struct SPropTagArray *proptag_array, gpointer data);

void
exchange_mapi_cal_util_generate_globalobjectid (gboolean is_clean, const char *uid, struct Binary_r *sb);

gchar *
exchange_mapi_cal_util_camel_helper (struct mapi_SPropValue_array *properties, 
				   GSList *streams, GSList *recipients, GSList *attachments);

uint32_t
exchange_mapi_cal_util_get_new_appt_id (mapi_id_t fid);

static const uint32_t cal_GetPropsList[] = {
	PR_FID, 
	PR_MID, 

	PR_SUBJECT, 
	PR_SUBJECT_UNICODE, 
	PR_NORMALIZED_SUBJECT, 
	PR_NORMALIZED_SUBJECT_UNICODE, 
	PR_CONVERSATION_TOPIC, 
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

	PR_SENT_REPRESENTING_NAME, 
	PR_SENT_REPRESENTING_NAME_UNICODE, 
	PR_SENT_REPRESENTING_ADDRTYPE, 
	PR_SENT_REPRESENTING_ADDRTYPE_UNICODE, 
	PR_SENT_REPRESENTING_EMAIL_ADDRESS, 
	PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE, 

	PR_SENDER_NAME, 
	PR_SENDER_NAME_UNICODE, 
	PR_SENDER_ADDRTYPE, 
	PR_SENDER_ADDRTYPE_UNICODE, 
	PR_SENDER_EMAIL_ADDRESS, 
	PR_SENDER_EMAIL_ADDRESS_UNICODE, 

	PR_RCVD_REPRESENTING_NAME, 
	PR_RCVD_REPRESENTING_NAME_UNICODE, 
	PR_RCVD_REPRESENTING_ADDRTYPE, 
	PR_RCVD_REPRESENTING_ADDRTYPE_UNICODE, 
	PR_RCVD_REPRESENTING_EMAIL_ADDRESS, 
	PR_RCVD_REPRESENTING_EMAIL_ADDRESS_UNICODE
};

static const uint32_t cal_IDList[] = {
	PR_FID, 
	PR_MID,
	PR_LAST_MODIFICATION_TIME
};

G_END_DECLS

#endif
