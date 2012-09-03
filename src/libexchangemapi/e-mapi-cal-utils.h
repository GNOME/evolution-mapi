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

#ifndef E_MAPI_CAL_UTILS_H
#define E_MAPI_CAL_UTILS_H

#include <libecal/libecal.h>

#include "e-mapi-connection.h"
#include "e-mapi-defs.h"
#include "e-mapi-utils.h"

#include "e-mapi-cal-tz-utils.h"
#include "e-mapi-cal-recur-utils.h"

G_BEGIN_DECLS

typedef enum {
	NOT_A_MEETING		= (1 << 0),
	MEETING_OBJECT		= (1 << 1),
	MEETING_OBJECT_SENT	= (1 << 2),
	MEETING_OBJECT_RCVD	= (1 << 3),
	MEETING_REQUEST		= (1 << 4),
	MEETING_REQUEST_RCVD	= (1 << 5),
	MEETING_RESPONSE	= (1 << 6),
	MEETING_RESPONSE_RCVD	= (1 << 7),
	MEETING_CANCEL		= (1 << 8),
	MEETING_CANCEL_RCVD	= (1 << 9)
} MAPIMeetingOptions;

struct cal_cbdata {
	gint kind;
	ECalComponent *comp;
	gboolean is_modify;

	/* These are appt specific data */
	MAPIMeetingOptions meeting_type;
	uint32_t appt_id;
	uint32_t appt_seq;
	struct SBinary_short *globalid;
	struct SBinary_short *cleanglobalid;

	uint32_t msgflags;
	OlResponseStatus resp;
	gchar *username;
	gchar *useridtype;
	gchar *userid;
	gchar *ownername;
	gchar *owneridtype;
	gchar *ownerid;

	/* custom callback to get timezone from a backend */
	gpointer get_tz_data;
	icaltimezone * (*get_timezone)(gpointer get_tz_data, const gchar *tzid);
};

void		e_mapi_cal_util_generate_globalobjectid		(gboolean is_clean,
								 const gchar *uid,
								 const struct timeval *exception_replace_time,
								 const struct FILETIME *creation_time,
								 struct SBinary_short *sb);

uint32_t	e_mapi_cal_util_get_new_appt_id			(EMapiConnection *conn,
								 mapi_id_t fid);

gboolean	e_mapi_cal_utils_get_free_busy_data		(EMapiConnection *conn,
								 const GSList *users,
								 time_t start,
								 time_t end,
								 GSList **freebusy,
								 GCancellable *cancellable,
								 GError **mapi_error);

ECalComponent *	e_mapi_cal_util_object_to_comp			(EMapiConnection *conn,
								 EMapiObject *object,
								 icalcomponent_kind kind,
								 gboolean is_reply,
								 const gchar *local_store_uri,
								 const gchar *use_uid,
								 GSList **detached_components);

gboolean	e_mapi_cal_utils_comp_to_object			(EMapiConnection *conn,
								 TALLOC_CTX *mem_ctx,
								 EMapiObject **pobject, /* out */
								 gpointer user_data,
								 GCancellable *cancellable,
								 GError **perror);

gchar *		e_mapi_cal_utils_get_icomp_x_prop		(icalcomponent *comp,
								 const gchar *key);

G_END_DECLS

#endif
