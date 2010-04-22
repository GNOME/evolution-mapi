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
	const gchar *username;
	const gchar *useridtype;
	const gchar *userid;
	const gchar *ownername;
	const gchar *owneridtype;
	const gchar *ownerid;

	/* custom callback to get timezone from a backend */
	gpointer get_tz_data;
	icaltimezone * (*get_timezone)(gpointer get_tz_data, const gchar *tzid);
};

void
exchange_mapi_cal_util_fetch_organizer (ECalComponent *comp, GSList **recip_list);
void
exchange_mapi_cal_util_fetch_recipients (ECalComponent *comp, GSList **recip_list);
void
exchange_mapi_cal_util_fetch_attachments (ECalComponent *comp, GSList **attach_list, const gchar *local_store_uri);

ECalComponent *
exchange_mapi_cal_util_mapi_props_to_comp (ExchangeMapiConnection *conn, icalcomponent_kind kind, const gchar *mid, struct mapi_SPropValue_array *properties,
					   GSList *streams, GSList *recipients, GSList *attachments,
					   const gchar *local_store_uri, const icaltimezone *default_zone);

void
exchange_mapi_cal_util_generate_globalobjectid (gboolean is_clean, const gchar *uid, struct Binary_r *sb);

gchar *
exchange_mapi_cal_util_camel_helper (ExchangeMapiConnection *conn, mapi_id_t fid, mapi_id_t mid, const gchar *msg_class,
				   GSList *streams, GSList *recipients, GSList *attachments);

uint32_t
exchange_mapi_cal_util_get_new_appt_id (ExchangeMapiConnection *conn, mapi_id_t fid);

gboolean exchange_mapi_cal_utils_add_named_ids (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gint pkind);
gboolean exchange_mapi_cal_utils_get_props_cb (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data);
gboolean exchange_mapi_cal_utils_write_props_cb (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropValue **values, uint32_t *n_values, gpointer data);

G_END_DECLS

#endif
