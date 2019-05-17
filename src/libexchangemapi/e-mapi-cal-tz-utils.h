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

#ifndef E_MAPI_CAL_TZ_UTILS_H
#define E_MAPI_CAL_TZ_UTILS_H

#include <glib.h>
#include <libecal/libecal.h>

#include "e-mapi-connection.h"

G_BEGIN_DECLS

const gchar *	e_mapi_cal_tz_util_get_mapi_equivalent	(const gchar *ical_tz_location);
const gchar *	e_mapi_cal_tz_util_get_ical_equivalent	(const gchar *mapi_tz_location);
const gchar *	e_mapi_cal_tz_util_ical_from_zone_struct(const guint8 *lpb,
							 guint32 cb);
gboolean	e_mapi_cal_tz_util_populate		(void);
void		e_mapi_cal_tz_util_destroy		(void);
void		e_mapi_cal_tz_util_dump			(void);
void		e_mapi_cal_util_mapi_tz_to_bin		(const gchar *mapi_tzid,
							 struct SBinary_short *bin,
							 TALLOC_CTX *mem_ctx,
							 gboolean is_recur);
int		e_mapi_cal_util_mapi_tz_pidlidtimezone	(ICalTimezone *ictz);
gchar *		e_mapi_cal_util_bin_to_mapi_tz		(const guint8 *lpb, guint32 cb);

G_END_DECLS

#endif
