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

#ifndef E_MAPI_CAL_RECUR_UTILS_H
#define E_MAPI_CAL_RECUR_UTILS_H

#include <glib.h>

#include "e-mapi-cal-utils.h"

G_BEGIN_DECLS

gboolean	e_mapi_cal_util_bin_to_rrule (GByteArray *ba, ECalComponent *comp, GSList **extra_detached, icaltimezone *recur_zone);

GByteArray *	e_mapi_cal_util_rrule_to_bin (ECalComponent *comp, GSList *modified_comps);

G_END_DECLS

#endif

