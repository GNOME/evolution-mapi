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

#ifndef E_CAL_BACKEND_MAPI_H
#define E_CAL_BACKEND_MAPI_H

#include <glib.h>

#include <libedata-cal/libedata-cal.h>

G_BEGIN_DECLS

#define E_TYPE_CAL_BACKEND_MAPI            (e_cal_backend_mapi_get_type ())
#define E_CAL_BACKEND_MAPI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), E_TYPE_CAL_BACKEND_MAPI,	ECalBackendMAPI))
#define E_CAL_BACKEND_MAPI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), E_TYPE_CAL_BACKEND_MAPI,	ECalBackendMAPIClass))
#define E_IS_CAL_BACKEND_MAPI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), E_TYPE_CAL_BACKEND_MAPI))
#define E_IS_CAL_BACKEND_MAPI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), E_TYPE_CAL_BACKEND_MAPI))

typedef struct _ECalBackendMAPI        ECalBackendMAPI;
typedef struct _ECalBackendMAPIClass   ECalBackendMAPIClass;
typedef struct _ECalBackendMAPIPrivate ECalBackendMAPIPrivate;

struct _ECalBackendMAPI {
	ECalBackend backend;

	/* Private data */
	ECalBackendMAPIPrivate *priv;
};

struct _ECalBackendMAPIClass {
	ECalBackendClass parent_class;
};

GType	e_cal_backend_mapi_get_type(void);

G_END_DECLS

#endif /* E_CAL_BACKEND_MAPI_H */
