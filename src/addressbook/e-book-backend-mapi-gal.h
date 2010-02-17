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
 *    Bharath Acharya <abharath@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef __E_BOOK_BACKEND_MAPIGAL_H__
#define __E_BOOK_BACKEND_MAPIGAL_H__

#include <libedata-book/e-book-backend.h>
#include <libedata-book/e-book-backend-sync.h>
#include "exchange-mapi-connection.h"
#include "exchange-mapi-defs.h"
#include "exchange-mapi-utils.h"

typedef struct _EBookBackendMAPIGALPrivate EBookBackendMAPIGALPrivate;

typedef struct {
	EBookBackend             parent_object;
	EBookBackendMAPIGALPrivate *priv;
} EBookBackendMAPIGAL;

typedef struct {
	EBookBackendClass parent_class;
} EBookBackendMAPIGALClass;

EBookBackend *e_book_backend_mapi_gal_new      (void);
GType       e_book_backend_mapi_gal_get_type (void);

#define E_TYPE_BOOK_BACKEND_MAPIGAL        (e_book_backend_mapi_gal_get_type ())
#define E_BOOK_BACKEND_MAPIGAL(o)          (G_TYPE_CHECK_INSTANCE_CAST ((o), E_TYPE_BOOK_BACKEND_MAPIGAL, EBookBackendMAPIGAL))
#define E_BOOK_BACKEND_MAPIGAL_CLASS(k)    (G_TYPE_CHECK_CLASS_CAST ((k), E_TYPE_BOOK_BACKEND_MAPIGAL, EBookBackendMAPIGALClass))
#define E_IS_BOOK_BACKEND_MAPIGAL(o)       (G_TYPE_CHECK_INSTANCE_TYPE ((o), E_TYPE_BOOK_BACKEND_MAPIGAL))
#define E_IS_BOOK_BACKEND_MAPIGAL_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), E_TYPE_BOOK_BACKEND_MAPIGAL))

#endif /* ! __E_BOOK_BACKEND_MAPIGAL_H__ */

