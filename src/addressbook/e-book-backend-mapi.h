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
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef E_BOOK_BACKEND_MAPI_H
#define E_BOOK_BACKEND_MAPI_H

#include <glib.h>
#include <gio/gio.h>

#include <libedata-book/libedata-book.h>

#include "e-mapi-connection.h"
#include "e-mapi-defs.h"
#include "e-mapi-utils.h"
#include "e-mapi-book-utils.h"

G_BEGIN_DECLS

#define E_TYPE_BOOK_BACKEND_MAPI           (e_book_backend_mapi_get_type ())
#define E_BOOK_BACKEND_MAPI(o)             (G_TYPE_CHECK_INSTANCE_CAST ((o), E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPI))
#define E_BOOK_BACKEND_MAPI_CLASS(k)       (G_TYPE_CHECK_CLASS_CAST((k), E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPIClass))
#define E_IS_BOOK_BACKEND_MAPI(o)          (G_TYPE_CHECK_INSTANCE_TYPE ((o), E_TYPE_BOOK_BACKEND_MAPI))
#define E_IS_BOOK_BACKEND_MAPI_CLASS(k)    (G_TYPE_CHECK_CLASS_TYPE ((k), E_TYPE_BOOK_BACKEND_MAPI))
#define E_BOOK_BACKEND_MAPI_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPIClass))

typedef struct _EBookBackendMAPIPrivate EBookBackendMAPIPrivate;

typedef struct
{
	EBookMetaBackend parent_object;
	EBookBackendMAPIPrivate *priv;
} EBookBackendMAPI;

typedef struct
{
	EBookMetaBackendClass parent_class;
} EBookBackendMAPIClass;

GType		e_book_backend_mapi_get_type	(void);

void		e_book_backend_mapi_set_is_gal	(EBookBackendMAPI *bbmapi,
						 gboolean is_gal);
gboolean	e_book_backend_mapi_get_is_gal	(EBookBackendMAPI *bbmapi);

G_END_DECLS

#endif /* E_BOOK_BACKEND_MAPI_H */
