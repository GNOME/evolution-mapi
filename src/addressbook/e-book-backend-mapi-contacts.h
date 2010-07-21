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
 *    Srinivasa Ragavan <sragavan@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef __E_BOOK_BACKEND_MAPI_CONTACTS_H__
#define __E_BOOK_BACKEND_MAPI_CONTACTS_H__

#include "e-book-backend-mapi.h"

G_BEGIN_DECLS

#define E_TYPE_BOOK_BACKEND_MAPI_CONTACTS         (e_book_backend_mapi_contacts_get_type ())
#define E_BOOK_BACKEND_MAPI_CONTACTS(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, EBookBackendMAPIContacts))
#define E_BOOK_BACKEND_MAPI_CONTACTS_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, EBookBackendMAPIContactsClass))
#define E_IS_BOOK_BACKEND_MAPI_CONTACTS(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), E_TYPE_BOOK_BACKEND_MAPI_CONTACTS))
#define E_IS_BOOK_BACKEND_MAPI_CONTACTS_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), E_TYPE_BOOK_BACKEND_MAPI_CONTACTS))
#define E_BOOK_BACKEND_MAPI_CONTACTS_GET_CLASS(k) (G_TYPE_INSTANCE_GET_CLASS ((obj), E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, EBookBackendMAPIContactsClass))

typedef struct _EBookBackendMAPIContactsPrivate EBookBackendMAPIContactsPrivate;

typedef struct
{
	EBookBackendMAPI                 parent_object;
	EBookBackendMAPIContactsPrivate *priv;
} EBookBackendMAPIContacts;

typedef struct
{
	EBookBackendMAPIClass parent_class;
} EBookBackendMAPIContactsClass;

EBookBackend *e_book_backend_mapi_contacts_new      (void);
GType         e_book_backend_mapi_contacts_get_type (void);

G_END_DECLS

#endif /* __E_BOOK_BACKEND_MAPI_CONTACTS_H__ */
