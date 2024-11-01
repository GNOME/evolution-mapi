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

#include "evolution-mapi-config.h"

#include "e-book-backend-mapi-contacts.h"

struct _EBookBackendMAPIContactsPrivate
{
	gint32 unused;
};

G_DEFINE_TYPE_WITH_PRIVATE (EBookBackendMAPIContacts, e_book_backend_mapi_contacts, E_TYPE_BOOK_BACKEND_MAPI)

static void
e_book_backend_mapi_contacts_init (EBookBackendMAPIContacts *bbmcontacts)
{
	bbmcontacts->priv = e_book_backend_mapi_contacts_get_instance_private (bbmcontacts);

	e_book_backend_mapi_set_is_gal (E_BOOK_BACKEND_MAPI (bbmcontacts), FALSE);
}

static void
e_book_backend_mapi_contacts_class_init (EBookBackendMAPIContactsClass *klass)
{
	EBookMetaBackendClass *meta_backend_class;

	meta_backend_class = E_BOOK_META_BACKEND_CLASS (klass);
	meta_backend_class->backend_factory_type_name = "EBookBackendMapiContactsFactory";
}
