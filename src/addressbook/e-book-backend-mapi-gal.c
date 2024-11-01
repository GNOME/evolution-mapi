/*
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 * Copyright (C) 2017 Red Hat, Inc. (www.redhat.com)
 *
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
 */

#include "evolution-mapi-config.h"

#include "e-book-backend-mapi-gal.h"

struct _EBookBackendMAPIGALPrivate
{
	gint32 unused;
};

G_DEFINE_TYPE_WITH_PRIVATE (EBookBackendMAPIGAL, e_book_backend_mapi_gal, E_TYPE_BOOK_BACKEND_MAPI)

static void
e_book_backend_mapi_gal_init (EBookBackendMAPIGAL *bbmgal)
{
	bbmgal->priv = e_book_backend_mapi_gal_get_instance_private (bbmgal);

	e_book_backend_mapi_set_is_gal (E_BOOK_BACKEND_MAPI (bbmgal), TRUE);
}

static void
e_book_backend_mapi_gal_class_init (EBookBackendMAPIGALClass *klass)
{
	EBookMetaBackendClass *meta_backend_class;

	meta_backend_class = E_BOOK_META_BACKEND_CLASS (klass);
	meta_backend_class->backend_factory_type_name = "EBookBackendMapiGalFactory";
}
