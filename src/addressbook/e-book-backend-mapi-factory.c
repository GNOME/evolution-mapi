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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libebackend/e-data-server-module.h>
#include <libedata-book/e-book-backend-factory.h>

#include "e-book-backend-mapi-contacts.h"
#include "e-book-backend-mapi-gal.h"

E_BOOK_BACKEND_FACTORY_SIMPLE (mapi,    MAPI,    e_book_backend_mapi_contacts_new)
E_BOOK_BACKEND_FACTORY_SIMPLE (mapigal, MAPIGAL, e_book_backend_mapi_gal_new)

static GType mapi_type[2];

void
eds_module_initialize (GTypeModule *module)
{
	mapi_type[0] = _mapi_factory_get_type (module);
	mapi_type[1] = _mapigal_factory_get_type (module);
}

void
eds_module_shutdown (void)
{
}

void
eds_module_list_types (const GType **types, gint *num_types)
{
	*types = mapi_type;
	*num_types = G_N_ELEMENTS (mapi_type);
}
