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

#include "evolution-mapi-config.h"

#include <glib/gi18n-lib.h>

#include <libedata-book/libedata-book.h>

#include "e-book-backend-mapi-contacts.h"
#include "e-book-backend-mapi-gal.h"
#include "e-source-mapi-folder.h"

typedef EBookBackendFactory EBookBackendMapiContactsFactory;
typedef EBookBackendFactoryClass EBookBackendMapiContactsFactoryClass;

typedef EBookBackendFactory EBookBackendMapiGalFactory;
typedef EBookBackendFactoryClass EBookBackendMapiGalFactoryClass;

static EModule *e_module;

/* Module Entry Points */
void e_module_load (GTypeModule *type_module);
void e_module_unload (GTypeModule *type_module);

/* Forward Declarations */
GType e_book_backend_mapi_contacts_factory_get_type (void);
GType e_book_backend_mapi_gal_factory_get_type (void);

G_DEFINE_DYNAMIC_TYPE (
	EBookBackendMapiContactsFactory,
	e_book_backend_mapi_contacts_factory,
	E_TYPE_BOOK_BACKEND_FACTORY)

G_DEFINE_DYNAMIC_TYPE (
	EBookBackendMapiGalFactory,
	e_book_backend_mapi_gal_factory,
	E_TYPE_BOOK_BACKEND_FACTORY)

static void
e_book_backend_mapi_contacts_factory_class_init (EBookBackendFactoryClass *class)
{
	EBackendFactoryClass *backend_factory_class;

	backend_factory_class = E_BACKEND_FACTORY_CLASS (class);
	backend_factory_class->e_module = e_module;
	backend_factory_class->share_subprocess = TRUE;

	class->factory_name = "mapi";
	class->backend_type = E_TYPE_BOOK_BACKEND_MAPI_CONTACTS;
}

static void
e_book_backend_mapi_contacts_factory_class_finalize (EBookBackendFactoryClass *class)
{
}

static void
e_book_backend_mapi_contacts_factory_init (EBookBackendFactory *factory)
{
}

static void
e_book_backend_mapi_gal_factory_class_init (EBookBackendFactoryClass *class)
{
	EBackendFactoryClass *backend_factory_class;

	backend_factory_class = E_BACKEND_FACTORY_CLASS (class);
	backend_factory_class->e_module = e_module;
	backend_factory_class->share_subprocess = TRUE;

	class->factory_name = "mapigal";
	class->backend_type = E_TYPE_BOOK_BACKEND_MAPI_GAL;
}

static void
e_book_backend_mapi_gal_factory_class_finalize (EBookBackendFactoryClass *class)
{
}

static void
e_book_backend_mapi_gal_factory_init (EBookBackendFactory *factory)
{
}

G_MODULE_EXPORT void
e_module_load (GTypeModule *type_module)
{
	bindtextdomain (GETTEXT_PACKAGE, EXCHANGE_MAPI_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	e_module = E_MODULE (type_module);

	e_source_mapi_folder_type_register (type_module);

	e_book_backend_mapi_contacts_factory_register_type (type_module);
	e_book_backend_mapi_gal_factory_register_type (type_module);
}

G_MODULE_EXPORT void
e_module_unload (GTypeModule *type_module)
{
	e_module = NULL;
}

