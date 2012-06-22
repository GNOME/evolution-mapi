/*
 * e-book-config-mapi.c
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <misc/e-book-source-config.h>

#include "e-book-config-mapi.h"
#include "e-mapi-config-utils.h"

G_DEFINE_DYNAMIC_TYPE (EBookConfigMapi, e_book_config_mapi, E_TYPE_SOURCE_CONFIG_BACKEND)

static gboolean
book_config_mapi_allow_creation (ESourceConfigBackend *backend)
{
	return TRUE;
}

static void
book_config_mapi_insert_widgets (ESourceConfigBackend *backend,
				 ESource *scratch_source)
{
	e_mapi_config_utils_insert_widgets (backend, scratch_source);
}

static void
e_book_config_mapi_class_init (EBookConfigMapiClass *class)
{
	EExtensionClass *extension_class;
	ESourceConfigBackendClass *backend_class;

	extension_class = E_EXTENSION_CLASS (class);
	extension_class->extensible_type = E_TYPE_BOOK_SOURCE_CONFIG;

	backend_class = E_SOURCE_CONFIG_BACKEND_CLASS (class);
	backend_class->backend_name = "mapi";
	backend_class->allow_creation = book_config_mapi_allow_creation;
	backend_class->insert_widgets = book_config_mapi_insert_widgets;
}

static void
e_book_config_mapi_class_finalize (EBookConfigMapiClass *class)
{
}

static void
e_book_config_mapi_init (EBookConfigMapi *backend)
{
}

void
e_book_config_mapi_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_book_config_mapi_register_type (type_module);
}
