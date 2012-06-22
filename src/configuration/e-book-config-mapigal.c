/*
 * e-book-config-mapigal.c
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

#include <glib/gi18n-lib.h>

#include <misc/e-book-source-config.h>

#include "e-source-mapi-folder.h"
#include "e-book-config-mapigal.h"

G_DEFINE_DYNAMIC_TYPE (
	EBookConfigMapigal,
	e_book_config_mapigal,
	E_TYPE_SOURCE_CONFIG_BACKEND)

static gboolean
book_config_mapigal_allow_creation (ESourceConfigBackend *backend)
{
	return FALSE;
}

static void
book_config_mapigal_insert_widgets (ESourceConfigBackend *backend,
				    ESource *scratch_source)
{
	ESourceBackend *backend_ext;
	ESourceMapiFolder *folder_ext;
	ESourceConfig *config;
	GtkWidget *widget;

	if (!e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_ADDRESS_BOOK))
		return;

	backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
	if (!backend_ext || g_strcmp0 (e_source_backend_get_backend_name (backend_ext), "mapigal") != 0)
		return;

	folder_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	g_return_if_fail (folder_ext != NULL);

	config = e_source_config_backend_get_config (backend);
	e_book_source_config_add_offline_toggle (E_BOOK_SOURCE_CONFIG (config), scratch_source);

	widget = gtk_check_button_new_with_mnemonic (_("Allow _partial search results"));
	e_source_config_insert_widget (config, scratch_source, NULL, widget);
	gtk_widget_show (widget);

	g_object_bind_property (
		folder_ext, "allow-partial",
		widget, "active",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);
}

static void
e_book_config_mapigal_class_init (EBookConfigMapigalClass *class)
{
	EExtensionClass *extension_class;
	ESourceConfigBackendClass *backend_class;

	extension_class = E_EXTENSION_CLASS (class);
	extension_class->extensible_type = E_TYPE_BOOK_SOURCE_CONFIG;

	backend_class = E_SOURCE_CONFIG_BACKEND_CLASS (class);
	backend_class->backend_name = "mapigal";
	backend_class->allow_creation = book_config_mapigal_allow_creation;
	backend_class->insert_widgets = book_config_mapigal_insert_widgets;
}

static void
e_book_config_mapigal_class_finalize (EBookConfigMapigalClass *class)
{
}

static void
e_book_config_mapigal_init (EBookConfigMapigal *backend)
{
}

void
e_book_config_mapigal_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_book_config_mapigal_register_type (type_module);
}
