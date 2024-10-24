/*
 * e-mapi-config-ui-extension.c
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

#include "evolution-mapi-config.h"

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#include <shell/e-shell-view.h>

#include "e-mapi-config-utils.h"

#include "e-mapi-config-ui-extension.h"

G_DEFINE_DYNAMIC_TYPE (EMapiConfigUIExtension, e_mapi_config_ui_extension, E_TYPE_EXTENSION)

static void
e_mapi_config_ui_extension_constructed (GObject *object)
{
	EExtension *extension;
	EExtensible *extensible;
	EShellViewClass *shell_view_class;

	extension = E_EXTENSION (object);
	extensible = e_extension_get_extensible (extension);

	/* Chain up to parent's constructed() method. */
	G_OBJECT_CLASS (e_mapi_config_ui_extension_parent_class)->constructed (object);

	shell_view_class = E_SHELL_VIEW_GET_CLASS (extensible);
	g_return_if_fail (shell_view_class != NULL);

	e_mapi_config_utils_init_ui (E_SHELL_VIEW (extensible), shell_view_class->ui_manager_id);
}

static void
e_mapi_config_ui_extension_class_init (EMapiConfigUIExtensionClass *class)
{
	GObjectClass *object_class;
	EExtensionClass *extension_class;

	object_class = G_OBJECT_CLASS (class);
	object_class->constructed = e_mapi_config_ui_extension_constructed;

	extension_class = E_EXTENSION_CLASS (class);
	extension_class->extensible_type = E_TYPE_SHELL_VIEW;
}

static void
e_mapi_config_ui_extension_class_finalize (EMapiConfigUIExtensionClass *class)
{
}

static void
e_mapi_config_ui_extension_init (EMapiConfigUIExtension *extension)
{
}

void
e_mapi_config_ui_extension_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_mapi_config_ui_extension_register_type (type_module);
}
