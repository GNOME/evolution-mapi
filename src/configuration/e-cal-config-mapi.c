/*
 * e-cal-config-mapi.c
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

#include "e-cal-config-mapi.h"
#include "e-mapi-config-utils.h"

G_DEFINE_DYNAMIC_TYPE (ECalConfigMapi, e_cal_config_mapi, E_TYPE_SOURCE_CONFIG_BACKEND)

static gboolean
cal_config_mapi_allow_creation (ESourceConfigBackend *backend)
{
	return TRUE;
}

static void
cal_config_mapi_insert_widgets (ESourceConfigBackend *backend,
				ESource *scratch_source)
{
	e_mapi_config_utils_insert_widgets (backend, scratch_source);
}

static gboolean
cal_config_mapi_check_complete (ESourceConfigBackend *backend,
				ESource *scratch_source)
{
	return e_mapi_config_utils_check_complete (scratch_source);
}

static void
e_cal_config_mapi_class_init (ECalConfigMapiClass *class)
{
	EExtensionClass *extension_class;
	ESourceConfigBackendClass *backend_class;

	extension_class = E_EXTENSION_CLASS (class);
	extension_class->extensible_type = E_TYPE_CAL_SOURCE_CONFIG;

	backend_class = E_SOURCE_CONFIG_BACKEND_CLASS (class);
	backend_class->backend_name = "mapi";
	backend_class->allow_creation = cal_config_mapi_allow_creation;
	backend_class->insert_widgets = cal_config_mapi_insert_widgets;
	backend_class->check_complete = cal_config_mapi_check_complete;
}

static void
e_cal_config_mapi_class_finalize (ECalConfigMapiClass *class)
{
}

static void
e_cal_config_mapi_init (ECalConfigMapi *backend)
{
}

void
e_cal_config_mapi_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_cal_config_mapi_register_type (type_module);
}
