/*
 * module-mapi-mail-config.c
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

#include "e-book-config-mapi.h"
#include "e-book-config-mapigal.h"
#include "e-cal-config-mapi.h"
#include "e-mail-config-mapi-backend.h"
#include "e-mail-config-mapi-page.h"
#include "e-mail-config-mapi-extension.h"
#include "e-mapi-config-ui-extension.h"
#include "e-source-mapi-folder.h"

/* Module Entry Points */
void e_module_load (GTypeModule *type_module);
void e_module_unload (GTypeModule *type_module);

G_MODULE_EXPORT void
e_module_load (GTypeModule *type_module)
{
	bindtextdomain (GETTEXT_PACKAGE, EXCHANGE_MAPI_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	e_source_mapi_folder_type_register (type_module);

	e_book_config_mapi_type_register (type_module);
	e_book_config_mapigal_type_register (type_module);
	e_cal_config_mapi_type_register (type_module);
	e_mail_config_mapi_backend_type_register (type_module);
	e_mail_config_mapi_page_type_register (type_module);
	e_mail_config_mapi_extension_type_register (type_module);
	e_mapi_config_ui_extension_type_register (type_module);
}

G_MODULE_EXPORT void
e_module_unload (GTypeModule *type_module)
{
}
