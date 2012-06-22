/*
 * e-mail-config-mapi-extension.c
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

#include <mail/e-mail-config-notebook.h>

#include "e-mail-config-mapi-page.h"
#include "camel-mapi-settings.h"

#include "e-mail-config-mapi-extension.h"

G_DEFINE_DYNAMIC_TYPE (
	EMailConfigMapiExtension,
	e_mail_config_mapi_extension,
	E_TYPE_EXTENSION)

static void
e_mail_config_mapi_extension_constructed (GObject *object)
{
	EExtension *extension;
	EExtensible *extensible;
	ESource *source;
	ESourceBackend *backend_ext;
	EMailConfigNotebook *notebook;
	const gchar *backend_name;
	const gchar *extension_name;

	extension = E_EXTENSION (object);
	extensible = e_extension_get_extensible (extension);

	/* Chain up to parent's constructed() method. */
	G_OBJECT_CLASS (e_mail_config_mapi_extension_parent_class)->constructed (object);

	notebook = E_MAIL_CONFIG_NOTEBOOK (extensible);
	source = e_mail_config_notebook_get_account_source (notebook);

	extension_name = E_SOURCE_EXTENSION_MAIL_ACCOUNT;
	backend_ext = e_source_get_extension (source, extension_name);
	backend_name = e_source_backend_get_backend_name (backend_ext);

	if (g_strcmp0 (backend_name, "mapi") == 0) {
		ESource *profile_source;
		ESourceCamel *camel_ext;
		ESourceRegistry *registry;
		EMailSession *mail_session;
		CamelSettings *settings;
		const gchar *profile;

		mail_session = e_mail_config_notebook_get_session (notebook);
		registry = e_mail_session_get_registry (mail_session);

		if (e_source_get_parent (source))
			profile_source = e_source_registry_ref_source (registry, e_source_get_parent (source));
		else
			profile_source = g_object_ref (source);

		camel_ext = e_source_get_extension (profile_source, e_source_camel_get_extension_name (backend_name));
		settings = e_source_camel_get_settings (camel_ext);
		profile = camel_mapi_settings_get_profile (CAMEL_MAPI_SETTINGS (settings));

		/* add page only when editing already configured accounts */
		if (profile && *profile) {
			EMailConfigPage *page;

			page = e_mail_config_mapi_page_new (source, registry);
			e_mail_config_notebook_add_page (notebook, page);
		}

		g_object_unref (profile_source);
	}
}

static void
e_mail_config_mapi_extension_class_init (EMailConfigMapiExtensionClass *class)
{
	GObjectClass *object_class;
	EExtensionClass *extension_class;

	object_class = G_OBJECT_CLASS (class);
	object_class->constructed = e_mail_config_mapi_extension_constructed;

	extension_class = E_EXTENSION_CLASS (class);
	extension_class->extensible_type = E_TYPE_MAIL_CONFIG_NOTEBOOK;
}

static void
e_mail_config_mapi_extension_class_finalize (EMailConfigMapiExtensionClass *class)
{
}

static void
e_mail_config_mapi_extension_init (EMailConfigMapiExtension *extension)
{
}

void
e_mail_config_mapi_extension_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_mail_config_mapi_extension_register_type (type_module);
}
