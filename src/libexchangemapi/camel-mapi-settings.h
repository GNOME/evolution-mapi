/*
 * camel-mapi-settings.h
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

#ifndef CAMEL_MAPI_SETTINGS_H
#define CAMEL_MAPI_SETTINGS_H

#include <camel/camel.h>

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_SETTINGS \
	(camel_mapi_settings_get_type ())
#define CAMEL_MAPI_SETTINGS(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_SETTINGS, CamelMapiSettings))
#define CAMEL_MAPI_SETTINGS_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_SETTINGS, CamelMapiSettingsClass))
#define CAMEL_IS_MAPI_SETTINGS(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_SETTINGS))
#define CAMEL_IS_MAPI_SETTINGS_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_SETTINGS))
#define CAMEL_MAPI_SETTINGS_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_SETTINGS, CamelMapiSettingsClass))

G_BEGIN_DECLS

typedef struct _CamelMapiSettings CamelMapiSettings;
typedef struct _CamelMapiSettingsClass CamelMapiSettingsClass;
typedef struct _CamelMapiSettingsPrivate CamelMapiSettingsPrivate;

struct _CamelMapiSettings {
	CamelOfflineSettings parent;
	CamelMapiSettingsPrivate *priv;
};

struct _CamelMapiSettingsClass {
	CamelOfflineSettingsClass parent_class;
};

GType		camel_mapi_settings_get_type
						(void) G_GNUC_CONST;
gboolean	camel_mapi_settings_get_check_all
						(CamelMapiSettings *settings);
void		camel_mapi_settings_set_check_all
						(CamelMapiSettings *settings,
						 gboolean check_all);
const gchar *	camel_mapi_settings_get_domain	(CamelMapiSettings *settings);
void		camel_mapi_settings_set_domain	(CamelMapiSettings *settings,
						 const gchar *domain);
gboolean	camel_mapi_settings_get_filter_junk
						(CamelMapiSettings *settings);
void		camel_mapi_settings_set_filter_junk
						(CamelMapiSettings *settings,
						 gboolean filter_junk);
gboolean	camel_mapi_settings_get_filter_junk_inbox
						(CamelMapiSettings *settings);
void		camel_mapi_settings_set_filter_junk_inbox
						(CamelMapiSettings *settings,
						 gboolean filter_junk_inbox);
gboolean	camel_mapi_settings_get_kerberos
						(CamelMapiSettings *settings);
void		camel_mapi_settings_set_kerberos
						(CamelMapiSettings *settings,
						 gboolean kerberos);
const gchar *	camel_mapi_settings_get_profile	(CamelMapiSettings *settings);
void		camel_mapi_settings_set_profile	(CamelMapiSettings *settings,
						 const gchar *profile);
const gchar *	camel_mapi_settings_get_realm	(CamelMapiSettings *settings);
void		camel_mapi_settings_set_realm	(CamelMapiSettings *settings,
						 const gchar *realm);

G_END_DECLS

#endif /* CAMEL_MAPI_SETTINGS_H */
