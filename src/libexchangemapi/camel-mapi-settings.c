/*
 * camel-mapi-settings.c
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

#include "camel-mapi-settings.h"

#define CAMEL_MAPI_SETTINGS_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE \
	((obj), CAMEL_TYPE_MAPI_SETTINGS, CamelMapiSettingsPrivate))

struct _CamelMapiSettingsPrivate {
	gboolean check_all;
	gboolean filter_junk;
	gboolean filter_junk_inbox;
	gboolean kerberos;

	gchar *domain;
	gchar *profile;
	gchar *realm;
};

enum {
	PROP_0,
	PROP_CHECK_ALL,
	PROP_DOMAIN,
	PROP_FILTER_JUNK,
	PROP_FILTER_JUNK_INBOX,
	PROP_KERBEROS,
	PROP_PROFILE,
	PROP_REALM,
	PROP_SECURITY_METHOD
};

G_DEFINE_TYPE_WITH_CODE (
	CamelMapiSettings,
	camel_mapi_settings,
	CAMEL_TYPE_OFFLINE_SETTINGS,
	G_IMPLEMENT_INTERFACE (
		CAMEL_TYPE_NETWORK_SETTINGS, NULL))

static void
mapi_settings_set_property (GObject *object,
                                 guint property_id,
                                 const GValue *value,
                                 GParamSpec *pspec)
{
	switch (property_id) {
		case PROP_CHECK_ALL:
			camel_mapi_settings_set_check_all (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_boolean (value));
			return;

		case PROP_DOMAIN:
			camel_mapi_settings_set_domain (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_string (value));
			return;

		case PROP_FILTER_JUNK:
			camel_mapi_settings_set_filter_junk (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_boolean (value));
			return;

		case PROP_FILTER_JUNK_INBOX:
			camel_mapi_settings_set_filter_junk_inbox (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_boolean (value));
			return;

		case PROP_KERBEROS:
			camel_mapi_settings_set_kerberos (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_boolean (value));
			return;

		case PROP_PROFILE:
			camel_mapi_settings_set_profile (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_string (value));
			return;

		case PROP_REALM:
			camel_mapi_settings_set_realm (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_string (value));
			return;

		case PROP_SECURITY_METHOD:
			camel_network_settings_set_security_method (
				CAMEL_NETWORK_SETTINGS (object),
				g_value_get_enum (value));
			return;
	}

	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
}

static void
mapi_settings_get_property (GObject *object,
                                 guint property_id,
                                 GValue *value,
                                 GParamSpec *pspec)
{
	switch (property_id) {
		case PROP_CHECK_ALL:
			g_value_set_boolean (
				value,
				camel_mapi_settings_get_check_all (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_DOMAIN:
			g_value_set_string (
				value,
				camel_mapi_settings_get_domain (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_FILTER_JUNK:
			g_value_set_boolean (
				value,
				camel_mapi_settings_get_filter_junk (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_FILTER_JUNK_INBOX:
			g_value_set_boolean (
				value,
				camel_mapi_settings_get_filter_junk_inbox (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_KERBEROS:
			g_value_set_boolean (
				value,
				camel_mapi_settings_get_kerberos (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_PROFILE:
			g_value_set_string (
				value,
				camel_mapi_settings_get_profile (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_REALM:
			g_value_set_string (
				value,
				camel_mapi_settings_get_realm (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_SECURITY_METHOD:
			g_value_set_enum (
				value,
				camel_network_settings_get_security_method (
				CAMEL_NETWORK_SETTINGS (object)));
			return;
	}

	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
}

static void
mapi_settings_finalize (GObject *object)
{
	CamelMapiSettingsPrivate *priv;

	priv = CAMEL_MAPI_SETTINGS_GET_PRIVATE (object);

	g_free (priv->profile);

	/* Chain up to parent's finalize() method. */
	G_OBJECT_CLASS (camel_mapi_settings_parent_class)->finalize (object);
}

static void
camel_mapi_settings_class_init (CamelMapiSettingsClass *class)
{
	GObjectClass *object_class;

	g_type_class_add_private (class, sizeof (CamelMapiSettingsPrivate));

	object_class = G_OBJECT_CLASS (class);
	object_class->set_property = mapi_settings_set_property;
	object_class->get_property = mapi_settings_get_property;
	object_class->finalize = mapi_settings_finalize;

	g_object_class_install_property (
		object_class,
		PROP_CHECK_ALL,
		g_param_spec_boolean (
			"check-all",
			"Check All",
			"Check all folders for new messages",
			FALSE,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (
		object_class,
		PROP_DOMAIN,
		g_param_spec_string (
			"domain",
			"Domain",
			"Windows domain",
			NULL,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (
		object_class,
		PROP_FILTER_JUNK,
		g_param_spec_boolean (
			"filter-junk",
			"Filter Junk",
			"Whether to filter junk from all folders",
			FALSE,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (
		object_class,
		PROP_FILTER_JUNK_INBOX,
		g_param_spec_boolean (
			"filter-junk-inbox",
			"Filter Junk Inbox",
			"Whether to filter junk from Inbox only",
			FALSE,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (
		object_class,
		PROP_KERBEROS,
		g_param_spec_boolean (
			"kerberos",
			"Kerberos",
			"Use Kerberos authentication",
			FALSE,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (
		object_class,
		PROP_PROFILE,
		g_param_spec_string (
			"profile",
			"Profile",
			"OpenChange user profile",
			NULL,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (
		object_class,
		PROP_REALM,
		g_param_spec_string (
			"realm",
			"Realm",
			"Kerberos realm",
			NULL,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	/* Inherited from CamelNetworkSettings. */
	g_object_class_override_property (
		object_class,
		PROP_SECURITY_METHOD,
		"security-method");
}

static void
camel_mapi_settings_init (CamelMapiSettings *settings)
{
	settings->priv = CAMEL_MAPI_SETTINGS_GET_PRIVATE (settings);
}

gboolean
camel_mapi_settings_get_check_all (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), FALSE);

	return settings->priv->check_all;
}

void
camel_mapi_settings_set_check_all (CamelMapiSettings *settings,
                                   gboolean check_all)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	settings->priv->check_all = check_all;

	g_object_notify (G_OBJECT (settings), "check-all");
}

const gchar *
camel_mapi_settings_get_domain (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	return settings->priv->domain;
}

void
camel_mapi_settings_set_domain (CamelMapiSettings *settings,
                                const gchar *domain)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	/* The value should never be NULL. */
	if (domain == NULL)
		domain = "";

	g_free (settings->priv->domain);
	settings->priv->domain = g_strdup (domain);

	g_object_notify (G_OBJECT (settings), "domain");
}

gboolean
camel_mapi_settings_get_filter_junk (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), FALSE);

	return settings->priv->filter_junk;
}

void
camel_mapi_settings_set_filter_junk (CamelMapiSettings *settings,
                                     gboolean filter_junk)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	settings->priv->filter_junk = filter_junk;

	g_object_notify (G_OBJECT (settings), "filter-junk");
}

gboolean
camel_mapi_settings_get_filter_junk_inbox (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), FALSE);

	return settings->priv->filter_junk_inbox;
}

void
camel_mapi_settings_set_filter_junk_inbox (CamelMapiSettings *settings,
                                           gboolean filter_junk_inbox)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	settings->priv->filter_junk_inbox = filter_junk_inbox;

	g_object_notify (G_OBJECT (settings), "filter-junk-inbox");
}

gboolean
camel_mapi_settings_get_kerberos (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), FALSE);

	return settings->priv->kerberos;
}

void
camel_mapi_settings_set_kerberos (CamelMapiSettings *settings,
                                  gboolean kerberos)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	settings->priv->kerberos = kerberos;

	g_object_notify (G_OBJECT (settings), "kerberos");
}

const gchar *
camel_mapi_settings_get_profile (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	return settings->priv->profile;
}

void
camel_mapi_settings_set_profile (CamelMapiSettings *settings,
                                 const gchar *profile)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	g_free (settings->priv->profile);
	settings->priv->profile = g_strdup (profile);

	g_object_notify (G_OBJECT (settings), "profile");
}

const gchar *
camel_mapi_settings_get_realm (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	return settings->priv->realm;
}

void
camel_mapi_settings_set_realm (CamelMapiSettings *settings,
                               const gchar *realm)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	/* The value should never be NULL. */
	if (realm == NULL)
		realm = "";

	g_free (settings->priv->realm);
	settings->priv->realm = g_strdup (realm);

	g_object_notify (G_OBJECT (settings), "realm");
}