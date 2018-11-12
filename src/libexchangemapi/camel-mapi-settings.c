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
	GMutex property_lock;

	gboolean check_all;
	gboolean filter_junk;
	gboolean filter_junk_inbox;
	gboolean kerberos;
	gboolean listen_notifications;

	gchar *domain;
	gchar *profile;
	gchar *realm;
};

enum {
	PROP_0,
	PROP_AUTH_MECHANISM,
	PROP_CHECK_ALL,
	PROP_DOMAIN,
	PROP_FILTER_JUNK,
	PROP_FILTER_JUNK_INBOX,
	PROP_HOST,
	PROP_KERBEROS,
	PROP_PORT,
	PROP_PROFILE,
	PROP_REALM,
	PROP_SECURITY_METHOD,
	PROP_USER,
	PROP_LISTEN_NOTIFICATIONS
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
		case PROP_AUTH_MECHANISM:
			camel_network_settings_set_auth_mechanism (
				CAMEL_NETWORK_SETTINGS (object),
				g_value_get_string (value));
			return;

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

		case PROP_HOST:
			camel_network_settings_set_host (
				CAMEL_NETWORK_SETTINGS (object),
				g_value_get_string (value));
			return;

		case PROP_KERBEROS:
			camel_mapi_settings_set_kerberos (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_boolean (value));
			return;

		case PROP_PORT:
			camel_network_settings_set_port (
				CAMEL_NETWORK_SETTINGS (object),
				g_value_get_uint (value));
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

		case PROP_USER:
			camel_network_settings_set_user (
				CAMEL_NETWORK_SETTINGS (object),
				g_value_get_string (value));
			return;

		case PROP_LISTEN_NOTIFICATIONS:
			camel_mapi_settings_set_listen_notifications (
				CAMEL_MAPI_SETTINGS (object),
				g_value_get_boolean (value));
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
		case PROP_AUTH_MECHANISM:
			g_value_set_string (
				value,
				camel_network_settings_get_auth_mechanism (
				CAMEL_NETWORK_SETTINGS (object)));
			return;

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

		case PROP_HOST:
			g_value_set_string (
				value,
				camel_network_settings_get_host (
				CAMEL_NETWORK_SETTINGS (object)));
			return;

		case PROP_KERBEROS:
			g_value_set_boolean (
				value,
				camel_mapi_settings_get_kerberos (
				CAMEL_MAPI_SETTINGS (object)));
			return;

		case PROP_PORT:
			g_value_set_uint (
				value,
				camel_network_settings_get_port (
				CAMEL_NETWORK_SETTINGS (object)));
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

		case PROP_USER:
			g_value_set_string (
				value,
				camel_network_settings_get_user (
				CAMEL_NETWORK_SETTINGS (object)));
			return;

		case PROP_LISTEN_NOTIFICATIONS:
			g_value_set_boolean (
				value,
				camel_mapi_settings_get_listen_notifications (
				CAMEL_MAPI_SETTINGS (object)));
			return;
	}

	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
}

static void
mapi_settings_finalize (GObject *object)
{
	CamelMapiSettingsPrivate *priv;

	priv = CAMEL_MAPI_SETTINGS_GET_PRIVATE (object);

	g_mutex_clear (&priv->property_lock);

	g_free (priv->domain);
	g_free (priv->profile);
	g_free (priv->realm);

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

	/* Inherited from CamelNetworkSettings. */
	g_object_class_override_property (
		object_class,
		PROP_AUTH_MECHANISM,
		"auth-mechanism");

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

	/* Inherited from CamelNetworkSettings. */
	g_object_class_override_property (
		object_class,
		PROP_HOST,
		"host");

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

	/* Inherited from CamelNetworkSettings. */
	g_object_class_override_property (
		object_class,
		PROP_PORT,
		"port");

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

	g_object_class_install_property (
		object_class,
		PROP_LISTEN_NOTIFICATIONS,
		g_param_spec_boolean (
			"listen-notifications",
			"Listen Notifications",
			"Whether to listen for server notifications",
			TRUE,
			G_PARAM_READWRITE |
			G_PARAM_CONSTRUCT |
			G_PARAM_STATIC_STRINGS));

	/* Inherited from CamelNetworkSettings. */
	g_object_class_override_property (
		object_class,
		PROP_SECURITY_METHOD,
		"security-method");

	/* Inherited from CamelNetworkSettings. */
	g_object_class_override_property (
		object_class,
		PROP_USER,
		"user");
}

static void
camel_mapi_settings_init (CamelMapiSettings *settings)
{
	settings->priv = CAMEL_MAPI_SETTINGS_GET_PRIVATE (settings);
	g_mutex_init (&settings->priv->property_lock);
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

	if ((settings->priv->check_all ? 1 : 0) == (check_all ? 1 : 0))
		return;

	settings->priv->check_all = check_all;

	g_object_notify (G_OBJECT (settings), "check-all");
}

const gchar *
camel_mapi_settings_get_domain (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	return settings->priv->domain;
}

gchar *
camel_mapi_settings_dup_domain (CamelMapiSettings *settings)
{
	const gchar *protected;
	gchar *duplicate;

	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	g_mutex_lock (&settings->priv->property_lock);

	protected = camel_mapi_settings_get_domain (settings);
	duplicate = g_strdup (protected);

	g_mutex_unlock (&settings->priv->property_lock);

	return duplicate;
}

void
camel_mapi_settings_set_domain (CamelMapiSettings *settings,
                                const gchar *domain)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	/* The value should never be NULL. */
	if (domain == NULL)
		domain = "";

	g_mutex_lock (&settings->priv->property_lock);

	if (g_strcmp0 (settings->priv->domain, domain) == 0) {
		g_mutex_unlock (&settings->priv->property_lock);
		return;
	}

	g_free (settings->priv->domain);
	settings->priv->domain = g_strdup (domain);

	g_mutex_unlock (&settings->priv->property_lock);

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

	if ((settings->priv->filter_junk ? 1 : 0) == (filter_junk ? 1 : 0))
		return;

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

	if ((settings->priv->filter_junk_inbox ? 1 : 0) == (filter_junk_inbox ? 1 : 0))
		return;

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

	if ((settings->priv->kerberos ? 1 : 0) == (kerberos ? 1 : 0))
		return;

	settings->priv->kerberos = kerberos;

	g_object_notify (G_OBJECT (settings), "kerberos");
}

const gchar *
camel_mapi_settings_get_profile (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	return settings->priv->profile;
}

gchar *
camel_mapi_settings_dup_profile (CamelMapiSettings *settings)
{
	const gchar *protected;
	gchar *duplicate;

	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	g_mutex_lock (&settings->priv->property_lock);

	protected = camel_mapi_settings_get_profile (settings);
	duplicate = g_strdup (protected);

	g_mutex_unlock (&settings->priv->property_lock);

	return duplicate;
}

void
camel_mapi_settings_set_profile (CamelMapiSettings *settings,
                                 const gchar *profile)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	g_mutex_lock (&settings->priv->property_lock);

	if (g_strcmp0 (settings->priv->profile, profile) == 0) {
		g_mutex_unlock (&settings->priv->property_lock);
		return;
	}

	g_free (settings->priv->profile);
	settings->priv->profile = g_strdup (profile);

	g_mutex_unlock (&settings->priv->property_lock);

	g_object_notify (G_OBJECT (settings), "profile");
}

const gchar *
camel_mapi_settings_get_realm (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	return settings->priv->realm;
}

gchar *
camel_mapi_settings_dup_realm (CamelMapiSettings *settings)
{
	const gchar *protected;
	gchar *duplicate;

	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), NULL);

	g_mutex_lock (&settings->priv->property_lock);

	protected = camel_mapi_settings_get_realm (settings);
	duplicate = g_strdup (protected);

	g_mutex_unlock (&settings->priv->property_lock);

	return duplicate;
}

void
camel_mapi_settings_set_realm (CamelMapiSettings *settings,
                               const gchar *realm)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	/* The value should never be NULL. */
	if (realm == NULL)
		realm = "";

	g_mutex_lock (&settings->priv->property_lock);

	if (g_strcmp0 (settings->priv->realm, realm) == 0) {
		g_mutex_unlock (&settings->priv->property_lock);
		return;
	}

	g_free (settings->priv->realm);
	settings->priv->realm = g_strdup (realm);

	g_mutex_unlock (&settings->priv->property_lock);

	g_object_notify (G_OBJECT (settings), "realm");
}

gboolean
camel_mapi_settings_get_listen_notifications (CamelMapiSettings *settings)
{
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), FALSE);

	return settings->priv->listen_notifications;
}

void
camel_mapi_settings_set_listen_notifications (CamelMapiSettings *settings,
					      gboolean listen_notifications)
{
	g_return_if_fail (CAMEL_IS_MAPI_SETTINGS (settings));

	if ((settings->priv->listen_notifications ? 1 : 0) == (listen_notifications ? 1 : 0))
		return;

	settings->priv->listen_notifications = listen_notifications;

	g_object_notify (G_OBJECT (settings), "listen-notifications");
}
