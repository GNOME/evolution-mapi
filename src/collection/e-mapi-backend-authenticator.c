/*
 * e-mapi-backend-authenticator.c
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

#include "e-mapi-utils.h"

#include "e-mapi-backend-authenticator.h"

typedef struct _EMapiBackendAuthenticator EMapiBackendAuthenticator;
typedef struct _EMapiBackendAuthenticatorClass EMapiBackendAuthenticatorClass;

struct _EMapiBackendAuthenticator {
	GObject parent;

	EBackend *backend;
	CamelMapiSettings *mapi_settings;
	EMapiBackendAuthenticatorFunc func;
	gpointer func_user_data;
	gboolean success;
};

struct _EMapiBackendAuthenticatorClass {
	GObjectClass parent_class;
};

static ESourceAuthenticationResult
mapi_config_utils_authenticator_try_password_sync (ESourceAuthenticator *auth,
						   const GString *password,
						   GCancellable *cancellable,
						   GError **error)
{
	EMapiBackendAuthenticator *authenticator = (EMapiBackendAuthenticator *) auth;
	EMapiProfileData empd = { 0 };
	EMapiConnection *conn;
	CamelNetworkSettings *network_settings;
	GError *mapi_error = NULL;

	network_settings = CAMEL_NETWORK_SETTINGS (authenticator->mapi_settings);

	empd.server = camel_network_settings_get_host (network_settings);
	empd.username = camel_network_settings_get_user (network_settings);
	e_mapi_util_profiledata_from_settings (&empd, authenticator->mapi_settings);

	conn = e_mapi_connection_new (
		NULL,
		camel_mapi_settings_get_profile (authenticator->mapi_settings),
		password, cancellable, &mapi_error);

	if (mapi_error) {
		g_warn_if_fail (!conn);

		g_propagate_error (error, mapi_error);

		return E_SOURCE_AUTHENTICATION_ERROR;
	}

	g_warn_if_fail (conn != NULL);

	authenticator->success = authenticator->func (
		authenticator->backend,
		authenticator->mapi_settings,
		conn,
		authenticator->func_user_data,
		cancellable,
		error);

	g_object_unref (conn);

	return E_SOURCE_AUTHENTICATION_ACCEPTED;
}

#define E_TYPE_MAPI_BACKEND_AUTHENTICATOR (e_mapi_backend_authenticator_get_type ())

GType e_mapi_backend_authenticator_get_type (void) G_GNUC_CONST;

static void e_mapi_backend_authenticator_authenticator_init (ESourceAuthenticatorInterface *interface);

G_DEFINE_TYPE_EXTENDED (EMapiBackendAuthenticator, e_mapi_backend_authenticator, G_TYPE_OBJECT, 0,
	G_IMPLEMENT_INTERFACE (E_TYPE_SOURCE_AUTHENTICATOR, e_mapi_backend_authenticator_authenticator_init))

static void
mapi_config_utils_authenticator_finalize (GObject *object)
{
	EMapiBackendAuthenticator *authenticator = (EMapiBackendAuthenticator *) object;

	g_object_unref (authenticator->mapi_settings);

	G_OBJECT_CLASS (e_mapi_backend_authenticator_parent_class)->finalize (object);
}

static void
e_mapi_backend_authenticator_class_init (EMapiBackendAuthenticatorClass *class)
{
	GObjectClass *object_class;

	object_class = G_OBJECT_CLASS (class);
	object_class->finalize = mapi_config_utils_authenticator_finalize;
}

static void
e_mapi_backend_authenticator_authenticator_init (ESourceAuthenticatorInterface *interface)
{
	interface->try_password_sync = mapi_config_utils_authenticator_try_password_sync;
}

static void
e_mapi_backend_authenticator_init (EMapiBackendAuthenticator *authenticator)
{
}

gboolean
e_mapi_backend_authenticator_run (EBackend *backend,
				  CamelMapiSettings *settings,
				  EMapiBackendAuthenticatorFunc func,
			          gpointer user_data,
				  GCancellable *cancellable,
				  GError **error)
{
	EMapiBackendAuthenticator *authenticator;
	gboolean success;

	g_return_val_if_fail (E_IS_BACKEND (backend), FALSE);
	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (settings), FALSE);
	g_return_val_if_fail (func != NULL, FALSE);

	authenticator = g_object_new (E_TYPE_MAPI_BACKEND_AUTHENTICATOR, NULL);

	authenticator->backend = g_object_ref (backend);
	authenticator->mapi_settings = g_object_ref (settings);
	authenticator->func = func;
	authenticator->func_user_data = user_data;
	authenticator->success = FALSE;

	e_backend_authenticate_sync (
		backend, E_SOURCE_AUTHENTICATOR (authenticator),
		cancellable, error);

	success = authenticator->success;

	g_object_unref (authenticator->backend);
	g_object_unref (authenticator->mapi_settings);
	g_object_unref (authenticator);

	return success;
}
