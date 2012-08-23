/*
 * e-mapi-backend-authenticator.h
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

#ifndef E_MAPI_BACKEND_AUTHENTICATOR_H
#define E_MAPI_BACKEND_AUTHENTICATOR_H

#include <libebackend/libebackend.h>
#include <camel-mapi-settings.h>
#include <e-mapi-connection.h>

typedef gboolean (* EMapiBackendAuthenticatorFunc) (EBackend *backend,
						    CamelMapiSettings *settings,
						    EMapiConnection *conn,
						    gpointer user_data,
						    GCancellable *cancellable,
						    GError **error);

gboolean
e_mapi_backend_authenticator_run (EBackend *backend,
				  CamelMapiSettings *settings,
				  EMapiBackendAuthenticatorFunc func,
			          gpointer user_data,
				  GCancellable *cancellable,
				  GError **error);

#endif
