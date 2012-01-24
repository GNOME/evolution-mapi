/*
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
 *
 * Authors:
 *		Srinivasa Ragavan <sragavan@novell.com>
 *		Johnny Jacob  <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef E_MAPI_ACCOUNT_SETUP_H
#define E_MAPI_ACCOUNT_SETUP_H

#include <gtk/gtk.h>

#include "e-mapi-account-listener.h"
#include <e-mapi-connection.h>

#define MAPI_URI_PREFIX   "mapi://" 
#define MAPI_PREFIX_LENGTH 7

EMapiAccountListener *	e_mapi_accounts_peek_config_listener	(void);

typedef void		(* EMapiSetupFunc)			(GObject *with_object,
								 gpointer user_data,
								 GCancellable *cancellable,
								 GError **perror);

void			e_mapi_run_in_thread_with_feedback	(GtkWindow *parent,
								 GObject *with_object,
								 const gchar *description,
								 EMapiSetupFunc thread_func,
								 EMapiSetupFunc idle_func,
								 gpointer user_data,
								 GDestroyNotify free_user_data);

EMapiConnection	*	e_mapi_account_open_connection_for	(GtkWindow *parent,
								 const gchar *login_profile,
								 const gchar *login_username,
								 const gchar *login_url,
								 GCancellable *cancellable,
								 GError **perror);

void			e_mapi_account_unref_conn_in_thread	(EMapiConnection *conn);

#endif /* E_MAPI_ACCOUNT_SETUP_H */
