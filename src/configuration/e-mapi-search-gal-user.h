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
 *    Milan Crha <mcrha@redhat.com>
 *
 * Copyright (C) 2012 Red Hat, Inc. (www.redhat.com)
 *
 */

#ifndef E_MAPI_SEARCH_GAL_USER_H
#define E_MAPI_SEARCH_GAL_USER_H

#include <gtk/gtk.h>
#include <e-mapi-connection.h>

typedef enum {
	E_MAPI_GAL_USER_NONE		= 0,
	E_MAPI_GAL_USER_DEFAULT		= 1 << 0,
	E_MAPI_GAL_USER_ANONYMOUS	= 1 << 1,
	E_MAPI_GAL_USER_REGULAR		= 1 << 2
} EMapiGalUserType;

gboolean	e_mapi_search_gal_user_modal	(GtkWindow *parent,
						 EMapiConnection *conn,
						 const gchar *search_this,
						 EMapiGalUserType *searched_type, /* one of from the enum */
						 gchar **display_name,
						 gchar **email,
						 gchar **user_dn,
						 struct SBinary_short **entry_id); /* allocated with GLib, not talloc */

#endif /* E_MAPI_SEARCH_GAL_USER_H */
