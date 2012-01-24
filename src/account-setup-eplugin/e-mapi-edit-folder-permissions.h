/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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

#ifndef E_MAPI_EDIT_FOLDER_PERMISSIONS_H
#define E_MAPI_EDIT_FOLDER_PERMISSIONS_H

#include <gtk/gtk.h>
#include <libmapi/libmapi.h>

#include <e-mapi-folder.h>

void	e_mapi_edit_folder_permissions	(GtkWindow *parent,
					 const gchar *login_profile,
					 const gchar *login_username,
					 const gchar *login_url,
					 const gchar *account_name,
					 const gchar *folder_name,
					 mapi_id_t folder_id,
					 EMapiFolderCategory folder_category,
					 const gchar *foreign_username,
					 gboolean with_freebusy);

#endif /* E_MAPI_EDIT_FOLDER_PERMISSIONS_H */
