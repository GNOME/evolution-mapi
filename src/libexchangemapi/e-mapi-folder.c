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
 *    Srinivasa Ragavan <sragavan@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "e-mapi-connection.h"
#include "e-mapi-folder.h"

#define d(x)

static EMapiFolderType
container_class_to_type (const gchar *type)
{
	EMapiFolderType folder_type = MAPI_FOLDER_TYPE_UNKNOWN;;

	if (!strcmp (type, IPF_APPOINTMENT))
		folder_type = MAPI_FOLDER_TYPE_APPOINTMENT;
	else if (!strcmp (type, IPF_CONTACT))
		folder_type = MAPI_FOLDER_TYPE_CONTACT;
	else if (!strcmp (type, IPF_STICKYNOTE))
		folder_type = MAPI_FOLDER_TYPE_MEMO;
	else if (!strcmp (type, IPF_TASK))
		folder_type = MAPI_FOLDER_TYPE_TASK;
	else if (!strcmp (type, IPF_NOTE))
		folder_type = MAPI_FOLDER_TYPE_MAIL;
	/* Fixme : no definition for this is available in mapidef.h */
	else if (!strcmp (type, "IPF.Note.HomePage"))
		folder_type = MAPI_FOLDER_TYPE_NOTE_HOMEPAGE;
	else if (!strcmp (type, IPF_JOURNAL))
		folder_type = MAPI_FOLDER_TYPE_JOURNAL;

	return folder_type;
}

EMapiFolder *
e_mapi_folder_new (const gchar *folder_name, const gchar *container_class, EMapiFolderCategory category, mapi_id_t folder_id, mapi_id_t parent_folder_id, uint32_t child_count, uint32_t unread_count, uint32_t total, time_t last_modified)
{
	EMapiFolder *folder;

	folder = g_new0 (EMapiFolder, 1);
	folder->is_default = FALSE;
	folder->folder_name = g_strdup (folder_name);
	folder->container_class = container_class_to_type (container_class);
	folder->folder_id = folder_id;
	folder->parent_folder_id = parent_folder_id;
	folder->child_count = child_count;
	folder->unread_count = unread_count;
	folder->total = total;
	folder->category = category;
	folder->last_modified = last_modified;

	return folder;
}

EMapiFolder *
e_mapi_folder_copy (EMapiFolder *src)
{
	EMapiFolder *res;

	g_return_val_if_fail (src != NULL, NULL);

	res = g_new0 (EMapiFolder, 1);
	*res = *src;
	
	res->owner_name = g_strdup (src->owner_name);
	res->owner_email = g_strdup (src->owner_email);
	res->user_name = g_strdup (src->user_name);
	res->user_email = g_strdup (src->user_email);
	res->folder_name = g_strdup (src->folder_name);

	return res;
}

void
e_mapi_folder_free (EMapiFolder *folder)
{
	if (folder) {
		g_free (folder->folder_name);
		g_free (folder);
	}
}

EMapiFolderType
e_mapi_container_class (gchar *type)
{
	return container_class_to_type (type);
}

const gchar *
e_mapi_folder_get_name (EMapiFolder *folder)
{
	return folder->folder_name;
}

guint64
e_mapi_folder_get_fid (EMapiFolder *folder)
{
	return folder->folder_id;
}

guint64
e_mapi_folder_get_parent_id (EMapiFolder *folder)
{
	return folder->parent_folder_id;
}

gboolean
e_mapi_folder_is_root (EMapiFolder *folder)
{
	return (folder->parent_folder_id == 0);
}

EMapiFolderType
e_mapi_folder_get_type (EMapiFolder *folder)
{
	return folder->container_class;
}

guint32
e_mapi_folder_get_unread_count (EMapiFolder *folder)
{
	return folder->unread_count;
}

guint32
e_mapi_folder_get_total_count (EMapiFolder *folder)
{
	return folder->total;
}

GSList *
e_mapi_folder_copy_list (GSList *folder_list)
{
	GSList *res, *ii;
	
	res = g_slist_copy (folder_list);
	for (ii = res; ii; ii = ii->next) {
		ii->data = e_mapi_folder_copy (ii->data);
	}

	return res;
}

void
e_mapi_folder_free_list (GSList *folder_list)
{
	g_slist_foreach (folder_list, (GFunc) e_mapi_folder_free, NULL);
	g_slist_free (folder_list);
}
