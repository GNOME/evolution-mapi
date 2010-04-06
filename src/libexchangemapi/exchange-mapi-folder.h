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

#ifndef EXCHANGE_MAPI_FOLDER_H
#define EXCHANGE_MAPI_FOLDER_H

#include <glib.h>

#include <libmapi/libmapi.h>

typedef enum  {
	MAPI_FOLDER_TYPE_MAIL=1,
	MAPI_FOLDER_TYPE_APPOINTMENT,
	MAPI_FOLDER_TYPE_CONTACT,
	MAPI_FOLDER_TYPE_MEMO,
	MAPI_FOLDER_TYPE_JOURNAL,
	MAPI_FOLDER_TYPE_TASK,
	MAPI_FOLDER_TYPE_NOTE_HOMEPAGE,
	MAPI_FOLDER_TYPE_UNKNOWN
} ExchangeMAPIFolderType;

typedef enum {
	MAPI_PERSONAL_FOLDER,
	MAPI_FAVOURITE_FOLDER,
	MAPI_FOREIGN_FOLDER
} ExchangeMAPIFolderCategory;

typedef struct _ExchangeMAPIFolder {
	/* We'll need this separation of 'owner' and 'user' when we do delegation */
	gchar *owner_name;
	gchar *owner_email;
	gchar *user_name;
	gchar *user_email;

	/* Need this info - default calendars/address books/notes folders can't be deleted */
	gboolean is_default;
	guint32 default_type;

	gchar *folder_name;
	ExchangeMAPIFolderType container_class;
	ExchangeMAPIFolderCategory category;
	mapi_id_t folder_id;
	mapi_id_t parent_folder_id;
	guint32 child_count;
	guint32 unread_count;
	guint32 total;
	guint32 size;

	/* reserved */
	gpointer reserved1;
	gpointer reserved2;
	gpointer reserved3;
} ExchangeMAPIFolder;

ExchangeMAPIFolder *
exchange_mapi_folder_new (const gchar *folder_name, const gchar *container_class,
			  ExchangeMAPIFolderCategory catgory,
			  mapi_id_t folder_id, mapi_id_t parent_folder_id,
			  uint32_t child_count, uint32_t unread_count, uint32_t total);
void exchange_mapi_folder_free (ExchangeMAPIFolder *folder);
ExchangeMAPIFolderType exchange_mapi_container_class (gchar *type);

const gchar * exchange_mapi_folder_get_name (ExchangeMAPIFolder *folder);
guint64 exchange_mapi_folder_get_fid (ExchangeMAPIFolder *folder);
guint64 exchange_mapi_folder_get_parent_id (ExchangeMAPIFolder *folder);
ExchangeMAPIFolderType exchange_mapi_folder_get_type (ExchangeMAPIFolder *folder);
guint32 exchange_mapi_folder_get_unread_count (ExchangeMAPIFolder *folder);
guint32 exchange_mapi_folder_get_total_count (ExchangeMAPIFolder *folder);

gboolean exchange_mapi_folder_is_root (ExchangeMAPIFolder *folder);
GSList * exchange_mapi_peek_folder_list (void);
void exchange_mapi_folder_list_free (void);
ExchangeMAPIFolder * exchange_mapi_folder_get_folder (mapi_id_t fid);
void exchange_mapi_folder_list_add (ExchangeMAPIFolder *folder);

#endif
