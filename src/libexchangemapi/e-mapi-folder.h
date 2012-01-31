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

#ifndef E_MAPI_FOLDER_H
#define E_MAPI_FOLDER_H

#include <glib.h>

#include <libmapi/libmapi.h>

#define CALENDAR_SOURCES	"/apps/evolution/calendar/sources"
#define TASK_SOURCES		"/apps/evolution/tasks/sources"
#define JOURNAL_SOURCES		"/apps/evolution/memos/sources"
#define SELECTED_CALENDARS	"/apps/evolution/calendar/display/selected_calendars"
#define SELECTED_TASKS		"/apps/evolution/calendar/tasks/selected_tasks"
#define SELECTED_JOURNALS	"/apps/evolution/calendar/memos/selected_memos"
#define ADDRESSBOOK_SOURCES     "/apps/evolution/addressbook/sources"

typedef enum  {
	E_MAPI_FOLDER_TYPE_UNKNOWN = 0,
	E_MAPI_FOLDER_TYPE_MAIL,
	E_MAPI_FOLDER_TYPE_APPOINTMENT,
	E_MAPI_FOLDER_TYPE_CONTACT,
	E_MAPI_FOLDER_TYPE_MEMO,
	E_MAPI_FOLDER_TYPE_JOURNAL,
	E_MAPI_FOLDER_TYPE_TASK,
	E_MAPI_FOLDER_TYPE_NOTE_HOMEPAGE
} EMapiFolderType;

typedef enum {
	E_MAPI_FOLDER_CATEGORY_UNKNOWN = 0,
	E_MAPI_FOLDER_CATEGORY_PERSONAL,
	E_MAPI_FOLDER_CATEGORY_PUBLIC,
	E_MAPI_FOLDER_CATEGORY_FOREIGN
} EMapiFolderCategory;

typedef struct _EMapiFolder {
	/* We'll need this separation of 'owner' and 'user' when we do delegation */
	gchar *owner_name;
	gchar *owner_email;
	gchar *user_name;
	gchar *user_email;

	/* Need this info - default calendars/address books/notes folders can't be deleted */
	gboolean is_default;
	guint32 default_type;

	gchar *folder_name;
	EMapiFolderType container_class;
	EMapiFolderCategory category;
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
} EMapiFolder;

EMapiFolderType		e_mapi_folder_type_from_string	(const gchar *container_class);
const gchar *		e_mapi_folder_type_to_string	(EMapiFolderType folder_type);

EMapiFolder *		e_mapi_folder_new		(const gchar *folder_name,
							 const gchar *container_class,
							 EMapiFolderCategory catgory,
							 mapi_id_t folder_id,
							 mapi_id_t parent_folder_id,
							 uint32_t child_count,
							 uint32_t unread_count,
							 uint32_t total);
EMapiFolder *		e_mapi_folder_copy		(EMapiFolder *src);
void			e_mapi_folder_free		(EMapiFolder *folder);

const gchar *		e_mapi_folder_get_name		(EMapiFolder *folder);
mapi_id_t		e_mapi_folder_get_fid		(EMapiFolder *folder);
mapi_id_t		e_mapi_folder_get_parent_id	(EMapiFolder *folder);
EMapiFolderType		e_mapi_folder_get_type		(EMapiFolder *folder);
guint32			e_mapi_folder_get_unread_count	(EMapiFolder *folder);
guint32			e_mapi_folder_get_total_count	(EMapiFolder *folder);
gboolean		e_mapi_folder_is_root		(EMapiFolder *folder);

GSList *		e_mapi_folder_copy_list		(GSList *folder_list);
void			e_mapi_folder_free_list		(GSList *folder_list);

gchar *			e_mapi_folder_pick_color_spec	(gint move_by,
							 gboolean around_middle);

gboolean		e_mapi_folder_add_as_esource	(EMapiFolderType folder_type,
							 const gchar *login_profile,
							 const gchar *login_domain,
							 const gchar *login_realm,
							 const gchar *login_host,
							 const gchar *login_user,
							 gboolean login_kerberos,
							 gboolean offline_sync,
							 EMapiFolderCategory folder_category,
							 const gchar *foreign_username, /* NULL for public folder */
							 const gchar *folder_name,
							 const gchar *fid,
							 GError **perror);

gboolean		e_mapi_folder_remove_as_esource	(EMapiFolderType folder_type,
							 const gchar *login_host,
							 const gchar *login_user,
							 const gchar *fid,
							 GError **perror);

gboolean		e_mapi_folder_is_subscribed_as_esource
							(EMapiFolderType folder_type,
							 const gchar *login_host,
							 const gchar *login_user,
							 const gchar *fid);
#endif
