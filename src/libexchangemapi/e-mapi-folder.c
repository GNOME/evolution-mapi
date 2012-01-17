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

#include <glib/gi18n-lib.h>

#include <libedataserver/e-source.h>
#include <libedataserver/e-source-group.h>
#include <libedataserver/e-source-list.h>

#include "e-mapi-connection.h"
#include "e-mapi-folder.h"

#define d(x)

static struct _folder_type_map {
	const gchar *container_class;
	EMapiFolderType folder_type;
} folder_type_map[] = {
	{ IPF_APPOINTMENT,	E_MAPI_FOLDER_TYPE_APPOINTMENT },
	{ IPF_CONTACT,		E_MAPI_FOLDER_TYPE_CONTACT },
	{ IPF_STICKYNOTE,	E_MAPI_FOLDER_TYPE_MEMO },
	{ IPF_TASK,		E_MAPI_FOLDER_TYPE_TASK },
	{ IPF_NOTE,		E_MAPI_FOLDER_TYPE_MAIL },
	{ "IPF.Note.HomePage",	E_MAPI_FOLDER_TYPE_NOTE_HOMEPAGE },
	{ IPF_JOURNAL,		E_MAPI_FOLDER_TYPE_JOURNAL}
};

EMapiFolderType
e_mapi_folder_type_from_string (const gchar *container_class)
{
	gint ii;

	if (!container_class)
		return E_MAPI_FOLDER_TYPE_UNKNOWN;

	for (ii = 0; ii < G_N_ELEMENTS (folder_type_map); ii++) {
		if (g_str_equal (folder_type_map[ii].container_class, container_class))
			return folder_type_map[ii].folder_type;
	}

	return E_MAPI_FOLDER_TYPE_UNKNOWN;
}

const gchar *
e_mapi_folder_type_to_string (EMapiFolderType folder_type)
{
	gint ii;

	for (ii = 0; ii < G_N_ELEMENTS (folder_type_map); ii++) {
		if (folder_type_map[ii].folder_type == folder_type)
			return folder_type_map[ii].container_class;
	}

	return NULL;
}

EMapiFolder *
e_mapi_folder_new (const gchar *folder_name,
		   const gchar *container_class,
		   EMapiFolderCategory category,
		   mapi_id_t folder_id,
		   mapi_id_t parent_folder_id,
		   uint32_t child_count,
		   uint32_t unread_count,
		   uint32_t total)
{
	EMapiFolder *folder;

	folder = g_new0 (EMapiFolder, 1);
	folder->is_default = FALSE;
	folder->folder_name = g_strdup (folder_name);
	folder->container_class = e_mapi_folder_type_from_string (container_class);
	folder->folder_id = folder_id;
	folder->parent_folder_id = parent_folder_id;
	folder->child_count = child_count;
	folder->unread_count = unread_count;
	folder->total = total;
	folder->category = category;

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
		g_free (folder->owner_name);
		g_free (folder->owner_email);
		g_free (folder->user_name);
		g_free (folder->user_email);
		g_free (folder->folder_name);
		g_free (folder);
	}
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

gchar *
e_mapi_folder_pick_color_spec (gint move_by,
			       gboolean around_middle)
{
	static gint color_mover = 0;
	static gint color_indexer = -1;
	const guint32 colors[] = {
		0x1464ae, /* dark blue */
		0x14ae64, /* dark green */
		0xae1464, /* dark red */
		0
	};
	guint32 color;

	if (move_by <= 0)
		move_by = 1;

	while (move_by > 0) {
		move_by--;

		color_indexer++;
		if (colors[color_indexer] == 0) {
			color_mover += 1;
			color_indexer = 0;
		}
	}

	color = colors[color_indexer];
	color = (color & ~(0xFF << (color_indexer * 8))) |
		(((((color >> (color_indexer * 8)) & 0xFF) + (0x33 * color_mover)) % 0xFF) << (color_indexer * 8));

	if (around_middle) {
		gint rr, gg, bb, diff;

		rr = (0xFF0000 & color) >> 16;
		gg = (0x00FF00 & color) >>  8;
		bb = (0x0000FF & color);

		diff = 0x80 - rr;
		if (diff < 0x80 - gg)
			diff = 0x80 - gg;
		if (diff < 0x80 - bb)
			diff = 0x80 - bb;

		rr = rr + diff < 0 ? 0 : rr + diff > 0xCC ? 0xCC : rr + diff;
		gg = gg + diff < 0 ? 0 : gg + diff > 0xCC ? 0xCC : gg + diff;
		bb = bb + diff < 0 ? 0 : bb + diff > 0xCC ? 0xCC : bb + diff;

		color = (rr << 16) + (gg << 8) + bb;
	}

	return g_strdup_printf ("#%06x", color);
}

#define MAPI_URI_PREFIX   "mapi://" 

gboolean
e_mapi_folder_add_as_esource (EMapiFolderType folder_type,
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
			      GError **perror)
{
	ESourceList *source_list = NULL;
	ESourceGroup *group = NULL;
	const gchar *conf_key = NULL;
	GConfClient* client;
	GSList *sources;
	ESource *source = NULL;
	gchar *relative_uri = NULL;
	gchar *base_uri = NULL;

	g_return_val_if_fail (login_profile != NULL, FALSE);
	g_return_val_if_fail (login_host != NULL, FALSE);
	g_return_val_if_fail (login_user != NULL, FALSE);
	g_return_val_if_fail (folder_name != NULL, FALSE);
	g_return_val_if_fail (fid != NULL, FALSE);
	g_return_val_if_fail (folder_category == E_MAPI_FOLDER_CATEGORY_PUBLIC || folder_category == E_MAPI_FOLDER_CATEGORY_FOREIGN, FALSE);
	if (folder_category == E_MAPI_FOLDER_CATEGORY_FOREIGN)
		g_return_val_if_fail (foreign_username != NULL, FALSE);

	if (folder_type == E_MAPI_FOLDER_TYPE_APPOINTMENT)
		conf_key = CALENDAR_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_TASK)
		conf_key = TASK_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_MEMO)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_JOURNAL)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_CONTACT)
		conf_key = ADDRESSBOOK_SOURCES;
	else {
		g_propagate_error (perror, g_error_new_literal (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER, _("Cannot add folder, unsupported folder type")));
		return FALSE;
	}

	client = gconf_client_get_default ();
	source_list = e_source_list_new_for_gconf (client, conf_key);
	base_uri = g_strdup_printf ("%s%s@%s/", MAPI_URI_PREFIX, login_user, login_host);
	group = e_source_list_peek_group_by_base_uri (source_list, base_uri);
	if (!group) {
		g_propagate_error (perror, g_error_new_literal (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER, _("Cannot add folder, group of sources not found")));
		g_object_unref (source_list);
		g_object_unref (client);
		g_free (base_uri);

		return FALSE;
	}

	sources = e_source_group_peek_sources (group);
	for (; sources != NULL; sources = g_slist_next (sources)) {
		ESource *source = E_SOURCE (sources->data);
		gchar *folder_id = e_source_get_duped_property (source, "folder-id");
		if (folder_id) {
			if (g_str_equal (fid, folder_id)) {
				g_object_unref (source_list);
				g_object_unref (client);
				g_free (folder_id);
				g_free (base_uri);
				
				g_propagate_error (perror,
					g_error_new (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER,
						_("Cannot add folder, folder already exists as '%s'"), e_source_peek_name (source)));
				return FALSE;
			}

			g_free (folder_id);
		}
	}

	relative_uri = g_strconcat (";", fid, NULL);
	source = e_source_new (folder_name, relative_uri);
	e_source_set_property (source, "username", login_user);
	e_source_set_property (source, "host", login_host);
	e_source_set_property (source, "profile", login_profile);
	e_source_set_property (source, "domain", login_domain);
	e_source_set_property (source, "realm", login_realm);
	e_source_set_property (source, "folder-id", fid);
	e_source_set_property (source, "offline_sync", offline_sync ? "1" : "0");
	e_source_set_property (source, "delete", "yes");
	if (folder_category == E_MAPI_FOLDER_CATEGORY_PUBLIC)
		e_source_set_property (source, "public", "yes");
	else
		e_source_set_property (source, "foreign-username", foreign_username);
	if (login_kerberos) {
		e_source_set_property (source, "kerberos", "required");
	} else {
		e_source_set_property (source, "auth", "1");
		e_source_set_property (source, "auth-type", "plain/password");
	}

	/* set also color for calendar-like sources */
	if (folder_type != E_MAPI_FOLDER_TYPE_CONTACT) {
		GSList *sources = e_source_group_peek_sources (group);
		gchar *color_str;

		color_str = e_mapi_folder_pick_color_spec (1 + g_slist_length (sources), folder_type != E_MAPI_FOLDER_TYPE_APPOINTMENT);
		e_source_set_color_spec (source, color_str);
		g_free (color_str);
	}

	e_source_group_add_source (group, source, -1);

	g_object_unref (source);
	g_object_unref (client);
	g_free (relative_uri);
	g_free (base_uri);

	if (!e_source_list_sync (source_list, perror)) {
		g_object_unref (source_list);
		return FALSE;
	}

	g_object_unref (source_list);
	return TRUE;
}

gboolean
e_mapi_folder_remove_as_esource (EMapiFolderType folder_type,
				 const gchar *login_host,
				 const gchar *login_user,
				 const gchar *fid,
				 GError **perror)
{
	ESourceList *source_list = NULL;
	ESourceGroup *group = NULL;
	const gchar *conf_key = NULL;
	GConfClient* client;
	GSList *sources = NULL;
	gchar *base_uri = NULL;

	g_return_val_if_fail (login_host != NULL, FALSE);
	g_return_val_if_fail (login_user != NULL, FALSE);
	g_return_val_if_fail (fid != NULL, FALSE);

	if (folder_type == E_MAPI_FOLDER_TYPE_APPOINTMENT)
		conf_key = CALENDAR_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_TASK)
		conf_key = TASK_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_MEMO)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_JOURNAL)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == E_MAPI_FOLDER_TYPE_CONTACT)
		conf_key = ADDRESSBOOK_SOURCES;
	else {
		g_propagate_error (perror, g_error_new_literal (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER, _("Cannot remove folder, unsupported folder type")));
		return FALSE;
	}

	client = gconf_client_get_default ();
	source_list = e_source_list_new_for_gconf (client, conf_key);
	base_uri = g_strdup_printf ("%s%s@%s/", MAPI_URI_PREFIX, login_user, login_host);
	group = e_source_list_peek_group_by_base_uri (source_list, base_uri);
	if (!group) {
		g_free (base_uri);
		g_object_unref (source_list);
		g_object_unref (client);

		return TRUE;
	}

	sources = e_source_group_peek_sources (group);
	for (; sources != NULL; sources = g_slist_next (sources)) {
		ESource *source = E_SOURCE (sources->data);
		gchar *folder_id = e_source_get_duped_property (source, "folder-id");
		if (folder_id) {
			if (g_str_equal (fid, folder_id)) {
				g_free (folder_id);

				e_source_group_remove_source (group, source);
				break;
			}

			g_free (folder_id);
		}
	}

	g_free (base_uri);
	g_object_unref (source_list);
	g_object_unref (client);

	return TRUE;
}
