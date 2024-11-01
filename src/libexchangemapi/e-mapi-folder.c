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

#include "evolution-mapi-config.h"

#include <glib/gi18n-lib.h>

#include <libedataserver/libedataserver.h>

#include "e-mapi-connection.h"
#include "e-mapi-folder.h"
#include "e-mapi-utils.h"
#include "e-source-mapi-folder.h"

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
e_mapi_folder_get_id (EMapiFolder *folder)
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

EMapiFolderCategory
e_mapi_folder_get_category (EMapiFolder *folder)
{
	return folder->category;
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

gboolean
e_mapi_folder_populate_esource (ESource *source,
				const GList *sources,
				EMapiFolderType folder_type,
				const gchar *profile,
				gboolean offline_sync,
				EMapiFolderCategory folder_category,
				const gchar *foreign_username, /* NULL for public folder */
				const gchar *folder_name,
				mapi_id_t folder_id,
				gint color_seed,
				GCancellable *cancellable,
				GError **perror)
{
	ESource *master_source;
	gboolean res = FALSE;

	master_source = e_mapi_utils_get_master_source (sources, profile);

	if (master_source) {
		ESourceBackend *backend_ext;

		e_source_set_parent (source, e_source_get_uid (master_source));
		e_source_set_display_name (source, folder_name);

		switch (folder_type) {
			case E_MAPI_FOLDER_TYPE_APPOINTMENT:
				backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_CALENDAR);
				break;
			case E_MAPI_FOLDER_TYPE_JOURNAL:
			case E_MAPI_FOLDER_TYPE_MEMO:
				backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MEMO_LIST);
				break;
			case E_MAPI_FOLDER_TYPE_TASK:
				backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_TASK_LIST);
				break;
			case E_MAPI_FOLDER_TYPE_CONTACT:
				backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
				break;
			default:
				backend_ext = NULL;
				break;
		}

		if (backend_ext) {
			ESourceMapiFolder *folder_ext;
			ESourceOffline *offline_ext;

			e_source_backend_set_backend_name (backend_ext , "mapi");

			folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
			e_source_mapi_folder_set_id (folder_ext, folder_id);
			if (folder_category == E_MAPI_FOLDER_CATEGORY_PUBLIC)
				e_source_mapi_folder_set_is_public (folder_ext, TRUE);
			else
				e_source_mapi_folder_set_foreign_username (folder_ext, foreign_username);
			
			offline_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_OFFLINE);
			e_source_offline_set_stay_synchronized (offline_ext, offline_sync);

			/* set also color for calendar-like sources */
			if (folder_type != E_MAPI_FOLDER_TYPE_CONTACT) {
				gchar *color_str;

				color_str = e_mapi_folder_pick_color_spec (1 + g_list_length ((GList *) sources), folder_type != E_MAPI_FOLDER_TYPE_APPOINTMENT);
				e_source_selectable_set_color (E_SOURCE_SELECTABLE (backend_ext), color_str);
				g_free (color_str);
			}

			res = TRUE;
		} else {
			g_propagate_error (perror, g_error_new_literal (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER, _("Cannot add folder, unsupported folder type")));
		}
	} else {
		g_propagate_error (perror, g_error_new_literal (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER, _("Cannot add folder, master source not found")));
	}

	return res;
}

gboolean
e_mapi_folder_add_as_esource (ESourceRegistry *pregistry,
			      EMapiFolderType folder_type,
			      const gchar *profile,
			      gboolean offline_sync,
			      EMapiFolderCategory folder_category,
			      const gchar *foreign_username, /* NULL for public folder */
			      const gchar *folder_name,
			      mapi_id_t folder_id,
			      gint color_seed,
			      GCancellable *cancellable,
			      GError **perror)
{
	ESourceRegistry *registry;
	GList *sources;
	ESource *source;
	gboolean res = FALSE;

	registry = pregistry;
	if (!registry) {
		registry = e_source_registry_new_sync (cancellable, perror);
		if (!registry)
			return FALSE;
	}

	sources = e_source_registry_list_sources (registry, NULL);
	source = e_source_new (NULL, NULL, NULL);

	if (e_mapi_folder_populate_esource (
		source,
		sources,
		folder_type,
		profile,
		offline_sync,
		folder_category,
		foreign_username,
		folder_name,
		folder_id,
		color_seed,
		cancellable,
		perror)) {
		res = e_source_registry_commit_source_sync (registry, source, cancellable, perror);
	}
	g_object_unref (source);

	g_list_free_full (sources, g_object_unref);
	if (!pregistry)
		g_object_unref (registry);

	return res;
}

gboolean
e_mapi_folder_remove_as_esource (ESourceRegistry *pregistry,
				 const gchar *profile,
				 mapi_id_t folder_id,
				 GCancellable *cancellable,
				 GError **perror)
{
	ESourceRegistry *registry;
	ESource *source;
	GList *sources;
	gboolean res = TRUE;

	registry = pregistry;
	if (!registry) {
		registry = e_source_registry_new_sync (cancellable, perror);
		if (!registry)
			return FALSE;
	}

	sources = e_source_registry_list_sources (registry, NULL);
	source = e_mapi_utils_get_source_for_folder (sources, profile, folder_id);

	if (source)
		res = e_source_remove_sync (source, cancellable, perror);

	g_list_free_full (sources, g_object_unref);
	if (!pregistry)
		g_object_unref (registry);

	return res;
}

gboolean
e_mapi_folder_is_subscribed_as_esource (const GList *esources,
					const gchar *profile,
					mapi_id_t fid)
{
	return e_mapi_utils_get_source_for_folder (esources, profile, fid) != NULL;
}
