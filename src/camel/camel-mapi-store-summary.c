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
 *     Johnny Jacob <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#include "evolution-mapi-config.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include <e-mapi-utils.h>

#include "camel-mapi-store.h"
#include "camel-mapi-store-summary.h"

#define d(x) 

#define MAPI_STORE_SUMMARY_MARKER	0x0b0e1107
#define MAPI_STORE_SUMMARY_VERSION	2

static gint summary_header_load (CamelStoreSummary *, FILE *);
static gint summary_header_save (CamelStoreSummary *, FILE *);
static CamelStoreInfo *store_info_load (CamelStoreSummary *s, FILE *in);
static gint store_info_save (CamelStoreSummary *s, FILE *out, CamelStoreInfo *mi);
static void store_info_free (CamelStoreSummary *s, CamelStoreInfo *mi);
static void store_info_set_value (CamelStoreSummary *s, CamelStoreInfo *mi, gint type, const gchar *str);

G_DEFINE_TYPE (CamelMapiStoreSummary, camel_mapi_store_summary, CAMEL_TYPE_STORE_SUMMARY)

static void
camel_mapi_store_summary_class_init (CamelMapiStoreSummaryClass *class)
{
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (class);
	store_summary_class->store_info_size = sizeof (CamelMapiStoreInfo);
	store_summary_class->summary_header_load = summary_header_load;
	store_summary_class->summary_header_save = summary_header_save;
	store_summary_class->store_info_load = store_info_load;
	store_summary_class->store_info_save = store_info_save;
	store_summary_class->store_info_free = store_info_free;
	store_summary_class->store_info_set_value = store_info_set_value;
}

static void
camel_mapi_store_summary_init (CamelMapiStoreSummary *mapi_store_summary)
{
}

static gint
summary_header_load (CamelStoreSummary *s, FILE *in)
{
	CamelStoreSummaryClass *store_summary_class;
	guint32 marker = 0, zero = 1, version = 0;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class);

	if (store_summary_class->summary_header_load (s, in) == -1)
		return -1;

	if (camel_file_util_decode_uint32 (in, &marker) == -1 ||
	    camel_file_util_decode_uint32 (in, &zero) == -1 ||
	    camel_file_util_decode_uint32 (in, &version) == -1)
		return -1;

	if (marker != MAPI_STORE_SUMMARY_MARKER ||
	    zero != 0 ||
	    version > MAPI_STORE_SUMMARY_VERSION ||
	    version < 2) /* when the version saving begun */
		return -1;

	return 0;
}

static gint
summary_header_save (CamelStoreSummary *s, FILE *out)
{
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class);

	if (store_summary_class->summary_header_save (s, out) == -1)
		return -1;

	if (camel_file_util_encode_uint32 (out, MAPI_STORE_SUMMARY_MARKER) == -1 ||
	    camel_file_util_encode_uint32 (out, 0) == -1 ||
	    camel_file_util_encode_uint32 (out, MAPI_STORE_SUMMARY_VERSION) == -1)
		return -1;

	return 0;
}

static CamelStoreInfo *
store_info_load (CamelStoreSummary *s, FILE *in)
{
	CamelStoreSummaryClass *store_summary_class;
	CamelStoreInfo *si;
	CamelMapiStoreInfo *msi;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class);

	si = store_summary_class->store_info_load (s, in);
	if (si) {
		gchar *folder_id_str = NULL, *parent_id_str = NULL;

		msi = (CamelMapiStoreInfo *) si;
		if (camel_file_util_decode_string (in, &folder_id_str) == -1
		    || camel_file_util_decode_string (in, &parent_id_str) == -1
		    || camel_file_util_decode_uint32 (in, &msi->camel_folder_flags) == -1
		    || camel_file_util_decode_uint32 (in, &msi->mapi_folder_flags) == -1
		    || camel_file_util_decode_string (in, &msi->foreign_username) == -1
		    || !e_mapi_util_mapi_id_from_string (folder_id_str, &msi->folder_id)
		    || !e_mapi_util_mapi_id_from_string (parent_id_str, &msi->parent_id)) {
			camel_store_info_unref (si);
			si = NULL;
		} else {
			if (msi->foreign_username && !*msi->foreign_username) {
				g_free (msi->foreign_username);
				msi->foreign_username = NULL;
			}

			/* personal folders are not subscribable */
			if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PERSONAL) != 0) {
				si->flags &= ~(CAMEL_STORE_INFO_FOLDER_SUBSCRIBED | CAMEL_FOLDER_SUBSCRIBED);
				msi->camel_folder_flags &= ~(CAMEL_STORE_INFO_FOLDER_SUBSCRIBED | CAMEL_FOLDER_SUBSCRIBED);
			}
		}

		g_free (folder_id_str);
		g_free (parent_id_str);
	}

	return si;
}

static gint
store_info_save (CamelStoreSummary *s, FILE *out, CamelStoreInfo *si)
{
	CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;
	CamelStoreSummaryClass *store_summary_class;
	gchar *folder_id_str = NULL, *parent_id_str = NULL;
	gint res = -1;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class);

	folder_id_str = e_mapi_util_mapi_id_to_string (msi->folder_id);
	parent_id_str = e_mapi_util_mapi_id_to_string (msi->parent_id);

	if (store_summary_class->store_info_save (s, out, si) == -1
	    || camel_file_util_encode_string (out, folder_id_str) == -1
	    || camel_file_util_encode_string (out, parent_id_str) == -1
	    || camel_file_util_encode_uint32 (out, msi->camel_folder_flags) == -1
	    || camel_file_util_encode_uint32 (out, msi->mapi_folder_flags) == -1
	    || camel_file_util_encode_string (out, msi->foreign_username ? msi->foreign_username : "") == -1)
		res = -1;
	else
		res = 0;

	g_free (folder_id_str);
	g_free (parent_id_str);

	return res;
}

static void
store_info_free (CamelStoreSummary *s, CamelStoreInfo *si)
{
	CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

	g_free (msi->foreign_username);

	CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class)->store_info_free (s, si);
}

static void
store_info_set_value (CamelStoreSummary *s, CamelStoreInfo *si, gint type, const gchar *str)
{
	CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

	if (type == CAMEL_MAPI_STORE_INFO_FOREIGN_USERNAME) {
		g_free (msi->foreign_username);
		msi->foreign_username = g_strdup (str);

		camel_store_summary_touch (s);
	} else
		CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class)->store_info_set_value (s, si, type, str);
}

CamelStoreSummary *
camel_mapi_store_summary_new (void)
{
	return g_object_new (CAMEL_TYPE_MAPI_STORE_SUMMARY, NULL);
}

CamelStoreInfo *
camel_mapi_store_summary_add_from_full (CamelStoreSummary *s,
					const gchar *path,
					mapi_id_t folder_id,
					mapi_id_t parent_id,
					guint32 camel_folder_flags,
					guint32 mapi_folder_flags,
					const gchar *foreign_username)
{
	CamelStoreInfo *si;

	si = camel_store_summary_path (s, path);
	if (si) {
		camel_store_info_unref (si);
		return si;
	}

	si = camel_store_summary_add_from_path (s, path);
	if (si) {
		CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

		si->flags = camel_folder_flags;

		msi->folder_id = folder_id;
		msi->parent_id = parent_id;
		msi->camel_folder_flags = camel_folder_flags;
		msi->mapi_folder_flags = mapi_folder_flags;
		msi->foreign_username = g_strdup ((foreign_username && *foreign_username) ? foreign_username : NULL);

		msi->latest_last_modify = 0;
		msi->last_obj_total = -1;
	}

	return si;
}

/* free the returned pointer with camel_store_info_unref(), if not NULL */
CamelStoreInfo *
camel_mapi_store_summary_get_folder_id (CamelStoreSummary *s, mapi_id_t folder_id)
{
	CamelStoreInfo *adept = NULL;
	GPtrArray *array;
	guint ii;

	array = camel_store_summary_array (s);

	for (ii = 0; ii < array->len; ii++) {
		CamelStoreInfo *si;
		CamelMapiStoreInfo *msi;

		si = g_ptr_array_index (array, ii);
		msi = (CamelMapiStoreInfo *) si;

		if (msi->folder_id == folder_id) {
			/* public folders can be stored in a summary twice, once as "All Public Folders/..."
			   and once as a subscribed variant, "Favorites/...". In that case prefer
			   the subscribed folder folder, from the general public folder
			*/
			if ((msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC_REAL) == 0) {
				if (adept)
					camel_store_info_unref (adept);

				adept = camel_store_info_ref (si);
				break;
			} else {
				if (adept)
					camel_store_info_unref (adept);
				adept = camel_store_info_ref (si);
			}
		}
	}

	camel_store_summary_array_free (s, array);

	return adept;
}
