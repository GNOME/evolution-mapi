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
 *     Johnny Jacob <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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
static void store_info_set_string (CamelStoreSummary *s, CamelStoreInfo *mi, gint type, const gchar *str);
static const gchar *store_info_string (CamelStoreSummary *s, const CamelStoreInfo *mi, gint type);

G_DEFINE_TYPE (CamelMapiStoreSummary, camel_mapi_store_summary, CAMEL_TYPE_STORE_SUMMARY)

static void
camel_mapi_store_summary_class_init (CamelMapiStoreSummaryClass *class)
{
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (class);
	store_summary_class->summary_header_load = summary_header_load;
	store_summary_class->summary_header_save = summary_header_save;
	store_summary_class->store_info_load = store_info_load;
	store_summary_class->store_info_save = store_info_save;
	store_summary_class->store_info_free = store_info_free;
	store_summary_class->store_info_string = store_info_string;
	store_summary_class->store_info_set_string = store_info_set_string;
}

static void
camel_mapi_store_summary_init (CamelMapiStoreSummary *mapi_store_summary)
{
	CamelStoreSummary *store_summary;

	store_summary = CAMEL_STORE_SUMMARY (mapi_store_summary);
	store_summary->store_info_size = sizeof (CamelMapiStoreInfo);
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
		    || camel_file_util_decode_string (in, &msi->foreign_user_name) == -1
		    || !e_mapi_util_mapi_id_from_string (folder_id_str, &msi->folder_mid)
		    || !e_mapi_util_mapi_id_from_string (parent_id_str, &msi->parent_mid)) {
			camel_store_summary_info_free (s, si);
			si = NULL;
		} else {
			if (msi->foreign_user_name && !*msi->foreign_user_name) {
				g_free (msi->foreign_user_name);
				msi->foreign_user_name = NULL;
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

	folder_id_str = e_mapi_util_mapi_id_to_string (msi->folder_mid);
	parent_id_str = e_mapi_util_mapi_id_to_string (msi->parent_mid);

	if (store_summary_class->store_info_save (s, out, si) == -1
	    || camel_file_util_encode_string (out, folder_id_str) == -1
	    || camel_file_util_encode_string (out, parent_id_str) == -1
	    || camel_file_util_encode_uint32 (out, msi->camel_folder_flags) == -1
	    || camel_file_util_encode_uint32 (out, msi->mapi_folder_flags) == -1
	    || camel_file_util_encode_string (out, msi->foreign_user_name ? msi->foreign_user_name : "") == -1)
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

	g_free (msi->foreign_user_name);

	CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class)->store_info_free (s, si);
}

static const gchar *
store_info_string (CamelStoreSummary *s, const CamelStoreInfo *si, gint type)
{
	CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

	if (type == CAMEL_MAPI_STORE_INFO_FOREIGN_USER_NAME)
		return msi->foreign_user_name;

	return CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class)->store_info_string (s, si, type);
}

static void
store_info_set_string (CamelStoreSummary *s, CamelStoreInfo *si, gint type, const gchar *str)
{
	CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

	if (type == CAMEL_MAPI_STORE_INFO_FOREIGN_USER_NAME) {
		g_free (msi->foreign_user_name);
		msi->foreign_user_name = g_strdup (str);

		camel_store_summary_touch (s);
	} else
		CAMEL_STORE_SUMMARY_CLASS (camel_mapi_store_summary_parent_class)->store_info_set_string (s, si, type, str);
}

CamelStoreSummary *
camel_mapi_store_summary_new (void)
{
	return g_object_new (CAMEL_TYPE_MAPI_STORE_SUMMARY, NULL);
}

CamelStoreInfo *
camel_mapi_store_summary_add_from_full (CamelStoreSummary *s,
					const gchar *path,
					mapi_id_t folder_mid,
					mapi_id_t parent_mid,
					guint32 camel_folder_flags,
					guint32 mapi_folder_flags,
					const gchar *foreign_user_name)
{
	CamelStoreInfo *si;

	si = camel_store_summary_path (s, path);
	if (si) {
		camel_store_summary_info_free (s, si);
		return si;
	}

	si = camel_store_summary_add_from_path (s, path);
	if (si) {
		CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

		msi->folder_mid = folder_mid;
		msi->parent_mid = parent_mid;
		msi->camel_folder_flags = camel_folder_flags;
		msi->mapi_folder_flags = mapi_folder_flags;
		msi->foreign_user_name = g_strdup ((foreign_user_name && *foreign_user_name) ? foreign_user_name : "");
	}

	return si;
}

/* free the returned pointer with camel_store_summary_info_free(), if not NULL */
CamelStoreInfo *
camel_mapi_store_summary_get_folder_id (CamelStoreSummary *s, mapi_id_t folder_mid)
{
	gint ii, count;

	count = camel_store_summary_count (s);
	for (ii = 0; ii < count; ii++) {
		CamelStoreInfo *si = camel_store_summary_index (s, ii);
		CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

		if (si == NULL)
			continue;

		if (msi->folder_mid == folder_mid)
			return si;

		camel_store_summary_info_free (s, si);
	}

	return NULL;
}
