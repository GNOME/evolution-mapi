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

#include "evolution-mapi-config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "camel-mapi-folder.h"
#include "camel-mapi-folder-summary.h"
#include "camel-mapi-store.h"

#define CAMEL_MAPI_FOLDER_SUMMARY_VERSION (1)

/*Prototypes*/
static CamelFIRecord *mapi_summary_header_save (CamelFolderSummary *, GError **error);
static gboolean mapi_summary_header_load (CamelFolderSummary *, CamelFIRecord *fir);

/*End of Prototypes*/

G_DEFINE_TYPE (CamelMapiFolderSummary, camel_mapi_folder_summary, CAMEL_TYPE_FOLDER_SUMMARY)

static void
camel_mapi_folder_summary_class_init (CamelMapiFolderSummaryClass *class)
{
	CamelFolderSummaryClass *folder_summary_class;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (class);
	folder_summary_class->message_info_type = CAMEL_TYPE_MAPI_MESSAGE_INFO;
	folder_summary_class->summary_header_save = mapi_summary_header_save;
	folder_summary_class->summary_header_load = mapi_summary_header_load;
}

static void
camel_mapi_folder_summary_init (CamelMapiFolderSummary *mapi_summary)
{
}

/**
 * camel_mapi_folder_summary_new:
 *
 * This will create a new CamelMapiFolderSummary object and read in the
 * summary data from disk, if it exists.
 *
 * Return value: A new CamelMapiFolderSummary object.
 **/
CamelFolderSummary *
camel_mapi_folder_summary_new (CamelFolder *folder)
{
	CamelFolderSummary *summary;
	GError *local_error = NULL;

	summary = g_object_new (CAMEL_TYPE_MAPI_FOLDER_SUMMARY, "folder", folder, NULL);

	if (!camel_folder_summary_load (summary, &local_error)) {
		/* FIXME: Isn't this dangerous ? We clear the summary
		if it cannot be loaded, for some random reason.
		We need to pass the ex and find out why it is not loaded etc. ? */
		camel_folder_summary_clear (summary, NULL);
		g_warning ("Unable to load summary %s\n", local_error ? local_error->message : "Unknown error");
	}

	g_clear_error (&local_error);

	return summary;
}

static gboolean
mapi_summary_header_load (CamelFolderSummary *summary, CamelFIRecord *fir)
{
	CamelMapiFolderSummary *mapi_summary = CAMEL_MAPI_FOLDER_SUMMARY (summary);
	CamelFolderSummaryClass *folder_summary_class;
	gchar *part;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	if (!folder_summary_class->summary_header_load (summary, fir))
		return FALSE;

	part = fir->bdata;

	if (part)
		mapi_summary->version = camel_util_bdata_get_number (&part, 0);

	return TRUE;
}

static CamelFIRecord *
mapi_summary_header_save (CamelFolderSummary *summary, GError **error)
{
	CamelFolderSummaryClass *folder_summary_class;
	struct _CamelFIRecord *fir;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (camel_mapi_folder_summary_parent_class);

	fir = folder_summary_class->summary_header_save (summary, error);

	if (!fir)
		return NULL;

	fir->bdata = g_strdup_printf ("%d", CAMEL_MAPI_FOLDER_SUMMARY_VERSION);

	return fir;
}

void
mapi_summary_clear (CamelFolderSummary *summary, gboolean uncache)
{
	CamelFolderChangeInfo *changes;
	CamelMessageInfo *info;
	gint i;
	const gchar *uid;
	GPtrArray *known_uids;

	changes = camel_folder_change_info_new ();
	known_uids = camel_folder_summary_get_array (summary);
	for (i = 0; known_uids && i < known_uids->len; i++) {
		if (!(info = camel_folder_summary_get (summary, g_ptr_array_index (known_uids, i))))
			continue;

		uid = camel_message_info_get_uid (info);
		camel_folder_change_info_remove_uid (changes, uid);
		camel_folder_summary_remove_uid (summary, uid);
		g_clear_object (&info);
	}

	camel_folder_summary_free_array (known_uids);
	camel_folder_summary_clear (summary, NULL);

	if (camel_folder_change_info_changed (changes))
		camel_folder_changed (camel_folder_summary_get_folder (summary), changes);
	camel_folder_change_info_free (changes);
}
