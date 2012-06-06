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
static CamelFIRecord* mapi_summary_header_to_db (CamelFolderSummary *, GError **error);
static gboolean mapi_summary_header_from_db (CamelFolderSummary *, CamelFIRecord *fir);

static CamelMessageInfo *mapi_message_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir);
static CamelMIRecord *mapi_message_info_to_db (CamelFolderSummary *s, CamelMessageInfo *info);

static CamelMessageContentInfo * mapi_content_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir);
static gboolean mapi_content_info_to_db (CamelFolderSummary *s, CamelMessageContentInfo *info, CamelMIRecord *mir);

/*End of Prototypes*/

G_DEFINE_TYPE (CamelMapiFolderSummary, camel_mapi_folder_summary, CAMEL_TYPE_FOLDER_SUMMARY)

static void
mapi_summary_finalize (GObject *object)
{
	/* Chain up to parent's finalize() method. */
	G_OBJECT_CLASS (camel_mapi_folder_summary_parent_class)->finalize (object);
}

static CamelMessageInfo *
mapi_message_info_clone(CamelFolderSummary *s, const CamelMessageInfo *mi)
{
	CamelMapiMessageInfo *to;
	const CamelMapiMessageInfo *from = (const CamelMapiMessageInfo *)mi;
	CamelFolderSummaryClass *folder_summary_class;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	to = (CamelMapiMessageInfo *)folder_summary_class->message_info_clone(s, mi);
	to->server_flags = from->server_flags;
	to->last_modified = from->last_modified;

	/* FIXME: parent clone should do this */
	to->info.content = camel_folder_summary_content_info_new(s);

	return (CamelMessageInfo *)to;
}

static void
camel_mapi_folder_summary_class_init (CamelMapiFolderSummaryClass *class)
{
	GObjectClass *object_class;
	CamelFolderSummaryClass *folder_summary_class;

	object_class = G_OBJECT_CLASS (class);
	object_class->finalize = mapi_summary_finalize;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (class);
	folder_summary_class->message_info_size = sizeof (CamelMapiMessageInfo);
	folder_summary_class->content_info_size = sizeof (CamelMapiMessageContentInfo);
	folder_summary_class->message_info_clone = mapi_message_info_clone;
	folder_summary_class->summary_header_to_db = mapi_summary_header_to_db;
	folder_summary_class->summary_header_from_db = mapi_summary_header_from_db;
	folder_summary_class->message_info_to_db = mapi_message_info_to_db;
	folder_summary_class->message_info_from_db = mapi_message_info_from_db;
	folder_summary_class->content_info_to_db = mapi_content_info_to_db;
	folder_summary_class->content_info_from_db = mapi_content_info_from_db;
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

	camel_folder_summary_set_build_content (summary, FALSE);

	if (!camel_folder_summary_load_from_db (summary, &local_error)) {
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
mapi_summary_header_from_db (CamelFolderSummary *summary, CamelFIRecord *fir)
{
	CamelMapiFolderSummary *mapi_summary = CAMEL_MAPI_FOLDER_SUMMARY (summary);
	CamelFolderSummaryClass *folder_summary_class;
	gchar *part;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	if (!folder_summary_class->summary_header_from_db (summary, fir))
		return FALSE;

	part = fir->bdata;

	if (part)
		mapi_summary->version = bdata_extract_digit (&part);

	return TRUE;
}

static CamelFIRecord *
mapi_summary_header_to_db (CamelFolderSummary *summary, GError **error)
{
	CamelFolderSummaryClass *folder_summary_class;
	struct _CamelFIRecord *fir;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	fir = folder_summary_class->summary_header_to_db (summary, error);

	if (!fir)
		return NULL;

	fir->bdata = g_strdup_printf ("%d", CAMEL_MAPI_FOLDER_SUMMARY_VERSION);

	return fir;
}

static CamelMessageInfo*
mapi_message_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir)
{
	CamelFolderSummaryClass *folder_summary_class;
	CamelMessageInfo *info;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	info = folder_summary_class->message_info_from_db (s, mir);
	if (info) {
		gchar *part = mir->bdata;
		if (part && *part) {
			CamelMapiMessageInfo *m_info;

			m_info = (CamelMapiMessageInfo *) info;
			m_info->server_flags = bdata_extract_digit (&part);
			m_info->last_modified = bdata_extract_digit (&part);
		}
	}

	return info;
}

static CamelMIRecord *
mapi_message_info_to_db (CamelFolderSummary *s, CamelMessageInfo *info)
{
	CamelFolderSummaryClass *folder_summary_class;
	CamelMapiMessageInfo *m_info = (CamelMapiMessageInfo *) info;
	struct _CamelMIRecord *mir;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	mir = folder_summary_class->message_info_to_db (s, info);
	if (mir)
		mir->bdata = g_strdup_printf ("%u %u", m_info->server_flags, (guint32) m_info->last_modified);

	return mir;
}

static CamelMessageContentInfo*
mapi_content_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir)
{
	CamelFolderSummaryClass *folder_summary_class;
	gchar *part = mir->cinfo;
	guint32 type=0;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	if (part)
		type = bdata_extract_digit (&part);

	mir->cinfo = part;

	if (type)
		return folder_summary_class->content_info_from_db (s, mir);
	else
		return camel_folder_summary_content_info_new (s);
}

static gboolean
mapi_content_info_to_db (CamelFolderSummary *s, CamelMessageContentInfo *info, CamelMIRecord *mir)
{
	CamelFolderSummaryClass *folder_summary_class;

	folder_summary_class = CAMEL_FOLDER_SUMMARY_CLASS (
		camel_mapi_folder_summary_parent_class);

	if (info->type) {
		mir->cinfo = g_strdup ("1");
		return folder_summary_class->content_info_to_db (s, info, mir);
	} else {
		mir->cinfo = g_strdup ("0");
		return TRUE;
	}
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

		uid = camel_message_info_uid (info);
		camel_folder_change_info_remove_uid (changes, uid);
		camel_folder_summary_remove_uid (summary, uid);
		camel_message_info_free(info);
	}

	camel_folder_summary_free_array (known_uids);
	camel_folder_summary_clear (summary, NULL);

	if (camel_folder_change_info_changed (changes))
		camel_folder_changed (camel_folder_summary_get_folder (summary), changes);
	camel_folder_change_info_free (changes);
}
