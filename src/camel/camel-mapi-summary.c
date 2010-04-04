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
#include "camel-mapi-summary.h"

#define CAMEL_MAPI_SUMMARY_VERSION (1)

/* Macros for DB Summary */
#define MS_EXTRACT_FIRST_DIGIT(val) val=strtoul (part, &part, 10);

/*Prototypes*/
static CamelFIRecord* mapi_summary_header_to_db (CamelFolderSummary *, CamelException *ex);
static int mapi_summary_header_from_db (CamelFolderSummary *, CamelFIRecord *fir);

static CamelMessageInfo *mapi_message_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir) ;
static CamelMIRecord *mapi_message_info_to_db (CamelFolderSummary *s, CamelMessageInfo *info) ;

static CamelMessageContentInfo * mapi_content_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir) ;
static int mapi_content_info_to_db (CamelFolderSummary *s, CamelMessageContentInfo *info, CamelMIRecord *mir) ;

static void camel_mapi_summary_class_init (CamelMapiSummaryClass *klass);
static void camel_mapi_summary_init       (CamelMapiSummary *obj);
static void camel_mapi_summary_finalize   (CamelObject *obj);

/*End of Prototypes*/


static CamelFolderSummaryClass *camel_mapi_summary_parent ;


CamelType
camel_mapi_summary_get_type (void)
{
	static CamelType type = CAMEL_INVALID_TYPE;

	if (type == CAMEL_INVALID_TYPE) {
		type = camel_type_register(
				camel_folder_summary_get_type(), "CamelMapiSummary",
				sizeof (CamelMapiSummary),
				sizeof (CamelMapiSummaryClass),
				(CamelObjectClassInitFunc) camel_mapi_summary_class_init,
				NULL,
				(CamelObjectInitFunc) camel_mapi_summary_init,
				(CamelObjectFinalizeFunc) camel_mapi_summary_finalize);
	}

	return type;
}

static CamelMessageInfo *
mapi_message_info_clone(CamelFolderSummary *s, const CamelMessageInfo *mi)
{
	CamelMapiMessageInfo *to;
	const CamelMapiMessageInfo *from = (const CamelMapiMessageInfo *)mi;

	to = (CamelMapiMessageInfo *)camel_mapi_summary_parent->message_info_clone(s, mi);
	to->server_flags = from->server_flags;

	/* FIXME: parent clone should do this */
	to->info.content = camel_folder_summary_content_info_new(s);

	return (CamelMessageInfo *)to;
}

static void
camel_mapi_summary_class_init (CamelMapiSummaryClass *klass)
{
	CamelFolderSummaryClass *cfs_class = (CamelFolderSummaryClass *) klass;

	camel_mapi_summary_parent = CAMEL_FOLDER_SUMMARY_CLASS (camel_type_get_global_classfuncs (camel_folder_summary_get_type()));

	cfs_class->message_info_clone = mapi_message_info_clone ;

	cfs_class->summary_header_to_db = mapi_summary_header_to_db;
	cfs_class->summary_header_from_db = mapi_summary_header_from_db;
	cfs_class->message_info_to_db = mapi_message_info_to_db;
	cfs_class->message_info_from_db = mapi_message_info_from_db;
	cfs_class->content_info_to_db = mapi_content_info_to_db;
	cfs_class->content_info_from_db = mapi_content_info_from_db;
}


static void
camel_mapi_summary_init (CamelMapiSummary *obj)
{
	CamelFolderSummary *s = (CamelFolderSummary *)obj;

	/* subclasses need to set the right instance data sizes */
	s->message_info_size = sizeof(CamelMapiMessageInfo);
	s->content_info_size = sizeof(CamelMapiMessageContentInfo);
	
	/* Meta-summary - Overriding UID len */
	s->meta_summary->uid_len = 2048;
}

static void
camel_mapi_summary_finalize (CamelObject *obj)
{
	CamelMapiSummary *s = (CamelMapiSummary *)obj;

	g_free (s->sync_time_stamp);
}

/**
 * camel_mapi_summary_new:
 * @filename: the file to store the summary in.
 *
 * This will create a new CamelMapiSummary object and read in the
 * summary data from disk, if it exists.
 *
 * Return value: A new CamelMapiSummary object.
 **/
CamelFolderSummary *
camel_mapi_summary_new (struct _CamelFolder *folder, const char *filename)
{
	CamelException ex;

	CamelFolderSummary *summary = CAMEL_FOLDER_SUMMARY (
			camel_object_new (camel_mapi_summary_get_type ()));

	camel_exception_init (&ex);
	
	summary->folder = folder ;
	camel_folder_summary_set_build_content (summary, TRUE);
	camel_folder_summary_set_filename (summary, filename);

	if (camel_folder_summary_load_from_db (summary, &ex) == -1) {
		/* FIXME: Isn't this dangerous ? We clear the summary
		if it cannot be loaded, for some random reason.
		We need to pass the ex and find out why it is not loaded etc. ? */
		camel_folder_summary_clear_db (summary);
		g_warning ("Unable to load summary %s\n", camel_exception_get_description (&ex));
		camel_exception_clear (&ex);
	}

	return summary;
}

static int
mapi_summary_header_from_db (CamelFolderSummary *summary, CamelFIRecord *fir) 
{
	CamelMapiSummary *mapi_summary = CAMEL_MAPI_SUMMARY (summary);
	gchar *part;

	if (camel_mapi_summary_parent->summary_header_from_db (summary, fir) == -1)
		return -1 ;

	part = fir->bdata;

	if (part)
		MS_EXTRACT_FIRST_DIGIT(mapi_summary->version);

	if (part && part++) {
		g_free (mapi_summary->sync_time_stamp);
		mapi_summary->sync_time_stamp = g_strdup (part);
	}

	return 0;
}
static CamelFIRecord *
mapi_summary_header_to_db (CamelFolderSummary *summary, CamelException *ex) 
{
	CamelMapiSummary *mapi_summary = CAMEL_MAPI_SUMMARY(summary);
	struct _CamelFIRecord *fir;

	fir = camel_mapi_summary_parent->summary_header_to_db (summary, ex);

	if(!fir)
		return NULL;

	fir->bdata = g_strdup_printf ("%d %s", CAMEL_MAPI_SUMMARY_VERSION, mapi_summary->sync_time_stamp);

	return fir;
}

static CamelMessageInfo*
mapi_message_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir) 
{
	CamelMessageInfo *info ;

	info = camel_mapi_summary_parent->message_info_from_db (s, mir) ;

	return info ;
}

static CamelMIRecord *
mapi_message_info_to_db (CamelFolderSummary *s, CamelMessageInfo *info) 
{
	struct _CamelMIRecord *mir;

	mir = camel_mapi_summary_parent->message_info_to_db (s, info);

	return mir;
}

static CamelMessageContentInfo* 
mapi_content_info_from_db (CamelFolderSummary *s, CamelMIRecord *mir) 
{
	char *part = mir->cinfo;
	guint32 type=0;
	
	if (part) 
		MS_EXTRACT_FIRST_DIGIT (type);

	mir->cinfo = part;

	if (type)
		return camel_mapi_summary_parent->content_info_from_db (s, mir);
	else
		return camel_folder_summary_content_info_new (s);
}

static int
mapi_content_info_to_db (CamelFolderSummary *s, CamelMessageContentInfo *info, CamelMIRecord *mir)
{
	if (info->type) {
		mir->cinfo = g_strdup ("1");
		return camel_mapi_summary_parent->content_info_to_db (s, info, mir);
	} else {
		mir->cinfo = g_strdup ("0");
		return 0;
	}
}

void
mapi_summary_clear (CamelFolderSummary *summary, gboolean uncache)
{
	CamelFolderChangeInfo *changes;
	CamelMessageInfo *info;
	int i, count;
	const char *uid;

	changes = camel_folder_change_info_new ();
	count = camel_folder_summary_count (summary);
	for (i = 0; i < count; i++) {
		if (!(info = camel_folder_summary_index (summary, i)))
			continue;

		uid = camel_message_info_uid (info);
		camel_folder_change_info_remove_uid (changes, uid);
		camel_folder_summary_remove_uid (summary, uid);
		camel_message_info_free(info);
	}

	camel_folder_summary_clear_db (summary);

	if (camel_folder_change_info_changed (changes))
		camel_object_trigger_event (summary->folder, "folder_changed", changes);
	camel_folder_change_info_free (changes);
}
