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

#ifndef CAMEL_MAPI_STORE_SUMMARY_H
#define CAMEL_MAPI_STORE_SUMMARY_H

#include <camel/camel.h>

#define CAMEL_MAPI_STORE_SUMMARY_VERSION (0)

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_STORE_SUMMARY \
	(camel_mapi_store_summary_get_type ())
#define CAMEL_MAPI_STORE_SUMMARY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_STORE_SUMMARY, CamelMapiStoreSummary))
#define CAMEL_MAPI_STORE_SUMMARY_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_STORE_SUMMARY, CamelMapiStoreSummaryClass))
#define CAMEL_IS_MAPI_STORE_SUMMARY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_STORE_SUMMARY))
#define CAMEL_IS_MAPI_STORE_SUMMARY_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_STORE_SUMMARY))
#define CAMEL_MAPI_STORE_SUMMARY_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_STORE_SUMMARY, CamelMapiStoreSummaryClass))

G_BEGIN_DECLS

typedef struct _CamelMapiStoreSummary CamelMapiStoreSummary;
typedef struct _CamelMapiStoreSummaryClass CamelMapiStoreSummaryClass;
typedef struct _CamelMapiStoreSummaryPrivate CamelMapiStoreSummaryPrivate;

typedef struct _CamelMapiStoreInfo CamelMapiStoreInfo;

enum {
	CAMEL_MAPI_STORE_INFO_FULL_NAME = CAMEL_STORE_INFO_LAST,
	CAMEL_MAPI_STORE_INFO_FOLDER_ID,
	CAMEL_MAPI_STORE_INFO_PARENT_ID,
	CAMEL_MAPI_STORE_INFO_LAST
};

struct _CamelMapiStoreInfo {
	CamelStoreInfo info;
	gchar *full_name;
	gchar *folder_id;
	gchar *parent_id;
};

struct _CamelMapiStoreSummary {
	CamelStoreSummary parent;
	CamelMapiStoreSummaryPrivate *priv;

	/* header info */
	guint32 version;        /* version of base part of file */
	guint32 capabilities;
};

struct _CamelMapiStoreSummaryClass {
	CamelStoreSummaryClass summary_class;
};

GType                        camel_mapi_store_summary_get_type      (void);
CamelMapiStoreSummary      *camel_mapi_store_summary_new        (void);
CamelStoreInfo *camel_mapi_store_summary_full_name(CamelMapiStoreSummary *s, const gchar *full_name);
CamelMapiStoreInfo *camel_mapi_store_summary_add_from_full(CamelMapiStoreSummary *s, const gchar *full, gchar dir_sep,
							   const gchar *folder_id, const gchar *parent_id);

gchar *camel_mapi_store_summary_full_to_path(CamelMapiStoreSummary *s, const gchar *full_name, gchar dir_sep);
gchar *camel_mapi_store_summary_path_to_full(CamelMapiStoreSummary *s, const gchar *path, gchar dir_sep);
gchar *camel_mapi_store_summary_full_from_path(CamelMapiStoreSummary *s, const gchar *path);

#define camel_mapi_store_info_full_name(s, i) (camel_store_info_string((CamelStoreSummary *)s, (const CamelStoreInfo *)i, CAMEL_MAPI_STORE_INFO_FULL_NAME))
#define camel_mapi_store_info_folder_id(s, i) (camel_store_info_string((CamelStoreSummary *)s, (const CamelStoreInfo *)i, CAMEL_MAPI_STORE_INFO_FOLDER_ID))
#define camel_mapi_store_info_parent_id(s, i) (camel_store_info_string((CamelStoreSummary *)s, (const CamelStoreInfo *)i, CAMEL_MAPI_STORE_INFO_PARENT_ID))

G_END_DECLS

#endif /* CAMEL_MAPI_STORE_SUMMARY_H */
