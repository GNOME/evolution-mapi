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

#ifndef _CAMEL_MAPI_STORE_SUMMARY_H
#define _CAMEL_MAPI_STORE_SUMMARY_H

#include <camel/camel-object.h>
#include <camel/camel-store-summary.h>

#define CAMEL_MAPI_STORE_SUMMARY_VERSION (0)

#define CAMEL_MAPI_STORE_SUMMARY(obj)         CAMEL_CHECK_CAST (obj, camel_mapi_store_summary_get_type (), CamelMapiStoreSummary)
#define CAMEL_MAPI_STORE_SUMMARY_CLASS(klass) CAMEL_CHECK_CLASS_CAST (klass, camel_mapi_store_summary_get_type (), CamelMapiStoreSummaryClass)
#define CAMEL_IS_MAPI_STORE_SUMMARY(obj)      CAMEL_CHECK_TYPE (obj, camel_mapi_store_summary_get_type ())

G_BEGIN_DECLS

typedef struct _CamelMapiStoreSummary      CamelMapiStoreSummary;
typedef struct _CamelMapiStoreSummaryClass CamelMapiStoreSummaryClass;

typedef struct _CamelMapiStoreInfo CamelMapiStoreInfo;

enum {
	CAMEL_MAPI_STORE_INFO_FULL_NAME = CAMEL_STORE_INFO_LAST,
	CAMEL_MAPI_STORE_INFO_LAST,
};

struct _CamelMapiStoreInfo {
	CamelStoreInfo info;
	char *full_name;
};

struct _CamelMapiStoreSummary {
	CamelStoreSummary summary;

	struct _CamelMapiStoreSummaryPrivate *priv;

	/* header info */
	guint32 version;        /* version of base part of file */
	guint32 capabilities;
};

struct _CamelMapiStoreSummaryClass {
	CamelStoreSummaryClass summary_class;
};

CamelType                        camel_mapi_store_summary_get_type      (void);
CamelMapiStoreSummary      *camel_mapi_store_summary_new        (void);
CamelMapiStoreInfo *camel_mapi_store_summary_full_name(CamelMapiStoreSummary *s, const char *full_name) ;
CamelMapiStoreInfo *camel_mapi_store_summary_add_from_full(CamelMapiStoreSummary *s, const char *full, char dir_sep) ;

char *camel_mapi_store_summary_full_to_path(CamelMapiStoreSummary *s, const char *full_name, char dir_sep) ;
char *camel_mapi_store_summary_path_to_full(CamelMapiStoreSummary *s, const char *path, char dir_sep) ;
char *camel_mapi_store_summary_full_from_path(CamelMapiStoreSummary *s, const char *path) ;

#define camel_mapi_store_info_full_name(s, i) (camel_store_info_string((CamelStoreSummary *)s, (const CamelStoreInfo *)i, CAMEL_STORE_INFO_LAST))

G_END_DECLS

#endif /* ! _CAMEL_MAPI_STORE_SUMMARY_H */
