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

#ifndef _CAMEL_MAPI_SUMMARY_H
#define _CAMEL_MAPI_SUMMARY_H

#include <camel/camel-folder-summary.h>
#include <camel/camel-exception.h>
#include <camel/camel-store.h>

#define CAMEL_MAPI_SUMMARY(obj)         CAMEL_CHECK_CAST (obj, camel_mapi_summary_get_type (), CamelMapiSummary)
#define CAMEL_MAPI_SUMMARY_CLASS(klass) CAMEL_CHECK_CLASS_CAST (klass, camel_mapi_summary_get_type (), CamelMapiSummaryClass)
#define CAMEL_IS_MAPI_SUMMARY(obj)      CAMEL_CHECK_TYPE (obj, camel_mapi_summary_get_type ())

G_BEGIN_DECLS

typedef struct _CamelMapiSummary CamelMapiSummary ;
typedef struct _CamelMapiSummaryClass CamelMapiSummaryClass ;
typedef struct _CamelMapiMessageInfo CamelMapiMessageInfo ;
typedef struct _CamelMapiMessageContentInfo CamelMapiMessageContentInfo ;

/* extra summary flags*/
enum {
	CAMEL_GW_MESSAGE_JUNK = 1<<17,
	CAMEL_GW_MESSAGE_NOJUNK = 1<<18,
};

struct _CamelMapiMessageInfo {
	CamelMessageInfoBase info;

	guint32 server_flags;
} ;


struct _CamelMapiMessageContentInfo {
	CamelMessageContentInfo info ;
} ; 


struct _CamelMapiSummary {
	CamelFolderSummary parent ;

	gchar *sync_time_stamp;
	guint32 version ;
	guint32 validity ;
} ;


struct _CamelMapiSummaryClass {
	CamelFolderSummaryClass parent_class ;
} ;


CamelType camel_mapi_summary_get_type (void) ;

CamelFolderSummary *camel_mapi_summary_new (struct _CamelFolder *folder, const char *filename) ;

void mapi_summary_clear (CamelFolderSummary *summary, gboolean uncache);

G_END_DECLS

#endif /*_CAMEL_GW_SUMMARY_H*/
