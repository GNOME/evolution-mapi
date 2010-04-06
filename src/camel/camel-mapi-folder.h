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

#ifndef __MAPI_FOLDER_H__
#define __MAPI_FOLDER_H__

#include <camel/camel.h>
#include <libmapi/libmapi.h>
#include <exchange-mapi-connection.h>

#define PATH_FOLDER ".evolution/mail/mapi"

#define CAMEL_MAPI_FOLDER_TYPE     (camel_mapi_folder_get_type ())
#define CAMEL_MAPI_FOLDER(obj)     (CAMEL_CHECK_CAST((obj), CAMEL_MAPI_FOLDER_TYPE, CamelMapiFolder))
#define CAMEL_MAPI_FOLDER_CLASS(k) (CAMEL_CHECK_CLASS_CAST ((k), CAMEL_MAPI_FOLDER_TYPE, CamelMapiFolderClass))
#define CAMEL_IS_MAPI_FOLDER(o)    (CAMEL_CHECK_TYPE((o), CAMEL_MAPI_FOLDER_TYPE))

/**
 * DATA STRUCTURES
 */

G_BEGIN_DECLS

typedef enum  {
	MAPI_ITEM_TYPE_MAIL=1,
	MAPI_ITEM_TYPE_APPOINTMENT,
	MAPI_ITEM_TYPE_CONTACT,
	MAPI_ITEM_TYPE_JOURNAL,
	MAPI_ITEM_TYPE_TASK
} MapiItemType;

typedef enum  {
	PART_TYPE_PLAIN_TEXT=1,
	PART_TYPE_TEXT_HTML
} MapiItemPartType;

typedef struct {
	gchar *subject;
	gchar *from;
	gchar *from_email;
	gchar *from_type;

	gchar *references;
	gchar *message_id;
	gchar *in_reply_to;
	/*TODO : Obsolete this. Moved to recipient list*/
	gchar *to;
	gchar *cc;
	gchar *bcc;

	gint flags;
	glong size;
	time_t recieved_time;
	time_t send_time;
	guint cpid; /* codepage id */
	gchar *transport_headers;
} MapiItemHeader;

typedef struct {
	GSList *body_parts;
} MapiItemMessage;

typedef struct  {
	mapi_id_t fid;
	mapi_id_t mid;

	MapiItemHeader header;
	MapiItemMessage msg;

	gboolean is_cal;

	GSList *recipients;
	GSList *attachments;
	GSList *generic_streams;
}MapiItem;

void mapi_item_free (MapiItem *item);

typedef struct  _CamelMapiFolder CamelMapiFolder;
typedef struct  _CamelMapiFolderClass CamelMapiFolderClass;

struct _CamelMapiFolder {
	CamelOfflineFolder parent_object;

	struct _CamelMapiFolderPrivate *priv;

	CamelFolderSearch *search;

	CamelOfflineJournal *journal;
	CamelDataCache *cache;

	guint32 type;

	guint need_rescan:1;
	guint need_refresh:1;
	guint read_only:1;
};

struct _CamelMapiFolderClass {
	CamelOfflineFolderClass parent_class;

	/* Virtual methods */

} ;

typedef struct {
	GSList *items_list;
	GTimeVal last_modification_time;
	CamelFolder *folder;
	CamelFolderChangeInfo *changes;
}fetch_items_data;

/* Standard Camel function */
CamelType camel_mapi_folder_get_type (void);

/* implemented */
CamelFolder *
camel_mapi_folder_new(CamelStore *store, const gchar *folder_name, const gchar *folder_dir, guint32 flags, CamelException *ex);

void mapi_update_summary ( CamelFolder *folder, GList *item_list,CamelException *ex);
void mapi_refresh_folder(CamelFolder *folder, CamelException *ex);
gboolean camel_mapi_folder_fetch_summary (CamelStore *store, const mapi_id_t fid, struct mapi_SRestriction *res,
					  struct SSortOrderSet *sort, fetch_items_data *fetch_data, guint32 options);

G_END_DECLS

#endif /* CAMEL_GROUPWISE_FOLDER_H */
