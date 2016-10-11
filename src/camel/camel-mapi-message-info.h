/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016 Red Hat, Inc. (www.redhat.com)
 *
 * This library is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CAMEL_MAPI_MESSAGE_INFO_H
#define CAMEL_MAPI_MESSAGE_INFO_H

#include <glib-object.h>

#include <camel/camel.h>

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_MESSAGE_INFO \
	(camel_mapi_message_info_get_type ())
#define CAMEL_MAPI_MESSAGE_INFO(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_MESSAGE_INFO, CamelMapiMessageInfo))
#define CAMEL_MAPI_MESSAGE_INFO_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_MESSAGE_INFO, CamelMapiMessageInfoClass))
#define CAMEL_IS_MAPI_MESSAGE_INFO(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_MESSAGE_INFO))
#define CAMEL_IS_MAPI_MESSAGE_INFO_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_MESSAGE_INFO))
#define CAMEL_MAPI_MESSAGE_INFO_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_MESSAGE_INFO, CamelMapiMessageInfoClass))

G_BEGIN_DECLS

#define CAMEL_MAPI_MESSAGE_WITH_READ_RECEIPT (CAMEL_MESSAGE_FOLDER_FLAGGED << 1)

typedef struct _CamelMapiMessageInfo CamelMapiMessageInfo;
typedef struct _CamelMapiMessageInfoClass CamelMapiMessageInfoClass;
typedef struct _CamelMapiMessageInfoPrivate CamelMapiMessageInfoPrivate;

struct _CamelMapiMessageInfo {
	CamelMessageInfoBase parent;
	CamelMapiMessageInfoPrivate *priv;
};

struct _CamelMapiMessageInfoClass {
	CamelMessageInfoBaseClass parent_class;
};

GType		camel_mapi_message_info_get_type	(void);

guint32		camel_mapi_message_info_get_server_flags
							(const CamelMapiMessageInfo *mmi);
gboolean	camel_mapi_message_info_set_server_flags
							(CamelMapiMessageInfo *mmi,
							 guint32 server_flags);
gint64		camel_mapi_message_info_get_last_modified
							(const CamelMapiMessageInfo *mmi);
gboolean	camel_mapi_message_info_set_last_modified
							(CamelMapiMessageInfo *mmi,
							 gint64 last_modified);

G_END_DECLS

#endif /* CAMEL_MAPI_MESSAGE_INFO_H */
