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
 *    Milan Crha <mcrha@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc. (www.redhat.com)
 *
 */

#ifndef E_MAPI_FAST_TRANSFER_H
#define E_MAPI_FAST_TRANSFER_H

#include <glib.h>
#include <glib-object.h>

#include <libmapi/libmapi.h>
#include "exchange-mapi-connection.h"

G_BEGIN_DECLS

struct _EMapiMessage;
struct _EMapiRecipient;
struct _EMapiAttachment;

typedef struct _EMapiMessage EMapiMessage;
typedef struct _EMapiRecipient EMapiRecipient;
typedef struct _EMapiAttachment EMapiAttachment;

typedef gboolean (*EMapiFastTransferCB) (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, /* const */ EMapiMessage *message, guint32 msg_index, guint32 msg_total, gpointer user_data, GError **perror);

struct _EMapiRecipient
{
	struct mapi_SPropValue_array properties;

	EMapiRecipient *next;
};

struct _EMapiAttachment
{
	struct mapi_SPropValue_array properties;
	EMapiMessage *embeded_message;

	EMapiAttachment *next;
};

struct _EMapiMessage {
	struct mapi_SPropValue_array properties;
	EMapiRecipient *recipients; /* NULL when none */
	EMapiAttachment *attachments; /* NULL when none */

	EMapiMessage *parent; /* chain up to parent's message, if this is embeded attachment */
};

EMapiRecipient *	e_mapi_recipient_new		(TALLOC_CTX *mem_ctx);
void			e_mapi_recipient_free		(EMapiRecipient *recipient);

EMapiAttachment *	e_mapi_attachment_new		(TALLOC_CTX *mem_ctx);
void			e_mapi_attachment_free		(EMapiAttachment *attachment);

EMapiMessage *		e_mapi_message_new		(TALLOC_CTX *mem_ctx);
void			e_mapi_message_free		(EMapiMessage *message);
void			e_mapi_message_dump		(EMapiMessage *message,
							 gint indent,
							 gboolean with_properties);

enum MAPISTATUS		e_mapi_fast_transfer_objects	(ExchangeMapiConnection *conn,
							 mapi_id_t fid,
							 TALLOC_CTX *mem_ctx,
							 mapi_object_t *obj_folder,
							 mapi_id_array_t *ids,
							 EMapiFastTransferCB cb,
							 gpointer cb_user_data,
							 GError **perror);

typedef enum {
	E_MAPI_FAST_TRANSFER_FLAG_NONE		= 0,
	E_MAPI_FAST_TRANSFER_FLAG_ATTACHMENTS	= 1 << 0,
	E_MAPI_FAST_TRANSFER_FLAG_RECIPIENTS	= 1 << 1,
	E_MAPI_FAST_TRANSFER_FLAG_ALL		= E_MAPI_FAST_TRANSFER_FLAG_ATTACHMENTS | E_MAPI_FAST_TRANSFER_FLAG_RECIPIENTS
} EMapiFastTransferFlags;

enum MAPISTATUS		e_mapi_fast_transfer_object	(ExchangeMapiConnection *conn,
							 mapi_id_t fid,
							 TALLOC_CTX *mem_ctx,
							 mapi_object_t *obj_message,
							 guint32 transfer_flags, /* bit OR of EMapiFastTransferFlags */
							 EMapiFastTransferCB cb,
							 gpointer cb_user_data,
							 GError **perror);

G_END_DECLS

#endif /* E_MAPI_FAST_TRANSFER_H */
