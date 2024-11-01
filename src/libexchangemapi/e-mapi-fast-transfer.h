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
#include <gio/gio.h>

#include <libmapi/libmapi.h>
#include "e-mapi-connection.h"

G_BEGIN_DECLS

enum MAPISTATUS		e_mapi_fast_transfer_objects	(EMapiConnection *conn,
							 TALLOC_CTX *mem_ctx,
							 mapi_object_t *obj_folder,
							 mapi_id_array_t *ids,
							 TransferObjectCB cb,
							 gpointer cb_user_data,
							 GCancellable *cancellable,
							 GError **perror);

typedef enum {
	E_MAPI_FAST_TRANSFER_FLAG_NONE		= 0,
	E_MAPI_FAST_TRANSFER_FLAG_ATTACHMENTS	= 1 << 0,
	E_MAPI_FAST_TRANSFER_FLAG_RECIPIENTS	= 1 << 1,
	E_MAPI_FAST_TRANSFER_FLAG_ALL		= E_MAPI_FAST_TRANSFER_FLAG_ATTACHMENTS | E_MAPI_FAST_TRANSFER_FLAG_RECIPIENTS
} EMapiFastTransferFlags;

enum MAPISTATUS		e_mapi_fast_transfer_object	(EMapiConnection *conn,
							 TALLOC_CTX *mem_ctx,
							 mapi_object_t *object,
							 guint32 transfer_flags, /* bit OR of EMapiFastTransferFlags */
							 TransferObjectCB cb,
							 gpointer cb_user_data,
							 GCancellable *cancellable,
							 GError **perror);

enum MAPISTATUS		e_mapi_fast_transfer_properties	(EMapiConnection *conn,
							 TALLOC_CTX *mem_ctx,
							 mapi_object_t *object,
							 struct SPropTagArray *tags,
							 TransferObjectCB cb,
							 gpointer cb_user_data,
							 GCancellable *cancellable,
							 GError **perror);

G_END_DECLS

#endif /* E_MAPI_FAST_TRANSFER_H */
