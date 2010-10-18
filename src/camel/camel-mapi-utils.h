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
 * Copyright (C) 1999-2009 Novell, Inc. (www.novell.com)
 *
 */

#ifndef CAMEL_MAPI_UTILS_H
#define CAMEL_MAPI_UTILS_H

G_BEGIN_DECLS

#include <exchange-mapi-connection.h>
#include <exchange-mapi-mail-utils.h>
#include <camel/camel.h>

MailItem *
camel_mapi_utils_mime_to_item (CamelMimeMessage *message, gint32 message_camel_flags, CamelAddress *from, GCancellable *cancellable, GError **error);

gboolean
camel_mapi_utils_create_item_build_props (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropValue **values, uint32_t *n_values, gpointer data);

G_END_DECLS

#endif /* CAMEL_MAPI_UTILS_H */
