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
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef E_MAPI_MAIL_UTILS_H
#define E_MAPI_MAIL_UTILS_H 

#include "evolution-mapi-config.h"

#include <glib.h>
#include <gio/gio.h>

#include <libmapi/libmapi.h>

#include <e-mapi-connection.h>

struct _CamelAddress;
struct _CamelMimeMessage;

struct _CamelMimeMessage *e_mapi_mail_utils_object_to_message	(EMapiConnection *conn,
								 /* const */ EMapiObject *object);

gboolean		e_mapi_mail_utils_message_to_object	(struct _CamelMimeMessage *message,
								 guint32 message_camel_flags,
								 EMapiCreateFlags create_flags,
								 EMapiObject **pobject,
								 TALLOC_CTX *mem_ctx,
								 GCancellable *cancellable,
								 GError **perror);

void			e_mapi_mail_utils_decode_email_address	(EMapiConnection *conn,
								 struct mapi_SPropValue_array *properties,
								 const uint32_t *name_proptags,
								 guint name_proptags_len,
								 const uint32_t *email_proptags,
								 guint email_proptags_len,
								 uint32_t email_type_proptag,
								 uint32_t email_proptag,
								 gchar **name,
								 gchar **email);
void			e_mapi_mail_utils_decode_email_address1	(EMapiConnection *conn,
								 struct mapi_SPropValue_array *properties,
								 uint32_t name_proptag,
								 uint32_t email_proptag,
								 uint32_t email_type_proptag,
								 gchar **name,
								 gchar **email);
void			e_mapi_mail_utils_decode_recipients	(EMapiConnection *conn,
								 EMapiRecipient *recipients,
								 struct _CamelAddress *to,
								 struct _CamelAddress *cc,
								 struct _CamelAddress *bcc);

#endif /* E_MAPI_MAIL_UTILS */
