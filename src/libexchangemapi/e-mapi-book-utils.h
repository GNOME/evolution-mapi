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
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef E_MAPI_BOOK_UTILS_H
#define E_MAPI_BOOK_UTILS_H

#include <libebook/libebook.h>

#include <e-mapi-connection.h>
#include <e-mapi-defs.h>
#include <e-mapi-utils.h>

/* vCard parameter name in contact list */
#define EMA_X_MEMBERID "X-EMA-MEMBER-ID"
#define EMA_X_MEMBERVALUE "X-EMA-MEMBER-VALUE"

G_BEGIN_DECLS

EContact *	e_mapi_book_utils_contact_from_object		(EMapiConnection *conn,
								 EMapiObject *object,
								 const gchar *book_uri);

gboolean	e_mapi_book_utils_contact_to_object		(EContact *contact,
								 EContact *old_contact, /* can be NULL */
								 EMapiObject **pobject,
								 TALLOC_CTX *mem_ctx,
								 GCancellable *cancellable,
								 GError **perror);

/* converts time_t to string, suitable for E_CONTACT_REV field value;
   free returned pointer with g_free() */
gchar *		e_mapi_book_utils_timet_to_string		(time_t tt);

/* converts sexp_query into mapi_SRestriction, which is completely
   allocated on the given mem_ctx */
gboolean	e_mapi_book_utils_build_sexp_restriction	(EMapiConnection *conn,
								 TALLOC_CTX *mem_ctx,
								 struct mapi_SRestriction **restrictions,
								 gpointer user_data, /* const gchar *sexp */
								 GCancellable *cancellable,
								 GError **perror);

GSList *	e_mapi_book_utils_get_supported_contact_fields	(void);

gboolean	e_mapi_book_utils_get_supported_mapi_proptags	(TALLOC_CTX *mem_ctx,
								 struct SPropTagArray **propTagArray);

G_END_DECLS

#endif
