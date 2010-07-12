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

#ifndef __E_BOOK_BACKEND_MAPI_UTILS_H__
#define __E_BOOK_BACKEND_MAPI_UTILS_H__

#include <libedata-book/e-data-book.h>
#include "exchange-mapi-connection.h"

#define EDB_ERROR(_code) e_data_book_create_error (E_DATA_BOOK_STATUS_ ## _code, NULL)
#define EDB_ERROR_EX(_code, _msg) e_data_book_create_error (E_DATA_BOOK_STATUS_ ## _code, _msg)

void mapi_error_to_edb_error (GError **perror, const GError *mapi_error, EDataBookStatus code, const gchar *context);

/* vCard parameter name in contact list */
#define EMA_X_MEMBERID "X-EMA-MEMBER-ID"
#define EMA_X_MEMBERVALUE "X-EMA-MEMBER-VALUE"

GList *mapi_book_utils_get_supported_fields (void);

#define GET_ALL_KNOWN_IDS (GINT_TO_POINTER(1))
#define GET_SHORT_SUMMARY (GINT_TO_POINTER(2))

/* data is one of GET_ALL_KNOWN_IDS or GET_SHORT_SUMMARY */
gboolean mapi_book_utils_get_prop_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data);

/* only one of mapi_properties and aRow can be set */
EContact *mapi_book_utils_contact_from_props (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SPropValue_array *mapi_properties, struct SRow *aRow);

#endif /* __E_BOOK_BACKEND_MAPI_UTILS_H__ */
