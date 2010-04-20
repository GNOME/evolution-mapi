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
 *    Suman Manjunath <msuman@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef EXCHANGE_MAPI_UTILS_H
#define EXCHANGE_MAPI_UTILS_H 

#include "exchange-mapi-connection.h"

gchar *
utf8tolinux (const gchar *wstring);

gchar *
exchange_mapi_util_mapi_id_to_string (mapi_id_t id);
gboolean
exchange_mapi_util_mapi_id_from_string (const gchar *str, mapi_id_t *id);

gchar *
exchange_mapi_util_mapi_ids_to_uid (mapi_id_t fid, mapi_id_t mid);
gboolean
exchange_mapi_util_mapi_ids_from_uid (const gchar *str, mapi_id_t *fid, mapi_id_t *mid);

gconstpointer
exchange_mapi_util_find_SPropVal_array_propval (struct SPropValue *values, uint32_t proptag);
gconstpointer
exchange_mapi_util_find_row_propval (struct SRow *aRow, uint32_t proptag);
gconstpointer
exchange_mapi_util_find_array_propval (struct mapi_SPropValue_array *properties, uint32_t proptag);

ExchangeMAPIStream *
exchange_mapi_util_find_stream (GSList *stream_list, uint32_t proptag);

void
exchange_mapi_util_free_attachment_list (GSList **attach_list);
void
exchange_mapi_util_free_recipient_list (GSList **recip_list);
void
exchange_mapi_util_free_stream_list (GSList **stream_list);

void
exchange_mapi_debug_property_dump (struct mapi_SPropValue_array *properties);

void exchange_mapi_util_entryid_generate_oneoff (TALLOC_CTX *mem_ctx, struct Binary_r *entryid, const gchar *display_name, const gchar *email);
gboolean exchange_mapi_util_entryid_decode_oneoff (const struct Binary_r *entyrid, gchar **display_name, gchar **email);

struct Binary_r *
exchange_mapi_util_entryid_generate_local (TALLOC_CTX *mem_ctx, const gchar *exchange_dn);

gchar *
exchange_lf_to_crlf (const gchar *in);
gchar *
exchange_crlf_to_lf (const gchar *in);

gchar *exchange_mapi_util_profile_name (const gchar *username, const gchar *domain, const gchar *hostname, gboolean migrate);

#endif

