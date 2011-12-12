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

#ifndef E_MAPI_UTILS_H
#define E_MAPI_UTILS_H 

#include "camel-mapi-settings.h"
#include "e-mapi-debug.h"
#include "e-mapi-connection.h"

gchar *  e_mapi_util_mapi_id_to_string (mapi_id_t id);
gboolean e_mapi_util_mapi_id_from_string (const gchar *str, mapi_id_t *id);

gconstpointer	e_mapi_util_find_SPropVal_array_propval (struct SPropValue *values, uint32_t proptag);
gconstpointer	e_mapi_util_find_SPropVal_array_namedid (struct SPropValue *values, EMapiConnection *conn, mapi_id_t fid, uint32_t namedid);
gconstpointer	e_mapi_util_find_row_propval (struct SRow *aRow, uint32_t proptag);
gconstpointer	e_mapi_util_find_row_namedid (struct SRow *aRow, EMapiConnection *conn, mapi_id_t fid, uint32_t namedid);
gconstpointer	e_mapi_util_find_array_propval (struct mapi_SPropValue_array *properties, uint32_t proptag);
gconstpointer	e_mapi_util_find_array_namedid (struct mapi_SPropValue_array *properties, EMapiConnection *conn, mapi_id_t fid, uint32_t namedid);
uint32_t	e_mapi_util_find_array_proptag (struct mapi_SPropValue_array *properties, uint32_t proptag);

enum MAPISTATUS e_mapi_util_find_array_datetime_propval (struct timeval *tv, struct mapi_SPropValue_array *properties, uint32_t proptag);
enum MAPISTATUS e_mapi_util_find_array_datetime_namedid (struct timeval *tv, struct mapi_SPropValue_array *properties, EMapiConnection *conn, mapi_id_t fid, uint32_t namedid);

ExchangeMAPIStream *e_mapi_util_find_stream (GSList *stream_list, uint32_t proptag);
ExchangeMAPIStream *e_mapi_util_find_stream_namedid (GSList *stream_list, EMapiConnection *conn, mapi_id_t fid, uint32_t namedid);

void e_mapi_util_free_attachment_list (GSList **attach_list);
void e_mapi_util_free_recipient_list (GSList **recip_list);
void e_mapi_util_free_stream_list (GSList **stream_list);

void	 e_mapi_util_recip_entryid_generate_smtp (TALLOC_CTX *mem_ctx, struct Binary_r *entryid, const gchar *display_name, const gchar *email);
void	 e_mapi_util_recip_entryid_generate_ex  (TALLOC_CTX *mem_ctx, struct Binary_r *entryid, const gchar *exchange_dn);
gboolean e_mapi_util_recip_entryid_decode (EMapiConnection *conn, const struct Binary_r *entyrid, gchar **display_name, gchar **email);

gchar *exchange_lf_to_crlf (const gchar *in);
gchar *exchange_crlf_to_lf (const gchar *in);

void e_mapi_util_profiledata_from_settings (EMapiProfileData *empd, CamelMapiSettings *settings);
gchar *		e_mapi_util_profile_name			(struct mapi_context *mapi_ctx,
								 const EMapiProfileData *empd,
								 gboolean migrate);
gboolean e_mapi_util_trigger_krb_auth (const EMapiProfileData *empd, GError **error);

gboolean	e_mapi_utils_add_props_to_props_array		(TALLOC_CTX *mem_ctx,
								 struct SPropTagArray *props,
								 const uint32_t *prop_ids,
								 guint prop_ids_n_elems);
gboolean	e_mapi_utils_add_named_ids_to_props_array	(EMapiConnection *conn,
								 mapi_id_t fid,
								 TALLOC_CTX *mem_ctx,
								 struct SPropTagArray *props,
								 ResolveNamedIDsData *named_ids_list,
								 guint named_ids_n_elems,
								 GCancellable *cancellable,
								 GError **perror);

gboolean	e_mapi_utils_add_spropvalue			(TALLOC_CTX *mem_ctx,
								 struct SPropValue **values_array,
								 uint32_t *n_values,
								 uint32_t prop_tag,
								 gconstpointer prop_value);
gboolean	e_mapi_utils_add_spropvalue_namedid		(EMapiConnection *conn,
								 mapi_id_t fid,
								 TALLOC_CTX *mem_ctx,
								 struct SPropValue **values_array,
								 uint32_t *n_values,
								 uint32_t named_id,
								 gconstpointer prop_value,
								 GCancellable *cancellable,
								 GError **perror);
gboolean	e_mapi_utils_add_property			(struct mapi_SPropValue_array *properties,
								 uint32_t proptag,
								 gconstpointer propvalue,
								 TALLOC_CTX *mem_ctx);
gboolean	e_mapi_utils_ensure_utf8_string			(uint32_t proptag,
								 const uint32_t *cpid,
								 const guint8 *buf_data,
								 guint32 buf_len,
								 gchar **out_utf8);

uint32_t e_mapi_utils_push_crc32 (uint32_t crc32, uint8_t *bytes, uint32_t n_bytes);

struct Binary_r *e_mapi_util_copy_binary_r (const struct Binary_r *bin);
void e_mapi_util_free_binary_r (struct Binary_r *bin);

time_t e_mapi_util_filetime_to_time_t (const struct FILETIME *filetime);
void e_mapi_util_time_t_to_filetime (const time_t tt, struct FILETIME *filetime);

gboolean	e_mapi_utils_propagate_cancelled_error		(const GError *mapi_error,
								 GError **error);

void		e_mapi_utils_global_lock			(void);
void		e_mapi_utils_global_unlock			(void);
gboolean	e_mapi_utils_create_mapi_context		(struct mapi_context **mapi_ctx,
								 GError **perror);
void		e_mapi_utils_destroy_mapi_context		(struct mapi_context *mapi_ctx);

gboolean	e_mapi_utils_build_last_modify_restriction	(EMapiConnection *conn,
								 mapi_id_t fid,
								 TALLOC_CTX *mem_ctx,
								 struct mapi_SRestriction **restrictions,
								 gpointer user_data, /* const time_t * */
								 GCancellable *cancellable,
								 GError **perror);
struct FolderBasicPropertiesData
{
	mapi_id_t fid;
	time_t last_modified;
	guint32 obj_total;
};

gboolean	e_mapi_utils_get_folder_basic_properties_cb	(EMapiConnection *conn,
								 mapi_id_t fid,
								 TALLOC_CTX *mem_ctx,
								 /* const */ struct mapi_SPropValue_array *properties,
								 gpointer user_data, /* struct FolderBasicPropertiesData * */
								 GCancellable *cancellable,
								 GError **perror);
gboolean	e_mapi_utils_copy_to_mapi_SPropValue		(TALLOC_CTX *mem_ctx,
								 struct mapi_SPropValue *mapi_sprop, 
								 struct SPropValue *sprop);
#endif
