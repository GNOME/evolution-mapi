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

#ifndef __E_BOOK_BACKEND_MAPI_H__
#define __E_BOOK_BACKEND_MAPI_H__

#include <glib.h>
#include <gio/gio.h>

#include <libedata-book/e-book-backend.h>
#include <libedata-book/e-book-backend-cache.h>
#include <libedata-book/e-book-backend-summary.h>
#include <libedata-book/e-data-book.h>
#include <libedata-book/e-data-book-view.h>

#include "exchange-mapi-connection.h"
#include "exchange-mapi-defs.h"
#include "exchange-mapi-utils.h"

G_BEGIN_DECLS

#define E_TYPE_BOOK_BACKEND_MAPI           (e_book_backend_mapi_get_type ())
#define E_BOOK_BACKEND_MAPI(o)             (G_TYPE_CHECK_INSTANCE_CAST ((o), E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPI))
#define E_BOOK_BACKEND_MAPI_CLASS(k)       (G_TYPE_CHECK_CLASS_CAST((k), E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPIClass))
#define E_IS_BOOK_BACKEND_MAPI(o)          (G_TYPE_CHECK_INSTANCE_TYPE ((o), E_TYPE_BOOK_BACKEND_MAPI))
#define E_IS_BOOK_BACKEND_MAPI_CLASS(k)    (G_TYPE_CHECK_CLASS_TYPE ((k), E_TYPE_BOOK_BACKEND_MAPI))
#define E_BOOK_BACKEND_MAPI_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPIClass))

typedef struct _EBookBackendMAPIPrivate EBookBackendMAPIPrivate;

typedef struct
{
	EBookBackend             parent_object;
	EBookBackendMAPIPrivate *priv;
} EBookBackendMAPI;

typedef struct
{
	EBookBackendClass parent_class;

	void (*op_load_source) (EBookBackendMAPI *ebma, ESource *source, gboolean only_if_exists, GError **error);
	void (*op_remove) (EBookBackendMAPI *ebma, GError **error);

	void (*op_create_contact)  (EBookBackendMAPI *ebma, const gchar *vcard, EContact **contact, GError **error);
	void (*op_remove_contacts) (EBookBackendMAPI *ebma, const GList *id_list, GList **removed_ids, GError **error);
	void (*op_modify_contact)  (EBookBackendMAPI *ebma, const gchar *vcard, EContact **contact, GError **error);
	void (*op_get_contact) (EBookBackendMAPI *ebma, const gchar *id, gchar **vcard, GError **error);
	void (*op_get_contact_list) (EBookBackendMAPI *ebma, const gchar *query, GList **vCards, GError **error);
	void (*op_get_changes) (EBookBackendMAPI *ebma, const gchar *change_id, GList **changes, GError **error);
	void (*op_authenticate_user) (EBookBackendMAPI *ebma, const gchar *user, const gchar *passwd, const gchar *auth_method, GError **error);
	void (*op_get_required_fields) (EBookBackendMAPI *ebma, GList **fields, GError **error);
	void (*op_get_supported_fields) (EBookBackendMAPI *ebma, GList **fields, GError **error);
	void (*op_get_supported_auth_methods) (EBookBackendMAPI *ebma, GList **auth_methods, GError **error);

	/* called when online state changes on the backend */
	void (*op_connection_status_changed) (EBookBackendMAPI *ebma, gboolean is_online);

	/* returns a status message for a progress of fetching entries "index/total";
	   returned string is freed by g_free() */
	gchar * (*op_get_status_message) (EBookBackendMAPI *ebma, gint index, gint total);

	/* function called for each new book_view, in a separate thread;
	   this function is optional, contacts from cache are always processed
	   before this function call */
	void (*op_book_view_thread) (EBookBackendMAPI *ebma, EDataBookView *book_view, GError **error);

	/* function called to populate cache or similar operations;
	   restriction and book_view can be NULL, call e_book_backend_mapi_notify_contact_update for each
	   fetched contact with this book_view and notify_contact_data */
	void (*op_fetch_contacts) (EBookBackendMAPI *ebma, struct mapi_SRestriction *restriction, EDataBookView *book_view, gpointer notify_contact_data, GError **error);

	/* function to fetch list of known uids (strings) on the server;
	   it's used to synchronize local cache with deleted items;
	   uids has the uid key, as a newly allocated string; value should be GINT_TO_POINTER(1) always */
	void (*op_fetch_known_uids) (EBookBackendMAPI *ebma, GCancellable *cancelled, GHashTable *uids, GError **error);
} EBookBackendMAPIClass;

GType e_book_backend_mapi_get_type (void);

gboolean e_book_backend_mapi_debug_enabled (void);
const gchar *e_book_backend_mapi_get_book_uri (EBookBackendMAPI *ebma);
void e_book_backend_mapi_lock_connection (EBookBackendMAPI *ebma);
void e_book_backend_mapi_unlock_connection (EBookBackendMAPI *ebma);
ExchangeMapiConnection *e_book_backend_mapi_get_connection (EBookBackendMAPI *ebma);
void e_book_backend_mapi_get_summary_and_cache (EBookBackendMAPI *ebma, EBookBackendSummary **summary, EBookBackendCache **cache);
gboolean e_book_backend_mapi_book_view_is_running (EBookBackendMAPI *ebma, EDataBookView *book_view);
void e_book_backend_mapi_update_view_by_cache (EBookBackendMAPI *ebma, EDataBookView *book_view, GError **error);
gboolean e_book_backend_mapi_is_marked_for_offline (EBookBackendMAPI *ebma);
gboolean e_book_backend_mapi_notify_contact_update (EBookBackendMAPI *ebma, EDataBookView *book_view, EContact *contact, const struct timeval *pr_last_modification_time, gint index, gint total, gpointer notify_contact_data);
void e_book_backend_mapi_notify_contact_removed (EBookBackendMAPI *ebma, const gchar *uid);
void   e_book_backend_mapi_cache_set (EBookBackendMAPI *ebma, const gchar *key, const gchar *value);
gchar *e_book_backend_mapi_cache_get (EBookBackendMAPI *ebma, const gchar *key);

/* utility functions/macros */

#define EDB_ERROR(_code) e_data_book_create_error (E_DATA_BOOK_STATUS_ ## _code, NULL)
#define EDB_ERROR_EX(_code, _msg) e_data_book_create_error (E_DATA_BOOK_STATUS_ ## _code, _msg)

void mapi_error_to_edb_error (GError **perror, const GError *mapi_error, EDataBookStatus code, const gchar *context);

/* vCard parameter name in contact list */
#define EMA_X_MEMBERID "X-EMA-MEMBER-ID"
#define EMA_X_MEMBERVALUE "X-EMA-MEMBER-VALUE"

#define GET_ALL_KNOWN_IDS (GINT_TO_POINTER(1))
#define GET_UIDS_ONLY     (GINT_TO_POINTER(2))

/* data is one of GET_ALL_KNOWN_IDS or GET_UIDS_ONLY */
gboolean mapi_book_utils_get_prop_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data);

/* only one of mapi_properties and aRow can be set */
EContact *mapi_book_utils_contact_from_props (ExchangeMapiConnection *conn, mapi_id_t fid, const gchar *book_uri, struct mapi_SPropValue_array *mapi_properties, struct SRow *aRow);

G_END_DECLS

#endif /* __E_BOOK_BACKEND_MAPI_H__ */
