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
#include <libedata-book/e-data-book.h>
#include <libedata-book/e-data-book-view.h>

#include <libedata-book/e-book-backend-sqlitedb.h>
#include "e-mapi-connection.h"
#include "e-mapi-defs.h"
#include "e-mapi-utils.h"

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

struct ListKnownUidsData
{
	GHashTable *uid_to_rev;
	time_t latest_last_modify;
};

typedef struct
{
	EBookBackendClass parent_class;

	void (*op_open) (EBookBackendMAPI *ebma, GCancellable *cancellable, gboolean only_if_exists, GError **error);
	void (*op_remove) (EBookBackendMAPI *ebma, GCancellable *cancellable, GError **error);

	void (*op_create_contacts) (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **added_contacts, GError **error);
	void (*op_remove_contacts) (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *id_list, GSList **removed_ids, GError **error);
	void (*op_modify_contacts) (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **modified_contacts, GError **error);
	void (*op_get_contact) (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *id, gchar **vcard, GError **error);
	void (*op_get_contact_list) (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *query, GSList **vCards, GError **error);
	void (*op_authenticate_user) (EBookBackendMAPI *ebma, GCancellable *cancellable, ECredentials *credentials, GError **error);

	/* called when online state changes on the backend */
	void (*op_connection_status_changed) (EBookBackendMAPI *ebma, gboolean is_online);

	/* returns a status message for a progress of fetching entries "index/total";
	   returned string is freed by g_free() */
	gchar * (*op_get_status_message) (EBookBackendMAPI *ebma, gint index, gint total);

	/* function called for each new book_view, in a separate thread;
	   this function is optional, contacts from cache are always processed
	   before this function call */
	void (*op_book_view_thread) (EBookBackendMAPI *ebma, EDataBookView *book_view, GCancellable *cancellable, GError **error);

	/* gets current count of contacts in the folder corresponding to the backend */
	void (*op_get_contacts_count) (EBookBackendMAPI *ebma, guint32 *obj_total, GCancellable *cancellable, GError **error);

	/* function to fetch list of known uids (strings) on the server;
	   it's used to synchronize local cache with available items;
	   uids has the uid key, as a newly allocated string;
	   value is a revision (REV) field value as newly allocated string */
	void (*op_list_known_uids) (EBookBackendMAPI *ebma, BuildRestrictionsCB build_rs_cb, gpointer build_rs_cb_data, struct ListKnownUidsData *lku, GCancellable *cancellable, GError **error);

	/* function called to populate cache or similar operations;
	   book_view can be NULL, call e_book_backend_mapi_notify_contact_update for each
	   transferred contact with this book_view and notify_contact_data */
	void (*op_transfer_contacts) (EBookBackendMAPI *ebma, const GSList *uids, EDataBookView *book_view, gpointer notify_contact_data, GCancellable *cancellable, GError **error);
} EBookBackendMAPIClass;

GType e_book_backend_mapi_get_type (void);

gboolean e_book_backend_mapi_debug_enabled (void);
const gchar *e_book_backend_mapi_get_book_uri (EBookBackendMAPI *ebma);
void e_book_backend_mapi_lock_connection (EBookBackendMAPI *ebma);
void e_book_backend_mapi_unlock_connection (EBookBackendMAPI *ebma);
EMapiConnection *e_book_backend_mapi_get_connection (EBookBackendMAPI *ebma);
void e_book_backend_mapi_get_db (EBookBackendMAPI *ebma, EBookBackendSqliteDB **db);
gboolean e_book_backend_mapi_book_view_is_running (EBookBackendMAPI *ebma, EDataBookView *book_view);
void e_book_backend_mapi_update_view_by_cache (EBookBackendMAPI *ebma, EDataBookView *book_view, GError **error);
gboolean e_book_backend_mapi_is_marked_for_offline (EBookBackendMAPI *ebma);
gboolean e_book_backend_mapi_notify_contact_update (EBookBackendMAPI *ebma, EDataBookView *book_view, EContact *contact, gint index, gint total, gpointer notify_contact_data);
void e_book_backend_mapi_notify_contact_removed (EBookBackendMAPI *ebma, const gchar *uid);
void   e_book_backend_mapi_cache_set (EBookBackendMAPI *ebma, const gchar *key, const gchar *value);
gchar *e_book_backend_mapi_cache_get (EBookBackendMAPI *ebma, const gchar *key);

/* utility functions/macros */

#define EDB_ERROR(_code) e_data_book_create_error (E_DATA_BOOK_STATUS_ ## _code, NULL)
#define EDB_ERROR_EX(_code, _msg) e_data_book_create_error (E_DATA_BOOK_STATUS_ ## _code, _msg)

void mapi_error_to_edb_error (GError **perror, const GError *mapi_error, EDataBookStatus code, const gchar *context);

/* The EBookBackendSqliteDB functions allow for a single all-caches database,
 * which is a feature we do not use, and instead have per-folder databases.
 * Therefore we have a couple arbitrary constants... */
#define EMA_EBB_CACHE_PROFILEID	"EMA_PROFILE"
#define EMA_EBB_CACHE_FOLDERID	"EMA_FOLDER"

/* vCard parameter name in contact list */
#define EMA_X_MEMBERID "X-EMA-MEMBER-ID"
#define EMA_X_MEMBERVALUE "X-EMA-MEMBER-VALUE"

#define GET_ALL_KNOWN_IDS (GINT_TO_POINTER(1))
#define GET_UIDS_ONLY     (GINT_TO_POINTER(2))

/* data is one of GET_ALL_KNOWN_IDS or GET_UIDS_ONLY */
gboolean mapi_book_utils_get_prop_list (EMapiConnection *conn,
					mapi_id_t fid,
					TALLOC_CTX *mem_ctx,
					struct SPropTagArray *props,
					gpointer data,
					GCancellable *cancellable,
					GError **perror);

/* only one of mapi_properties and aRow can be set */
EContact *mapi_book_utils_contact_from_props (EMapiConnection *conn, mapi_id_t fid, const gchar *book_uri, struct mapi_SPropValue_array *mapi_properties, struct SRow *aRow);

/* converts time_t to string, suitable for E_CONTACT_REV field value;
   free returned pointer with g_free() */
gchar *mapi_book_utils_timet_to_string (time_t tt);

G_END_DECLS

#endif /* __E_BOOK_BACKEND_MAPI_H__ */
