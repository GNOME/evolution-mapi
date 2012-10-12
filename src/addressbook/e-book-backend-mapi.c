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
 *    Srinivasa Ragavan <sragavan@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n-lib.h>

#include <libebook/libebook.h>
#include <libedataserver/libedataserver.h>
#include <camel/camel.h>

#include <e-mapi-operation-queue.h>

#include "e-mapi-utils.h"
#include "e-mapi-defs.h"

#include "e-book-backend-mapi.h"

static void e_book_backend_mapi_authenticator_init (ESourceAuthenticatorInterface *interface);

G_DEFINE_TYPE_WITH_CODE (EBookBackendMAPI, e_book_backend_mapi, E_TYPE_BOOK_BACKEND,
	G_IMPLEMENT_INTERFACE (E_TYPE_SOURCE_AUTHENTICATOR, e_book_backend_mapi_authenticator_init))

struct _EBookBackendMAPIPrivate
{
	EMapiOperationQueue *op_queue;

	GRecMutex conn_lock;
	EMapiConnection *conn;
	gchar *book_uid;
	gboolean marked_for_offline;

	GThread *update_cache_thread;
	GCancellable *update_cache;
	time_t last_update_cache;

	EBookBackendSqliteDB *db;

	glong last_db_commit_time; /* when committed changes to db */

	guint32 last_server_contact_count;
	time_t last_modify_time;
	gboolean server_dirty;

	GHashTable *running_views; /* EDataBookView => GCancellable */
	GMutex running_views_lock;
};

static CamelMapiSettings *
ebbm_get_collection_settings (EBookBackendMAPI *ebbm)
{
	ESource *source;
	ESource *collection;
	ESourceCamel *extension;
	ESourceRegistry *registry;
	CamelSettings *settings;
	const gchar *extension_name;

	source = e_backend_get_source (E_BACKEND (ebbm));
	registry = e_book_backend_get_registry (E_BOOK_BACKEND (ebbm));

	extension_name = e_source_camel_get_extension_name ("mapi");
	e_source_camel_generate_subtype ("mapi", CAMEL_TYPE_MAPI_SETTINGS);

	/* The collection settings live in our parent data source. */
	collection = e_source_registry_find_extension (
		registry, source, extension_name);
	g_return_val_if_fail (collection != NULL, NULL);

	extension = e_source_get_extension (collection, extension_name);
	settings = e_source_camel_get_settings (extension);

	g_object_unref (collection);

	return CAMEL_MAPI_SETTINGS (settings);
}

static glong
get_current_time_ms (void)
{
	GTimeVal tv;

	g_get_current_time (&tv);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static gboolean
pick_view_cb (EDataBookView *view, gpointer user_data)
{
	EDataBookView **pick = user_data;

	g_return_val_if_fail (user_data != NULL, FALSE);

	/* just always use the first book view */
	*pick = view;
	return view == NULL;
}

static EDataBookView *
ebbm_pick_book_view (EBookBackendMAPI *ebma)
{
	EDataBookView *pick = NULL;

	e_book_backend_foreach_view (E_BOOK_BACKEND (ebma), pick_view_cb, &pick);

	return pick;
}

static gboolean
complete_view_cb (EDataBookView *view, gpointer user_data)
{
	EBookBackendMAPI *ebma = user_data;

	g_return_val_if_fail (ebma != NULL, FALSE);

	if (e_book_backend_mapi_book_view_is_running (ebma, view))
		e_book_backend_mapi_update_view_by_cache (ebma, view, NULL);

	e_data_book_view_notify_complete (view, NULL);

	return TRUE;
}

static void
complete_views (EBookBackendMAPI *ebma)
{
	e_book_backend_foreach_view (E_BOOK_BACKEND (ebma), complete_view_cb, ebma);
}

static void
ebbm_notify_connection_status (EBookBackendMAPI *ebma, gboolean is_online)
{
	EBookBackendMAPIClass *ebmac;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_if_fail (ebmac != NULL);

	if (ebmac->op_connection_status_changed)
		ebmac->op_connection_status_changed (ebma, is_online);
}

static void
ebbm_transfer_contacts (EBookBackendMAPI *ebma,
			const GSList *uids,
			EDataBookView *book_view,
			GCancellable *cancellable,
			GError **error)
{
	EBookBackendMAPIClass *ebmac;
	glong last_notification = 0;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (ebma->priv != NULL);
	g_return_if_fail (ebma->priv->conn != NULL);

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_if_fail (ebmac != NULL);
	g_return_if_fail (ebmac->op_transfer_contacts != NULL);

	e_book_backend_sqlitedb_lock_updates (ebma->priv->db, NULL);
	ebma->priv->last_db_commit_time = get_current_time_ms ();

	ebmac->op_transfer_contacts (ebma, uids, book_view, &last_notification, cancellable, error);

	e_book_backend_sqlitedb_unlock_updates (ebma->priv->db, TRUE, NULL);
}

static gboolean
unref_backend_idle_cb (gpointer data)
{
	EBookBackendMAPI *ebma = data;

	g_return_val_if_fail (ebma != NULL, FALSE);

	g_object_unref (ebma);

	return FALSE;
}

static gpointer
ebbm_update_cache_cb (gpointer data)
{
	EBookBackendMAPI *ebma = (EBookBackendMAPI *) data;
	EBookBackendMAPIPrivate *priv;
	EBookBackendMAPIClass *ebmac;
	guint32 server_stored_contacts = 0;
	time_t restr_tt = 0;
	gboolean partial_update = FALSE;
	GCancellable *cancellable;
	GError *error = NULL;

	g_return_val_if_fail (ebma != NULL, NULL);
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);

	priv = ebma->priv;
	g_return_val_if_fail (priv != NULL, NULL);
	g_return_val_if_fail (priv->db != NULL, NULL);
	g_return_val_if_fail (priv->conn != NULL, NULL);

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_val_if_fail (ebmac != NULL, NULL);

	cancellable = priv->update_cache;
	g_cancellable_reset (cancellable);

	do {
		GHashTable *local_known_uids, *server_known_uids;

		priv->server_dirty = FALSE;

		local_known_uids = e_book_backend_sqlitedb_get_uids_and_rev (priv->db, EMA_EBB_CACHE_FOLDERID, &error);
		server_known_uids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

		if (!error && !g_cancellable_is_cancelled (cancellable) && ebmac->op_get_contacts_count) {
			ebmac->op_get_contacts_count (ebma, &server_stored_contacts, cancellable, &error);
		}

		if (!error && !g_cancellable_is_cancelled (cancellable) && ebmac->op_list_known_uids) {
			struct ListKnownUidsData lku;

			restr_tt = priv->last_modify_time && server_stored_contacts == g_hash_table_size (local_known_uids) ? priv->last_modify_time + 1 : 0;
			partial_update = restr_tt > 0;

			lku.uid_to_rev = server_known_uids;
			lku.latest_last_modify = priv->last_modify_time;

			ebmac->op_list_known_uids (ebma, partial_update ? e_mapi_utils_build_last_modify_restriction : NULL, &restr_tt, &lku, cancellable, &error);

			restr_tt = lku.latest_last_modify;
		}

		if (!error && !g_cancellable_is_cancelled (cancellable) && ebmac->op_transfer_contacts && local_known_uids) {
			GSList *uids = NULL;
			GHashTableIter iter;
			gpointer key, value;

			g_hash_table_iter_init (&iter, server_known_uids);
			while (g_hash_table_iter_next (&iter, &key, &value)) {
				const gchar *uid = key, *rev = value, *local_rev;

				local_rev = g_hash_table_lookup (local_known_uids, uid);
				if (g_strcmp0 (local_rev, rev) != 0) {
					uids = g_slist_prepend (uids, (gpointer) uid);
				}

				g_hash_table_remove (local_known_uids, uid);
			}

			if (uids)
				ebbm_transfer_contacts (ebma, uids, NULL, cancellable, &error);

			if (!error && !g_cancellable_is_cancelled (cancellable) && !partial_update) {
				e_book_backend_sqlitedb_lock_updates (priv->db, NULL);

				g_hash_table_iter_init (&iter, local_known_uids);
				while (g_hash_table_iter_next (&iter, &key, &value)) {
					const gchar *uid = key;

					if (!uid)
						continue;

					e_book_backend_mapi_notify_contact_removed (ebma, uid);
				}

				e_book_backend_sqlitedb_unlock_updates (priv->db, TRUE, NULL);
			}

			priv->last_server_contact_count = server_stored_contacts;
			priv->last_modify_time = restr_tt;

			/* has borrowed data from server_known_uids */
			g_slist_free (uids);
		}

		priv->last_update_cache = time(NULL);

		g_hash_table_destroy (server_known_uids);
		if (local_known_uids)
			g_hash_table_destroy (local_known_uids);
	} while (!error && priv->server_dirty && !g_cancellable_is_cancelled (cancellable));

	g_clear_error (&error);

	complete_views (ebma);

	/* indicate the thread is not running */
	g_cancellable_cancel (priv->update_cache);

	/* May unref it out of the thread, in case it's the last reference to it */
	g_idle_add (unref_backend_idle_cb, ebma);

	return NULL;
}

static void
ebbm_maybe_invoke_cache_update (EBookBackendMAPI *ebma)
{
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (ebma->priv != NULL);

	priv = ebma->priv;

	if (priv->update_cache_thread) {
		if (!g_cancellable_is_cancelled (priv->update_cache))
			return;

		g_thread_join (priv->update_cache_thread);
		priv->update_cache_thread = NULL;
	}

	/* do not update more often than each 10 minutes */
	if (time (NULL) - priv->last_update_cache >= 60 * 10) {
		g_object_ref (ebma);

		g_cancellable_reset (priv->update_cache);
		priv->server_dirty = FALSE;
		priv->update_cache_thread = g_thread_create (ebbm_update_cache_cb, ebma, TRUE, NULL);
		if (!priv->update_cache_thread)
			g_object_unref (ebma);
	}
}

static ESourceAuthenticationResult
ebbm_connect_user (EBookBackendMAPI *ebma,
		   GCancellable *cancellable,
		   const GString *password,
		   GError **error)
{
	EBookBackendMAPIPrivate *priv = ebma->priv;
	EMapiConnection *old_conn;
	CamelMapiSettings *settings;
	GError *mapi_error = NULL;

	settings = ebbm_get_collection_settings (ebma);

	if (!e_backend_get_online (E_BACKEND (ebma))) {
		ebbm_notify_connection_status (ebma, FALSE);
	} else {
		if (priv->update_cache_thread) {
			g_cancellable_cancel (priv->update_cache);
			g_thread_join (priv->update_cache_thread);
			priv->update_cache_thread = NULL;
		}

		e_book_backend_mapi_lock_connection (ebma);

		if (g_cancellable_set_error_if_cancelled (cancellable, error)) {
			e_book_backend_mapi_unlock_connection (ebma);
			return E_SOURCE_AUTHENTICATION_ERROR;
		}

		old_conn = priv->conn;
		priv->conn = NULL;

		priv->conn = e_mapi_connection_new (
			e_book_backend_get_registry (E_BOOK_BACKEND (ebma)),
			camel_mapi_settings_get_profile (settings),
			password, cancellable, &mapi_error);
		if (!priv->conn) {
			priv->conn = e_mapi_connection_find (camel_mapi_settings_get_profile (settings));
			if (priv->conn && !e_mapi_connection_connected (priv->conn))
				e_mapi_connection_reconnect (priv->conn, password, cancellable, &mapi_error);
		}

		if (old_conn)
			g_object_unref (old_conn);

		if (!priv->conn || mapi_error) {
			gboolean is_network_error = g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NETWORK_ERROR) ||
				(mapi_error && mapi_error->domain != E_MAPI_ERROR);

			if (priv->conn) {
				g_object_unref (priv->conn);
				priv->conn = NULL;
			}

			if (is_network_error)
				mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);
			e_book_backend_mapi_unlock_connection (ebma);

			if (mapi_error)
				g_error_free (mapi_error);

			ebbm_notify_connection_status (ebma, FALSE);

			return is_network_error ? E_SOURCE_AUTHENTICATION_ERROR : E_SOURCE_AUTHENTICATION_REJECTED;
		}

		e_book_backend_mapi_unlock_connection (ebma);

		ebbm_notify_connection_status (ebma, TRUE);

		if (!g_cancellable_is_cancelled (cancellable) && priv->marked_for_offline) {
			ebbm_maybe_invoke_cache_update (ebma);
		}
	}

	return E_SOURCE_AUTHENTICATION_ACCEPTED;
}

/* connection lock should be already held when calling this function */
gboolean
e_book_backend_mapi_ensure_connected (EBookBackendMAPI *ebma,
				      GCancellable *cancellable, 
				      GError **error)
{
	CamelMapiSettings *settings;
	GError *local_error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), FALSE);

	if (ebma->priv->conn && e_mapi_connection_connected (ebma->priv->conn))
		return TRUE;

	settings = ebbm_get_collection_settings (ebma);

	if (!camel_mapi_settings_get_kerberos (settings) ||
	    ebbm_connect_user (ebma, cancellable, NULL, &local_error) != E_SOURCE_AUTHENTICATION_ACCEPTED) {
		e_backend_authenticate_sync (
			E_BACKEND (ebma),
			E_SOURCE_AUTHENTICATOR (ebma),
			cancellable, &local_error);
	}

	if (!local_error)
		return TRUE;

	g_propagate_error (error, local_error);

	return FALSE;
}

/* connection lock should be already held when calling this function */
void
e_book_backend_mapi_maybe_disconnect (EBookBackendMAPI *ebma,
				      const GError *mapi_error)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));

	/* no error or already disconnected */
	if (!mapi_error || !ebma->priv->conn)
		return;

	if (g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NETWORK_ERROR) ||
	    g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_CALL_FAILED)) {
		e_mapi_connection_disconnect (ebma->priv->conn,
			!g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NETWORK_ERROR),
			NULL, NULL);
		g_object_unref (ebma->priv->conn);
		ebma->priv->conn = NULL;
	}
}

static void
ebbm_open (EBookBackendMAPI *ebma,
	   GCancellable *cancellable,
	   gboolean only_if_exists,
	   GError **perror)
{
	EBookBackendMAPIPrivate *priv = ebma->priv;
	ESource *source = e_backend_get_source (E_BACKEND (ebma));
	ESourceOffline *offline_extension;
	const gchar *cache_dir;
	GError *error = NULL;

	if (e_book_backend_is_opened (E_BOOK_BACKEND (ebma))) {
		e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), NULL /* Success */);
		return;
	}

	offline_extension = e_source_get_extension (source, E_SOURCE_EXTENSION_OFFLINE);
	priv->marked_for_offline = e_source_offline_get_stay_synchronized (offline_extension);

	if (priv->book_uid)
		g_free (priv->book_uid);
	priv->book_uid = e_source_dup_uid (source);

	cache_dir = e_book_backend_get_cache_dir (E_BOOK_BACKEND (ebma));

	if (priv->db)
		g_object_unref (priv->db);
	priv->db = e_book_backend_sqlitedb_new (cache_dir,
						EMA_EBB_CACHE_PROFILEID,
						EMA_EBB_CACHE_FOLDERID,
						EMA_EBB_CACHE_FOLDERID,
	                                        TRUE, &error);

	if (error) {
		g_propagate_error (perror, error);
		return;
	}

	e_book_backend_notify_readonly (E_BOOK_BACKEND (ebma), TRUE);

	ebbm_notify_connection_status (ebma, e_backend_get_online (E_BACKEND (ebma)));

	/* Either we are in Online mode or this is marked for offline */
	if (!e_backend_get_online (E_BACKEND (ebma)) &&
	    !priv->marked_for_offline) {
		g_propagate_error (perror, EDB_ERROR (OFFLINE_UNAVAILABLE));
		e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), EDB_ERROR (OFFLINE_UNAVAILABLE));
		return;
	}

	/* Once aunthentication in address book works this can be removed */
	if (!e_backend_get_online (E_BACKEND (ebma))) {
		e_book_backend_notify_online (E_BOOK_BACKEND (ebma), FALSE);
		e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), NULL /* Success */);
		return;
	}

	e_book_backend_notify_online (E_BOOK_BACKEND (ebma), TRUE);

	e_book_backend_mapi_ensure_connected (ebma, cancellable, &error);

	if (error && perror)
		g_propagate_error (perror, g_error_copy (error));

	e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), error);
}

static ESourceAuthenticationResult
ebbm_try_password_sync (ESourceAuthenticator *authenticator,
			const GString *password,
			GCancellable *cancellable,
			GError **error)
{
	return ebbm_connect_user (E_BOOK_BACKEND_MAPI (authenticator), cancellable, password, error);
}

static void
ebbm_remove (EBookBackendMAPI *ebma, GCancellable *cancellable, GError **error)
{
	EBookBackendMAPIPrivate *priv;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (ebma->priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebma->priv;

	if (!priv->book_uid)
		return;

	e_book_backend_mapi_lock_connection (ebma);

	if (!priv->db) {
		const gchar *cache_dir = e_book_backend_get_cache_dir (E_BOOK_BACKEND (ebma));

		/* pity, but it's required to be removed completely */
		priv->db = e_book_backend_sqlitedb_new (cache_dir,
							EMA_EBB_CACHE_PROFILEID,
							EMA_EBB_CACHE_FOLDERID,
							EMA_EBB_CACHE_FOLDERID,
							TRUE, NULL);
	}

	if (priv->db) {
		e_book_backend_sqlitedb_remove (priv->db, NULL);
		g_object_unref (priv->db);
		priv->db = NULL;
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static gboolean
ebbm_get_backend_property (EBookBackendMAPI *ebma, const gchar *prop_name, gchar **prop_value, GError **error)
{
	gboolean processed = TRUE;

	g_return_val_if_fail (ebma != NULL, FALSE);
	g_return_val_if_fail (prop_name != NULL, FALSE);
	g_return_val_if_fail (prop_value != NULL, FALSE);

	if (g_str_equal (prop_name, CLIENT_BACKEND_PROPERTY_CAPABILITIES)) {
		if (e_book_backend_mapi_is_marked_for_offline (ebma))
			*prop_value = g_strdup ("net,bulk-removes,contact-lists,do-initial-query");
		else
			*prop_value = g_strdup ("net,bulk-removes,contact-lists");
	} else if (g_str_equal (prop_name, BOOK_BACKEND_PROPERTY_REQUIRED_FIELDS)) {
		*prop_value = g_strdup (e_contact_field_name (E_CONTACT_FILE_AS));
	} else if (g_str_equal (prop_name, BOOK_BACKEND_PROPERTY_SUPPORTED_FIELDS)) {
		GSList *fields = e_mapi_book_utils_get_supported_contact_fields ();

		*prop_value = e_data_book_string_slist_to_comma_string (fields);

		g_slist_free (fields);
	} else if (g_str_equal (prop_name, BOOK_BACKEND_PROPERTY_SUPPORTED_AUTH_METHODS)) {
		*prop_value = g_strdup ("plain/password");
	} else {
		processed = FALSE;
	}

	return processed;
}

static void
ebbm_notify_online_cb (EBookBackend *backend, GParamSpec *pspec)
{
	EBookBackendMAPI *ebma = E_BOOK_BACKEND_MAPI (backend);
	EBookBackendMAPIPrivate *priv = ebma->priv;
	gboolean online;

	online = e_backend_get_online (E_BACKEND (backend));

	if (e_book_backend_is_opened (backend)) {
		e_book_backend_mapi_lock_connection (ebma);

		if (!online) {
			e_book_backend_notify_readonly (backend, TRUE);
			ebbm_notify_connection_status (ebma, FALSE);

			if (priv->conn) {
				g_object_unref (priv->conn);
				priv->conn = NULL;
			}
		} else {
			ebbm_notify_connection_status (ebma, TRUE);
		}

		e_book_backend_mapi_unlock_connection (ebma);
	}

	e_book_backend_notify_online (backend, online);
}

static void
ebbm_get_contact (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *id, gchar **vcard, GError **error)
{
	EBookBackendMAPIPrivate *priv;
	gchar *contact;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (vcard != NULL);

	priv = ebma->priv;
	g_return_if_fail (priv != NULL);

	if (!priv->db) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	contact = e_book_backend_sqlitedb_get_vcard_string (priv->db,
							    EMA_EBB_CACHE_FOLDERID,
							    id, NULL, NULL, error);
	if (contact)
		*vcard = contact;
	else
		g_propagate_error (error, EDB_ERROR (CONTACT_NOT_FOUND));
}

static void
ebbm_get_contact_list (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *query, GSList **vCards, GError **error)
{
	EBookBackendMAPIPrivate *priv;
	GSList *hits, *l;
	GError *err = NULL;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (query != NULL);
	g_return_if_fail (vCards != NULL);

	priv = ebma->priv;
	g_return_if_fail (priv != NULL);

	if (!priv->db) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	hits = e_book_backend_sqlitedb_search (priv->db, EMA_EBB_CACHE_FOLDERID,
					       query, NULL, NULL, NULL, &err);

	for (l = hits; !err && l; l = l->next) {
		EbSdbSearchData *sdata = (EbSdbSearchData *) l->data;
		gchar *vcard = sdata->vcard;

		if (!err && vcard)
			*vCards = g_slist_prepend (*vCards, g_strdup (vcard));

		e_book_backend_sqlitedb_search_data_free (sdata);
	}

	if (err)
		g_propagate_error (error, err);

	g_slist_free (hits);
}

struct BookViewThreadData
{
	EBookBackendMAPI *ebma;
	EDataBookView *book_view;
	GCancellable *cancellable;
};

static gpointer
ebbm_book_view_thread (gpointer data)
{
	struct BookViewThreadData *bvtd = data;
	EBookBackendMAPIPrivate *priv;
	EBookBackendMAPIClass *ebmac;
	GError *error = NULL;

	g_return_val_if_fail (bvtd != NULL, NULL);
	g_return_val_if_fail (bvtd->ebma != NULL, NULL);
	g_return_val_if_fail (bvtd->book_view != NULL, NULL);

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (bvtd->ebma);
	g_return_val_if_fail (ebmac != NULL, NULL);

	priv = bvtd->ebma->priv;

	e_data_book_view_notify_progress (bvtd->book_view, -1, _("Searching"));

	if (!error && priv && priv->conn && (!priv->update_cache_thread || g_cancellable_is_cancelled (priv->update_cache))
	    && e_book_backend_mapi_book_view_is_running (bvtd->ebma, bvtd->book_view)) {
		EBookBackendMAPIClass *ebmac;

		ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (bvtd->ebma);
		if (ebmac && ebmac->op_book_view_thread)
			ebmac->op_book_view_thread (bvtd->ebma, bvtd->book_view, priv->update_cache, &error);

		if (priv->marked_for_offline) {
			e_book_backend_mapi_update_view_by_cache (bvtd->ebma, bvtd->book_view, &error);

			ebbm_maybe_invoke_cache_update (bvtd->ebma);

			e_book_backend_mapi_update_view_by_cache (bvtd->ebma, bvtd->book_view, &error);
		} else if (ebmac->op_list_known_uids && ebmac->op_transfer_contacts) {
			EBookBackendSExp *sexp;
			const gchar *query;

			sexp = e_data_book_view_get_sexp (bvtd->book_view);
			query = e_book_backend_sexp_text (sexp);

			/* search only if not searching for everything */
			if (query && *query && g_ascii_strcasecmp (query, "(contains \"x-evolution-any-field\" \"\")") != 0) {
				struct ListKnownUidsData lku = { 0 };
				GHashTable *local_known_uids, *server_known_uids;

				e_book_backend_mapi_update_view_by_cache (bvtd->ebma, bvtd->book_view, &error);

				local_known_uids = e_book_backend_sqlitedb_get_uids_and_rev (priv->db, EMA_EBB_CACHE_FOLDERID, &error);
				server_known_uids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

				lku.uid_to_rev = server_known_uids;
				lku.latest_last_modify = 0;

				ebmac->op_list_known_uids (bvtd->ebma, e_mapi_book_utils_build_sexp_restriction, (gpointer) query, &lku, bvtd->cancellable, &error);

				if (!g_cancellable_is_cancelled (bvtd->cancellable)) {
					GSList *uids = NULL;
					GHashTableIter iter;
					gpointer key, value;

					g_hash_table_iter_init (&iter, server_known_uids);
					while (g_hash_table_iter_next (&iter, &key, &value)) {
						const gchar *uid = key, *rev = value, *local_rev;

						local_rev = g_hash_table_lookup (local_known_uids, uid);
						if (g_strcmp0 (local_rev, rev) != 0) {
							uids = g_slist_prepend (uids, (gpointer) uid);
						}

						g_hash_table_remove (local_known_uids, uid);
					}

					if (uids) {
						ebbm_transfer_contacts (bvtd->ebma, uids, NULL, bvtd->cancellable, &error);
						e_book_backend_mapi_update_view_by_cache (bvtd->ebma, bvtd->book_view, &error);
					}

					/* has borrowed data from server_known_uids */
					g_slist_free (uids);
				}

				g_hash_table_destroy (server_known_uids);
				if (local_known_uids)
					g_hash_table_destroy (local_known_uids);
			}
		}
	}

	if (error && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		g_clear_error (&error);

	/* do not stop book view when filling cache */
	if (e_book_backend_mapi_book_view_is_running (bvtd->ebma, bvtd->book_view)
	    && (!priv->update_cache_thread || g_cancellable_is_cancelled (priv->update_cache)))
		e_data_book_view_notify_complete (bvtd->book_view, error);

	if (error)
		g_error_free (error);

	if (bvtd->cancellable)
		g_object_unref (bvtd->cancellable);
	g_object_unref (bvtd->book_view);
	/* May unref it out of the thread, in case it's the last reference to it */
	g_idle_add (unref_backend_idle_cb, bvtd->ebma);
	g_free (bvtd);

	return NULL;
}

/* Async OP functions, data structures and so on */

typedef enum {
	OP_OPEN,

	OP_CREATE_CONTACTS,
	OP_REMOVE_CONTACTS,
	OP_MODIFY_CONTACTS,
	OP_GET_CONTACT,
	OP_GET_CONTACT_LIST,
	OP_START_BOOK_VIEW,
	OP_STOP_BOOK_VIEW,
	OP_GET_BACKEND_PROPERTY
} OperationType;

typedef struct {
	OperationType ot;

	EDataBook *book;
	guint32 opid;
	GCancellable *cancellable;
} OperationBase;

typedef struct {
	OperationBase base;

	gboolean only_if_exists;
} OperationOpen;

typedef struct {
	OperationBase base;

	gchar *str;
} OperationStr;

typedef struct {
	OperationBase base;

	GSList *str_slist;
} OperationStrSlist;

typedef struct {
	OperationBase base;

	EDataBookView *book_view;
} OperationBookView;

static void
ebbm_operation_cb (OperationBase *op, gboolean cancelled, EBookBackend *backend)
{
	EBookBackendMAPI *ebma;
	EBookBackendMAPIClass *ebmac;
	GError *error = NULL;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND (backend));
	g_return_if_fail (op != NULL);

	ebma = E_BOOK_BACKEND_MAPI (backend);
	g_return_if_fail (ebma != NULL);

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_if_fail (ebmac != NULL);

	cancelled = cancelled || (op->cancellable && g_cancellable_is_cancelled (op->cancellable));

	switch (op->ot) {
	case OP_OPEN: {
		OperationOpen *opo = (OperationOpen *) op;

		if (!cancelled) {
			if (ebmac->op_open)
				ebmac->op_open (ebma, op->cancellable, opo->only_if_exists, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_data_book_respond_open (op->book, op->opid, error);
		}
	} break;
	case OP_CREATE_CONTACTS: {
		OperationStrSlist *ops = (OperationStrSlist *) op;

		if (!cancelled) {
			GSList *added_contacts = NULL;

			if (ebmac->op_create_contacts)
				ebmac->op_create_contacts (ebma, op->cancellable, ops->str_slist, &added_contacts, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			if (added_contacts && !error) {
				const GSList *l;

				e_book_backend_sqlitedb_lock_updates (ebma->priv->db, NULL);

				for (l = added_contacts; l; l = l->next) {
					e_book_backend_mapi_notify_contact_update (ebma, NULL, E_CONTACT (l->data), -1, -1, TRUE, NULL);
				}

				e_book_backend_sqlitedb_unlock_updates (ebma->priv->db, TRUE, NULL);
			}

			e_data_book_respond_create_contacts (op->book, op->opid, error, added_contacts);

			e_util_free_object_slist (added_contacts);
		}

		e_util_free_string_slist (ops->str_slist);
	} break;
	case OP_REMOVE_CONTACTS: {
		OperationStrSlist *ops = (OperationStrSlist *) op;

		if (!cancelled) {
			GSList *removed_ids = NULL;

			if (ebmac->op_remove_contacts)
				ebmac->op_remove_contacts (ebma, op->cancellable, ops->str_slist, &removed_ids, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			if (!error) {
				GSList *r;

				e_book_backend_sqlitedb_lock_updates (ebma->priv->db, NULL);

				for (r = removed_ids; r; r = r->next) {
					const gchar *uid = r->data;

					if (uid)
						e_book_backend_mapi_notify_contact_removed (ebma, uid);
				}

				e_book_backend_sqlitedb_unlock_updates (ebma->priv->db, TRUE, NULL);
			}

			e_data_book_respond_remove_contacts (op->book, op->opid, error, removed_ids);

			g_slist_foreach (removed_ids, (GFunc) g_free, NULL);
			g_slist_free (removed_ids);
		}

		e_util_free_string_slist (ops->str_slist);
	} break;
	case OP_MODIFY_CONTACTS: {
		OperationStrSlist *ops = (OperationStrSlist *) op;

		if (!cancelled) {
			GSList *modified_contacts = NULL;

			if (ebmac->op_modify_contacts)
				ebmac->op_modify_contacts (ebma, op->cancellable, ops->str_slist, &modified_contacts, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			if (modified_contacts && !error) {
				const GSList *l;

				e_book_backend_sqlitedb_lock_updates (ebma->priv->db, NULL);

				for (l = modified_contacts; l; l = l->next) {
					e_book_backend_mapi_notify_contact_update (ebma, NULL, E_CONTACT (l->data), -1, -1, TRUE, NULL);
				}

				e_book_backend_sqlitedb_unlock_updates (ebma->priv->db, TRUE, NULL);
			}

			e_data_book_respond_modify_contacts (op->book, op->opid, error, modified_contacts);

			e_util_free_object_slist (modified_contacts);
		}

		e_util_free_string_slist (ops->str_slist);
	} break;
	case OP_GET_CONTACT: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *id = ops->str;

		if (!cancelled) {
			gchar *vcard = NULL;

			if (ebmac->op_get_contact)
				ebmac->op_get_contact (ebma, op->cancellable, id, &vcard, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_data_book_respond_get_contact (op->book, op->opid, error, vcard);

			g_free (vcard);
		}

		g_free (ops->str);
	} break;
	case OP_GET_CONTACT_LIST: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *query = ops->str;

		if (!cancelled) {
			GSList *vCards = NULL;

			if (ebmac->op_get_contact_list)
				ebmac->op_get_contact_list (ebma, op->cancellable, query, &vCards, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_data_book_respond_get_contact_list (op->book, op->opid, error, vCards);

			g_slist_foreach (vCards, (GFunc) g_free, NULL);
			g_slist_free (vCards);
		}

		g_free (ops->str);
	} break;
	case OP_START_BOOK_VIEW: {
		OperationBookView *opbv = (OperationBookView *) op;

		if (!cancelled && e_book_backend_mapi_book_view_is_running (ebma, opbv->book_view)) {
			GError *err = NULL;
			struct BookViewThreadData *bvtd = g_new0 (struct BookViewThreadData, 1);

			g_mutex_lock (&ebma->priv->running_views_lock);

			bvtd->ebma = g_object_ref (ebma);
			bvtd->book_view = g_object_ref (opbv->book_view);
			bvtd->cancellable = g_hash_table_lookup (ebma->priv->running_views, bvtd->book_view);

			if (bvtd->cancellable)
				g_object_ref (bvtd->cancellable);

			g_mutex_unlock (&ebma->priv->running_views_lock);

			g_thread_create (ebbm_book_view_thread, bvtd, FALSE, &err);

			if (err) {
				error = EDB_ERROR_EX (OTHER_ERROR, err->message);
				e_data_book_view_notify_complete (opbv->book_view, error);
				g_error_free (error);
				g_error_free (err);
			}
		}

		g_object_unref (opbv->book_view);
	} break;
	case OP_STOP_BOOK_VIEW: {
		OperationBookView *opbv = (OperationBookView *) op;

		if (!cancelled) {
			e_data_book_view_notify_complete (opbv->book_view, NULL);
		}

		g_object_unref (opbv->book_view);
	} break;
	case OP_GET_BACKEND_PROPERTY: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *prop_name = ops->str;

		if (!cancelled) {
			gchar *prop_value = NULL;

			if (ebbm_get_backend_property (ebma, prop_name, &prop_value, &error))
				e_data_book_respond_get_backend_property (op->book, op->opid, error, prop_value);
			else
				(* E_BOOK_BACKEND_CLASS (e_book_backend_mapi_parent_class)->get_backend_property) (backend, op->book, op->opid, op->cancellable, prop_name);
		}

		g_free (ops->str);
	} break;
	}

	if (op->cancellable)
		g_object_unref (op->cancellable);
	if (op->book)
		g_object_unref (op->book);
	g_free (op);

	/* for cases when this is the last reference */
	e_mapi_utils_unref_in_thread (G_OBJECT (backend));
}

static void
str_op_abstract (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, const gchar *str, OperationType ot)
{
	OperationStr *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);
	if (book)
		g_object_ref (book);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationStr, 1);
	op->base.ot = ot;
	op->base.book = book;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->str = g_strdup (str);

	e_mapi_operation_queue_push (priv->op_queue, op);
}

static void
str_slist_op_abstract (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, const GSList *str_slist, OperationType ot)
{
	OperationStrSlist *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;
	GSList *l;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));
	g_return_if_fail (str_slist != NULL);

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);
	if (book)
		g_object_ref (book);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationStrSlist, 1);
	op->base.ot = ot;
	op->base.book = book;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->str_slist = g_slist_copy ((GSList *) str_slist);

	for (l = op->str_slist; l; l = l->next) {
		l->data = g_strdup (l->data);
	}

	e_mapi_operation_queue_push (priv->op_queue, op);
}

#define STR_OP_DEF(_func, _ot)							\
static void									\
_func (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, const gchar *str)	\
{										\
	str_op_abstract (backend, book, opid, cancellable, str, _ot);		\
}

#define STR_SLIST_OP_DEF(_func, _ot)							\
static void										\
_func (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, const GSList *str_slist)	\
{											\
	str_slist_op_abstract (backend, book, opid, cancellable, str_slist, _ot);	\
}

STR_SLIST_OP_DEF (ebbm_op_create_contacts, OP_CREATE_CONTACTS)
STR_SLIST_OP_DEF (ebbm_op_modify_contacts, OP_MODIFY_CONTACTS)
STR_SLIST_OP_DEF (ebbm_op_remove_contacts, OP_REMOVE_CONTACTS)
STR_OP_DEF  (ebbm_op_get_contact, OP_GET_CONTACT)
STR_OP_DEF  (ebbm_op_get_contact_list, OP_GET_CONTACT_LIST)
STR_OP_DEF  (ebbm_op_get_backend_property, OP_GET_BACKEND_PROPERTY)

static void
ebbm_op_open (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, gboolean only_if_exists)
{
	OperationOpen *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);
	if (book)
		g_object_ref (book);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationOpen, 1);
	op->base.ot = OP_OPEN;
	op->base.book = book;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->only_if_exists = only_if_exists;

	e_mapi_operation_queue_push (priv->op_queue, op);
}

static void
ebbm_op_start_view (EBookBackend *backend, EDataBookView *book_view)
{
	OperationBookView *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));
	g_return_if_fail (book_view != NULL);

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);

	op = g_new0 (OperationBookView, 1);
	op->base.ot = OP_START_BOOK_VIEW;
	op->base.book = NULL;
	op->base.opid = 0;
	op->book_view = g_object_ref (book_view);

	g_mutex_lock (&priv->running_views_lock);
	g_hash_table_insert (priv->running_views, book_view, g_cancellable_new ());
	g_mutex_unlock (&priv->running_views_lock);

	e_mapi_operation_queue_push (priv->op_queue, op);
}

static void
ebbm_op_stop_view (EBookBackend *backend, EDataBookView *book_view)
{
	OperationBookView *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;
	GCancellable *cancellable;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));
	g_return_if_fail (book_view != NULL);

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);

	op = g_new0 (OperationBookView, 1);
	op->base.ot = OP_STOP_BOOK_VIEW;
	op->base.book = NULL;
	op->base.opid = 0;
	op->book_view = g_object_ref (book_view);

	g_mutex_lock (&priv->running_views_lock);
	cancellable = g_hash_table_lookup (priv->running_views, book_view);
	if (cancellable)
		g_cancellable_cancel (cancellable);
	g_hash_table_remove (priv->running_views, book_view);
	g_mutex_unlock (&priv->running_views_lock);

	e_mapi_operation_queue_push (priv->op_queue, op);
}

static void
e_book_backend_mapi_init (EBookBackendMAPI *ebma)
{
	ebma->priv = G_TYPE_INSTANCE_GET_PRIVATE (ebma, E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPIPrivate);

	ebma->priv->op_queue = e_mapi_operation_queue_new ((EMapiOperationQueueFunc) ebbm_operation_cb, ebma);
	ebma->priv->running_views = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_object_unref);
	g_mutex_init (&ebma->priv->running_views_lock);
	g_rec_mutex_init (&ebma->priv->conn_lock);

	ebma->priv->update_cache = g_cancellable_new ();
	ebma->priv->update_cache_thread = NULL;
	ebma->priv->last_update_cache = 0;
	ebma->priv->last_server_contact_count = 0;
	ebma->priv->last_modify_time = 0;
	ebma->priv->server_dirty = FALSE;
	ebma->priv->last_db_commit_time = 0;

	g_signal_connect (
		ebma, "notify::online",
		G_CALLBACK (ebbm_notify_online_cb), NULL);
}

static void
ebbm_dispose (GObject *object)
{
	EBookBackendMAPI *ebma = E_BOOK_BACKEND_MAPI (object);
	EBookBackendMAPIPrivate *priv = ebma->priv;

	if (priv) {
		if (priv->update_cache_thread) {
			g_cancellable_cancel (priv->update_cache);
			g_thread_join (priv->update_cache_thread);
			priv->update_cache_thread = NULL;
		}

		#define FREE(x) if (x) { g_free (x); x = NULL; }
		#define UNREF(x) if (x) { g_object_unref (x); x = NULL; }

		e_book_backend_mapi_lock_connection (ebma);
		UNREF (priv->conn);
		e_book_backend_mapi_unlock_connection (ebma);
		UNREF (priv->op_queue);
		UNREF (priv->db);
		UNREF (priv->update_cache);

		FREE (priv->book_uid);

		g_hash_table_destroy (priv->running_views);
		g_mutex_clear (&priv->running_views_lock);
		g_rec_mutex_clear (&priv->conn_lock);

		#undef UNREF
		#undef FREE

		ebma->priv = NULL;
	}

	/* Chain up to parent's dispose() method. */
	if (G_OBJECT_CLASS (e_book_backend_mapi_parent_class)->dispose)
		G_OBJECT_CLASS (e_book_backend_mapi_parent_class)->dispose (object);
}

static void
e_book_backend_mapi_class_init (EBookBackendMAPIClass *klass)
{
	GObjectClass  *object_class = G_OBJECT_CLASS (klass);
	EBookBackendClass *backend_class = E_BOOK_BACKEND_CLASS (klass);

	g_type_class_add_private (klass, sizeof (EBookBackendMAPIPrivate));

	object_class->dispose			= ebbm_dispose;

	backend_class->open			= ebbm_op_open;
	backend_class->create_contacts		= ebbm_op_create_contacts;
	backend_class->remove_contacts		= ebbm_op_remove_contacts;
	backend_class->modify_contacts		= ebbm_op_modify_contacts;
	backend_class->get_contact		= ebbm_op_get_contact;
	backend_class->get_contact_list		= ebbm_op_get_contact_list;
	backend_class->start_view		= ebbm_op_start_view;
	backend_class->stop_view		= ebbm_op_stop_view;
	backend_class->get_backend_property	= ebbm_op_get_backend_property;
	klass->op_open				= ebbm_open;
	klass->op_remove			= ebbm_remove;
	klass->op_get_contact			= ebbm_get_contact;
	klass->op_get_contact_list		= ebbm_get_contact_list;

	klass->op_connection_status_changed	= NULL;
	klass->op_get_status_message		= NULL;
	klass->op_book_view_thread		= NULL;
	klass->op_get_contacts_count		= NULL;
	klass->op_list_known_uids		= NULL;
	klass->op_transfer_contacts		= NULL;
}

static void
e_book_backend_mapi_authenticator_init (ESourceAuthenticatorInterface *interface)
{
	interface->try_password_sync = ebbm_try_password_sync;
}

const gchar *
e_book_backend_mapi_get_book_uid (EBookBackendMAPI *ebma)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);
	g_return_val_if_fail (ebma->priv != NULL, NULL);

	return ebma->priv->book_uid;
}

void
e_book_backend_mapi_lock_connection (EBookBackendMAPI *ebma)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);

	g_rec_mutex_lock (&ebma->priv->conn_lock);
}

void
e_book_backend_mapi_unlock_connection (EBookBackendMAPI *ebma)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);

	g_rec_mutex_unlock (&ebma->priv->conn_lock);
}

EMapiConnection *
e_book_backend_mapi_get_connection (EBookBackendMAPI *ebma,
				    GCancellable *cancellable,
				    GError **perror)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);
	g_return_val_if_fail (ebma->priv != NULL, NULL);

	if (ebma->priv->conn)
		return ebma->priv->conn;

	if (!e_backend_get_online (E_BACKEND (ebma)))
		return NULL;

	if (!e_book_backend_mapi_ensure_connected (ebma, cancellable, perror))
		return NULL;

	return ebma->priv->conn;
}

void
e_book_backend_mapi_get_db (EBookBackendMAPI *ebma, EBookBackendSqliteDB **db)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);

	if (db)
		*db = ebma->priv->db;
}

gboolean
e_book_backend_mapi_book_view_is_running (EBookBackendMAPI *ebma, EDataBookView *book_view)
{
	gboolean res;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), FALSE);
	g_return_val_if_fail (ebma->priv != NULL, FALSE);

	g_mutex_lock (&ebma->priv->running_views_lock);
	res = g_hash_table_lookup (ebma->priv->running_views, book_view) != NULL;
	g_mutex_unlock (&ebma->priv->running_views_lock);

	return res;
}

gboolean
e_book_backend_mapi_is_marked_for_offline (EBookBackendMAPI *ebma)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), FALSE);
	g_return_val_if_fail (ebma->priv != NULL, FALSE);

	return ebma->priv->marked_for_offline;
}

void
e_book_backend_mapi_update_view_by_cache (EBookBackendMAPI *ebma, EDataBookView *book_view, GError **error)
{
	gint i = 0;
	const gchar *query = NULL;
	EBookBackendSExp *sexp;
	EBookBackendSqliteDB *db = NULL;
	GSList *hits, *l;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (book_view != NULL);
	g_return_if_fail (E_IS_DATA_BOOK_VIEW (book_view));

	sexp = e_data_book_view_get_sexp (book_view);
	query = e_book_backend_sexp_text (sexp);

	e_book_backend_mapi_get_db (ebma, &db);

	g_return_if_fail (db != NULL);

	hits = e_book_backend_sqlitedb_search (db, EMA_EBB_CACHE_FOLDERID,
					       query, NULL, NULL, NULL, error);

	for (l = hits; (!error || !*error) && l; l = l->next) {
		EbSdbSearchData *sdata = (EbSdbSearchData *) l->data;
		gchar *vcard = sdata->vcard;

		if (((i++) % 10) == 0 && !e_book_backend_mapi_book_view_is_running (ebma, book_view))
			break;

		if (vcard) {
			EContact *contact = e_contact_new_from_vcard (vcard);
			e_data_book_view_notify_update (book_view, contact);
			g_object_unref (contact);
		}
	}

	if (hits) {
		g_slist_foreach (hits, (GFunc) e_book_backend_sqlitedb_search_data_free, NULL);
		g_slist_free (hits);
	}
}

/* called from op_transfer_contacts - book_view and notify_contact_data are taken from there;
   notify_contact_data is a pointer to glong last_notification, if not NULL;
   returns whether can continue with fetching */
gboolean
e_book_backend_mapi_notify_contact_update (EBookBackendMAPI *ebma,
					   EDataBookView *pbook_view,
					   EContact *contact,
					   gint index,
					   gint total,
					   gboolean cache_is_locked,
					   gpointer notify_contact_data)
{
	EBookBackendMAPIPrivate *priv;
	glong *last_notification = notify_contact_data;
	EDataBookView *book_view = pbook_view;
	glong current_time;
	GError *error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), FALSE);
	g_return_val_if_fail (ebma->priv, FALSE);
	g_return_val_if_fail (contact != NULL, FALSE);

	priv = ebma->priv;
	g_return_val_if_fail (priv != NULL, FALSE);

	current_time = get_current_time_ms ();

	/* report progres to any book_view, if not passed in;
	   it can happen when cache is filling and the book view started later */
	if (!book_view)
		book_view = ebbm_pick_book_view (ebma);

	if (book_view) {
		if (!e_book_backend_mapi_book_view_is_running (ebma, book_view))
			return FALSE;

		if (index > 0 && last_notification && current_time - *last_notification > 333) {
			gchar *status_msg = NULL;
			EBookBackendMAPIClass *ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);

			if (ebmac->op_get_status_message)
				status_msg = ebmac->op_get_status_message (ebma, index, total);

			if (status_msg)
				e_data_book_view_notify_progress (book_view, -1, status_msg);

			g_free (status_msg);

			*last_notification = current_time;
		}
	}

	if (!pbook_view && g_cancellable_is_cancelled (priv->update_cache))
		return FALSE;

	e_book_backend_sqlitedb_add_contact (priv->db,
					     EMA_EBB_CACHE_FOLDERID, contact,
					     FALSE, &error);

	/* commit not often than each minute, also to not lose data already transferred */
	if (cache_is_locked && current_time - priv->last_db_commit_time >= 60000) {
		e_book_backend_sqlitedb_unlock_updates (priv->db, TRUE, NULL);
		e_book_backend_sqlitedb_lock_updates (priv->db, NULL);

		priv->last_db_commit_time = current_time;
	}

	if (!error) {
		e_book_backend_notify_update (E_BOOK_BACKEND (ebma), contact);
		return TRUE;
	}

	g_error_free (error);

	return FALSE;
}

void
e_book_backend_mapi_notify_contact_removed (EBookBackendMAPI *ebma, const gchar *uid)
{
	EBookBackendMAPIPrivate *priv;
	GError *error = NULL;
	gboolean ret;

	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv);
	g_return_if_fail (uid != NULL);

	priv = ebma->priv;
	g_return_if_fail (priv != NULL);

	ret = e_book_backend_sqlitedb_remove_contact (priv->db,
						      EMA_EBB_CACHE_FOLDERID,
						      uid, &error);
	if (ret && !error)
		e_book_backend_notify_remove (E_BOOK_BACKEND (ebma), uid);

	if (error)
		g_error_free (error);
}

void
e_book_backend_mapi_cache_set (EBookBackendMAPI *ebma, const gchar *key, const gchar *value)
{
	g_return_if_fail (ebma != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);
	g_return_if_fail (ebma->priv->db != NULL);
	g_return_if_fail (key != NULL);

	e_book_backend_sqlitedb_set_key_value (ebma->priv->db, EMA_EBB_CACHE_FOLDERID, key, value, NULL);
}

gchar *
e_book_backend_mapi_cache_get (EBookBackendMAPI *ebma, const gchar *key)
{
	g_return_val_if_fail (ebma != NULL, NULL);
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);
	g_return_val_if_fail (ebma->priv != NULL, NULL);
	g_return_val_if_fail (ebma->priv->db != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	return e_book_backend_sqlitedb_get_key_value (ebma->priv->db, EMA_EBB_CACHE_FOLDERID, key, NULL);
}

void
e_book_backend_mapi_refresh_cache (EBookBackendMAPI *ebma)
{
	g_return_if_fail (ebma != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));

	ebma->priv->last_update_cache = 0;
	ebma->priv->last_modify_time = 0;
	ebma->priv->server_dirty = TRUE;

	ebbm_maybe_invoke_cache_update (ebma);
}

/* utility functions/macros */

void
mapi_error_to_edb_error (GError **perror, const GError *mapi_error, EDataBookStatus code, const gchar *context)
{
	gchar *err_msg = NULL;

	if (!perror)
		return;

	if (g_error_matches (mapi_error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_propagate_error (perror, g_error_copy (mapi_error));
		return;
	}

	if (code == E_DATA_BOOK_STATUS_OTHER_ERROR && mapi_error && mapi_error->domain == E_MAPI_ERROR) {
		/* Change error to more accurate only with OTHER_ERROR */
		switch (mapi_error->code) {
		case MAPI_E_PASSWORD_CHANGE_REQUIRED:
		case MAPI_E_PASSWORD_EXPIRED:
			code = E_DATA_BOOK_STATUS_AUTHENTICATION_REQUIRED;
			break;
		case MAPI_E_NETWORK_ERROR:
			code = E_DATA_BOOK_STATUS_REPOSITORY_OFFLINE;
			break;
		default:
			break;
		}
	}

	if (context)
		err_msg = g_strconcat (context, mapi_error ? ": " : NULL, mapi_error ? mapi_error->message : NULL, NULL);

	g_propagate_error (perror, e_data_book_create_error (code, err_msg ? err_msg : mapi_error ? mapi_error->message : _("Unknown error")));

	g_free (err_msg);
}
