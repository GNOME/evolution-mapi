/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 * Copyright (C) 2017 Red Hat, Inc. (www.redhat.com)
 *
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
 */

#include "evolution-mapi-config.h"

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n-lib.h>

#include <libebook/libebook.h>
#include <libedataserver/libedataserver.h>
#include <camel/camel.h>

#include "e-mapi-utils.h"
#include "e-mapi-defs.h"
#include "e-source-mapi-folder.h"

#include "e-book-backend-mapi.h"

/* default value for "partial-count", upper bound of objects to download during partial search */
#define DEFAULT_PARTIAL_COUNT 50

struct _EBookBackendMAPIPrivate
{
	GRecMutex conn_lock;
	EMapiConnection *conn;

	gboolean is_gal;
};

G_DEFINE_TYPE_WITH_PRIVATE (EBookBackendMAPI, e_book_backend_mapi, E_TYPE_BOOK_META_BACKEND)

static void
ebb_mapi_error_to_client_error (GError **perror,
				const GError *mapi_error,
				EClientError code,
				const gchar *context)
{
	gchar *err_msg = NULL;

	if (!perror)
		return;

	if (g_error_matches (mapi_error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_propagate_error (perror, g_error_copy (mapi_error));
		return;
	}

	if (code == E_CLIENT_ERROR_OTHER_ERROR && mapi_error && mapi_error->domain == E_MAPI_ERROR) {
		/* Change error to more accurate only with OTHER_ERROR */
		switch (mapi_error->code) {
		case MAPI_E_PASSWORD_CHANGE_REQUIRED:
		case MAPI_E_PASSWORD_EXPIRED:
			code = E_CLIENT_ERROR_AUTHENTICATION_REQUIRED;
			break;
		case ecRpcFailed:
			code = E_CLIENT_ERROR_REPOSITORY_OFFLINE;
			break;
		default:
			break;
		}
	}

	if (context)
		err_msg = g_strconcat (context, mapi_error ? ": " : NULL, mapi_error ? mapi_error->message : NULL, NULL);

	g_propagate_error (perror, e_client_error_create (code, err_msg ? err_msg : mapi_error ? mapi_error->message : _("Unknown error")));

	g_free (err_msg);
}

static void
ebb_mapi_lock_connection (EBookBackendMAPI *bbmapi)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi));

	g_rec_mutex_lock (&bbmapi->priv->conn_lock);
}

static void
ebb_mapi_unlock_connection (EBookBackendMAPI *bbmapi)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi));

	g_rec_mutex_unlock (&bbmapi->priv->conn_lock);
}

static CamelMapiSettings *
ebb_mapi_get_collection_settings (EBookBackendMAPI *ebbm)
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

static gboolean
ebb_mapi_contacts_open_folder (EBookBackendMAPI *bbmapi,
			       mapi_object_t *out_obj_folder,
			       GCancellable *cancellable,
			       GError **error)
{
	ESource *source;
	ESourceMapiFolder *ext_mapi_folder;
	mapi_id_t fid;
	gchar *foreign_username;
	gboolean success;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi), FALSE);
	g_return_val_if_fail (bbmapi->priv->conn != NULL, FALSE);
	g_return_val_if_fail (out_obj_folder != NULL, FALSE);

	source = e_backend_get_source (E_BACKEND (bbmapi));
	ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

	fid = e_source_mapi_folder_get_id (ext_mapi_folder);
	foreign_username = e_source_mapi_folder_dup_foreign_username (ext_mapi_folder);

	if (foreign_username && *foreign_username)
		success = e_mapi_connection_open_foreign_folder (bbmapi->priv->conn, foreign_username, fid, out_obj_folder, cancellable, error);
	else if (e_source_mapi_folder_is_public (ext_mapi_folder))
		success = e_mapi_connection_open_public_folder (bbmapi->priv->conn, fid, out_obj_folder, cancellable, error);
	else
		success = e_mapi_connection_open_personal_folder (bbmapi->priv->conn, fid, out_obj_folder, cancellable, error);

	g_free (foreign_username);

	return success;
}

static void
ebb_mapi_maybe_disconnect (EBookBackendMAPI *bbmapi,
			   const GError *mapi_error)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi));

	/* no error or already disconnected */
	if (!mapi_error || !bbmapi->priv->conn)
		return;

	if (g_error_matches (mapi_error, E_MAPI_ERROR, ecRpcFailed) ||
	    g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_CALL_FAILED)) {
		e_mapi_connection_disconnect (bbmapi->priv->conn,
			!g_error_matches (mapi_error, E_MAPI_ERROR, ecRpcFailed),
			NULL, NULL);
		g_clear_object (&bbmapi->priv->conn);
	}
}

static gboolean
ebb_mapi_is_marked_for_offline (EBookBackendMAPI *bbmapi)
{
	ESource *source;
	ESourceOffline *offline_extension;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi), FALSE);

	source = e_backend_get_source (E_BACKEND (bbmapi));

	offline_extension = e_source_get_extension (source, E_SOURCE_EXTENSION_OFFLINE);

	return e_source_offline_get_stay_synchronized (offline_extension);
}

static void
ebb_mapi_server_notification_cb (EMapiConnection *conn,
				 guint event_mask,
				 gpointer event_data,
				 gpointer user_data)
{
	EBookBackendMAPI *bbmapi = user_data;
	mapi_id_t update_folder1 = 0, update_folder2 = 0;

	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi));

	switch (event_mask) {
	case fnevNewMail:
	case fnevNewMail | fnevMbit: {
		struct NewMailNotification *newmail = event_data;

		if (newmail)
			update_folder1 = newmail->FID;
		} break;
	case fnevObjectCreated:
	case fnevMbit | fnevObjectCreated: {
		struct MessageCreatedNotification *msgcreated = event_data;

		if (msgcreated)
			update_folder1 = msgcreated->FID;
		} break;
	case fnevObjectModified:
	case fnevMbit | fnevObjectModified: {
		struct MessageModifiedNotification *msgmodified = event_data;

		if (msgmodified)
			update_folder1 = msgmodified->FID;
		} break;
	case fnevObjectDeleted:
	case fnevMbit | fnevObjectDeleted: {
		struct MessageDeletedNotification *msgdeleted = event_data;

		if (msgdeleted)
			update_folder1 = msgdeleted->FID;
		} break;
	case fnevObjectMoved:
	case fnevMbit | fnevObjectMoved: {
		struct MessageMoveCopyNotification *msgmoved = event_data;

		if (msgmoved) {
			update_folder1 = msgmoved->OldFID;
			update_folder2 = msgmoved->FID;
		}
		} break;
	case fnevObjectCopied:
	case fnevMbit | fnevObjectCopied: {
		struct MessageMoveCopyNotification *msgcopied = event_data;

		if (msgcopied) {
			update_folder1 = msgcopied->OldFID;
			update_folder2 = msgcopied->FID;
		}
		} break;
	default:
		break;
	}

	if (update_folder1 || update_folder2) {
		ESource *source;
		ESourceMapiFolder *ext_mapi_folder;

		source = e_backend_get_source (E_BACKEND (bbmapi));
		ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

		if (update_folder1 == e_source_mapi_folder_get_id (ext_mapi_folder) ||
		    update_folder2 == e_source_mapi_folder_get_id (ext_mapi_folder)) {
			e_book_meta_backend_schedule_refresh (E_BOOK_META_BACKEND (bbmapi));
		}
	}
}

static gboolean
ebb_mapi_connect_sync (EBookMetaBackend *meta_backend,
		       const ENamedParameters *credentials,
		       ESourceAuthenticationResult *out_auth_result,
		       gchar **out_certificate_pem,
		       GTlsCertificateFlags *out_certificate_errors,
		       GCancellable *cancellable,
		       GError **error)
{
	EBookBackendMAPI *bbmapi;
	EMapiConnection *old_conn;
	CamelMapiSettings *settings;
	ESource *source;
	ESourceMapiFolder *ext_mapi_folder;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (out_auth_result != NULL, FALSE);

	bbmapi = E_BOOK_BACKEND_MAPI (meta_backend);

	ebb_mapi_lock_connection (bbmapi);

	if (bbmapi->priv->conn &&
	    e_mapi_connection_connected (bbmapi->priv->conn)) {
		ebb_mapi_unlock_connection (bbmapi);
		return TRUE;
	}

	settings = ebb_mapi_get_collection_settings (bbmapi);
	source = e_backend_get_source (E_BACKEND (bbmapi));
	ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

	old_conn = bbmapi->priv->conn;

	bbmapi->priv->conn = e_mapi_connection_new (
		e_book_backend_get_registry (E_BOOK_BACKEND (bbmapi)),
		camel_mapi_settings_get_profile (settings),
		credentials, cancellable, &mapi_error);

	if (!bbmapi->priv->conn) {
		bbmapi->priv->conn = e_mapi_connection_find (camel_mapi_settings_get_profile (settings));
		if (bbmapi->priv->conn && !e_mapi_connection_connected (bbmapi->priv->conn))
			e_mapi_connection_reconnect (bbmapi->priv->conn, credentials, cancellable, &mapi_error);
	}

	if (old_conn)
		g_signal_handlers_disconnect_by_func (old_conn, G_CALLBACK (ebb_mapi_server_notification_cb), bbmapi);

	g_clear_object (&old_conn);

	if (!bbmapi->priv->conn || mapi_error) {
		gboolean is_network_error = mapi_error && mapi_error->domain != E_MAPI_ERROR;

		g_clear_object (&bbmapi->priv->conn);
		ebb_mapi_unlock_connection (bbmapi);

		if (is_network_error)
			ebb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR_OTHER_ERROR, NULL);

		g_clear_error (&mapi_error);

		if (is_network_error) {
			*out_auth_result = E_SOURCE_AUTHENTICATION_ERROR;
		} else if ((!credentials || !e_named_parameters_count (credentials)) && !camel_mapi_settings_get_kerberos (settings)) {
			*out_auth_result = E_SOURCE_AUTHENTICATION_REQUIRED;
		} else {
			*out_auth_result = E_SOURCE_AUTHENTICATION_REJECTED;
		}

		return FALSE;
	}

	if (!e_book_backend_mapi_get_is_gal (bbmapi) &&
	    e_source_mapi_folder_get_server_notification (ext_mapi_folder)) {
		mapi_object_t obj_folder;

		g_signal_connect (bbmapi->priv->conn, "server-notification", G_CALLBACK (ebb_mapi_server_notification_cb), bbmapi);

		if (ebb_mapi_contacts_open_folder (bbmapi, &obj_folder, cancellable, &mapi_error)) {
			e_mapi_connection_enable_notifications (bbmapi->priv->conn, &obj_folder,
				fnevObjectCreated | fnevObjectModified | fnevObjectDeleted | fnevObjectMoved | fnevObjectCopied,
				cancellable, &mapi_error);

			e_mapi_connection_close_folder (bbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
		}

		if (mapi_error) {
			ebb_mapi_maybe_disconnect (bbmapi, mapi_error);
			g_clear_error (&mapi_error);
		}
	}

	ebb_mapi_unlock_connection (bbmapi);

	*out_auth_result = E_SOURCE_AUTHENTICATION_ACCEPTED;

	return TRUE;
}

static gboolean
ebb_mapi_disconnect_sync (EBookMetaBackend *meta_backend,
			  GCancellable *cancellable,
			  GError **error)
{
	EBookBackendMAPI *bbmapi;
	gboolean success = TRUE;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);

	bbmapi = E_BOOK_BACKEND_MAPI (meta_backend);

	ebb_mapi_lock_connection (bbmapi);

	if (bbmapi->priv->conn) {
		g_signal_handlers_disconnect_by_func (bbmapi->priv->conn, G_CALLBACK (ebb_mapi_server_notification_cb), bbmapi);

		success = e_mapi_connection_disconnect (bbmapi->priv->conn, FALSE, cancellable, error);
		g_clear_object (&bbmapi->priv->conn);
	}

	ebb_mapi_unlock_connection (bbmapi);

	return success;
}

typedef struct _LoadMultipleData {
	gboolean is_gal;
	gchar *book_uid;
	GSList **out_contacts; /* EContact * */
} LoadMultipleData;

static gboolean
transfer_contacts_cb (EMapiConnection *conn,
		      TALLOC_CTX *mem_ctx,
		      /* const */ EMapiObject *object,
		      guint32 obj_index,
		      guint32 obj_total,
		      gpointer user_data,
		      GCancellable *cancellable,
		      GError **perror)
{
	LoadMultipleData *lmd = user_data;
	EContact *contact;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (lmd != NULL, FALSE);

	contact = e_mapi_book_utils_contact_from_object (conn, object, lmd->book_uid);
	if (!contact) {
		/* being it GAL, just ignore failures */
		return lmd->is_gal;
	}

	*lmd->out_contacts = g_slist_prepend (*lmd->out_contacts, contact);

	return TRUE;
}

static gboolean
ebb_mapi_load_multiple_sync (EBookBackendMAPI *bbmapi,
			     const GSList *uids, /* gchar * */
			     GSList **out_contacts, /* EContact * */
			     GCancellable *cancellable,
			     GError **error)
{
	LoadMultipleData lmd;
	const gchar *error_text;
	gint partial_count = -1;
	GSList *mids = NULL, *link;
	ESource *source;
	gboolean success;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi), FALSE);
	g_return_val_if_fail (uids != NULL, FALSE);
	g_return_val_if_fail (out_contacts != NULL, FALSE);

	source = e_backend_get_source (E_BACKEND (bbmapi));

	if (e_book_backend_mapi_get_is_gal (bbmapi) &&
	    !ebb_mapi_is_marked_for_offline (bbmapi)) {
		ESourceMapiFolder *ext_mapi_folder;

		ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
		if (e_source_mapi_folder_get_allow_partial (ext_mapi_folder)) {
			partial_count = e_source_mapi_folder_get_partial_count (ext_mapi_folder);

			if (partial_count <= 0)
				partial_count = DEFAULT_PARTIAL_COUNT;
		}
	}

	for (link = (GSList *) uids; link && (partial_count == -1 || partial_count > 0); link = g_slist_next (link)) {
		mapi_id_t *pmid, mid;

		if (e_mapi_util_mapi_id_from_string  (link->data, &mid)) {
			pmid = g_new0 (mapi_id_t, 1);
			*pmid = mid;

			mids = g_slist_prepend (mids, pmid);

			if (partial_count > 0)
				partial_count--;
		}
	}

	lmd.is_gal = e_book_backend_mapi_get_is_gal (bbmapi);
	lmd.book_uid = e_source_dup_uid (source);
	lmd.out_contacts = out_contacts;

	ebb_mapi_lock_connection (bbmapi);

	if (e_book_backend_mapi_get_is_gal (bbmapi)) {
		error_text = _("Failed to fetch GAL entries");

		success = e_mapi_connection_transfer_gal_objects (bbmapi->priv->conn, mids, NULL, NULL, transfer_contacts_cb, &lmd, cancellable, &mapi_error);
	} else {
		mapi_object_t obj_folder;

		error_text = _("Failed to transfer contacts from a server");

		success = ebb_mapi_contacts_open_folder (bbmapi, &obj_folder, cancellable, &mapi_error);

		if (success) {
			success = e_mapi_connection_transfer_objects (bbmapi->priv->conn, &obj_folder, mids, transfer_contacts_cb, &lmd, cancellable, &mapi_error);

			e_mapi_connection_close_folder (bbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
		}
	}

	if (mapi_error) {
		ebb_mapi_maybe_disconnect (bbmapi, mapi_error);
		ebb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR_OTHER_ERROR, error_text);
		g_error_free (mapi_error);

		success = FALSE;
	}

	ebb_mapi_unlock_connection (bbmapi);

	g_slist_free_full (mids, g_free);
	g_free (lmd.book_uid);

	return success;
}

static gboolean
ebb_mapi_preload_infos_sync (EBookBackendMAPI *bbmapi,
			     GSList *created_objects,
			     GSList *modified_objects,
			     GCancellable *cancellable,
			     GError **error)
{
	GHashTable *infos;
	GSList *uids = NULL, *link;
	gboolean success = TRUE;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi), FALSE);

	infos = g_hash_table_new (g_str_hash, g_str_equal);

	for (link = created_objects; link; link = g_slist_next (link)) {
		EBookMetaBackendInfo *nfo = link->data;

		if (nfo && nfo->uid) {
			uids = g_slist_prepend (uids, nfo->uid);
			g_hash_table_insert (infos, nfo->uid, nfo);
		}
	}

	for (link = modified_objects; link; link = g_slist_next (link)) {
		EBookMetaBackendInfo *nfo = link->data;

		if (nfo && nfo->uid) {
			uids = g_slist_prepend (uids, nfo->uid);
			g_hash_table_insert (infos, nfo->uid, nfo);
		}
	}

	uids = g_slist_reverse (uids);
	if (uids) {
		GSList *contacts = NULL;

		success = ebb_mapi_load_multiple_sync (bbmapi, uids, &contacts, cancellable, error);
		if (success) {
			for (link = contacts; link; link = g_slist_next (link)) {
				EContact *contact = link->data;

				if (contact) {
					EBookMetaBackendInfo *nfo = g_hash_table_lookup (infos, e_contact_get_const (contact, E_CONTACT_UID));

					if (nfo && !nfo->object)
						nfo->object = e_vcard_to_string (E_VCARD (contact), EVC_FORMAT_VCARD_30);
				}
			}
		}

		g_slist_free_full (contacts, g_object_unref);
	}

	g_hash_table_destroy (infos);
	g_slist_free (uids);

	return success;
}

static gboolean
ebb_mapi_get_changes_sync (EBookMetaBackend *meta_backend,
			   const gchar *last_sync_tag,
			   gboolean is_repeat,
			   gchar **out_new_sync_tag,
			   gboolean *out_repeat,
			   GSList **out_created_objects,
			   GSList **out_modified_objects,
			   GSList **out_removed_objects,
			   GCancellable *cancellable,
			   GError **error)
{
	EBookBackendMAPI *bbmapi;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (out_created_objects != NULL, FALSE);
	g_return_val_if_fail (out_modified_objects != NULL, FALSE);

	/* Chain up to parent's method */
	if (!E_BOOK_META_BACKEND_CLASS (e_book_backend_mapi_parent_class)->get_changes_sync (meta_backend,
		last_sync_tag, is_repeat, out_new_sync_tag, out_repeat, out_created_objects,
		out_modified_objects, out_removed_objects, cancellable, error)) {
		return FALSE;
	}

	bbmapi = E_BOOK_BACKEND_MAPI (meta_backend);

	/* Preload some of the contacts in chunk, to speed-up things;
	   ignore errors, to not break whole update process. */
	ebb_mapi_preload_infos_sync (bbmapi, *out_created_objects, *out_modified_objects, cancellable, NULL);

	return TRUE;
}

static gboolean
ebb_mapi_list_existing_uids_cb (EMapiConnection *conn,
				TALLOC_CTX *mem_ctx,
				const ListObjectsData *object_data,
				guint32 obj_index,
				guint32 obj_total,
				gpointer user_data,
				GCancellable *cancellable,
				GError **perror)
{
	GSList **out_existing_objects = user_data;
	gchar *uid;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (object_data != NULL, FALSE);
	g_return_val_if_fail (out_existing_objects != NULL, FALSE);

	uid = e_mapi_util_mapi_id_to_string (object_data->mid);
	if (uid) {
		gchar *rev;

		rev = e_mapi_book_utils_timet_to_string (object_data->last_modified);

		*out_existing_objects = g_slist_prepend (*out_existing_objects,
			e_book_meta_backend_info_new (uid, rev, NULL, NULL));

		g_free (uid);
		g_free (rev);
	}

	return TRUE;
}

static gboolean
ebb_mapi_list_existing_with_restrictions_sync (EBookMetaBackend *meta_backend,
					       BuildRestrictionsCB build_rs_cb,
					       gpointer build_rs_cb_data,
					       gchar **out_new_sync_tag,
					       GSList **out_existing_objects, /* EBookMetaBackendInfo * */
					       GCancellable *cancellable,
					       GError **error)
{
	EBookBackendMAPI *bbmapi;
	const gchar *error_text;
	gboolean success;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (out_existing_objects, FALSE);

	*out_existing_objects = NULL;

	bbmapi = E_BOOK_BACKEND_MAPI (meta_backend);

	ebb_mapi_lock_connection (bbmapi);

	if (e_book_backend_mapi_get_is_gal (bbmapi)) {
		error_text = _("Failed to fetch GAL entries");

		success = e_mapi_connection_list_gal_objects (bbmapi->priv->conn, NULL, NULL,
			ebb_mapi_list_existing_uids_cb, out_existing_objects, cancellable, &mapi_error);
	} else {
		mapi_object_t obj_folder;

		error_text = _("Failed to list items from a server");

		success = ebb_mapi_contacts_open_folder (bbmapi, &obj_folder, cancellable, &mapi_error);
		if (success) {
			success = e_mapi_connection_list_objects (bbmapi->priv->conn, &obj_folder, NULL, NULL,
				ebb_mapi_list_existing_uids_cb, out_existing_objects, cancellable, &mapi_error);

			e_mapi_connection_close_folder (bbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
		}
	}

	if (mapi_error) {
		ebb_mapi_maybe_disconnect (bbmapi, mapi_error);
		ebb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR_OTHER_ERROR, error_text);
		g_error_free (mapi_error);

		success = FALSE;
	}

	ebb_mapi_unlock_connection (bbmapi);

	return success;
}


static gboolean
ebb_mapi_list_existing_sync (EBookMetaBackend *meta_backend,
			     gchar **out_new_sync_tag,
			     GSList **out_existing_objects,
			     GCancellable *cancellable,
			     GError **error)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);

	return ebb_mapi_list_existing_with_restrictions_sync (meta_backend, NULL, NULL,
		out_new_sync_tag, out_existing_objects, cancellable, error);
}

static gboolean
ebb_mapi_load_contact_sync (EBookMetaBackend *meta_backend,
			      const gchar *uid,
			      const gchar *extra,
			      EContact **out_contact,
			      gchar **out_extra,
			      GCancellable *cancellable,
			      GError **error)
{
	EBookBackendMAPI *bbmapi;
	GSList *uids, *contacts = NULL;
	gboolean success;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (uid != NULL, FALSE);
	g_return_val_if_fail (out_contact != NULL, FALSE);

	*out_contact = NULL;

	bbmapi = E_BOOK_BACKEND_MAPI (meta_backend);

	uids = g_slist_prepend (NULL, (gpointer) uid);

	success = ebb_mapi_load_multiple_sync (bbmapi, uids, &contacts, cancellable, error);

	ebb_mapi_unlock_connection (bbmapi);

	if (success && contacts) {
		*out_contact = g_object_ref (contacts->data);
	}

	g_slist_free_full (contacts, g_object_unref);
	g_slist_free (uids);

	return success;
}

typedef struct _SaveContactData {
	EBookBackendMAPI *bbmapi;
	EContact *contact;
} SaveContactData;

static gboolean
ebb_mapi_create_object_cb (EMapiConnection *conn,
			   TALLOC_CTX *mem_ctx,
			   EMapiObject **pobject, /* out */
			   gpointer user_data,
			   GCancellable *cancellable,
			   GError **error)
{
	SaveContactData *scd = user_data;
	const gchar *uid = NULL;
	EContact *old_contact = NULL;
	gboolean success;

	g_return_val_if_fail (scd != NULL, FALSE);
	g_return_val_if_fail (scd->bbmapi != NULL, FALSE);
	g_return_val_if_fail (scd->contact != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (pobject != NULL, FALSE);

	uid = e_contact_get_const (scd->contact, E_CONTACT_UID);
	if (uid) {
		EBookCache *book_cache;

		book_cache = e_book_meta_backend_ref_cache (E_BOOK_META_BACKEND (scd->bbmapi));
		if (book_cache &&
		    !e_book_cache_get_contact (book_cache, uid, FALSE, &old_contact, cancellable, NULL)) {
			old_contact = NULL;
		}

		g_clear_object (&book_cache);
	}

	success = e_mapi_book_utils_contact_to_object (scd->contact, old_contact, pobject, mem_ctx, cancellable, error);

	g_clear_object (&old_contact);

	return success;
}

static gboolean
ebb_mapi_save_contact_sync (EBookMetaBackend *meta_backend,
			    gboolean overwrite_existing,
			    EConflictResolution conflict_resolution,
			    /* const */ EContact *contact,
			    const gchar *extra,
			    guint32 opflags,
			    gchar **out_new_uid,
			    gchar **out_new_extra,
			    GCancellable *cancellable,
			    GError **error)
{
	EBookBackendMAPI *bbmapi;
	mapi_object_t obj_folder;
	mapi_id_t mid = 0;
	gboolean success;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (E_IS_CONTACT (contact), FALSE);
	g_return_val_if_fail (out_new_uid != NULL, FALSE);

	*out_new_uid = NULL;

	bbmapi = E_BOOK_BACKEND_MAPI (meta_backend);

	if (e_book_backend_mapi_get_is_gal (bbmapi)) {
		g_propagate_error (error, e_client_error_create (E_CLIENT_ERROR_PERMISSION_DENIED, NULL));
		return FALSE;
	}

	ebb_mapi_lock_connection (bbmapi);

	success = ebb_mapi_contacts_open_folder (bbmapi, &obj_folder, cancellable, &mapi_error);
	if (success) {
		SaveContactData scd;

		scd.bbmapi = bbmapi;
		scd.contact = contact;

		if (overwrite_existing) {
			success = e_mapi_util_mapi_id_from_string (e_contact_get_const (contact, E_CONTACT_UID), &mid) &&
				e_mapi_connection_modify_object (bbmapi->priv->conn, &obj_folder, mid,
					ebb_mapi_create_object_cb, &scd, cancellable, &mapi_error);

		} else {
			success = e_mapi_connection_create_object (bbmapi->priv->conn, &obj_folder, E_MAPI_CREATE_FLAG_NONE,
				ebb_mapi_create_object_cb, &scd, &mid, cancellable, &mapi_error);
		}

		e_mapi_connection_close_folder (bbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error || !mid) {
		ebb_mapi_maybe_disconnect (bbmapi, mapi_error);
		ebb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR_OTHER_ERROR,
			overwrite_existing ? _("Failed to modify item on a server") : _("Failed to create item on a server"));
		g_clear_error (&mapi_error);

		success = FALSE;
	}

	ebb_mapi_unlock_connection (bbmapi);

	if (success)
		*out_new_uid = e_mapi_util_mapi_id_to_string (mid);

	return success;
}

static gboolean
ebb_mapi_remove_contact_sync (EBookMetaBackend *meta_backend,
			      EConflictResolution conflict_resolution,
			      const gchar *uid,
			      const gchar *extra,
			      const gchar *object,
			      guint32 opflags,
			      GCancellable *cancellable,
			      GError **error)
{
	EBookBackendMAPI *bbmapi;
	mapi_id_t mid = 0;
	gboolean success = TRUE;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (uid != NULL, FALSE);

	bbmapi = E_BOOK_BACKEND_MAPI (meta_backend);

	if (e_book_backend_mapi_get_is_gal (bbmapi)) {
		g_propagate_error (error, e_client_error_create (E_CLIENT_ERROR_PERMISSION_DENIED, NULL));
		return FALSE;
	}

	if (e_mapi_util_mapi_id_from_string (uid, &mid)) {
		mapi_object_t obj_folder;

		ebb_mapi_lock_connection (bbmapi);

		success = ebb_mapi_contacts_open_folder (bbmapi, &obj_folder, cancellable, &mapi_error);
		if (success) {
			GSList *mids;

			mids = g_slist_prepend (NULL, &mid);

			success = e_mapi_connection_remove_items (bbmapi->priv->conn, &obj_folder, mids, cancellable, &mapi_error);

			e_mapi_connection_close_folder (bbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);

			g_slist_free (mids);
		}

		ebb_mapi_unlock_connection (bbmapi);
	}

	if (mapi_error || !mid) {
		ebb_mapi_maybe_disconnect (bbmapi, mapi_error);
		ebb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR_OTHER_ERROR, _("Failed to remove item from a server"));
		g_clear_error (&mapi_error);

		success = FALSE;
	}

	return success;
}

static gboolean
ebb_mapi_update_cache_for_expression (EBookBackendMAPI *bbmapi,
				      const gchar *expr,
				      GCancellable *cancellable,
				      GError **error)
{
	EBookMetaBackend *meta_backend;
	GSList *found_infos = NULL;
	gboolean success = TRUE;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi), FALSE);

	meta_backend = E_BOOK_META_BACKEND (bbmapi);

	ebb_mapi_lock_connection (bbmapi);

	/* Search only if not searching for everything */
	if (expr && *expr && g_ascii_strcasecmp (expr, "(contains \"x-evolution-any-field\" \"\")") != 0) {
		success = e_book_meta_backend_ensure_connected_sync (meta_backend, cancellable, error) &&
			ebb_mapi_list_existing_with_restrictions_sync (meta_backend,
				e_mapi_book_utils_build_sexp_restriction, (gpointer) expr,
				NULL, &found_infos, cancellable, error);

		if (success) {
			GSList *created_objects = NULL, *modified_objects = NULL;

			success = e_book_meta_backend_split_changes_sync (meta_backend, found_infos, &created_objects,
				&modified_objects, NULL, cancellable, error);
			if (success)
				success = ebb_mapi_preload_infos_sync (bbmapi, created_objects, modified_objects, cancellable, error);
			if (success)
				success = e_book_meta_backend_process_changes_sync (meta_backend, created_objects,
					modified_objects, NULL, cancellable, error);

			g_slist_free_full (created_objects, e_book_meta_backend_info_free);
			g_slist_free_full (modified_objects, e_book_meta_backend_info_free);
		}

		g_slist_free_full (found_infos, e_book_meta_backend_info_free);
	}

	ebb_mapi_unlock_connection (bbmapi);

	return success;
}

static gboolean
ebb_mapi_search_sync (EBookMetaBackend *meta_backend,
		      const gchar *expr,
		      gboolean meta_contact,
		      GSList **out_contacts,
		      GCancellable *cancellable,
		      GError **error)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);

	/* Ignore errors, just try its best */
	ebb_mapi_update_cache_for_expression (E_BOOK_BACKEND_MAPI (meta_backend), expr, cancellable, NULL);

	/* Chain up to parent's method */
	return E_BOOK_META_BACKEND_CLASS (e_book_backend_mapi_parent_class)->search_sync (meta_backend, expr, meta_contact,
		out_contacts, cancellable, error);
}

static gboolean
ebb_mapi_search_uids_sync (EBookMetaBackend *meta_backend,
			   const gchar *expr,
			   GSList **out_uids,
			   GCancellable *cancellable,
			   GError **error)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (meta_backend), FALSE);

	/* Ignore errors, just try its best */
	ebb_mapi_update_cache_for_expression (E_BOOK_BACKEND_MAPI (meta_backend), expr, cancellable, NULL);

	/* Chain up to parent's method */
	return E_BOOK_META_BACKEND_CLASS (e_book_backend_mapi_parent_class)->search_uids_sync (meta_backend, expr,
		out_uids, cancellable, error);
}

static gchar *
ebb_mapi_get_backend_property (EBookBackend *backend,
			       const gchar *prop_name)
{
	EBookBackendMAPI *bbmapi;

	g_return_val_if_fail (prop_name != NULL, NULL);

	bbmapi = E_BOOK_BACKEND_MAPI (backend);

	if (g_str_equal (prop_name, CLIENT_BACKEND_PROPERTY_CAPABILITIES)) {
		return g_strjoin (",",
			"net",
			"contact-lists",
			e_book_meta_backend_get_capabilities (E_BOOK_META_BACKEND (backend)),
			ebb_mapi_is_marked_for_offline (bbmapi) ? "do-initial-query" : NULL,
			NULL);
	} else if (g_str_equal (prop_name, E_BOOK_BACKEND_PROPERTY_REQUIRED_FIELDS)) {
		return g_strdup (e_contact_field_name (E_CONTACT_FILE_AS));
	} else if (g_str_equal (prop_name, E_BOOK_BACKEND_PROPERTY_SUPPORTED_FIELDS)) {
		GSList *fields;
		gchar *prop_value;

		fields = e_mapi_book_utils_get_supported_contact_fields ();
		prop_value = e_data_book_string_slist_to_comma_string (fields);
		g_slist_free (fields);

		return prop_value;
	}

	/* Chain up to parent's method */
	return E_BOOK_BACKEND_CLASS (e_book_backend_mapi_parent_class)->impl_get_backend_property (backend, prop_name);
}

static gboolean
ebb_mapi_get_destination_address (EBackend *backend,
				  gchar **host,
				  guint16 *port)
{
	ESourceRegistry *registry;
	ESource *source;
	gboolean result = FALSE;

	g_return_val_if_fail (host != NULL, FALSE);
	g_return_val_if_fail (port != NULL, FALSE);

	registry = e_book_backend_get_registry (E_BOOK_BACKEND (backend));
	source = e_backend_get_source (backend);

	/* Sanity checking */
	if (!registry || !source || !e_source_get_parent (source))
		return FALSE;

	source = e_source_registry_ref_source (registry, e_source_get_parent (source));
	if (!source)
		return FALSE;

	if (e_source_has_extension (source, E_SOURCE_EXTENSION_AUTHENTICATION)) {
		ESourceAuthentication *auth = e_source_get_extension (source, E_SOURCE_EXTENSION_AUTHENTICATION);

		*host = g_strdup (e_source_authentication_get_host (auth));
		*port = e_source_authentication_get_port (auth);

		if (!*port)
			*port = 135;

		result = *host && **host;
		if (!result) {
			g_free (*host);
			*host = NULL;
		}
	}

	g_object_unref (source);

	return result;
}

static void
ebb_mapi_constructed (GObject *object)
{
	EBookBackendMAPI *bbmapi = E_BOOK_BACKEND_MAPI (object);

	/* Chaing up to parent's method */
	G_OBJECT_CLASS (e_book_backend_mapi_parent_class)->constructed (object);

	/* Reset the connectable, it steals data from Authentication extension,
	   where is written no address */
	e_backend_set_connectable (E_BACKEND (object), NULL);

	e_book_backend_set_writable (E_BOOK_BACKEND (bbmapi), !e_book_backend_mapi_get_is_gal (bbmapi));
}

static void
ebb_mapi_dispose (GObject *object)
{
	EBookBackendMAPI *bbmapi = E_BOOK_BACKEND_MAPI (object);

	g_clear_object (&bbmapi->priv->conn);

	/* Chain up to parent's method */
	G_OBJECT_CLASS (e_book_backend_mapi_parent_class)->dispose (object);
}

static void
ebb_mapi_finalize (GObject *object)
{
	EBookBackendMAPI *bbmapi = E_BOOK_BACKEND_MAPI (object);

	g_rec_mutex_clear (&bbmapi->priv->conn_lock);

	/* Chain up to parent's method */
	G_OBJECT_CLASS (e_book_backend_mapi_parent_class)->finalize (object);
}

static void
e_book_backend_mapi_class_init (EBookBackendMAPIClass *klass)
{
	GObjectClass *object_class;
	EBackendClass *backend_class;
	EBookBackendClass *book_backend_class;
	EBookMetaBackendClass *meta_backend_class;

	meta_backend_class = E_BOOK_META_BACKEND_CLASS (klass);
	meta_backend_class->backend_module_directory = BACKENDDIR;
	meta_backend_class->backend_module_filename = "libebookbackendmapi.so";
	meta_backend_class->connect_sync = ebb_mapi_connect_sync;
	meta_backend_class->disconnect_sync = ebb_mapi_disconnect_sync;
	meta_backend_class->get_changes_sync = ebb_mapi_get_changes_sync;
	meta_backend_class->list_existing_sync = ebb_mapi_list_existing_sync;
	meta_backend_class->load_contact_sync = ebb_mapi_load_contact_sync;
	meta_backend_class->save_contact_sync = ebb_mapi_save_contact_sync;
	meta_backend_class->remove_contact_sync = ebb_mapi_remove_contact_sync;
	meta_backend_class->search_sync = ebb_mapi_search_sync;
	meta_backend_class->search_uids_sync = ebb_mapi_search_uids_sync;

	book_backend_class = E_BOOK_BACKEND_CLASS (klass);
	book_backend_class->impl_get_backend_property = ebb_mapi_get_backend_property;

	backend_class = E_BACKEND_CLASS (klass);
	backend_class->get_destination_address = ebb_mapi_get_destination_address;

	object_class = G_OBJECT_CLASS (klass);
	object_class->constructed = ebb_mapi_constructed;
	object_class->dispose = ebb_mapi_dispose;
	object_class->finalize = ebb_mapi_finalize;
}

static void
e_book_backend_mapi_init (EBookBackendMAPI *bbmapi)
{
	bbmapi->priv = e_book_backend_mapi_get_instance_private (bbmapi);

	g_rec_mutex_init (&bbmapi->priv->conn_lock);
}

void
e_book_backend_mapi_set_is_gal (EBookBackendMAPI *bbmapi,
				gboolean is_gal)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi));

	bbmapi->priv->is_gal = is_gal;
}

gboolean
e_book_backend_mapi_get_is_gal (EBookBackendMAPI *bbmapi)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (bbmapi), FALSE);

	return bbmapi->priv->is_gal;
}
