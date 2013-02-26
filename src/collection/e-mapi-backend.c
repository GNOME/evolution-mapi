/*
 * e-mapi-backend.c
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>

#include <e-mapi-connection.h>
#include <e-mapi-folder.h>
#include <e-mapi-utils.h>
#include <e-source-mapi-folder.h>
#include <camel-mapi-settings.h>

#include "e-mapi-backend-authenticator.h"
#include "e-mapi-backend.h"

#define E_MAPI_BACKEND_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE \
	((obj), E_TYPE_MAPI_BACKEND, EMapiBackendPrivate))

struct _EMapiBackendPrivate {
	/* Folder ID -> ESource */
	GHashTable *folders;

	gboolean need_update_folders;
};

static void e_mapi_backend_authenticator_init (ESourceAuthenticatorInterface *interface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (
	EMapiBackend,
	e_mapi_backend,
	E_TYPE_COLLECTION_BACKEND,
	0,
	G_IMPLEMENT_INTERFACE_DYNAMIC (
		E_TYPE_SOURCE_AUTHENTICATOR,
		e_mapi_backend_authenticator_init))

static CamelMapiSettings *
mapi_backend_get_settings (EMapiBackend *backend)
{
	ESource *source;
	ESourceCamel *extension;
	CamelSettings *settings;
	const gchar *extension_name;

	source = e_backend_get_source (E_BACKEND (backend));
	extension_name = e_source_camel_get_extension_name ("mapi");
	extension = e_source_get_extension (source, extension_name);
	settings = e_source_camel_get_settings (extension);

	return CAMEL_MAPI_SETTINGS (settings);
}

static ESourceAuthenticationResult
mapi_backend_try_password_sync (ESourceAuthenticator *authenticator,
				const GString *password,
				GCancellable *cancellable,
				GError **error);

static gpointer
mapi_backend_authenticate_kerberos_thread (gpointer user_data)
{
	EMapiBackend *mapi_backend = user_data;
	CamelMapiSettings *mapi_settings;
	GError *error = NULL;

	g_return_val_if_fail (E_IS_MAPI_BACKEND (mapi_backend), NULL);

	mapi_settings = mapi_backend_get_settings (mapi_backend);
	e_mapi_util_trigger_krb_auth_from_settings (mapi_settings, &error);

	if (error) {
		g_warning ("[evolution-mapi] Failed to trigger KrbAuthDialog: %s", error->message);
		g_clear_error (&error);
	}

	mapi_backend_try_password_sync (E_SOURCE_AUTHENTICATOR (mapi_backend), NULL, NULL, NULL);

	g_object_unref (mapi_backend);

	return NULL;
}

static void
mapi_backend_queue_auth_session (EMapiBackend *backend)
{
	CamelMapiSettings *mapi_settings;

	mapi_settings = mapi_backend_get_settings (backend);

	backend->priv->need_update_folders = FALSE;

	/* kerberos doesn't use passwords, do it directly */
	if (camel_mapi_settings_get_kerberos (mapi_settings)) {
		GThread *thread;

		thread = g_thread_new (NULL, mapi_backend_authenticate_kerberos_thread, g_object_ref (backend));
		g_thread_unref (thread);

		return;
	}

	/* For now at least, we don't need to know the
	 * results, so no callback function is needed. */
	e_backend_authenticate (
		E_BACKEND (backend),
		E_SOURCE_AUTHENTICATOR (backend),
		NULL, NULL, NULL);
}

struct SyndFoldersData
{
	EMapiBackend *backend;
	GSList *folders;
	gchar *profile;
};

static void
sync_folders_data_free (gpointer data)
{
	struct SyndFoldersData *sfd = data;

	if (!sfd)
		return;

	e_mapi_folder_free_list (sfd->folders);
	g_object_unref (sfd->backend);
	g_free (sfd->profile);
	g_free (sfd);
}

static gboolean
mapi_backend_sync_folders_idle_cb (gpointer user_data)
{
	struct SyndFoldersData *sfd = user_data;
	GSList *iter;
	GList *configured, *all_sources, *citer;
	ESourceRegistryServer *server;
	EMapiBackend *backend;
	GSList *mapi_folders;
	gboolean has_gal = FALSE;
	gint color_seed;

	g_return_val_if_fail (sfd != NULL, FALSE);
	g_return_val_if_fail (sfd->backend != NULL, FALSE);
	g_return_val_if_fail (sfd->profile != NULL, FALSE);

	backend = sfd->backend;
	mapi_folders = sfd->folders;

	server = e_collection_backend_ref_server (E_COLLECTION_BACKEND (backend));
	all_sources = e_source_registry_server_list_sources (server, NULL);
	configured = e_mapi_utils_filter_sources_for_profile (all_sources, sfd->profile);
	g_list_free_full (all_sources, g_object_unref);

	color_seed = g_list_length (configured);

	for (iter = mapi_folders; iter; iter = iter->next) {
		EMapiFolder *folder = iter->data;
		ESource *source;

		if (e_mapi_folder_get_category (folder) != E_MAPI_FOLDER_CATEGORY_PERSONAL)
			continue;

		switch (e_mapi_folder_get_type (folder)) {
		case E_MAPI_FOLDER_TYPE_APPOINTMENT:
		case E_MAPI_FOLDER_TYPE_CONTACT:
		case E_MAPI_FOLDER_TYPE_MEMO:
		case E_MAPI_FOLDER_TYPE_JOURNAL:
		case E_MAPI_FOLDER_TYPE_TASK:
			break;
		default:
			continue;
		}

		source = e_mapi_utils_get_source_for_folder (configured, sfd->profile, e_mapi_folder_get_id (folder));
		if (source) {
			if (g_strcmp0 (e_source_get_display_name (source), e_mapi_folder_get_name (folder)) != 0)
				e_source_set_display_name (source, e_mapi_folder_get_name (folder));

			configured = g_list_remove (configured, source);
			g_object_unref (source);
		} else {
			gchar *fid_str, *res_id;
			const gchar *parent_id;

			source = e_backend_get_source (E_BACKEND (backend));

			parent_id = e_source_get_uid (source);
			fid_str = e_mapi_util_mapi_id_to_string (e_mapi_folder_get_id (folder));
			res_id = g_strconcat (parent_id ? parent_id : "mapi", ".", fid_str, NULL);
			g_free (fid_str);

			source = e_collection_backend_new_child (E_COLLECTION_BACKEND (backend), res_id);

			if (e_mapi_folder_populate_esource (
				source,
				configured,
				e_mapi_folder_get_type (folder),
				sfd->profile,
				TRUE,
				E_MAPI_FOLDER_CATEGORY_PERSONAL,
				NULL,
				e_mapi_folder_get_name (folder),
				e_mapi_folder_get_id (folder),
				color_seed,
				NULL,
				NULL)) {
				color_seed++;
				e_server_side_source_set_writable (E_SERVER_SIDE_SOURCE (source), TRUE);
				e_server_side_source_set_remote_deletable (E_SERVER_SIDE_SOURCE (source), TRUE);
				e_source_registry_server_add_source (server, source);
			}

			g_free (res_id);
			g_object_unref (source);
		}
	}

	/* those which left are either mail sources, GAL or removed from the server */
	for (citer = configured; citer; citer = citer->next) {
		ESource *source = citer->data;
		ESourceMapiFolder *folder_ext;
		const gchar *foreign_user_name;

		if (!e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER))
			continue;

		if (!e_source_has_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK) &&
		    !e_source_has_extension (source, E_SOURCE_EXTENSION_CALENDAR) &&
		    !e_source_has_extension (source, E_SOURCE_EXTENSION_MEMO_LIST) &&
		    !e_source_has_extension (source, E_SOURCE_EXTENSION_TASK_LIST))
			continue;

		folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
		if (e_source_mapi_folder_is_public (folder_ext))
			continue;

		foreign_user_name = e_source_mapi_folder_get_foreign_username (folder_ext);
		if (foreign_user_name && *foreign_user_name)
			continue;

		/* test GAL */
		if (!has_gal && e_source_has_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK)) {
			ESourceAddressBook *book_ext;

			book_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
			has_gal = g_strcmp0 ("mapigal", e_source_backend_get_backend_name (E_SOURCE_BACKEND (book_ext))) == 0;
			if (has_gal)
				continue;
		}

		e_source_registry_server_remove_source (server, source);
	}

	all_sources = e_collection_backend_claim_all_resources (E_COLLECTION_BACKEND (backend));
	for (citer = all_sources; citer; citer = citer->next) {
		ESource *source = citer->data;
		ESourceMapiFolder *extension;
		const gchar *foreign_username;

		if (!e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER))
			continue;

		/* foreign folders are just added */
		extension = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
		foreign_username = e_source_mapi_folder_get_foreign_username (extension);
		if (e_source_mapi_folder_is_public (extension) || (foreign_username && *foreign_username)) {
			e_server_side_source_set_writable (E_SERVER_SIDE_SOURCE (source), TRUE);
			e_server_side_source_set_remote_deletable (E_SERVER_SIDE_SOURCE (source), TRUE);
			e_source_registry_server_add_source (server, source);
		} else if (!has_gal && e_source_has_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK)) {
			ESourceAddressBook *book_ext;

			book_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
			has_gal = g_strcmp0 ("mapigal", e_source_backend_get_backend_name (E_SOURCE_BACKEND (book_ext))) == 0;
			if (has_gal)
				e_source_registry_server_add_source (server, source);
			else
				e_source_remove_sync (source, NULL, NULL);
		} else {
			e_source_remove_sync (source, NULL, NULL);
		}
	}
	g_list_free_full (all_sources, g_object_unref);

	/* add GAL, if not there already */
	if (!has_gal) {
		ESource *source;

		source = e_collection_backend_new_child (E_COLLECTION_BACKEND (backend), "mapigal");

		if (e_mapi_folder_populate_esource (
			source,
			configured,
			E_MAPI_FOLDER_TYPE_CONTACT,
			sfd->profile,
			FALSE,
			E_MAPI_FOLDER_CATEGORY_PERSONAL,
			NULL,
			_("Global Address List"),
			-1,
			0,
			NULL,
			NULL)) {
			ESourceAddressBook *book_ext;
			/* ESourceContancts *contacts_ext; */

			book_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
			e_source_backend_set_backend_name (E_SOURCE_BACKEND (book_ext), "mapigal");

			/* exclude GAL from Birthday & Anniversaries calendar by default */
			/* but it is not accessible from outside (yet)
			contacts_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_CONTACTS_BACKEND);
			e_source_contacts_set_include_me (contacts_ext, FALSE); */

			e_source_registry_server_add_source (server, source);
		}

		g_object_unref (source);
	}

	g_list_free_full (configured, g_object_unref);
	g_object_unref (server);

	return FALSE;
}

static void
mapi_backend_source_changed_cb (ESource *source,
				EMapiBackend *backend)
{
	/* does nothing currently */
	if (!e_source_get_enabled (source)) {
		backend->priv->need_update_folders = TRUE;
		return;
	}

	if (e_source_get_enabled (source) &&
	    e_backend_get_online (E_BACKEND (backend)) &&
	    backend->priv->need_update_folders)
		mapi_backend_queue_auth_session (backend);
}

static void
mapi_backend_constructed (GObject *object)
{
	EBackend *backend = E_BACKEND (object);
	ESource *source;

	/* Chain up to parent's constructed() method. */
	G_OBJECT_CLASS (e_mapi_backend_parent_class)->constructed (object);

	source = e_backend_get_source (backend);

	/* XXX Wondering if we ought to delay this until after folders
	 *     are initially populated, just to remove the possibility
	 *     of weird races with clients trying to create folders. */
	e_server_side_source_set_remote_creatable (
		E_SERVER_SIDE_SOURCE (source), TRUE);

	g_signal_connect (
		source, "changed",
		G_CALLBACK (mapi_backend_source_changed_cb), backend);
}

static void
mapi_backend_dispose (GObject *object)
{
	EMapiBackendPrivate *priv;

	priv = E_MAPI_BACKEND_GET_PRIVATE (object);

	g_hash_table_remove_all (priv->folders);

	/* Chain up to parent's dispose() method. */
	G_OBJECT_CLASS (e_mapi_backend_parent_class)->dispose (object);
}

static void
mapi_backend_finalize (GObject *object)
{
	EMapiBackendPrivate *priv;

	priv = E_MAPI_BACKEND_GET_PRIVATE (object);

	g_hash_table_destroy (priv->folders);

	/* Chain up to parent's finalize() method. */
	G_OBJECT_CLASS (e_mapi_backend_parent_class)->finalize (object);
}

static void
mapi_backend_populate (ECollectionBackend *backend)
{
	ESource *source;
	EMapiBackend *mapi_backend = E_MAPI_BACKEND (backend);

	source = e_backend_get_source (E_BACKEND (backend));

	mapi_backend->priv->need_update_folders = TRUE;

	/* do not do anything, if account is disabled */
	if (!e_source_get_enabled (source) ||
	    !e_backend_get_online (E_BACKEND (backend)))
		return;

	/* We test authentication passwords by attempting to synchronize
	 * the folder hierarchy.  Since we want to synchronize the folder
	 * hierarchy immediately on startup, schedule an authentication
	 * session first thing. */
	mapi_backend_queue_auth_session (mapi_backend);
}

static gchar *
mapi_backend_dup_resource_id (ECollectionBackend *backend,
			      ESource *child_source)
{
	ESourceMapiFolder *extension;
	const gchar *extension_name;
	gchar *fid_str, *res_id;
	const gchar *parent_id;
	ESource *source;

	extension_name = E_SOURCE_EXTENSION_MAPI_FOLDER;
	extension = e_source_get_extension (child_source, extension_name);
	source = e_backend_get_source (E_BACKEND (backend));

	parent_id = e_source_get_uid (source);
	fid_str = e_mapi_util_mapi_id_to_string (e_source_mapi_folder_get_id (extension));
	res_id = g_strconcat (parent_id ? parent_id : "mapi", ".", fid_str, NULL);
	g_free (fid_str);

	return res_id;
}

static void
mapi_backend_child_added (ECollectionBackend *backend,
                          ESource *child_source)
{
	EMapiBackendPrivate *priv;
	ESource *collection_source;
	const gchar *extension_name;
	gboolean is_mail = FALSE;

	priv = E_MAPI_BACKEND_GET_PRIVATE (backend);

	collection_source = e_backend_get_source (E_BACKEND (backend));

	extension_name = E_SOURCE_EXTENSION_MAIL_ACCOUNT;
	is_mail |= e_source_has_extension (child_source, extension_name);

	extension_name = E_SOURCE_EXTENSION_MAIL_IDENTITY;
	is_mail |= e_source_has_extension (child_source, extension_name);

	extension_name = E_SOURCE_EXTENSION_MAIL_TRANSPORT;
	is_mail |= e_source_has_extension (child_source, extension_name);

	/* Synchronize mail-related display names with the collection. */
	if (is_mail)
		g_object_bind_property (
			collection_source, "display-name",
			child_source, "display-name",
			G_BINDING_SYNC_CREATE);

	/* Synchronize mail-related user with the collection identity. */
	extension_name = E_SOURCE_EXTENSION_AUTHENTICATION;
	if (is_mail && e_source_has_extension (child_source, extension_name)) {
		ESourceAuthentication *auth_child_extension;
		ESourceCollection *collection_extension;

		extension_name = E_SOURCE_EXTENSION_COLLECTION;
		collection_extension = e_source_get_extension (
			collection_source, extension_name);

		extension_name = E_SOURCE_EXTENSION_AUTHENTICATION;
		auth_child_extension = e_source_get_extension (
			child_source, extension_name);

		g_object_bind_property (
			collection_extension, "identity",
			auth_child_extension, "user",
			G_BINDING_SYNC_CREATE);
	}

	/* We track MAPI folders in a hash table by folder ID. */
	extension_name = E_SOURCE_EXTENSION_MAPI_FOLDER;
	if (e_source_has_extension (child_source, extension_name)) {
		ESourceMapiFolder *extension;
		gchar *folder_id;

		extension = e_source_get_extension (
			child_source, extension_name);
		folder_id = e_mapi_util_mapi_id_to_string (e_source_mapi_folder_get_id (extension));
		if (folder_id != NULL)
			g_hash_table_insert (
				priv->folders, folder_id,
				g_object_ref (child_source));
	}

	/* Chain up to parent's child_added() method. */
	E_COLLECTION_BACKEND_CLASS (e_mapi_backend_parent_class)->
		child_added (backend, child_source);
}

static void
mapi_backend_child_removed (ECollectionBackend *backend,
                            ESource *child_source)
{
	EMapiBackendPrivate *priv;
	const gchar *extension_name;

	priv = E_MAPI_BACKEND_GET_PRIVATE (backend);

	/* We track MAPI folders in a hash table by folder ID. */
	extension_name = E_SOURCE_EXTENSION_MAPI_FOLDER;
	if (e_source_has_extension (child_source, extension_name)) {
		ESourceMapiFolder *extension;
		gchar *folder_id;

		extension = e_source_get_extension (child_source, extension_name);
		folder_id = e_mapi_util_mapi_id_to_string (e_source_mapi_folder_get_id (extension));
		if (folder_id != NULL)
			g_hash_table_remove (priv->folders, folder_id);
		g_free (folder_id);
	}

	/* Chain up to parent's child_removed() method. */
	E_COLLECTION_BACKEND_CLASS (e_mapi_backend_parent_class)->
		child_removed (backend, child_source);
}

static gboolean
mapi_backend_create_resource_cb (EBackend *backend,
				 CamelMapiSettings *settings,
				 EMapiConnection *conn,
				 gpointer user_data,
				 GCancellable *cancellable,
				 GError **error)
{
	ESourceBackend *backend_ext = NULL;
	const gchar *folder_type_str = NULL;
	ESource *source = user_data;
	ESourceMapiFolder *folder_ext;
	mapi_object_t obj_folder;
	const gchar *foreign_username;
	gboolean res = FALSE;
	guint64 fid;

	g_return_val_if_fail (e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER), FALSE);

	folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	foreign_username = e_source_mapi_folder_get_foreign_username (folder_ext);

	fid = e_source_mapi_folder_get_id (folder_ext);
	g_return_val_if_fail (fid == 0, FALSE);

	if (e_source_has_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK)) {
		backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
		folder_type_str = IPF_CONTACT;
	} else if (e_source_has_extension (source, E_SOURCE_EXTENSION_CALENDAR)) {
		backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_CALENDAR);
		folder_type_str = IPF_APPOINTMENT;
	} else if (e_source_has_extension (source, E_SOURCE_EXTENSION_TASK_LIST)) {
		backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_TASK_LIST);
		folder_type_str = IPF_TASK;
	} else if (e_source_has_extension (source, E_SOURCE_EXTENSION_MEMO_LIST)) {
		backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MEMO_LIST);
		folder_type_str = IPF_STICKYNOTE;
	}

	if (!backend_ext || g_strcmp0 (e_source_backend_get_backend_name (backend_ext), "mapi") != 0)
		return FALSE;

	fid = e_source_mapi_folder_get_parent_id (folder_ext);

	if (foreign_username && *foreign_username)
		res = e_mapi_connection_open_foreign_folder (conn, foreign_username, fid, &obj_folder, cancellable, error);
	else if (e_source_mapi_folder_is_public (folder_ext))
		res = e_mapi_connection_open_public_folder (conn, fid, &obj_folder, cancellable, error);
	else
		res = e_mapi_connection_open_personal_folder (conn, fid, &obj_folder, cancellable, error);

	if (res) {
		fid = 0;
		if (!e_mapi_connection_create_folder (conn, &obj_folder, e_source_get_display_name (source), folder_type_str, &fid, cancellable, error))
			fid = 0;
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, error);

		if (fid)
			e_source_mapi_folder_set_id (folder_ext, fid);
		else
			res = FALSE;
	}

	return res;
}

static gboolean
mapi_backend_create_resource_sync (ECollectionBackend *backend,
                                   ESource *source,
                                   GCancellable *cancellable,
                                   GError **error)
{
	ESourceRegistryServer *server;
	ESource *parent_source;
	CamelMapiSettings *settings;
	ESourceMapiFolder *folder_ext;
	const gchar *foreign_username;
	const gchar *cache_dir;
	const gchar *parent_uid;

	if (!e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER)) {
		g_set_error (
			error, G_IO_ERROR,
			G_IO_ERROR_INVALID_ARGUMENT,
			_("Data source '%s' does not represent a MAPI folder"),
			e_source_get_display_name (source));
		return FALSE;
	}

	settings = mapi_backend_get_settings (E_MAPI_BACKEND (backend));
	g_return_val_if_fail (settings != NULL, FALSE);

	folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	foreign_username = e_source_mapi_folder_get_foreign_username (folder_ext);

	if (!e_source_mapi_folder_is_public (folder_ext) &&
	    !(foreign_username && *foreign_username) &&
	    !e_mapi_backend_authenticator_run (
		E_BACKEND (backend), settings, mapi_backend_create_resource_cb, source, cancellable, error))
		return FALSE;

	/* Configure the source as a collection member. */
	parent_source = e_backend_get_source (E_BACKEND (backend));
	parent_uid = e_source_get_uid (parent_source);
	e_source_set_parent (source, parent_uid);

	/* Changes should be written back to the cache directory. */
	cache_dir = e_collection_backend_get_cache_dir (backend);
	e_server_side_source_set_write_directory (
		E_SERVER_SIDE_SOURCE (source), cache_dir);

	/* Set permissions for clients. */
	e_server_side_source_set_writable (
		E_SERVER_SIDE_SOURCE (source), TRUE);
	e_server_side_source_set_remote_deletable (
		E_SERVER_SIDE_SOURCE (source), TRUE);

	server = e_collection_backend_ref_server (backend);
	e_source_registry_server_add_source (server, source);
	g_object_unref (server);

	return TRUE;
}

static gboolean
mapi_backend_delete_resource_cb (EBackend *backend,
				 CamelMapiSettings *settings,
				 EMapiConnection *conn,
				 gpointer user_data,
				 GCancellable *cancellable,
				 GError **error)
{
	ESource *source = user_data;
	ESourceMapiFolder *folder_ext;
	mapi_object_t *obj_store = NULL;
	const gchar *foreign_username;
	gboolean res = FALSE;
	guint64 fid;

	g_return_val_if_fail (e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER), FALSE);

	folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	g_return_val_if_fail (!e_source_mapi_folder_is_public (folder_ext), FALSE);

	foreign_username = e_source_mapi_folder_get_foreign_username (folder_ext);
	g_return_val_if_fail (!foreign_username || !*foreign_username, FALSE);

	fid = e_source_mapi_folder_get_id (folder_ext);
	g_return_val_if_fail (fid != 0, FALSE);

	if (e_mapi_connection_peek_store (conn, FALSE, NULL, &obj_store, cancellable, error))
		res = e_mapi_connection_remove_folder (conn, obj_store, fid, cancellable, error);

	return res;
}

static gboolean
mapi_backend_delete_resource_sync (ECollectionBackend *backend,
                                   ESource *source,
                                   GCancellable *cancellable,
                                   GError **error)
{
	ESourceRegistryServer *server;
	CamelMapiSettings *settings;
	ESourceMapiFolder *folder_ext;
	const gchar *foreign_username;

	if (!e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER)) {
		g_set_error (
			error, G_IO_ERROR,
			G_IO_ERROR_INVALID_ARGUMENT,
			_("Data source '%s' does not represent a MAPI folder"),
			e_source_get_display_name (source));
		return FALSE;
	}

	settings = mapi_backend_get_settings (E_MAPI_BACKEND (backend));
	g_return_val_if_fail (settings != NULL, FALSE);

	folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	foreign_username = e_source_mapi_folder_get_foreign_username (folder_ext);

	if (!e_source_mapi_folder_is_public (folder_ext) &&
	    !(foreign_username && *foreign_username) &&
	    !e_mapi_backend_authenticator_run (
		E_BACKEND (backend), settings, mapi_backend_delete_resource_cb, source, cancellable, error))
		return FALSE;

	server = e_collection_backend_ref_server (backend);
	e_source_registry_server_remove_source (server, source);
	g_object_unref (server);

	return TRUE;
}

static ESourceAuthenticationResult
mapi_backend_try_password_sync (ESourceAuthenticator *authenticator,
				const GString *password,
				GCancellable *cancellable,
				GError **error)
{
	EMapiBackend *backend;
	EMapiConnection *conn;
	CamelMapiSettings *settings;
	GSList *mapi_folders = NULL;
	GError *mapi_error = NULL;

	backend = E_MAPI_BACKEND (authenticator);
	settings = mapi_backend_get_settings (backend);

	conn = e_mapi_connection_new (NULL,
		camel_mapi_settings_get_profile (settings),
		password, cancellable, &mapi_error);

	if (!conn) {
		ESourceAuthenticationResult res = E_SOURCE_AUTHENTICATION_ERROR;

		backend->priv->need_update_folders = TRUE;

		if (g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_PASSWORD_CHANGE_REQUIRED) ||
		    g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_PASSWORD_EXPIRED))
			res = E_SOURCE_AUTHENTICATION_REJECTED;

		if (res != E_SOURCE_AUTHENTICATION_REJECTED)
			g_propagate_error (error, mapi_error);
		else
			g_clear_error (&mapi_error);

		return res;
	}

	if (e_mapi_connection_get_folders_list (conn, &mapi_folders, NULL, NULL, cancellable, &mapi_error)) {
		struct SyndFoldersData *sfd;

		sfd = g_new0 (struct SyndFoldersData, 1);
		sfd->folders = mapi_folders;
		sfd->backend = g_object_ref (backend);
		sfd->profile = camel_mapi_settings_dup_profile (settings);

		g_idle_add_full (
			G_PRIORITY_DEFAULT_IDLE,
			mapi_backend_sync_folders_idle_cb, sfd,
			sync_folders_data_free);
	} else {
		ESource *source = e_backend_get_source (E_BACKEND (backend));

		backend->priv->need_update_folders = TRUE;

		g_message ("%s: Failed to get list of user's folders for '%s': %s",
			G_STRFUNC, e_source_get_display_name (source), mapi_error ? mapi_error->message : "Unknown error");
	}

	g_object_unref (conn);
	g_clear_error (&mapi_error);

	return E_SOURCE_AUTHENTICATION_ACCEPTED;
}

static void
e_mapi_backend_class_init (EMapiBackendClass *class)
{
	GObjectClass *object_class;
	ECollectionBackendClass *backend_class;

	g_type_class_add_private (class, sizeof (EMapiBackendPrivate));

	object_class = G_OBJECT_CLASS (class);
	object_class->constructed = mapi_backend_constructed;
	object_class->dispose = mapi_backend_dispose;
	object_class->finalize = mapi_backend_finalize;

	backend_class = E_COLLECTION_BACKEND_CLASS (class);
	backend_class->populate = mapi_backend_populate;
	backend_class->dup_resource_id = mapi_backend_dup_resource_id;
	backend_class->child_added = mapi_backend_child_added;
	backend_class->child_removed = mapi_backend_child_removed;
	backend_class->create_resource_sync = mapi_backend_create_resource_sync;
	backend_class->delete_resource_sync = mapi_backend_delete_resource_sync;

	/* This generates an ESourceCamel subtype for CamelMapiSettings. */
	e_source_camel_generate_subtype ("mapi", CAMEL_TYPE_MAPI_SETTINGS);
}

static void
e_mapi_backend_class_finalize (EMapiBackendClass *class)
{
}

static void
e_mapi_backend_authenticator_init (ESourceAuthenticatorInterface *interface)
{
	interface->try_password_sync = mapi_backend_try_password_sync;
}

static void
e_mapi_backend_init (EMapiBackend *backend)
{
	backend->priv = E_MAPI_BACKEND_GET_PRIVATE (backend);

	backend->priv->folders = g_hash_table_new_full (
		(GHashFunc) g_str_hash,
		(GEqualFunc) g_str_equal,
		(GDestroyNotify) g_free,
		(GDestroyNotify) g_object_unref);
}

void
e_mapi_backend_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_mapi_backend_register_type (type_module);
}
