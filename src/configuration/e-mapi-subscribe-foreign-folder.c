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
 *    Milan Crha <mcrha@redhat.com>
 *
 * Copyright (C) 2012 Red Hat, Inc. (www.redhat.com)
 *
 */

#include "evolution-mapi-config.h"

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#include <libemail-engine/libemail-engine.h>

#include "camel/camel-mapi-store.h"
#include "camel/camel-mapi-store-summary.h"

#include "e-mapi-config-utils.h"
#include "e-mapi-search-gal-user.h"
#include "e-mapi-subscribe-foreign-folder.h"
#include "e-mapi-utils.h"

#ifndef PidTagMailboxOwnerName
#define PidTagMailboxOwnerName PR_USER_NAME_UNICODE
#endif

#define STR_ACCOUNTS_COMBO		"e-mapi-accounts-combo"
#define STR_USER_NAME_SELECTOR_ENTRY	"e-mapi-name-selector-entry"
#define STR_FOLDER_NAME_COMBO		"e-mapi-folder-name-combo"
#define STR_SUBFOLDERS_CHECK		"e-mapi-subfolders-check"
#define STR_MAPI_CAMEL_SESSION		"e-mapi-camel-session"
#define STR_MAPI_DIRECT_USER_NAME	"e-mapi-direct-user-name"

enum {
	COLUMN_UID = 0,
	COLUMN_DISPLAY_NAME,
	COLUMN_STORE
};

static gboolean
add_foreign_folder_to_camel (CamelMapiStore *mapi_store,
			     const gchar *foreign_username,
			     mapi_id_t folder_id,
			     mapi_id_t parent_fid,
			     gboolean include_subfolders,
			     const gchar *display_username,
			     const gchar *display_foldername,
			     GError **perror)
{
	gboolean res = TRUE;
	gchar *parent_path = NULL;
	CamelStoreInfo *parent_si = NULL;
	GPtrArray *array;
	guint ii;

	g_return_val_if_fail (mapi_store != NULL, FALSE);
	g_return_val_if_fail (mapi_store->summary != NULL, FALSE);
	g_return_val_if_fail (foreign_username != NULL, FALSE);
	g_return_val_if_fail (folder_id != 0, FALSE);
	g_return_val_if_fail (folder_id != parent_fid, FALSE);
	g_return_val_if_fail (display_username != NULL, FALSE);
	g_return_val_if_fail (display_foldername != NULL, FALSE);

	array = camel_store_summary_array (mapi_store->summary);

	for (ii = 0; res && ii < array->len; ii++) {
		CamelStoreInfo *si;
		CamelMapiStoreInfo *msi;

		si = g_ptr_array_index (array, ii);

		msi = (CamelMapiStoreInfo *) si;

		/* folder_id is unique even between users, thus can just check for it */
		if (msi->folder_id == folder_id) {
			res = FALSE;
			g_propagate_error (perror,
				g_error_new (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER,
				_("Cannot add folder, folder already exists as “%s”"), camel_store_info_path (mapi_store->summary, si)));
		} else if (parent_fid != 0 && msi->folder_id == parent_fid) {
			if (g_strcmp0 (foreign_username, msi->foreign_username) == 0) {
				g_free (parent_path);
				parent_path = g_strdup (camel_store_info_path (mapi_store->summary, si));
				parent_si = si;
				camel_store_summary_info_ref (mapi_store->summary, parent_si);
			} else {
				g_debug ("%s: parent folder '%s' with other user '%s' than expected '%s', skipping chain",
					G_STRFUNC, camel_store_info_path (mapi_store->summary, si), msi->foreign_username, foreign_username);
			}
		}
	}

	camel_store_summary_array_free (mapi_store->summary, array);

	if (res) {
		gchar *path;

		if (!parent_path) {
			gchar *mailbox;

			/* Translators: The '%s' is replaced with user name, to whom the foreign mailbox belongs.
			   Example result: "Mailbox — John Smith"
			*/
			mailbox = g_strdup_printf (C_("ForeignFolder", "Mailbox — %s"), display_username);
			parent_path = g_strdup_printf ("%s/%s", DISPLAY_NAME_FOREIGN_FOLDERS, mailbox);

			g_free (mailbox);
		}

		path = g_strconcat (parent_path, "/", display_foldername, NULL);

		/* make sure the path is unique */
		camel_mapi_store_ensure_unique_path (mapi_store, &path);

		if (camel_mapi_store_summary_add_from_full (mapi_store->summary, path, folder_id, parent_fid,
			CAMEL_STORE_INFO_FOLDER_SUBSCRIBED | CAMEL_FOLDER_NOCHILDREN | CAMEL_FOLDER_SUBSCRIBED,
			CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN | CAMEL_MAPI_STORE_FOLDER_FLAG_MAIL |
			(include_subfolders ? CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN_WITH_SUBFOLDERS : 0),
			foreign_username)) {
			if (parent_si) {
				CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) parent_si;

				msi->camel_folder_flags = msi->camel_folder_flags & (~CAMEL_FOLDER_NOCHILDREN);
			}

			camel_store_summary_touch (mapi_store->summary);
			camel_store_summary_save (mapi_store->summary);

			camel_mapi_store_announce_subscribed_folder (mapi_store, path);
		} else {
			res = FALSE;
			g_propagate_error (perror,
				g_error_new (E_MAPI_ERROR, MAPI_E_INVALID_PARAMETER,
				_("Cannot add folder, failed to add to store’s summary")));
		}

		g_free (path);
	}

	if (parent_si)
		camel_store_summary_info_unref (mapi_store->summary, parent_si);
	g_free (parent_path);

	return res;
}

static void
enable_ok_button_by_data (GObject *dialog)
{
	GtkEntry *entry;
	GtkComboBoxText *combo;
	const gchar *entry_text;
	gchar *combo_text;

	g_return_if_fail (dialog != NULL);

	entry = g_object_get_data (dialog, STR_USER_NAME_SELECTOR_ENTRY);
	g_return_if_fail (entry != NULL);

	combo = g_object_get_data (dialog, STR_FOLDER_NAME_COMBO);
	g_return_if_fail (combo != NULL);

	entry_text = gtk_entry_get_text (entry);
	combo_text = gtk_combo_box_text_get_active_text (combo);

	gtk_dialog_set_response_sensitive (
		GTK_DIALOG (dialog), GTK_RESPONSE_OK,
		entry_text && *entry_text && *entry_text != ' ' && *entry_text != ',' &&
		combo_text && *combo_text);

	g_free (combo_text);
}

static void
name_entry_changed_cb (GObject *dialog)
{
	GtkEntry *entry;

	g_return_if_fail (dialog != NULL);

	entry = g_object_get_data (dialog, STR_USER_NAME_SELECTOR_ENTRY);
	g_return_if_fail (entry != NULL);

	g_object_set_data (G_OBJECT (entry), STR_MAPI_DIRECT_USER_NAME, NULL);

	enable_ok_button_by_data (dialog);
}

static void
folder_name_combo_changed_cb (GObject *dialog,
			      GtkComboBox *combo)
{
	enable_ok_button_by_data (dialog);
}

struct EMapiCheckForeignFolderData
{
	GtkWidget *dialog;
	gboolean include_subfolders;
	gchar *username;
	gchar *direct_username;
	gchar *user_displayname;
	gchar *orig_foldername;
	gchar *use_foldername;
	gchar *folder_displayname;
	gchar *folder_container_class;
	mapi_id_t folder_id;
	mapi_id_t parent_folder_id;
};

static void
e_mapi_check_foreign_folder_data_free (gpointer ptr)
{
	struct EMapiCheckForeignFolderData *cffd = ptr;

	if (!cffd)
		return;

	g_free (cffd->username);
	g_free (cffd->direct_username);
	g_free (cffd->user_displayname);
	g_free (cffd->orig_foldername);
	g_free (cffd->use_foldername);
	g_free (cffd->folder_displayname);
	g_free (cffd->folder_container_class);

	/* folder_id tells whether successfully finished,
	   then the dialog can be destroyed */
	if (cffd->folder_id && cffd->dialog)
		gtk_widget_destroy (cffd->dialog);

	g_free (cffd);
}

static gboolean
check_foreign_username_resolved_cb (EMapiConnection *conn,
				    TALLOC_CTX *mem_ctx,
				    /* const */ struct mapi_SPropValue_array *properties,
				    gpointer user_data,
				    GCancellable *cancellable,
				    GError **perror)
{
	struct EMapiCheckForeignFolderData *cffd = user_data;

	g_return_val_if_fail (properties != NULL, FALSE);
	g_return_val_if_fail (cffd != NULL, FALSE);
	g_return_val_if_fail (cffd->user_displayname == NULL, FALSE);

	cffd->user_displayname = g_strdup (e_mapi_util_find_array_propval (properties, PidTagDisplayName));

	return TRUE;
}

static gboolean
foreign_folder_add_props_cb (EMapiConnection *conn,
			     TALLOC_CTX *mem_ctx,
			     struct SPropTagArray *props,
			     gpointer data,
			     GCancellable *cancellable,
			     GError **perror)
{
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	SPropTagArray_add (mem_ctx, props, PidTagDisplayName);
	SPropTagArray_add (mem_ctx, props, PidTagContainerClass);
	SPropTagArray_add (mem_ctx, props, PidTagParentFolderId);

	return TRUE;
}

static gboolean
foreign_folder_get_props_cb (EMapiConnection *conn,
			     TALLOC_CTX *mem_ctx,
			     /* const */ struct mapi_SPropValue_array *properties,
			     gpointer user_data,
			     GCancellable *cancellable,
			     GError **perror)
{
	struct EMapiCheckForeignFolderData *cffd = user_data;
	const mapi_id_t *pid;

	g_return_val_if_fail (properties != NULL, FALSE);
	g_return_val_if_fail (cffd != NULL, FALSE);
	g_return_val_if_fail (cffd->folder_displayname == NULL, FALSE);
	g_return_val_if_fail (cffd->folder_container_class == NULL, FALSE);

	pid = e_mapi_util_find_array_propval (properties, PidTagParentFolderId);

	cffd->folder_displayname = g_strdup (e_mapi_util_find_array_propval (properties, PidTagDisplayName));
	cffd->folder_container_class = g_strdup (e_mapi_util_find_array_propval (properties, PidTagContainerClass));
	cffd->parent_folder_id = pid ? *pid : 0;

	if (!cffd->folder_container_class) {
		/* Default to mail folder */
		cffd->folder_container_class = g_strdup (IPF_NOTE);
	}

	return TRUE;
}

static void
check_foreign_folder_thread (GObject *with_object,
			     gpointer user_data,
			     GCancellable *cancellable,
			     GError **perror)
{
	struct EMapiCheckForeignFolderData *cffd = user_data;
	GError *local_error = NULL;
	EMapiConnection *conn;
	mapi_object_t obj_folder;
	mapi_id_t fid = 0;

	g_return_if_fail (with_object != NULL);
	g_return_if_fail (CAMEL_IS_MAPI_STORE (with_object));
	g_return_if_fail (user_data != NULL);
	g_return_if_fail (cffd->username != NULL);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		return;

	conn = camel_mapi_store_ref_connection (CAMEL_MAPI_STORE (with_object), cancellable, perror);
	if (!conn || !e_mapi_connection_connected (conn)) {
		if (conn)
			g_object_unref (conn);
		make_mapi_error (perror, "EMapiConnection", MAPI_E_NOT_INITIALIZED);
		return;
	}

	if (cffd->direct_username && *cffd->direct_username) {
		g_return_if_fail (cffd->user_displayname == NULL);

		cffd->user_displayname = cffd->username;
		cffd->username = g_strdup (cffd->direct_username);
	} else {
		if (!e_mapi_connection_resolve_username (conn, cffd->username,
			NULL, NULL,
			check_foreign_username_resolved_cb, cffd,
			cancellable, perror)) {
			g_object_unref (conn);
			make_mapi_error (perror, "e_mapi_connection_resolve_username", MAPI_E_CALL_FAILED);
			return;
		}
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		g_object_unref (conn);
		return;
	}

	if (!e_mapi_connection_test_foreign_folder (conn, cffd->username,
		cffd->use_foldername ? cffd->use_foldername : cffd->orig_foldername,
		&fid, cancellable, &local_error)) {
		if (g_error_matches (local_error, E_MAPI_ERROR, MAPI_E_NOT_FOUND)) {
			g_clear_error (&local_error);
			local_error = g_error_new (E_MAPI_ERROR, MAPI_E_NOT_FOUND,
				_("Folder “%s” not found. Either it does not exist or you do not have permission to access it."),
				cffd->orig_foldername);
		}

		g_object_unref (conn);
		g_propagate_error (perror, local_error);
		return;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		g_object_unref (conn);
		return;
	}

	if (!e_mapi_connection_open_foreign_folder (conn, cffd->username, fid, &obj_folder, cancellable, perror)) {
		g_object_unref (conn);
		make_mapi_error (perror, "e_mapi_connection_open_foreign_folder", MAPI_E_CALL_FAILED);
		return;
	}

	if (!e_mapi_connection_get_folder_properties (conn, &obj_folder,
		foreign_folder_add_props_cb, NULL,
		foreign_folder_get_props_cb, cffd,
		cancellable, perror)) {
		make_mapi_error (perror, "e_mapi_connection_get_folder_properties", MAPI_E_CALL_FAILED);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, perror);
		g_object_unref (conn);
		return;
	}

	e_mapi_connection_close_folder (conn, &obj_folder, cancellable, perror);
	g_object_unref (conn);

	if (!cffd->folder_container_class) {
		g_propagate_error (perror, g_error_new_literal (E_MAPI_ERROR, MAPI_E_CALL_FAILED, _("Cannot add folder, cannot determine folder’s type")));
		return;
	}

	cffd->folder_id = fid;
}

static void
check_foreign_folder_idle (GObject *with_object,
			   gpointer user_data,
			   GCancellable *cancellable,
			   GError **perror)
{
	struct EMapiCheckForeignFolderData *cffd = user_data;
	gchar *folder_name;
	const gchar *base_username, *base_foldername;
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	CamelMapiStore *mapi_store;
	ESourceRegistry *registry = NULL;
	CamelSession *session;
	EMapiFolderType folder_type;
	gchar *profile;

	g_return_if_fail (with_object != NULL);
	g_return_if_fail (CAMEL_IS_MAPI_STORE (with_object));
	g_return_if_fail (user_data != NULL);
	g_return_if_fail (cffd->username != NULL);
	g_return_if_fail (cffd->folder_container_class != NULL);

	if (!cffd->folder_id)
		return;

	base_username = cffd->user_displayname ? cffd->user_displayname : cffd->username;
	base_foldername = cffd->folder_displayname ? cffd->folder_displayname : cffd->orig_foldername;

	/* Translators: This is used to name foreign folder.
	   The first '%s' is replaced with user name to whom the folder belongs,
	   the second '%s' is replaced with folder name.
	   Example result: "John Smith — Calendar"
	*/
	folder_name = g_strdup_printf (C_("ForeignFolder", "%s — %s"), base_username, base_foldername);

	mapi_store = CAMEL_MAPI_STORE (with_object);

	settings = camel_service_ref_settings (CAMEL_SERVICE (mapi_store));

	mapi_settings = CAMEL_MAPI_SETTINGS (settings);
	profile = camel_mapi_settings_dup_profile (mapi_settings);

	g_object_unref (settings);

	session = camel_service_ref_session (CAMEL_SERVICE (mapi_store));
	if (E_IS_MAIL_SESSION (session))
		registry = e_mail_session_get_registry (E_MAIL_SESSION (session));

	folder_type = e_mapi_folder_type_from_string (cffd->folder_container_class);
	if ((folder_type == E_MAPI_FOLDER_TYPE_MAIL &&
	     !add_foreign_folder_to_camel (mapi_store,
		cffd->username,
		cffd->folder_id,
		cffd->parent_folder_id,
		cffd->include_subfolders,
		base_username,
		base_foldername,
		perror)) ||
	    (folder_type != E_MAPI_FOLDER_TYPE_MAIL && !e_mapi_folder_add_as_esource (registry, folder_type, profile,
		TRUE /* camel_offline_settings_get_stay_synchronized (CAMEL_OFFLINE_SETTINGS (mapi_settings)) */,
		E_MAPI_FOLDER_CATEGORY_FOREIGN,
		cffd->username,
		folder_name,
		cffd->folder_id,
		0,
		cancellable,
		perror))) {
		/* to not destroy the dialog on error */
		cffd->folder_id = 0;
	}

	g_object_unref (session);

	g_free (folder_name);
	g_free (profile);
}

static gpointer
ref_selected_store (GObject *dialog)
{
	GtkComboBox *combo_box;
	CamelStore *store = NULL;
	GtkTreeIter iter;

	combo_box = g_object_get_data (dialog, STR_ACCOUNTS_COMBO);
	g_return_val_if_fail (combo_box != NULL, NULL);

	if (gtk_combo_box_get_active_iter (combo_box, &iter)) {
		gtk_tree_model_get (gtk_combo_box_get_model (combo_box), &iter,
			COLUMN_STORE, &store, -1);
	}

	return store;
}

static void
subscribe_foreign_response_cb (GObject *dialog,
			       gint response_id)
{
	struct EMapiCheckForeignFolderData *cffd;
	ENameSelectorEntry *entry;
	GtkComboBoxText *combo_text;
	GtkToggleButton *subfolders_check;
	EDestinationStore *dest_store;
	CamelStore *cstore;
	gchar *description;
	const gchar *username;
	gchar *orig_foldername, *use_foldername = NULL;

	if (response_id != GTK_RESPONSE_OK) {
		gtk_widget_destroy (GTK_WIDGET (dialog));
		return;
	}

	g_return_if_fail (dialog != NULL);

	entry = g_object_get_data (dialog, STR_USER_NAME_SELECTOR_ENTRY);
	combo_text = g_object_get_data (dialog, STR_FOLDER_NAME_COMBO);
	subfolders_check = g_object_get_data (dialog, STR_SUBFOLDERS_CHECK);

	g_return_if_fail (entry != NULL);

	cstore = ref_selected_store (dialog);
	g_return_if_fail (cstore != NULL);

	username = NULL;
	dest_store = e_name_selector_entry_peek_destination_store (entry);
	if (dest_store && e_destination_store_get_destination_count (dest_store) > 0) {
		EDestination *dest;
		GList *dests = e_destination_store_list_destinations (dest_store);

		g_return_if_fail (dests != NULL);

		/* pick the first, there is no option to limit to only one destination */
		dest = dests->data;
		if (dest) {
			username = e_destination_get_email (dest);
			if (!username || !*username)
				username = e_destination_get_name (dest);
		}

		g_list_free (dests);
	}

	if (!username || !*username)
		username = gtk_entry_get_text (GTK_ENTRY (entry));

	orig_foldername = gtk_combo_box_text_get_active_text (combo_text);
	if (!orig_foldername)
		orig_foldername = g_strdup ("");

	/* convert well-known names to their non-localized form */
	if (g_strcmp0 (orig_foldername, _("Inbox")) == 0) {
		use_foldername = g_strdup ("Inbox");
	} else if (g_strcmp0 (orig_foldername, _("Contacts")) == 0) {
		use_foldername = g_strdup ("Contacts");
	} else if (g_strcmp0 (orig_foldername, _("Calendar")) == 0) {
		use_foldername = g_strdup ("Calendar");
	} else if (g_strcmp0 (orig_foldername, _("Memos")) == 0) {
		use_foldername = g_strdup ("Notes");
	} else if (g_strcmp0 (orig_foldername, _("Tasks")) == 0) {
		use_foldername = g_strdup ("Tasks");
	}

	cffd = g_new0 (struct EMapiCheckForeignFolderData, 1);
	cffd->dialog = GTK_WIDGET (dialog);
	cffd->username = g_strdup (username ? username : "");
	cffd->direct_username = g_strdup (g_object_get_data (G_OBJECT (entry), STR_MAPI_DIRECT_USER_NAME));
	cffd->orig_foldername = orig_foldername;
	cffd->use_foldername = use_foldername;
	cffd->folder_id = 0;
	cffd->parent_folder_id = 0;
	cffd->include_subfolders = gtk_toggle_button_get_active (subfolders_check);

	description = g_strdup_printf (_("Testing availability of folder “%s” of user “%s”, please wait..."), cffd->orig_foldername, cffd->username);

	e_mapi_config_utils_run_in_thread_with_feedback (
		GTK_WINDOW (dialog),
		G_OBJECT (cstore),
		description,
		check_foreign_folder_thread,
		check_foreign_folder_idle,
		cffd,
		e_mapi_check_foreign_folder_data_free);

	g_free (description);
	g_object_unref (cstore);
}

static void
pick_gal_user_clicked_cb (GtkButton *button,
			  GObject *dialog)
{
	GtkEntry *entry;
	CamelMapiStore *mapi_store;
	EMapiConnection *conn;
	gchar *text, *display_name = NULL, *dn = NULL;
	EMapiGalUserType searched_type = E_MAPI_GAL_USER_NONE;

	g_return_if_fail (dialog != NULL);

	entry = g_object_get_data (dialog, STR_USER_NAME_SELECTOR_ENTRY);

	g_return_if_fail (entry != NULL);

	mapi_store = ref_selected_store (dialog);
	g_return_if_fail (mapi_store != NULL);

	text = g_strstrip (g_strdup (gtk_entry_get_text (entry)));

	conn = camel_mapi_store_ref_connection (mapi_store, NULL, NULL);
	if (!conn) {
		e_notice (dialog, GTK_MESSAGE_ERROR, "%s", _("Cannot search for user when the account is offline"));
	} else if (e_mapi_search_gal_user_modal (GTK_WINDOW (dialog),
					  conn,
					  text,
					  &searched_type,
					  &display_name,
					  NULL,
					  &dn,
					  NULL)) {
		if (searched_type == E_MAPI_GAL_USER_REGULAR &&
		    display_name && dn && *dn && strchr (dn, '=')) {
			gtk_entry_set_text (entry, display_name);
			g_object_set_data_full (G_OBJECT (entry), STR_MAPI_DIRECT_USER_NAME, g_strdup (strrchr (dn, '=') + 1), g_free);
		}
	}

	g_object_unref (mapi_store);
	g_clear_object (&conn);
	g_free (text);
	g_free (display_name);
	g_free (dn);
}

static gint
sort_accounts_by_display_name_cb (gconstpointer ptr1,
				  gconstpointer ptr2)
{
	CamelService *service1 = (CamelService *) ptr1;
	CamelService *service2 = (CamelService *) ptr2;

	return g_utf8_collate (camel_service_get_display_name (service1), camel_service_get_display_name (service2));
}

static GtkWidget *
create_accounts_combo (CamelSession *session,
		       EClientCache *client_cache,
		       CamelStore *store)
{
	GtkListStore *list_store;
	GtkTreeIter iter;
	GtkComboBox *combo_box;
	ESourceRegistry *registry;
	GList *services, *link, *accounts = NULL;
	GtkCellRenderer *renderer;

	list_store = gtk_list_store_new (3,
		G_TYPE_STRING,		/* COLUMN_UID - UID of the CamelMAPIStore */
		G_TYPE_STRING,		/* COLUMN_DISPLAY_NAME */
		CAMEL_TYPE_MAPI_STORE);	/* COLUMN_STORE */

	registry = e_client_cache_ref_registry (client_cache);
	services = camel_session_list_services (session);

	for (link = services; link; link = g_list_next (link)) {
		CamelService *service = link->data;

		if (CAMEL_IS_MAPI_STORE (service)) {
			ESource *source;

			source = e_source_registry_ref_source (registry, camel_service_get_uid (service));
			if (source && e_source_registry_check_enabled (registry, source)) {
				accounts = g_list_prepend (accounts, service);
			}

			g_clear_object (&source);
		}
	}

	accounts = g_list_sort (accounts, sort_accounts_by_display_name_cb);

	for (link = accounts; link; link = g_list_next (link)) {
		CamelService *service = link->data;

		gtk_list_store_append (list_store, &iter);
		gtk_list_store_set (list_store, &iter,
			COLUMN_UID, camel_service_get_uid (service),
			COLUMN_DISPLAY_NAME, camel_service_get_display_name (service),
			COLUMN_STORE, service,
			-1);
	}

	g_list_free_full (services, g_object_unref);
	g_list_free (accounts);
	g_clear_object (&registry);

	combo_box = GTK_COMBO_BOX (gtk_combo_box_new_with_model (GTK_TREE_MODEL (list_store)));
	g_object_unref (list_store);

	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo_box), renderer, TRUE);
	gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (combo_box), renderer, "text", COLUMN_DISPLAY_NAME, NULL);

	gtk_combo_box_set_id_column (combo_box, COLUMN_UID);
	if (store)
		gtk_combo_box_set_active_id (combo_box, camel_service_get_uid (CAMEL_SERVICE (store)));
	else if (accounts)
		gtk_combo_box_set_active (combo_box, 0);

	return GTK_WIDGET (combo_box);
}

/* Opens dialog to subscribe to folders of other
   users in the given store */
void
e_mapi_subscribe_foreign_folder (GtkWindow *parent,
				 CamelSession *session,
				 CamelStore *store,
                                 EClientCache *client_cache)
{
	ENameSelector *name_selector;
	ENameSelectorModel *name_selector_model;
	ENameSelectorDialog *name_selector_dialog;
	GObject *dialog;
	GtkWidget *content;
	GtkWidget *label, *widget, *entry, *check, *accounts_combo;
	GtkGrid *grid;
	GtkComboBoxText *combo_text;
	gint row;

	g_return_if_fail (session != NULL);
	if (store)
		g_return_if_fail (CAMEL_IS_MAPI_STORE (store));

	dialog = G_OBJECT (gtk_dialog_new_with_buttons (
		_("Subscribe to folder of other MAPI user..."),
		parent,
		GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_CLOSE, GTK_RESPONSE_CLOSE,
		GTK_STOCK_OK, GTK_RESPONSE_OK,
		NULL));

	g_signal_connect (dialog, "response", G_CALLBACK (subscribe_foreign_response_cb), NULL);

	content = gtk_dialog_get_content_area (GTK_DIALOG (dialog));

	grid = GTK_GRID (gtk_grid_new ());
	gtk_grid_set_row_homogeneous (grid, FALSE);
	gtk_grid_set_row_spacing (grid, 6);
	gtk_grid_set_column_homogeneous (grid, FALSE);
	gtk_grid_set_column_spacing (grid, 6);
	gtk_container_set_border_width (GTK_CONTAINER (grid), 12);
	gtk_container_add (GTK_CONTAINER (content), GTK_WIDGET (grid));

	row = 0;

	label = gtk_label_new (_("Account:"));
	g_object_set (G_OBJECT (label),
		"hexpand", FALSE,
		"vexpand", FALSE,
		"xalign", 0.0,
		"halign", GTK_ALIGN_START,
		NULL);

	widget = create_accounts_combo (session, client_cache, store);
	g_object_set (G_OBJECT (widget),
		"hexpand", TRUE,
		"vexpand", FALSE,
		"halign", GTK_ALIGN_START,
		NULL);
	accounts_combo = widget;

	gtk_grid_attach (grid, label, 0, row, 1, 1);
	gtk_grid_attach (grid, widget, 1, row, 2, 1);

	row++;

	name_selector = e_name_selector_new (client_cache);
	name_selector_model = e_name_selector_peek_model (name_selector);
	e_name_selector_model_add_section (name_selector_model, "User", _("User"), NULL);
	name_selector_dialog = e_name_selector_peek_dialog (name_selector);
	g_signal_connect (name_selector_dialog, "response", G_CALLBACK (gtk_widget_hide), name_selector);
	e_name_selector_load_books (name_selector);

	g_object_set_data_full (dialog, "e-mapi-name-selector", name_selector, g_object_unref);

	label = gtk_label_new_with_mnemonic (_("_User:"));
	g_object_set (G_OBJECT (label),
		"hexpand", FALSE,
		"vexpand", FALSE,
		"xalign", 0.0,
		NULL);

	entry = GTK_WIDGET (e_name_selector_peek_section_entry (name_selector, "User"));
	g_object_set (G_OBJECT (entry),
		"hexpand", TRUE,
		"vexpand", FALSE,
		NULL);

	widget = gtk_button_new_with_mnemonic (_("C_hoose..."));
	g_object_set (G_OBJECT (entry),
		"hexpand", TRUE,
		"vexpand", FALSE,
		NULL);

	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);
	g_signal_connect (widget, "clicked", G_CALLBACK (pick_gal_user_clicked_cb), dialog);

	gtk_grid_attach (grid, label, 0, row, 1, 1);
	gtk_grid_attach (grid, entry, 1, row, 1, 1);
	gtk_grid_attach (grid, widget, 2, row, 1, 1);

	row++;

	label = gtk_label_new_with_mnemonic (_("_Folder name:"));
	g_object_set (G_OBJECT (label),
		"hexpand", FALSE,
		"vexpand", FALSE,
		"xalign", 0.0,
		NULL);

	widget = GTK_WIDGET (g_object_new (gtk_combo_box_text_get_type (),
		"has-entry", TRUE,
		"entry-text-column", 0,
		"hexpand", TRUE,
		"vexpand", FALSE,
		NULL));

	combo_text = GTK_COMBO_BOX_TEXT (widget);
	gtk_combo_box_text_append_text (combo_text, _("Inbox"));
	gtk_combo_box_text_append_text (combo_text, _("Contacts"));
	gtk_combo_box_text_append_text (combo_text, _("Calendar"));
	gtk_combo_box_text_append_text (combo_text, _("Memos"));
	gtk_combo_box_text_append_text (combo_text, _("Tasks"));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo_text), 0);

	gtk_label_set_mnemonic_widget (GTK_LABEL (label), widget);
	gtk_grid_attach (grid, label, 0, row, 1, 1);
	gtk_grid_attach (grid, widget, 1, row, 2, 1);

	row++;

	check = gtk_check_button_new_with_mnemonic (_("Include _subfolders"));
	gtk_grid_attach (grid, check, 1, row, 2, 1);

	/* remember widgets for later use */
	g_object_set_data (dialog, STR_ACCOUNTS_COMBO, accounts_combo);
	g_object_set_data (dialog, STR_USER_NAME_SELECTOR_ENTRY, entry);
	g_object_set_data (dialog, STR_FOLDER_NAME_COMBO, widget);
	g_object_set_data (dialog, STR_SUBFOLDERS_CHECK, check);

	g_object_set_data_full (dialog, STR_MAPI_CAMEL_SESSION, g_object_ref (session), g_object_unref);

	g_signal_connect_swapped (entry, "changed", G_CALLBACK (name_entry_changed_cb), dialog);
	g_signal_connect_swapped (combo_text, "changed", G_CALLBACK (folder_name_combo_changed_cb), dialog);
	g_signal_connect_swapped (accounts_combo, "changed", G_CALLBACK (name_entry_changed_cb), dialog);

	name_entry_changed_cb (dialog);

	gtk_widget_show_all (content);
	gtk_widget_show (GTK_WIDGET (dialog));
}
