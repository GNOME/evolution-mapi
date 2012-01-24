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
 *		Johnny Jacob  <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2009 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <gtk/gtk.h>

#include <libedataserver/e-xml-hash-utils.h>
#include <libedataserverui/e-passwords.h>
#include <libedataserverui/e-source-selector.h>
#include <libedataserver/e-account.h>
#include <e-util/e-util.h>
#include <e-util/e-dialog-utils.h>
#include <e-util/e-plugin-ui.h>

#include <e-mapi-folder.h>
#include <e-mapi-connection.h>
#include <e-mapi-utils.h>

#include <shell/e-shell-sidebar.h>
#include <shell/e-shell-view.h>
#include <shell/e-shell-window.h>

#include <mail/em-config.h>
#include <mail/em-folder-tree.h>

#include "e-mapi-account-listener.h"
#include "e-mapi-subscribe-foreign-folder.h"
#include "e-mapi-edit-folder-permissions.h"

#include "camel/camel-mapi-store.h"
#include "camel/camel-mapi-store-summary.h"

#define FOLDERSIZE_MENU_ITEM 0

enum {
	COL_FOLDERSIZE_NAME = 0,
	COL_FOLDERSIZE_SIZE,
	COL_FOLDERSIZE_MAX
};

typedef struct
{
	GtkDialog *dialog;
	GtkGrid *spinner_grid;

	gchar *profile;

	GSList *folder_list;
	EMapiConnection *conn;
} FolderSizeDialogData;

static gboolean
fill_folder_size_dialog_cb (gpointer data)
{
	GtkWidget *widget;
	GtkCellRenderer *renderer;
	GtkListStore *store;
	GtkTreeIter iter;
	GtkBox *content_area;
	FolderSizeDialogData *dialog_data = (FolderSizeDialogData *)data;

	/* Hide progress bar. Set status*/
	gtk_widget_destroy (GTK_WIDGET (dialog_data->spinner_grid));

	if (dialog_data->folder_list) {
		GtkWidget *scrolledwindow, *tree_view;

		scrolledwindow = gtk_scrolled_window_new (NULL, NULL);
		gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwindow), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
		gtk_widget_show (scrolledwindow);

		/*Tree View */
		tree_view =  gtk_tree_view_new ();
		renderer = gtk_cell_renderer_text_new ();
		gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (tree_view),-1,
							     _("Folder"), renderer, "text", COL_FOLDERSIZE_NAME,
							     NULL);

		renderer = gtk_cell_renderer_text_new ();
		gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (tree_view),-1,
							     _("Size"), renderer, "text", COL_FOLDERSIZE_SIZE,
							     NULL);
		/* Model for TreeView */
		store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
		gtk_tree_view_set_model (GTK_TREE_VIEW (tree_view), GTK_TREE_MODEL (store));

		/* Populate model with data */
		while (dialog_data->folder_list) {
			EMapiFolder *folder = (EMapiFolder *) dialog_data->folder_list->data;
			gchar *folder_size = g_format_size_for_display (folder->size);

			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,
					    COL_FOLDERSIZE_NAME, folder->folder_name,
					    COL_FOLDERSIZE_SIZE, folder_size,
					    -1);
			dialog_data->folder_list = g_slist_next (dialog_data->folder_list);
			g_free (folder_size);
		}

		gtk_container_add (GTK_CONTAINER (scrolledwindow), tree_view);
		widget = scrolledwindow;
	} else {
		widget = gtk_label_new (_("Unable to retrieve folder size information"));
	}

	gtk_widget_show_all (widget);

	/* Pack into content_area */
	content_area = GTK_BOX (gtk_dialog_get_content_area (dialog_data->dialog));
	gtk_box_pack_start (content_area, widget, TRUE, TRUE, 6);

	if (dialog_data->conn)
		g_object_unref (dialog_data->conn);

	return FALSE;
}

static gpointer
mapi_settings_get_folder_size (gpointer data)
{
	FolderSizeDialogData *dialog_data = (FolderSizeDialogData *)data;

	dialog_data->folder_list = NULL;
	dialog_data->conn = e_mapi_connection_find (dialog_data->profile);
	if (dialog_data->conn && e_mapi_connection_connected (dialog_data->conn))
		dialog_data->folder_list = e_mapi_connection_peek_folders_list (dialog_data->conn);

	g_timeout_add (100, fill_folder_size_dialog_cb, dialog_data);

	return NULL;
}

static void
mapi_settings_run_folder_size_dialog (const gchar *profile, gpointer data)
{
	GtkBox *content_area;
	GtkWidget *spinner, *alignment;
	GtkWidget *spinner_label;
	FolderSizeDialogData *dialog_data;

	dialog_data = g_new0 (FolderSizeDialogData, 1);

	dialog_data->dialog = (GtkDialog *)gtk_dialog_new_with_buttons (_("Folder Size"), NULL,
							   GTK_DIALOG_DESTROY_WITH_PARENT,
							   GTK_STOCK_CLOSE, GTK_RESPONSE_ACCEPT,
							   NULL);

	gtk_window_set_default_size (GTK_WINDOW (dialog_data->dialog), 250, 300);

	content_area = GTK_BOX (gtk_dialog_get_content_area (dialog_data->dialog));

	spinner = gtk_spinner_new ();
	gtk_spinner_start (GTK_SPINNER (spinner));
	spinner_label = gtk_label_new (_("Fetching folder list…"));

	dialog_data->spinner_grid = GTK_GRID (gtk_grid_new ());
	gtk_grid_set_column_spacing (dialog_data->spinner_grid, 6);
	gtk_grid_set_column_homogeneous (dialog_data->spinner_grid, FALSE);
	gtk_orientable_set_orientation (GTK_ORIENTABLE (dialog_data->spinner_grid), GTK_ORIENTATION_HORIZONTAL);

	alignment = gtk_alignment_new (1.0, 0.5, 0.0, 1.0);
	gtk_container_add (GTK_CONTAINER (alignment), spinner);
	gtk_misc_set_alignment (GTK_MISC (spinner_label), 0.0, 0.5);

	gtk_container_add (GTK_CONTAINER (dialog_data->spinner_grid), alignment);
	gtk_container_add (GTK_CONTAINER (dialog_data->spinner_grid), spinner_label);

	/* Pack the TreeView into dialog's content area */
	gtk_box_pack_start (content_area, GTK_WIDGET (dialog_data->spinner_grid), TRUE, TRUE, 6);
	gtk_widget_show_all (GTK_WIDGET (dialog_data->dialog));

	dialog_data->profile = g_strdup (profile);

	/* Fetch folder list and size information in a thread */
	g_thread_create (mapi_settings_get_folder_size, dialog_data, FALSE, NULL);

	/* Start the dialog */
	gtk_dialog_run (dialog_data->dialog);

	gtk_widget_destroy (GTK_WIDGET (dialog_data->dialog));

	g_free (dialog_data->profile);
	g_free (dialog_data);
}

static void
folder_size_clicked (GtkButton *button,
                     CamelMapiSettings *mapi_settings)
{
	const gchar *profile;

	profile = camel_mapi_settings_get_profile (mapi_settings);
	mapi_settings_run_folder_size_dialog (profile, NULL);
}

static gchar *
get_profile_name_from_folder_tree (EShellView *shell_view,
				   gchar **pfolder_path,
				   CamelStore **pstore)
{
	EShellSidebar *shell_sidebar;
	EMFolderTree *folder_tree;
	gchar *profile = NULL, *selected_path = NULL;
	CamelStore *selected_store = NULL;

	/* Get hold of Folder Tree */
	shell_sidebar = e_shell_view_get_shell_sidebar (shell_view);
	g_object_get (shell_sidebar, "folder-tree", &folder_tree, NULL);
	if (em_folder_tree_get_selected (folder_tree, &selected_store, &selected_path) ||
	    em_folder_tree_store_root_selected (folder_tree, &selected_store)) {
		if (selected_store) {
			CamelProvider *provider = camel_service_get_provider (CAMEL_SERVICE (selected_store));

			if (provider && g_ascii_strcasecmp (provider->protocol, "mapi") == 0) {
				CamelService *service;
				CamelSettings *settings;

				service = CAMEL_SERVICE (selected_store);
				settings = camel_service_get_settings (service);
				g_object_get (settings, "profile", &profile, NULL);

				if (pstore && profile)
					*pstore = g_object_ref (selected_store);

				if (pfolder_path)
					*pfolder_path = selected_path;
				else
					g_free (selected_path);

				selected_path = NULL;
			}

			g_object_unref (selected_store);
		}

		g_free (selected_path);
	}

	g_object_unref (folder_tree);

	return profile;
}

static void
action_folder_size_cb (GtkAction *action,
		       EShellView *shell_view)
{
	gchar *profile;

	profile = get_profile_name_from_folder_tree (shell_view, NULL, NULL);
	if (profile)
		mapi_settings_run_folder_size_dialog (profile, NULL);

	g_free (profile);
}

static void
action_subscribe_foreign_folder_cb (GtkAction *action,
				    EShellView *shell_view)
{
	gchar *profile;
	GtkWindow *parent;
	EShellBackend *backend;
	CamelSession *session = NULL;
	CamelStore *store = NULL;

	profile = get_profile_name_from_folder_tree (shell_view, NULL, &store);
	if (!profile)
		return;

	parent = GTK_WINDOW (e_shell_view_get_shell_window (shell_view));
	backend = e_shell_view_get_shell_backend (shell_view);
	g_object_get (G_OBJECT (backend), "session", &session, NULL);

	e_mapi_subscribe_foreign_folder (parent, session, store);

	g_object_unref (session);
	g_object_unref (store);
	g_free (profile);
}

static void
action_folder_permissions_mail_cb (GtkAction *action,
				   EShellView *shell_view)
{
	gchar *profile, *folder_path = NULL;
	GtkWindow *parent;
	CamelStore *store = NULL;
	CamelMapiStore *mapi_store;
	CamelNetworkSettings *network_settings;
	CamelStoreInfo *si;

	profile = get_profile_name_from_folder_tree (shell_view, &folder_path, &store);
	if (!profile)
		return;

	mapi_store = CAMEL_MAPI_STORE (store);
	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (folder_path != NULL);

	network_settings = CAMEL_NETWORK_SETTINGS (camel_service_get_settings (CAMEL_SERVICE (store)));
	g_return_if_fail (network_settings != NULL);

	parent = GTK_WINDOW (e_shell_view_get_shell_window (shell_view));

	si = camel_store_summary_path (mapi_store->summary, folder_path);
	if (!si) {
		e_notice (parent, GTK_MESSAGE_ERROR, _("Cannot edit permissions of folder '%s', choose other folder."), folder_path);
	} else {
		CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;

		e_mapi_edit_folder_permissions (parent,
			profile,
			camel_network_settings_get_user (network_settings),
			camel_network_settings_get_host (network_settings),
			camel_service_get_display_name (CAMEL_SERVICE (store)),
			folder_path,
			msi->folder_id,
			(msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0 ? E_MAPI_FOLDER_CATEGORY_FOREIGN :
			(msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ? E_MAPI_FOLDER_CATEGORY_PUBLIC :
			E_MAPI_FOLDER_CATEGORY_PERSONAL,
			msi->foreign_username,
			FALSE);
	}

	g_object_unref (store);
	g_free (folder_path);
}

GtkWidget *org_gnome_e_mapi_settings (EPlugin *epl, EConfigHookItemFactoryData *data);

/* used only in Account Editor */
GtkWidget *
org_gnome_e_mapi_settings (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	EMConfigTargetSettings *target_account;
	GtkGrid *vsettings;

	/* Miscelleneous setting */
	GtkFrame *frm_misc;
	GtkGrid *vgrid_misc;
	GtkTable *tbl_misc;
	GtkLabel *lbl_fsize;
	GtkButton *btn_fsize;

	target_account = (EMConfigTargetSettings *)data->config->target;

	if (!CAMEL_IS_MAPI_SETTINGS (target_account->storage_settings))
		return NULL;

	/* Verify the storage and transport settings are shared. */
	g_warn_if_fail (
		target_account->storage_settings ==
		target_account->transport_settings);

	vsettings = GTK_GRID (g_object_new (GTK_TYPE_GRID, "column-homogeneous", FALSE, "column-spacing", 6, "orientation", GTK_ORIENTATION_VERTICAL, NULL));
	gtk_container_set_border_width (GTK_CONTAINER (vsettings), 12);

	/* Miscellaneous settings */
	frm_misc = (GtkFrame*) g_object_new (GTK_TYPE_FRAME, "label", _("Miscellaneous"), NULL);
	gtk_container_add (GTK_CONTAINER (vsettings), GTK_WIDGET (frm_misc));

	vgrid_misc = GTK_GRID (g_object_new (GTK_TYPE_GRID, "column-homogeneous", FALSE, "column-spacing", 6, "orientation", GTK_ORIENTATION_VERTICAL, NULL));
	gtk_container_set_border_width (GTK_CONTAINER (vgrid_misc), 6);
	gtk_container_add (GTK_CONTAINER (frm_misc), GTK_WIDGET (vgrid_misc));

	tbl_misc = (GtkTable*) g_object_new (GTK_TYPE_TABLE, "n-rows", 1, "n-columns", 1,
					     "homogeneous", FALSE, "row-spacing", 6,
					     "column-spacing", 6, NULL);

	/* Folder Size */
	lbl_fsize = (GtkLabel*) g_object_new (GTK_TYPE_LABEL, "label",
					      _("View the size of all Exchange folders"), NULL);
	gtk_misc_set_alignment (GTK_MISC (lbl_fsize), 0, 0.5);
	btn_fsize = (GtkButton*) g_object_new (GTK_TYPE_BUTTON, "label", _("Folder Size"), NULL);
	g_signal_connect (btn_fsize, "clicked", G_CALLBACK (folder_size_clicked), target_account->storage_settings);
	gtk_table_attach_defaults (tbl_misc, GTK_WIDGET (lbl_fsize), 0, 1, 0, 1);
	gtk_table_attach (tbl_misc, GTK_WIDGET (btn_fsize), 1, 2, 0, 1, GTK_FILL, GTK_FILL, 0, 0);

	/*Note : Reason for placing this UI is because we try to be like outlook. */
	gtk_container_add (GTK_CONTAINER (vgrid_misc), GTK_WIDGET (tbl_misc));
	gtk_widget_show_all (GTK_WIDGET (vsettings));

	/*Insert the page*/
	gtk_notebook_insert_page (GTK_NOTEBOOK (data->parent), GTK_WIDGET (vsettings),
				  gtk_label_new(_("Exchange Settings")), 4);

	return GTK_WIDGET (vsettings);
}

static void
mapi_plugin_enable_actions (GtkActionGroup *action_group,
			    const GtkActionEntry *entries,
			    guint n_entries,
			    gboolean can_show,
			    gboolean is_online)
{
	gint ii;

	g_return_if_fail (action_group != NULL);
	g_return_if_fail (entries != NULL);

	for (ii = 0; ii < n_entries; ii++) {
		GtkAction *action;

		action = gtk_action_group_get_action (action_group, entries[ii].name);
		if (!action)
			continue;

		gtk_action_set_visible (action, can_show);
		if (can_show)
			gtk_action_set_sensitive (action, is_online);
	}
}

static GtkActionEntry mail_account_context_entries[] = {

	{ "mail-mapi-folder-size",
	  NULL,
	  N_("Folder size..."),
	  NULL,
	  NULL,  /* XXX Add a tooltip! */
	  G_CALLBACK (action_folder_size_cb) },

	{ "mail-mapi-subscribe-foreign-folder",
	  NULL,
	  N_("Subscribe to other user's folder..."),
	  NULL,
	  NULL,  /* XXX Add a tooltip! */
	  G_CALLBACK (action_subscribe_foreign_folder_cb) }
};

static GtkActionEntry mail_folder_context_entries[] = {
	{ "mail-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI folder permissions"),
	  G_CALLBACK (action_folder_permissions_mail_cb) }
};

static void
mapi_plugin_update_actions_mail_cb (EShellView *shell_view,
				    GtkActionEntry *entries)
{
	EShellWindow *shell_window;
	GtkActionGroup *action_group;
	GtkUIManager *ui_manager;
	EShellSidebar *shell_sidebar;
	EMFolderTree *folder_tree;
	CamelStore *selected_store = NULL;
	gchar *selected_path = NULL;
	gboolean account_node = FALSE, folder_node = FALSE;
	gboolean online = FALSE;

	shell_sidebar = e_shell_view_get_shell_sidebar (shell_view);
	g_object_get (shell_sidebar, "folder-tree", &folder_tree, NULL);
	if (em_folder_tree_get_selected (folder_tree, &selected_store, &selected_path) ||
	    em_folder_tree_store_root_selected (folder_tree, &selected_store)) {
		if (selected_store) {
			CamelProvider *provider = camel_service_get_provider (CAMEL_SERVICE (selected_store));

			if (provider && g_ascii_strcasecmp (provider->protocol, "mapi") == 0) {
				account_node = !selected_path || !*selected_path;
				folder_node = !account_node;
			}

			g_object_unref (selected_store);
		}
	}
	g_object_unref (folder_tree);

	g_free (selected_path);

	shell_window = e_shell_view_get_shell_window (shell_view);
	ui_manager = e_shell_window_get_ui_manager (shell_window);
	action_group = e_lookup_action_group (ui_manager, "mail");

	if (account_node || folder_node) {
		EShellBackend *backend;
		CamelSession *session = NULL;

		backend = e_shell_view_get_shell_backend (shell_view);
		g_object_get (G_OBJECT (backend), "session", &session, NULL);

		online = session && camel_session_get_online (session);

		if (session)
			g_object_unref (session);
	}

	mapi_plugin_enable_actions (action_group, mail_account_context_entries, G_N_ELEMENTS (mail_account_context_entries), account_node, online);
	mapi_plugin_enable_actions (action_group, mail_folder_context_entries, G_N_ELEMENTS (mail_folder_context_entries), folder_node, online);
}

gboolean mapi_ui_init_mail (GtkUIManager *ui_manager, EShellView *shell_view);

gboolean
mapi_ui_init_mail (GtkUIManager *ui_manager,
                   EShellView *shell_view)
{
	EShellWindow *shell_window;
	GtkActionGroup *action_group;

	shell_window = e_shell_view_get_shell_window (shell_view);
	action_group = e_shell_window_get_action_group (shell_window, "mail");

	/* Add actions to the "mail" action group. */
	e_action_group_add_actions_localized (action_group, GETTEXT_PACKAGE,
		mail_account_context_entries, G_N_ELEMENTS (mail_account_context_entries), shell_view);
	e_action_group_add_actions_localized (action_group, GETTEXT_PACKAGE,
		mail_folder_context_entries, G_N_ELEMENTS (mail_folder_context_entries), shell_view);

	/* Decide whether we want this option to be visible or not */
	g_signal_connect (shell_view, "update-actions",
			  G_CALLBACK (mapi_plugin_update_actions_mail_cb),
			  shell_view);

	g_object_unref (action_group);

	return TRUE;
}

static gboolean
get_selected_mapi_source (EShellView *shell_view,
			  ESource **selected_source)
{
	ESource *source;
	gchar *uri = NULL;
	EShellSidebar *shell_sidebar;
	ESourceSelector *selector = NULL;

	g_return_val_if_fail (shell_view != NULL, FALSE);

	shell_sidebar = e_shell_view_get_shell_sidebar (shell_view);
	g_return_val_if_fail (shell_sidebar != NULL, FALSE);

	g_object_get (shell_sidebar, "selector", &selector, NULL);
	g_return_val_if_fail (selector != NULL, FALSE);

	source = e_source_selector_peek_primary_selection (selector);
	uri = source ? e_source_get_uri (source) : NULL;
	if (uri && g_str_has_prefix (uri, "mapi://"))
		source = g_object_ref (source);
	else
		source = NULL;

	g_free (uri);
	g_object_unref (selector);

	if (selected_source)
		*selected_source = source;
	else if (source)
		g_object_unref (source);

	return source != NULL;
}

/* how many menu entries are defined; all calendar/tasks/memos/contacts
   actions should have same count */
#define MAPI_ESOURCE_NUM_ENTRIES 1

static void
update_mapi_source_entries_cb (EShellView *shell_view,
			       GtkActionEntry *entries)
{
	GtkActionGroup *action_group;
	EShell *shell;
	EShellWindow *shell_window;
	const gchar *group;
	gboolean is_mapi_source, is_online;

	g_return_if_fail (E_IS_SHELL_VIEW (shell_view));
	g_return_if_fail (entries != NULL);

	if (strstr (entries->name, "calendar"))
		group = "calendar";
	else if (strstr (entries->name, "tasks"))
		group = "tasks";
	else if (strstr (entries->name, "memos"))
		group = "memos";
	else if (strstr (entries->name, "contacts"))
		group = "contacts";
	else
		g_return_if_reached ();

	is_mapi_source = get_selected_mapi_source (shell_view, NULL);
	shell_window = e_shell_view_get_shell_window (shell_view);
	shell = e_shell_window_get_shell (shell_window);

	is_online = shell && e_shell_get_online (shell);
	action_group = e_shell_window_get_action_group (shell_window, group);

	mapi_plugin_enable_actions (action_group, entries, MAPI_ESOURCE_NUM_ENTRIES, is_mapi_source, is_online);
}

static void
setup_mapi_source_actions (EShellView *shell_view,
			   GtkActionEntry *entries,
			   guint n_entries)
{
	EShellWindow *shell_window;
	const gchar *group;

	g_return_if_fail (shell_view != NULL);
	g_return_if_fail (entries != NULL);
	g_return_if_fail (n_entries > 0);
	g_return_if_fail (n_entries == MAPI_ESOURCE_NUM_ENTRIES);

	if (strstr (entries->name, "calendar"))
		group = "calendar";
	else if (strstr (entries->name, "tasks"))
		group = "tasks";
	else if (strstr (entries->name, "memos"))
		group = "memos";
	else if (strstr (entries->name, "contacts"))
		group = "contacts";
	else
		g_return_if_reached ();

	shell_window = e_shell_view_get_shell_window (shell_view);

	e_action_group_add_actions_localized (
		e_shell_window_get_action_group (shell_window, group), GETTEXT_PACKAGE,
		entries, MAPI_ESOURCE_NUM_ENTRIES, shell_view);

	g_signal_connect (shell_view, "update-actions", G_CALLBACK (update_mapi_source_entries_cb), entries);
}

static void
action_folder_permissions_source_cb (GtkAction *action,
				     EShellView *shell_view)
{
	ESource *source = NULL;
	mapi_id_t folder_id = 0;
	const gchar *foreign_username;
	gboolean is_public;

	g_return_if_fail (action != NULL);
	g_return_if_fail (shell_view != NULL);
	g_return_if_fail (get_selected_mapi_source (shell_view, &source));
	g_return_if_fail (source != NULL);
	g_return_if_fail (e_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &folder_id));
	g_return_if_fail (gtk_action_get_name (action) != NULL);

	foreign_username = e_source_get_property (source, "foreign-username");
	is_public = !foreign_username && g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0;

	e_mapi_edit_folder_permissions (NULL,
		e_source_get_property (source, "profile"),
		e_source_get_property (source, "username"),
		e_source_get_property (source, "host"),
		e_source_group_peek_name (e_source_peek_group (source)),
		e_source_peek_name (source),
		folder_id,
		foreign_username ? E_MAPI_FOLDER_CATEGORY_FOREIGN :
		is_public ? E_MAPI_FOLDER_CATEGORY_PUBLIC :
		E_MAPI_FOLDER_CATEGORY_PERSONAL,
		foreign_username,
		strstr (gtk_action_get_name (action), "calendar") != NULL);

	g_object_unref (source);
}

static GtkActionEntry calendar_context_entries[] = {

	{ "calendar-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI calendar permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

gboolean mapi_ui_init_calendar (GtkUIManager *ui_manager, EShellView *shell_view);

gboolean
mapi_ui_init_calendar (GtkUIManager *ui_manager,
		       EShellView *shell_view)
{
	setup_mapi_source_actions (shell_view,
		calendar_context_entries,
		G_N_ELEMENTS (calendar_context_entries));

	return TRUE;
}

static GtkActionEntry tasks_context_entries[] = {

	{ "tasks-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI tasks permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

gboolean mapi_ui_init_tasks (GtkUIManager *ui_manager, EShellView *shell_view);

gboolean
mapi_ui_init_tasks (GtkUIManager *ui_manager,
		    EShellView *shell_view)
{
	setup_mapi_source_actions (shell_view,
		tasks_context_entries,
		G_N_ELEMENTS (tasks_context_entries));

	return TRUE;
}
static GtkActionEntry memos_context_entries[] = {

	{ "memos-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI memos permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

gboolean mapi_ui_init_memos (GtkUIManager *ui_manager, EShellView *shell_view);

gboolean
mapi_ui_init_memos (GtkUIManager *ui_manager,
		    EShellView *shell_view)
{
	setup_mapi_source_actions (shell_view,
		memos_context_entries,
		G_N_ELEMENTS (memos_context_entries));

	return TRUE;
}
static GtkActionEntry contacts_context_entries[] = {

	{ "contacts-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI contacts permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

gboolean mapi_ui_init_contacts (GtkUIManager *ui_manager, EShellView *shell_view);

gboolean
mapi_ui_init_contacts (GtkUIManager *ui_manager,
		       EShellView *shell_view)
{
	setup_mapi_source_actions (shell_view,
		contacts_context_entries,
		G_N_ELEMENTS (contacts_context_entries));

	return TRUE;
}
