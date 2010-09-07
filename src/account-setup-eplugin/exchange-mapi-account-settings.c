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
#include <libedataserver/e-account.h>
#include <e-util/e-util.h>
#include <e-util/e-dialog-utils.h>
#include <e-util/e-plugin-ui.h>

#include <exchange-mapi-folder.h>
#include <exchange-mapi-connection.h>
#include <exchange-mapi-utils.h>

#include <shell/e-shell-sidebar.h>
#include <shell/e-shell-view.h>
#include <shell/e-shell-window.h>

#include <mail/mail-config.h>
#include <mail/em-config.h>
#include <mail/em-folder-tree.h>

#include "exchange-mapi-account-listener.h"

#define FOLDERSIZE_MENU_ITEM 0

gboolean  e_plugin_ui_init (GtkUIManager *ui_manager,
			    EShellView *shell_view);

GtkWidget *org_gnome_exchange_mapi_settings (EPlugin *epl, EConfigHookItemFactoryData *data);

enum {
	COL_FOLDERSIZE_NAME = 0,
	COL_FOLDERSIZE_SIZE,
	COL_FOLDERSIZE_MAX
};

typedef struct
{
	GtkDialog *dialog;
	GtkBox *spinner_hbox;

	gchar *profile;

	GSList *folder_list;
	ExchangeMapiConnection *conn;
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
	gtk_widget_destroy (GTK_WIDGET (dialog_data->spinner_hbox));

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
			ExchangeMAPIFolder *folder = (ExchangeMAPIFolder *) dialog_data->folder_list->data;
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
	content_area = (GtkBox*) gtk_dialog_get_content_area (dialog_data->dialog);
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
	dialog_data->conn = exchange_mapi_connection_find (dialog_data->profile);
	if (dialog_data->conn && exchange_mapi_connection_connected (dialog_data->conn))
		dialog_data->folder_list = exchange_mapi_connection_peek_folders_list (dialog_data->conn);

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
	GThread *folder_list_thread;

	dialog_data = g_new0 (FolderSizeDialogData, 1);

	dialog_data->dialog = (GtkDialog *)gtk_dialog_new_with_buttons (_("Folder Size"), NULL,
							   GTK_DIALOG_DESTROY_WITH_PARENT,
							   GTK_STOCK_CLOSE, GTK_RESPONSE_ACCEPT,
							   NULL);

	gtk_window_set_default_size (GTK_WINDOW (dialog_data->dialog), 250, 300);

	content_area = (GtkBox *)gtk_dialog_get_content_area (dialog_data->dialog);

	spinner = gtk_spinner_new ();
	gtk_spinner_start (GTK_SPINNER (spinner));
	spinner_label = gtk_label_new (_("Fetching folder list…"));

	dialog_data->spinner_hbox = (GtkBox *) gtk_hbox_new (FALSE, 6);

	alignment = gtk_alignment_new (1.0, 0.5, 0.0, 1.0);
	gtk_container_add (GTK_CONTAINER (alignment), spinner);
	gtk_misc_set_alignment (GTK_MISC (spinner_label), 0.0, 0.5);

	gtk_box_pack_start (dialog_data->spinner_hbox, alignment, TRUE, TRUE, 0);
	gtk_box_pack_start (dialog_data->spinner_hbox, spinner_label, TRUE, TRUE, 0);

	/* Pack the TreeView into dialog's content area */
	gtk_box_pack_start (content_area, GTK_WIDGET (dialog_data->spinner_hbox), TRUE, TRUE, 6);
	gtk_widget_show_all (GTK_WIDGET (dialog_data->dialog));

	dialog_data->profile = g_strdup (profile);

	/* Fetch folder list and size information in a thread */
	folder_list_thread = g_thread_create (mapi_settings_get_folder_size, dialog_data, TRUE, NULL);

	/* Start the dialog */
	gtk_dialog_run (dialog_data->dialog);

	gtk_widget_destroy (GTK_WIDGET (dialog_data->dialog));

	g_free (dialog_data->profile);
	g_free (dialog_data);
}

static void
folder_size_clicked (GtkButton *button, EAccount *account)
{
	CamelURL *url;

	g_return_if_fail (account != NULL);
	g_return_if_fail (E_IS_ACCOUNT (account));

	url = camel_url_new (e_account_get_string (account,  E_ACCOUNT_SOURCE_URL), NULL);
	g_return_if_fail (url != NULL);

	mapi_settings_run_folder_size_dialog (camel_url_get_param (url, "profile"), NULL);

	camel_url_free (url);
}

static void
action_folder_size_cb (GtkAction *action,
		       EShellView *shell_view)
{
	EShellSidebar *shell_sidebar;
	EMFolderTree *folder_tree;
	gchar *folder_uri;
	GtkTreeSelection *selection;
	gchar *profile = NULL;

	/* Get hold of Folder Tree */
	shell_sidebar = e_shell_view_get_shell_sidebar (shell_view);
	g_object_get (shell_sidebar, "folder-tree", &folder_tree, NULL);
	folder_uri = em_folder_tree_get_selected_uri (folder_tree);
	selection = em_folder_tree_model_get_selection (EM_FOLDER_TREE_MODEL (gtk_tree_view_get_model (GTK_TREE_VIEW (folder_tree))));
	if (selection) {
		GtkTreeIter iter;
		GtkTreeModel *model = NULL;

		if (gtk_tree_selection_get_selected (selection, &model, &iter)) {
			gboolean is_folder = FALSE;
			CamelStore *store = NULL;

			gtk_tree_model_get (model, &iter,
				COL_BOOL_IS_FOLDER, &is_folder,
				COL_POINTER_CAMEL_STORE, &store,
				-1);

			if (is_folder && !store) {
				CamelFolder *folder = em_folder_tree_get_selected_folder (folder_tree);

				if (folder)
					store = camel_folder_get_parent_store (folder);
			}

			if (store && CAMEL_IS_SERVICE (store)) {
				CamelService *service = CAMEL_SERVICE (store);

				if (service->url)
					profile = g_strdup (camel_url_get_param (service->url, "profile"));
			}
		}
	}

	g_object_unref (folder_tree);
	g_return_if_fail (folder_uri != NULL);

	if (g_str_has_prefix (folder_uri, "mapi://"))
		mapi_settings_run_folder_size_dialog (profile, NULL);

	g_free (folder_uri);
	g_free (profile);
}

static void
folder_size_actions_update_cb (EShellView *shell_view, GtkActionEntry *entries)
{
	EShellContent *shell_content;
	EShellWindow *shell_window;
	GtkActionGroup *action_group;
	GtkUIManager *ui_manager;
	GtkAction *folder_size_action;

	EShellSidebar *shell_sidebar;
	EMFolderTree *folder_tree;
	gchar *folder_uri = NULL;
	CamelURL *url = NULL;
	gboolean show_menu_entry = FALSE;

	shell_sidebar = e_shell_view_get_shell_sidebar (shell_view);
	g_object_get (shell_sidebar, "folder-tree", &folder_tree, NULL);
	folder_uri = em_folder_tree_get_selected_uri (folder_tree);
	g_object_unref (folder_tree);
	if (!(folder_uri && *folder_uri)) {
		g_free (folder_uri);
		return;
	}

	shell_content = e_shell_view_get_shell_content (shell_view);
	shell_window = e_shell_view_get_shell_window (shell_view);

	ui_manager = e_shell_window_get_ui_manager (shell_window);
	action_group = e_lookup_action_group (ui_manager, "mail");

	folder_size_action = gtk_action_group_get_action (action_group,
							  "mail-mapi-folder-size");

	/* Show / Hide action entry */
	if (g_str_has_prefix (folder_uri, "mapi://")) {
		show_menu_entry = TRUE;
		url = camel_url_new (folder_uri, NULL);
		if (url && *url->path && strlen (url->path) > 1)
			show_menu_entry = FALSE;
		camel_url_free (url);
	}

	gtk_action_set_visible (folder_size_action, show_menu_entry);
	g_free (folder_uri);
}

/* used only in Account Editor */
GtkWidget *
org_gnome_exchange_mapi_settings (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	EMConfigTargetAccount *target_account;
	CamelURL *url;
	const gchar *source_url;
	GtkVBox *settings;

	/* Miscelleneous setting */
	GtkFrame *frm_misc;
	GtkVBox *vbox_misc;
	GtkTable *tbl_misc;
	GtkLabel *lbl_fsize;
	GtkButton *btn_fsize;

	target_account = (EMConfigTargetAccount *)data->config->target;

	source_url = e_account_get_string (target_account->account,  E_ACCOUNT_SOURCE_URL);

	url = camel_url_new(source_url, NULL);
	if (url == NULL || strcmp(url->protocol, "mapi") != 0) {
		if (url)
			camel_url_free(url);
		return NULL;
	}

	settings = (GtkVBox*) g_object_new (GTK_TYPE_VBOX, "homogeneous", FALSE, "spacing", 6, NULL);
	gtk_container_set_border_width (GTK_CONTAINER (settings), 12);

	/* Miscellaneous settings */
	frm_misc = (GtkFrame*) g_object_new (GTK_TYPE_FRAME, "label", _("Miscellaneous"), NULL);
	gtk_box_pack_start (GTK_BOX (settings), GTK_WIDGET (frm_misc), FALSE, FALSE, 0);

	vbox_misc = (GtkVBox*) g_object_new (GTK_TYPE_VBOX, "homogeneous", FALSE, "spacing", 6, NULL);
	gtk_container_set_border_width (GTK_CONTAINER (vbox_misc), 6);
	gtk_container_add (GTK_CONTAINER (frm_misc), GTK_WIDGET (vbox_misc));

	tbl_misc = (GtkTable*) g_object_new (GTK_TYPE_TABLE, "n-rows", 1, "n-columns", 1,
					     "homogeneous", FALSE, "row-spacing", 6,
					     "column-spacing", 6, NULL);

	/* Folder Size */
	lbl_fsize = (GtkLabel*) g_object_new (GTK_TYPE_LABEL, "label",
					      _("View the size of all Exchange folders"), NULL);
	gtk_misc_set_alignment (GTK_MISC (lbl_fsize), 0, 0.5);
	btn_fsize = (GtkButton*) g_object_new (GTK_TYPE_BUTTON, "label", _("Folder Size"), NULL);
	g_signal_connect (btn_fsize, "clicked", G_CALLBACK (folder_size_clicked), target_account->account);
	gtk_table_attach_defaults (tbl_misc, GTK_WIDGET (lbl_fsize), 0, 1, 0, 1);
	gtk_table_attach (tbl_misc, GTK_WIDGET (btn_fsize), 1, 2, 0, 1, GTK_FILL, GTK_FILL, 0, 0);

	/*Note : Reason for placing this UI is because we try to be like outlook. */
	gtk_box_pack_start (GTK_BOX (vbox_misc), GTK_WIDGET (tbl_misc), FALSE, FALSE, 0);
	gtk_widget_show_all (GTK_WIDGET (settings));

	/*Insert the page*/
	gtk_notebook_insert_page (GTK_NOTEBOOK (data->parent), GTK_WIDGET (settings),
				  gtk_label_new(_("Exchange Settings")), 4);

	return GTK_WIDGET (settings);
}

static GtkActionEntry folder_size_entries[] = {

	{ "mail-mapi-folder-size",
	  NULL,
	  N_("Folder size"),
	  NULL,
	  NULL,  /* XXX Add a tooltip! */
	  G_CALLBACK (action_folder_size_cb) }
};

gboolean
e_plugin_ui_init (GtkUIManager *ui_manager,
                  EShellView *shell_view)
{
	EShellWindow *shell_window;
	GtkActionGroup *action_group;

	shell_window = e_shell_view_get_shell_window (shell_view);
	action_group = e_shell_window_get_action_group (shell_window, "mail");

	/* Add actions to the "mail" action group. */
	gtk_action_group_add_actions (action_group, folder_size_entries,
				      G_N_ELEMENTS (folder_size_entries),
				      shell_view);

	/* Decide whether we want this option to be visible or not */
	g_signal_connect (shell_view, "update-actions",
			  G_CALLBACK (folder_size_actions_update_cb),
			  shell_view);

	g_object_unref (action_group);

	return TRUE;
}
