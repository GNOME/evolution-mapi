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

#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <camel/camel-provider.h>
#include <camel/camel-url.h>
#include <camel/camel-service.h>
#include <camel/camel-folder.h>
#include <libedataserver/e-xml-hash-utils.h>
#include <libedataserverui/e-passwords.h>
#include <libedataserver/e-account.h>
#include <e-util/e-dialog-utils.h>

#include <exchange-mapi-folder.h>
#include <exchange-mapi-connection.h>
#include <exchange-mapi-utils.h>

#include "mail/em-config.h"
#include "exchange-mapi-account-listener.h"

enum {
	COL_FOLDERSIZE_NAME = 0,
	COL_FOLDERSIZE_SIZE,
	COL_FOLDERSIZE_MAX
};

static void
mapi_settings_run_folder_size_dialog ()
{
	GtkDialog *dialog; 
	GtkBox *content_area;
	/* TreeView */
	GtkTreeView *view;
	GtkCellRenderer *renderer;
	GtkListStore *store;
	GtkTreeIter iter;

	/* TODO :This should be in a thread. If the folder list is not cached, we would be blocking UI. */
	GSList *folder_list = exchange_mapi_account_listener_peek_folder_list ();
	
	dialog = (GtkDialog *)gtk_dialog_new_with_buttons (_("Folder Size"), NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
							   GTK_STOCK_CLOSE, GTK_RESPONSE_ACCEPT, NULL);
	content_area = gtk_dialog_get_content_area (dialog);

	/*Tree View */
	view = gtk_tree_view_new ();
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),-1, 
						     _("Folder"), renderer, "text", COL_FOLDERSIZE_NAME,
						     NULL);

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),-1, 
						     _("Size"), renderer, "text", COL_FOLDERSIZE_SIZE,
						     NULL);
	/* Model for TreeView */
	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_tree_view_set_model (GTK_TREE_VIEW (view), GTK_TREE_MODEL (store));

	while (folder_list) {
		  ExchangeMAPIFolder *folder = (ExchangeMAPIFolder *) folder_list->data;
		  gchar *folder_size = g_format_size_for_display (folder->size);

		  gtk_list_store_append (store, &iter);
		  gtk_list_store_set (store, &iter, 
				      COL_FOLDERSIZE_NAME, folder->folder_name,
				      COL_FOLDERSIZE_SIZE, folder_size,
				      -1);
		  folder_list = g_slist_next (folder_list);
		  g_free (folder_size);
	}

	/* Pack the TreeView into dialog's content area */
	gtk_box_pack_start (content_area, view, TRUE, TRUE, 6);

	gtk_widget_show_all (dialog);

	gtk_dialog_run (dialog);
	gtk_widget_destroy (dialog);
}

static void
folder_size_clicked (GtkButton *button, gpointer data)
{
	mapi_settings_run_folder_size_dialog ();
}

/* only used in editor */
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

	/* Miscelleneous settings */
	frm_misc = (GtkFrame*) g_object_new (GTK_TYPE_FRAME, "label", _("Miscelleneous"), NULL);
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
	btn_fsize = (GtkButton*) g_object_new (GTK_TYPE_BUTTON, "label", _("Folders Size"), NULL);
	g_signal_connect (btn_fsize, "clicked", G_CALLBACK (folder_size_clicked), NULL);
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
