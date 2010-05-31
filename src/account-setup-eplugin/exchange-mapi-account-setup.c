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
 *		Srinivasa Ragavan <sragavan@novell.com>
 *		Johnny Jacob  <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <unistd.h>
#include <glib/gi18n-lib.h>

#include <gtk/gtk.h>
#include <camel/camel-provider.h>
#include <camel/camel-url.h>
#include <camel/camel-service.h>
#include <camel/camel-folder.h>
#include <libedataserver/e-xml-hash-utils.h>
#include <libedataserverui/e-passwords.h>
#include <libedataserver/e-account.h>
#include <e-util/e-dialog-utils.h>
#include "mail/em-config.h"
#include "exchange-mapi-account-setup.h"
#include <addressbook/gui/widgets/eab-config.h>
#include <calendar/gui/e-cal-config.h>

#include <exchange-mapi-folder.h>
#include <exchange-mapi-connection.h>
#include <exchange-mapi-utils.h>

#define d(x) x

int e_plugin_lib_enable (EPlugin *ep, int enable);

/* Account Setup */
GtkWidget *org_gnome_exchange_mapi_account_setup (EPlugin *epl, EConfigHookItemFactoryData *data);
gboolean org_gnome_exchange_mapi_check_options(EPlugin *epl, EConfigHookPageCheckData *data);

/* New Addressbook/CAL */
GtkWidget *exchange_mapi_create_addressbook (EPlugin *epl, EConfigHookItemFactoryData *data);
GtkWidget *exchange_mapi_create_calendar (EPlugin *epl, EConfigHookItemFactoryData *data);

/* New Addressbook */
gboolean exchange_mapi_book_check (EPlugin *epl, EConfigHookPageCheckData *data);
void exchange_mapi_book_commit (EPlugin *epl, EConfigTarget *target);

/* New calendar/task list/memo list */
gboolean exchange_mapi_cal_check (EPlugin *epl, EConfigHookPageCheckData *data);
void exchange_mapi_cal_commit (EPlugin *epl, EConfigTarget *target);


static ExchangeMAPIAccountListener *config_listener = NULL;

static void 
free_mapi_listener ( void )
{
	g_object_unref (config_listener);
}

int
e_plugin_lib_enable (EPlugin *ep, int enable)
{
	g_debug ("Loading Exchange MAPI Plugin \n");

	if (!config_listener) {
		config_listener = exchange_mapi_account_listener_new ();
	 	g_atexit ( free_mapi_listener );
	}

	return 0;
}

ExchangeMAPIAccountListener *
exchange_mapi_accounts_peek_config_listener ()
{
	return config_listener; 
}

enum {
  COL_MAPI_FULL_NAME = 0,
  COL_MAPI_ACCOUNT,
  COL_MAPI_INDEX,
  COLS_MAX
};

/* Callback for ProcessNetworkProfile. If we have more than one username, 
 we need to let the user select. */
static uint32_t
create_profile_callback (struct SRowSet *rowset, gpointer data)
{
	struct SPropValue *lpProp_fullname, *lpProp_account;
	gint response;
	guint32	i, index = 0;
	GtkTreeIter iter;
	GtkListStore *store;
	GtkCellRenderer *renderer;
	GtkTreeSelection *selection;
	GtkWidget *dialog, *view;
	GtkVBox *vbox;
	const gchar *username = (const gchar *)data;

	/* If we can find the exact username, then find & return its index. */
	for (i = 0; i < rowset->cRows; i++) {
		lpProp_account = get_SPropValue_SRow(&(rowset->aRow[i]), PR_ACCOUNT_UNICODE);
		if (!lpProp_account)
			lpProp_account = get_SPropValue_SRow(&(rowset->aRow[i]), PR_ACCOUNT);

		if (lpProp_account && lpProp_account->value.lpszA &&
		    !g_strcmp0 (username, lpProp_account->value.lpszA))
			return i;
	}

	/* NOTE: A good way would be display the list of username entries */
	/* using GtkEntryCompletion in the username gtkentry. But plugins */
	/* as of now does not have access to it */

	/*TODO : Fix strings*/
	dialog = gtk_dialog_new_with_buttons (_("Select username"),
					      NULL, GTK_DIALOG_MODAL,
					      GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
					      NULL);

	/*Tree View */
	view = gtk_tree_view_new ();
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
						     -1, _("Full name"), renderer,
						     "text", COL_MAPI_FULL_NAME, NULL);

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
						     -1, _("User name"), renderer, 
						     "text", COL_MAPI_ACCOUNT, NULL);

	/* Model for TreeView */
	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT);
	gtk_tree_view_set_model (GTK_TREE_VIEW (view), GTK_TREE_MODEL (store));

	for (i = 0; i < rowset->cRows; i++) {
		lpProp_fullname = get_SPropValue_SRow(&(rowset->aRow[i]), PR_DISPLAY_NAME_UNICODE);
		if (!lpProp_fullname)
			lpProp_fullname = get_SPropValue_SRow(&(rowset->aRow[i]), PR_DISPLAY_NAME);
		lpProp_account = get_SPropValue_SRow(&(rowset->aRow[i]), PR_ACCOUNT_UNICODE);
		if (!lpProp_account)
			lpProp_account = get_SPropValue_SRow(&(rowset->aRow[i]), PR_ACCOUNT);

		if (lpProp_fullname && lpProp_fullname->value.lpszA &&
		    lpProp_account && lpProp_account->value.lpszA) {
			gtk_list_store_append (store, &iter);
			/* Preserve the index inside the store*/
			gtk_list_store_set (store, &iter,
					    COL_MAPI_FULL_NAME, lpProp_fullname->value.lpszA,
					    COL_MAPI_ACCOUNT, lpProp_account->value.lpszA,
					    COL_MAPI_INDEX, i, -1);
		}
	}

	/* Pack the TreeView into dialog's content area */
	vbox = (GtkVBox *)gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	gtk_box_pack_start (GTK_BOX (vbox), view, TRUE, TRUE, 6);
	gtk_widget_show_all (GTK_WIDGET (vbox));

	response = gtk_dialog_run (GTK_DIALOG (dialog));
	if (response == GTK_RESPONSE_ACCEPT) {
	       /* Get the index from the selected value */
		selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (view));
		gtk_tree_selection_get_selected (selection, NULL, &iter);
		gtk_tree_model_get (GTK_TREE_MODEL (store), &iter, COL_MAPI_INDEX, 
				    &index, -1);
	} else /* If we return a value > available, we are canceling the login.*/
	       index = rowset->cRows + 1;

	gtk_widget_destroy (dialog);

	return index;
}

static void
validate_credentials (GtkWidget *widget, EConfig *config)
{
	EMConfigTargetAccount *target_account = (EMConfigTargetAccount *)(config->target);
	CamelURL *url = NULL;
 	gchar *key = NULL, *password = NULL;
	const gchar *domain_name = NULL; 

	url = camel_url_new (e_account_get_string (target_account->account, E_ACCOUNT_SOURCE_URL), NULL);
	domain_name = camel_url_get_param (url, "domain");

	/* Silently remove domain part from a user name when user enters it as such.
	   This change will be visible in the UI on new edit open. */
	if (url->user && strchr (url->user, '\\')) {
		gchar *tmp, *at;

		at = strrchr (url->user, '\\') + 1;
		tmp = g_strdup (at);
		camel_url_set_user (url, tmp);
		g_free (tmp);
	}

	if (!url->user || !*url->user || !url->host || !*url->host || !domain_name || !*domain_name) {
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Server, username and domain name cannot be empty. Please fill them with correct values."));
		return;
	}

	key = camel_url_to_string (url, CAMEL_URL_HIDE_PASSWORD | CAMEL_URL_HIDE_PARAMS);
	password = e_passwords_get_password (EXCHANGE_MAPI_PASSWORD_COMPONENT, key);
	if (!password || !*password) {
		gboolean remember = e_account_get_bool (target_account->account, E_ACCOUNT_SOURCE_SAVE_PASSWD);
		gchar *title;

		g_free (password);
		title = g_strdup_printf (_("Enter Password for %s@%s"), url->user, url->host);
		password = e_passwords_ask_password (title, EXCHANGE_MAPI_PASSWORD_COMPONENT, key, title,
						     E_PASSWORDS_REMEMBER_FOREVER|E_PASSWORDS_SECRET,
						     &remember, NULL);
		g_free (title);
	}

	/*Can there be a account without password ?*/
	if (password && *password && domain_name && *domain_name && *url->user && *url->host) {
		char *error_msg = NULL;
		gboolean status = exchange_mapi_create_profile (url->user, password, domain_name,
								url->host, &error_msg, 
								(mapi_profile_callback_t) create_profile_callback,
								url->user);
		if (status) {
			/* Things are successful */
			gchar *profname = NULL, *uri = NULL; 

			profname = exchange_mapi_util_profile_name (url->user, domain_name);
			camel_url_set_param(url, "profile", profname);
			g_free (profname);

			uri = camel_url_to_string(url, 0);
			e_account_set_string (target_account->account, E_ACCOUNT_SOURCE_URL, uri);
			e_account_set_string (target_account->account, E_ACCOUNT_TRANSPORT_URL, uri);
			g_free (uri);

			e_notice (NULL, GTK_MESSAGE_INFO, "%s", _("Authentication finished successfully."));
		} else {
			char *e;

			e_passwords_forget_password (EXCHANGE_MAPI_PASSWORD_COMPONENT, key);

			e = g_strconcat (_("Authentication failed."), "\n", error_msg, NULL);

			e_notice (NULL, GTK_MESSAGE_ERROR, "%s", e);

			g_free (e);
		}

		g_free (error_msg);
	} else {
		e_passwords_forget_password (EXCHANGE_MAPI_PASSWORD_COMPONENT, key);
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Authentication failed."));
	}

	g_free (password);
	g_free (key);
	camel_url_free (url);
}

static void
domain_entry_changed(GtkWidget *entry, EConfig *config)
{
	EMConfigTargetAccount *target = (EMConfigTargetAccount *)(config->target);
	CamelURL *url = NULL;
	const char *domain = NULL;
	char *url_string = NULL;

	url = camel_url_new (e_account_get_string(target->account, E_ACCOUNT_SOURCE_URL), NULL);
	domain = gtk_entry_get_text (GTK_ENTRY(entry));

	if (domain && domain[0])
		camel_url_set_param (url, "domain", domain);
	else
		camel_url_set_param (url, "domain", NULL);

	url_string = camel_url_to_string (url, 0);
	e_account_set_string (target->account, E_ACCOUNT_SOURCE_URL, url_string);
	e_account_set_string (target->account, E_ACCOUNT_TRANSPORT_URL, url_string);
	g_free (url_string);

	camel_url_free (url);
}

GtkWidget *
org_gnome_exchange_mapi_account_setup (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	EMConfigTargetAccount *target_account;
	CamelURL *url;
	GtkWidget *hbox = NULL;

	target_account = (EMConfigTargetAccount *)data->config->target;
	url = camel_url_new(e_account_get_string(target_account->account, E_ACCOUNT_SOURCE_URL), NULL);

	/* is NULL on New Account creation */
	if (url == NULL)
		return NULL; 

	if (!g_ascii_strcasecmp (url->protocol, "mapi")) {
		GtkWidget *label;
		GtkWidget *domain_name;
		GtkWidget *auth_button;
		const char *domain_value = camel_url_get_param (url, "domain");
		int row = ((GtkTable *)data->parent)->nrows;

		/* Domain name & Authenticate Button */
		hbox = gtk_hbox_new (FALSE, 6);
		label = gtk_label_new_with_mnemonic (_("_Domain name:"));
		gtk_widget_show (label);

		domain_name = gtk_entry_new ();
		gtk_label_set_mnemonic_widget (GTK_LABEL (label), domain_name);
		if (domain_value && *domain_value)
			gtk_entry_set_text (GTK_ENTRY (domain_name), domain_value);
		gtk_box_pack_start (GTK_BOX (hbox), domain_name, FALSE, FALSE, 0);
		g_signal_connect (domain_name, "changed", G_CALLBACK(domain_entry_changed), data->config);

		auth_button = gtk_button_new_with_mnemonic (_("_Authenticate"));
		gtk_box_pack_start (GTK_BOX (hbox), auth_button, FALSE, FALSE, 0);
		g_signal_connect(GTK_OBJECT(auth_button), "clicked",  G_CALLBACK(validate_credentials), data->config);

		gtk_table_attach (GTK_TABLE (data->parent), label, 0, 1, row, row+1, 0, 0, 0, 0);
		gtk_widget_show_all (GTK_WIDGET (hbox));
		gtk_table_attach (GTK_TABLE (data->parent), GTK_WIDGET (hbox), 1, 2, row, row+1, GTK_FILL|GTK_EXPAND, GTK_FILL, 0, 0); 
	}

	camel_url_free (url);
	return hbox;
}

gboolean
org_gnome_exchange_mapi_check_options(EPlugin *epl, EConfigHookPageCheckData *data)
{
	EMConfigTargetAccount *target = (EMConfigTargetAccount *)(data->config->target);
	gboolean status = TRUE;

	if (data->pageid != NULL && g_ascii_strcasecmp (data->pageid, "10.receive") == 0) {
		CamelURL *url = camel_url_new (e_account_get_string(target->account,  
								    E_ACCOUNT_SOURCE_URL), NULL);

		if (url && url->protocol && g_ascii_strcasecmp (url->protocol, "mapi") == 0) {
			const gchar *prof = NULL;

			/* We assume that if the profile is set, then the setting is valid. */
 			prof = camel_url_get_param (url, "profile");

			/*Profile not set. Do not proceed with account creation.*/
			if (!(prof && *prof))
			        status = FALSE;
		} 

		if (url)
			camel_url_free(url);
	}

	return status;
}

enum {
	NAME_COL,
	FID_COL,
	FOLDER_COL,
	NUM_COLS
};


static gboolean
check_node (GtkTreeStore *ts, ExchangeMAPIFolder *folder, GtkTreeIter iter)
{
	GtkTreeModel *ts_model;
	mapi_id_t fid;

	ts_model = GTK_TREE_MODEL (ts);
	
	gtk_tree_model_get (ts_model, &iter, 1, &fid, -1);
	if (fid && folder->parent_folder_id == fid) {
		/* Do something */
		GtkTreeIter node;
		gtk_tree_store_append (ts, &node, &iter);
		gtk_tree_store_set (ts, &node, NAME_COL, folder->folder_name, FID_COL, folder->folder_id, FOLDER_COL, folder,-1);
		return TRUE;
	}

	if (gtk_tree_model_iter_has_child (ts_model, &iter)) {
		GtkTreeIter child;
		gtk_tree_model_iter_children (ts_model, &child, &iter);
		if (check_node (ts, folder, child))
		    return TRUE;
	}

	if (gtk_tree_model_iter_next (ts_model, &iter)) {
		return check_node (ts, folder, iter);
	}

	return FALSE;
}

static void
add_to_store (GtkTreeStore *ts, ExchangeMAPIFolder *folder)
{
	GtkTreeModel *ts_model;
	GtkTreeIter iter;

	ts_model = GTK_TREE_MODEL (ts);
	
	gtk_tree_model_get_iter_first (ts_model, &iter);
	if (!check_node (ts, folder, iter)) {
		GtkTreeIter node;
		gtk_tree_store_append (ts, &node, &iter);		
		gtk_tree_store_set (ts, &node, NAME_COL, folder->folder_name, FID_COL, folder->folder_id, FOLDER_COL, folder, -1);
	}
}

static void
traverse_tree (GtkTreeModel *model, GtkTreeIter iter, ExchangeMAPIFolderType folder_type, gboolean *pany_sub_used)
{
	gboolean any_sub_used = FALSE;
	gboolean has_next = TRUE;

	do {
		gboolean sub_used = FALSE;
		GtkTreeIter next = iter;
		ExchangeMAPIFolder *folder = NULL;

		has_next = gtk_tree_model_iter_next (model, &next);

		if (gtk_tree_model_iter_has_child (model, &iter)) {
			GtkTreeIter child;

			gtk_tree_model_iter_children (model, &child, &iter);
			traverse_tree (model, child, folder_type, &sub_used);
		}

		gtk_tree_model_get (model, &iter, FOLDER_COL, &folder, -1);
		if (folder && (exchange_mapi_folder_get_type (folder) == folder_type || (folder_type == MAPI_FOLDER_TYPE_MEMO && exchange_mapi_folder_get_type (folder) == MAPI_FOLDER_TYPE_JOURNAL))) {
			sub_used = TRUE;
		}

		if (sub_used)
			any_sub_used = TRUE;
		else if (pany_sub_used && folder)
			gtk_tree_store_remove (GTK_TREE_STORE (model), &iter);

		iter = next;
	} while (has_next);

	if (pany_sub_used && any_sub_used)
		*pany_sub_used = TRUE;
}

static void
add_folders (GSList *folders, GtkTreeStore *ts, ExchangeMAPIFolderType folder_type)
{
	GSList *tmp = folders;
	GtkTreeIter iter;
	char *node = _("Personal Folders");
	
	/* add all... */
	gtk_tree_store_append (ts, &iter, NULL);
	gtk_tree_store_set (ts, &iter, NAME_COL, node, -1);
	while (tmp) {
		ExchangeMAPIFolder *folder = tmp->data;
		add_to_store (ts, folder);
		tmp = tmp->next;
	}

	/* ... then remove those which don't belong to folder_type */
	if (gtk_tree_model_get_iter_first ((GtkTreeModel *)ts, &iter)) {
		traverse_tree ((GtkTreeModel *)ts, iter, folder_type, NULL);
	}
}

static void
select_folder (GtkTreeModel *model, mapi_id_t fid, GtkWidget *tree_view)
{
	GtkTreeIter iter, next;
	gboolean found = FALSE, can = TRUE;

	g_return_if_fail (model != NULL);
	g_return_if_fail (tree_view != NULL);

	if (!gtk_tree_model_get_iter_first (model, &iter))
		return;

	while (!found && can) {
		ExchangeMAPIFolder *folder = NULL;

		gtk_tree_model_get (model, &iter, FOLDER_COL, &folder, -1);

		if (folder && exchange_mapi_folder_get_fid (folder) == fid) {
			gtk_tree_selection_select_iter (gtk_tree_view_get_selection (GTK_TREE_VIEW (tree_view)), &iter);
			found = TRUE;
			break;
		}

		can = FALSE;
		if (gtk_tree_model_iter_children (model, &next, &iter)) {
			iter = next;
			can = TRUE;
		}

		next = iter;
		if (!can && gtk_tree_model_iter_next (model, &next)) {
			iter = next;
			can = TRUE;
		}

		if (!can && gtk_tree_model_iter_parent (model, &next, &iter)) {
			while (!can) {
				iter = next;

				if (gtk_tree_model_iter_next (model, &iter)) {
					can = TRUE;
					break;
				}

				iter = next;
				if (!gtk_tree_model_iter_parent (model, &next, &iter))
					break;
			}
		}
	}
}

static void
exchange_mapi_cursor_change (GtkTreeView *treeview, ESource *source)
{
	GtkTreeSelection *selection;
	GtkTreeModel     *model;
	GtkTreeIter       iter;
	mapi_id_t pfid;
	gchar *sfid=NULL;
	
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
	gtk_tree_selection_get_selected(selection, &model, &iter);

	gtk_tree_model_get (model, &iter, FID_COL, &pfid, -1);
	sfid = exchange_mapi_util_mapi_id_to_string (pfid);
	e_source_set_property (source, "parent-fid", sfid); 
	g_free (sfid);
}

static GtkWidget *
exchange_mapi_create (GtkWidget *parent, ESource *source, ExchangeMAPIFolderType folder_type)
{
	GtkWidget *vbox, *label, *scroll, *tv;
	char *uri_text;
	GtkCellRenderer *rcell;
	GtkTreeStore *ts;
	GtkTreeViewColumn *tvc;
	const char *acc;
	GSList *folders;
	mapi_id_t fid = 0;

	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		return NULL;
	}

	folders = exchange_mapi_account_listener_peek_folder_list ();
	acc = e_source_group_peek_name (e_source_peek_group (source));
	ts = gtk_tree_store_new (NUM_COLS, G_TYPE_STRING, G_TYPE_INT64, G_TYPE_POINTER);

	add_folders (folders, ts, folder_type);
	
	vbox = gtk_vbox_new (FALSE, 6);

	if (folder_type == MAPI_FOLDER_TYPE_CONTACT) {
		gtk_container_add (GTK_CONTAINER (parent), vbox);
	} else {
		gint row;
		g_object_get (parent, "n-rows", &row, NULL);
		gtk_table_attach (GTK_TABLE (parent), vbox, 0, 2, row+1, row+2, GTK_FILL|GTK_EXPAND, 0, 0, 0);
	}

	label = gtk_label_new_with_mnemonic (_("_Location:"));
	gtk_widget_show (label);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
	
	rcell = gtk_cell_renderer_text_new ();
	tvc = gtk_tree_view_column_new_with_attributes (acc, rcell, "text", NAME_COL, NULL);
	tv = gtk_tree_view_new_with_model (GTK_TREE_MODEL (ts));
	gtk_tree_view_append_column (GTK_TREE_VIEW (tv), tvc);
	g_object_set (tv,"expander-column", tvc, "headers-visible", TRUE, NULL);
	gtk_tree_view_expand_all (GTK_TREE_VIEW (tv));
	
	if (e_source_get_property (source, "folder-id")) {
		exchange_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &fid);
		select_folder (GTK_TREE_MODEL (ts), fid, tv);
	}

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);
	g_object_set (scroll, "height-request", 150, NULL);
	gtk_container_add (GTK_CONTAINER (scroll), tv);
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), tv);
	g_signal_connect (G_OBJECT (tv), "cursor-changed", G_CALLBACK (exchange_mapi_cursor_change), source);
	gtk_widget_show_all (scroll);

	gtk_box_pack_start (GTK_BOX (vbox), scroll, FALSE, FALSE, 0);

	gtk_widget_show_all (vbox);
	return vbox;
}

GtkWidget *
exchange_mapi_create_addressbook (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) data->target;

	return exchange_mapi_create (data->parent, t->source, MAPI_FOLDER_TYPE_CONTACT);
}

GtkWidget *
exchange_mapi_create_calendar (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	ECalConfigTargetSource *t = (ECalConfigTargetSource *) data->target;
	ExchangeMAPIFolderType folder_type;

	switch (t->source_type) {
	case E_CAL_SOURCE_TYPE_EVENT:
		folder_type = MAPI_FOLDER_TYPE_APPOINTMENT;
		break;
	case E_CAL_SOURCE_TYPE_TODO:
		folder_type = MAPI_FOLDER_TYPE_TASK;
		break;
	case E_CAL_SOURCE_TYPE_JOURNAL:
		folder_type = MAPI_FOLDER_TYPE_MEMO;
		break;
	default:
		g_return_val_if_reached (NULL);
	}

	return exchange_mapi_create (data->parent, t->source, folder_type);
}

gboolean
exchange_mapi_book_check (EPlugin *epl, EConfigHookPageCheckData *data)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) data->target;
	ESource *source = t->source;
	char *uri_text = e_source_get_uri (source);

	if (!uri_text)
		return TRUE;

	/* FIXME: Offline handling */

	/* not a MAPI account */
	if (g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		g_free (uri_text);
		return TRUE;
	}

	/* does not have a parent-fid which is needed for folder creation on server */
	if (!e_source_get_property (source, "parent-fid")) {
		g_free (uri_text);
		return FALSE;
	}

	g_free (uri_text);
	return TRUE;
}

void 
exchange_mapi_book_commit (EPlugin *epl, EConfigTarget *target)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) target;
	ESource *source = t->source;
	char *uri_text;
	ESourceGroup *grp;
	
	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH))
		return;
	
	//FIXME: Offline handling
	grp = e_source_peek_group (source);
	e_source_set_property (source, "auth", "plain/password");
	e_source_set_property (source, "auth-domain", EXCHANGE_MAPI_PASSWORD_COMPONENT);
	e_source_set_property(source, "user", e_source_group_get_property (grp, "user"));
	e_source_set_property(source, "host", e_source_group_get_property (grp, "host"));
	e_source_set_property(source, "profile", e_source_group_get_property (grp, "profile"));
	e_source_set_property(source, "domain", e_source_group_get_property (grp, "domain"));
	e_source_set_relative_uri (source, g_strconcat (";",e_source_peek_name (source), NULL));

	e_source_set_property (source, "completion", "true");
	// Update the folder list in the plugin and ExchangeMAPIFolder

	return;
}


/* New calendar/task list/memo list */
gboolean
exchange_mapi_cal_check (EPlugin *epl, EConfigHookPageCheckData *data)
{
	ECalConfigTargetSource *t = (ECalConfigTargetSource *)(data->target);
	ESource *source = t->source;
	char *uri_text = e_source_get_uri (source);

	if (!uri_text)
		return TRUE; 

	/* FIXME: Offline handling */

	/* not a MAPI account */
	if (g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		g_free (uri_text); 
		return TRUE; 
	}

	g_free (uri_text);

	/* FIXME: Offline handling */

	/* does not have a parent-fid which is needed for folder creation on server */
	if (!e_source_get_property (source, "parent-fid"))
		return FALSE;

	return TRUE;
}

void 
exchange_mapi_cal_commit (EPlugin *epl, EConfigTarget *target)
{
	ECalConfigTargetSource *t = (ECalConfigTargetSource *) target;
	ESourceGroup *group;
	ESource *source = t->source;
	gchar *tmp, *sfid;
	mapi_id_t fid, pfid;
	uint32_t type;
	char *uri_text = e_source_get_uri (source);

	if (!uri_text || g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH))
		return;
	g_free (uri_text);

	switch (t->source_type) {
		case E_CAL_SOURCE_TYPE_EVENT: 
			type = olFolderCalendar; 
			break;
		case E_CAL_SOURCE_TYPE_TODO: 
			type = olFolderTasks; 
			break;
		case E_CAL_SOURCE_TYPE_JOURNAL: 
			type = olFolderNotes; 
			break;
		default: 
			g_warning ("%s: %s: Unknown ExchangeMAPIFolderType\n", G_STRLOC, G_STRFUNC);
			return;
	}

	/* FIXME: Offline handling */

	exchange_mapi_util_mapi_id_from_string (e_source_get_property (source, "parent-fid"), &pfid);

	fid = exchange_mapi_create_folder (type, pfid, e_source_peek_name (source));

	sfid = exchange_mapi_util_mapi_id_to_string (fid);
	tmp = g_strconcat (";", sfid, NULL);
	e_source_set_relative_uri (source, tmp);
	g_free (tmp);
	g_free (sfid);

	e_source_set_property (source, "auth", "1");
	e_source_set_property (source, "auth-domain", EXCHANGE_MAPI_PASSWORD_COMPONENT);
	e_source_set_property (source, "auth-type", "plain/password");

	group = e_source_peek_group (source);

	tmp = e_source_group_get_property (group, "username");
	e_source_set_property (source, "username", tmp);
	g_free (tmp);
	
	tmp = e_source_group_get_property (group, "host");
	e_source_set_property (source, "host", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (group, "profile");
	e_source_set_property (source, "profile", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (group, "domain");
	e_source_set_property (source, "domain", tmp);
	g_free (tmp);

	tmp = exchange_mapi_util_mapi_id_to_string (fid);
	e_source_set_property (source, "folder-id", tmp);
	g_free (tmp);

	e_source_set_property (source, "offline_sync", "0");

	/* Delegatees can never create folders for delegators. So we can copy safely. */
	tmp = e_source_group_get_property (group, "acl-user-name");
	e_source_set_property (source, "acl-user-name", tmp);
	g_free (tmp);
	tmp = e_source_group_get_property (group, "acl-user-email");
	e_source_set_property (source, "acl-user-email", tmp);
	g_free (tmp);
	tmp = e_source_group_get_property (group, "acl-owner-name");
	e_source_set_property (source, "acl-owner-name", tmp);
	g_free (tmp);
	tmp = e_source_group_get_property (group, "acl-owner-email");
	e_source_set_property (source, "acl-owner-email", tmp);
	g_free (tmp);

	// Update the folder list in the plugin and ExchangeMAPIFolder
	return;
}
