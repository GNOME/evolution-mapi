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
#include <libedataserver/e-xml-hash-utils.h>
#include <libedataserverui/e-passwords.h>
#include <libedataserver/e-account.h>
#include <e-util/e-dialog-utils.h>
#include "mail/em-config.h"
#include "e-mapi-account-setup.h"
#include <addressbook/gui/widgets/eab-config.h>
#include <calendar/gui/e-cal-config.h>
#include <shell/e-shell.h>

#include <e-mapi-folder.h>
#include <e-mapi-connection.h>
#include <e-mapi-utils.h>

#define d(x)

gint e_plugin_lib_enable (EPlugin *ep, gint enable);

/* Account Setup */
GtkWidget *org_gnome_e_mapi_account_setup (EPlugin *epl, EConfigHookItemFactoryData *data);
gboolean org_gnome_e_mapi_check_options(EPlugin *epl, EConfigHookPageCheckData *data);

/* New Addressbook/CAL */
GtkWidget *e_mapi_create_addressbook (EPlugin *epl, EConfigHookItemFactoryData *data);
GtkWidget *e_mapi_create_calendar (EPlugin *epl, EConfigHookItemFactoryData *data);

/* New Addressbook */
gboolean e_mapi_book_check (EPlugin *epl, EConfigHookPageCheckData *data);
void e_mapi_book_commit (EPlugin *epl, EConfigTarget *target);

/* New calendar/task list/memo list */
gboolean e_mapi_cal_check (EPlugin *epl, EConfigHookPageCheckData *data);
void e_mapi_cal_commit (EPlugin *epl, EConfigTarget *target);

static EMapiAccountListener *config_listener = NULL;

static void
free_mapi_listener ( void )
{
	g_object_unref (config_listener);
}

gint
e_plugin_lib_enable (EPlugin *ep, gint enable)
{
	d(e_mapi_debug_print ("Loading Exchange MAPI Plugin"));

	if (!config_listener) {
		config_listener = e_mapi_account_listener_new ();
		g_atexit ( free_mapi_listener );
	}

	return 0;
}

EMapiAccountListener *
e_mapi_accounts_peek_config_listener ()
{
	return config_listener;
}

enum {
  COL_MAPI_FULL_NAME = 0,
  COL_MAPI_ACCOUNT,
  COL_MAPI_INDEX,
  COLS_MAX
};

static void
tree_selection_changed (GtkTreeSelection *selection, GtkDialog *dialog)
{
	gtk_dialog_set_response_sensitive (dialog, GTK_RESPONSE_ACCEPT, gtk_tree_selection_get_selected (selection, NULL, NULL));
}

static gboolean
transform_security_method_to_boolean (GBinding *binding,
                                      const GValue *source_value,
                                      GValue *target_value,
                                      gpointer not_used)
{
	CamelNetworkSecurityMethod security_method;
	gboolean use_ssl;

	security_method = g_value_get_enum (source_value);
	use_ssl = (security_method != CAMEL_NETWORK_SECURITY_METHOD_NONE);
	g_value_set_boolean (target_value, use_ssl);

	return TRUE;
}

static gboolean
transform_boolean_to_security_method (GBinding *binding,
                                      const GValue *source_value,
                                      GValue *target_value,
                                      gpointer not_used)
{
	CamelNetworkSecurityMethod security_method;
	gboolean use_ssl;

	use_ssl = g_value_get_boolean (source_value);
	if (use_ssl)
		security_method = CAMEL_NETWORK_SECURITY_METHOD_SSL_ON_ALTERNATE_PORT;
	else
		security_method = CAMEL_NETWORK_SECURITY_METHOD_NONE;
	g_value_set_enum (target_value, security_method);

	return TRUE;
}

/* Callback for ProcessNetworkProfile. If we have more than one username,
 we need to let the user select. */
static uint32_t
create_profile_callback (struct SRowSet *rowset, gconstpointer data)
{
	struct SPropValue *lpProp_fullname, *lpProp_account;
	gint response;
	guint32	i, index = 0;
	GtkTreeIter iter;
	GtkListStore *store;
	GtkCellRenderer *renderer;
	GtkTreeSelection *selection;
	GtkWidget *dialog, *view;
	GtkBox *content_area;
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
					      GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
					      GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
					      NULL);

	/*Tree View */
	view = gtk_tree_view_new ();
	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
						     -1, _("Full name"), renderer,
						     "text", COL_MAPI_FULL_NAME, NULL);

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (view),
						     -1, _("Username"), renderer,
						     "text", COL_MAPI_ACCOUNT, NULL);

	gtk_tree_view_column_set_resizable (gtk_tree_view_get_column (GTK_TREE_VIEW (view), 0), TRUE);
	gtk_tree_view_column_set_resizable (gtk_tree_view_get_column (GTK_TREE_VIEW (view), 1), TRUE);

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
	content_area = GTK_BOX (gtk_dialog_get_content_area (GTK_DIALOG (dialog)));

	gtk_box_pack_start (content_area, gtk_label_new (_("There are more users with similar user name on a server.\nPlease select that you would like to use from the below list.")), TRUE, TRUE, 6);
	gtk_box_pack_start (content_area, view, TRUE, TRUE, 6);

	gtk_widget_show_all (GTK_WIDGET (content_area));

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (view));
	g_signal_connect (selection, "changed", G_CALLBACK (tree_selection_changed), dialog);
	tree_selection_changed (selection, GTK_DIALOG (dialog));

	response = gtk_dialog_run (GTK_DIALOG (dialog));
	if (response == GTK_RESPONSE_ACCEPT) {
	       /* Get the index from the selected value */
		if (gtk_tree_selection_get_selected (selection, NULL, &iter))
			gtk_tree_model_get (GTK_TREE_MODEL (store), &iter, COL_MAPI_INDEX, &index, -1);
		else
			index = rowset->cRows + 1;
	} else /* If we return a value > available, we are canceling the login.*/
	       index = rowset->cRows + 1;

	gtk_widget_destroy (dialog);

	return index;
}

static char*
prompt_password(const gchar *user, const gchar *host, const gchar *key,
		EMConfigTargetSettings *account)
{
	int pw_flags = E_PASSWORDS_REMEMBER_FOREVER|E_PASSWORDS_SECRET;
	gchar *password, *title;
	gboolean save = TRUE;

	title = g_strdup_printf (_("Enter Password for %s@%s"), user, host);
	password = e_passwords_ask_password (title, NULL, key, title, pw_flags,
					     &save, NULL);
	g_free (title);

	return password;
}

static void
validate_credentials (GtkWidget *widget, EConfig *config)
{
	EMConfigTargetSettings *target_account = (EMConfigTargetSettings *)(config->target);
	CamelURL *url = NULL;
	gchar *key = NULL;
	EMapiProfileData empd = { 0 };
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	CamelNetworkSettings *network_settings;
	const gchar *host;
	const gchar *user;
	GError *error = NULL;

	if (!e_shell_get_online (e_shell_get_default ())) {
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Cannot create MAPI folders in offline mode."));
		return;
	}

	settings = target_account->storage_settings;
	mapi_settings = CAMEL_MAPI_SETTINGS (settings);
	network_settings = CAMEL_NETWORK_SETTINGS (settings);

	host = camel_network_settings_get_host (network_settings);
	user = camel_network_settings_get_user (network_settings);

	/* Silently remove domain part from a username when user enters it as such.
	   This change will be visible in the UI on new edit open. */
	if (user != NULL && strchr (user, '\\') != NULL) {
		gchar *at;

		at = strrchr (user, '\\') + 1;
		camel_network_settings_set_user (network_settings, at);
		user = camel_network_settings_get_user (network_settings);
	}

	empd.server = host;
	empd.username = user;
	e_mapi_util_profiledata_from_settings (&empd, mapi_settings);

	if (!empd.username || !*(empd.username)
	    || !empd.server || !*(empd.server)
	    || ((!empd.domain || !*(empd.domain))
		&& !empd.krb_sso)) {
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Server, username and domain name cannot be empty. Please fill them with correct values."));
		return;
	} else if (empd.krb_sso && (!empd.krb_realm || !*(empd.krb_realm))) {
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Realm name cannot be empty when kerberos is selected. Please fill them with correct values."));
		return;
	}

	url = g_malloc0 (sizeof (CamelURL));
	camel_settings_save_to_url (settings, url);
	key = camel_url_to_string (url, CAMEL_URL_HIDE_PARAMS);
	camel_url_free (url);

	if (empd.krb_sso) {
		e_mapi_util_trigger_krb_auth (&empd, &error);
	} else {
		empd.password = prompt_password(empd.username, empd.server,
						key, target_account);
	}

	if (COMPLETE_PROFILEDATA(&empd)) {
		gboolean status;
		struct mapi_context *mapi_ctx = NULL;

		status = e_mapi_utils_create_mapi_context (&mapi_ctx, &error);
		status = status && e_mapi_create_profile (mapi_ctx, &empd, (mapi_profile_callback_t) create_profile_callback, empd.username, NULL, &error);
		if (status) {
			/* profile was created, try to connect to the server */
			EMapiConnection *conn;
			gchar *profname;

			status = FALSE;
			profname = e_mapi_util_profile_name (mapi_ctx, &empd, FALSE);

			conn = e_mapi_connection_new (profname, empd.password, NULL, &error);
			if (conn) {
				status = e_mapi_connection_connected (conn);
				g_object_unref (conn);
			}

			g_free (profname);
		}

		if (status) {
			/* Things are successful */
			gchar *profname = NULL;

			profname = e_mapi_util_profile_name (mapi_ctx, &empd, FALSE);
			camel_mapi_settings_set_profile (mapi_settings, profname);
			g_free (profname);

			e_notice (NULL, GTK_MESSAGE_INFO, "%s", _("Authentication finished successfully."));
		} else {
			gchar *e;

			e_passwords_forget_password (NULL, key);

			e = g_strconcat (_("Authentication failed."), "\n", error ? error->message : NULL, NULL);

			e_notice (NULL, GTK_MESSAGE_ERROR, "%s", e);

			g_free (e);
		}

		e_mapi_utils_destroy_mapi_context (mapi_ctx);
	} else {
		e_passwords_forget_password (NULL, key);
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Authentication failed."));
	}

	if (error)
		g_error_free (error);

	g_free (empd.password);
	g_free (key);
}

GtkWidget *
org_gnome_e_mapi_account_setup (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	EMConfigTargetSettings *target_account;
	CamelSettings *settings;
	GtkWidget *hgrid = NULL;
	GtkWidget *label;
	GtkWidget *domain_name;
	GtkWidget *realm_name;
	GtkWidget *auth_button;
	GtkWidget *secure_conn;
	GtkWidget *krb_sso;
	gint row;

	target_account = (EMConfigTargetSettings *)data->config->target;
	settings = target_account->storage_settings;

	if (!CAMEL_IS_MAPI_SETTINGS (settings))
		return NULL;

	g_object_get (data->parent, "n-rows", &row, NULL);

	/* Domain name & Authenticate Button */
	hgrid = g_object_new (GTK_TYPE_GRID, "column-homogeneous", FALSE, "column-spacing", 6, "orientation", GTK_ORIENTATION_HORIZONTAL, NULL);
	label = gtk_label_new_with_mnemonic (_("_Domain name:"));
	gtk_widget_show (label);

	domain_name = gtk_entry_new ();
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), domain_name);
	gtk_container_add (GTK_CONTAINER (hgrid), domain_name);
	g_object_bind_property (
		settings, "domain",
		domain_name, "text",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	auth_button = gtk_button_new_with_mnemonic (_("_Authenticate"));
	gtk_container_add (GTK_CONTAINER (hgrid), auth_button);
	g_signal_connect (auth_button, "clicked",  G_CALLBACK (validate_credentials), data->config);

	gtk_table_attach (GTK_TABLE (data->parent), label, 0, 1, row, row+1, 0, 0, 0, 0);
	gtk_widget_show_all (GTK_WIDGET (hgrid));
	gtk_table_attach (GTK_TABLE (data->parent), GTK_WIDGET (hgrid), 1, 2, row, row+1, GTK_FILL|GTK_EXPAND, GTK_FILL, 0, 0);

	row++;
	secure_conn = gtk_check_button_new_with_mnemonic (_("_Use secure connection"));
	gtk_widget_show (secure_conn);
	gtk_table_attach (GTK_TABLE (data->parent), GTK_WIDGET (secure_conn), 1, 2, row, row + 1, GTK_FILL | GTK_EXPAND, GTK_FILL, 0, 0);

	g_object_bind_property_full (
		settings, "security-method",
		secure_conn, "active",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE,
		transform_security_method_to_boolean,
		transform_boolean_to_security_method,
		NULL, (GDestroyNotify) NULL);

	row++;
	krb_sso = gtk_check_button_new_with_mnemonic (_("_Kerberos authentication"));

	g_object_bind_property (
		settings, "kerberos",
		krb_sso, "active",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);
	gtk_widget_show (krb_sso);
	gtk_table_attach (GTK_TABLE (data->parent), GTK_WIDGET (krb_sso), 1, 2, row, row + 1, GTK_FILL | GTK_EXPAND, GTK_FILL, 0, 0);

	row++;
	label = gtk_label_new_with_mnemonic (_("_Realm name:"));
	gtk_widget_show (label);

	g_object_bind_property (
		settings, "kerberos",
		label, "sensitive",
		G_BINDING_SYNC_CREATE);

	realm_name = gtk_entry_new ();
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), realm_name);
	gtk_widget_show (realm_name);

	g_object_bind_property (
		settings, "realm",
		realm_name, "text",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	g_object_bind_property (
		settings, "kerberos",
		realm_name, "sensitive",
		G_BINDING_SYNC_CREATE);

	gtk_table_attach (GTK_TABLE (data->parent), label, 0, 1, row, row + 1, 0, 0, 0, 0);
	gtk_table_attach (GTK_TABLE (data->parent), GTK_WIDGET (realm_name), 1, 2, row, row + 1, GTK_FILL | GTK_EXPAND, GTK_FILL, 0, 0);

	return hgrid;
}

gboolean
org_gnome_e_mapi_check_options(EPlugin *epl, EConfigHookPageCheckData *data)
{
	EMConfigTargetSettings *target = (EMConfigTargetSettings *)(data->config->target);
	CamelMapiSettings *mapi_settings;
	gboolean status = TRUE;

	if (!CAMEL_IS_MAPI_SETTINGS (target->storage_settings))
		return TRUE;

	mapi_settings = CAMEL_MAPI_SETTINGS (target->storage_settings);

	if (data->pageid != NULL && g_ascii_strcasecmp (data->pageid, "10.receive") == 0) {
		const gchar *profile = NULL;

		/* We assume that if the profile is set, then the setting is valid. */
		profile = camel_mapi_settings_get_profile (mapi_settings);

		/* Profile not set. Do not proceed with account creation.*/
		status = (profile != NULL && *profile != '\0');
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
check_node (GtkTreeStore *ts, EMapiFolder *folder, GtkTreeIter iter)
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
add_to_store (GtkTreeStore *ts, EMapiFolder *folder)
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
traverse_tree (GtkTreeModel *model, GtkTreeIter iter, EMapiFolderType folder_type, gboolean *pany_sub_used)
{
	gboolean any_sub_used = FALSE;
	gboolean has_next = TRUE;

	do {
		gboolean sub_used = FALSE;
		GtkTreeIter next = iter;
		EMapiFolder *folder = NULL;

		has_next = gtk_tree_model_iter_next (model, &next);

		if (gtk_tree_model_iter_has_child (model, &iter)) {
			GtkTreeIter child;

			gtk_tree_model_iter_children (model, &child, &iter);
			traverse_tree (model, child, folder_type, &sub_used);
		}

		gtk_tree_model_get (model, &iter, FOLDER_COL, &folder, -1);
		if (folder && (e_mapi_folder_get_type (folder) == folder_type || (folder_type == MAPI_FOLDER_TYPE_MEMO && e_mapi_folder_get_type (folder) == MAPI_FOLDER_TYPE_JOURNAL))) {
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
add_folders (GSList *folders, GtkTreeStore *ts, EMapiFolderType folder_type)
{
	GSList *tmp = folders;
	GtkTreeIter iter;
	gchar *node = _("Personal Folders");

	/* add all... */
	gtk_tree_store_append (ts, &iter, NULL);
	gtk_tree_store_set (ts, &iter, NAME_COL, node, -1);
	while (tmp) {
		EMapiFolder *folder = tmp->data;
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
		EMapiFolder *folder = NULL;

		gtk_tree_model_get (model, &iter, FOLDER_COL, &folder, -1);

		if (folder && e_mapi_folder_get_fid (folder) == fid) {
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
e_mapi_cursor_change (GtkTreeView *treeview, ESource *source)
{
	GtkTreeSelection *selection;
	GtkTreeModel     *model;
	GtkTreeIter       iter;
	mapi_id_t pfid;
	gchar *sfid = NULL;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
	if (gtk_tree_selection_get_selected (selection, &model, &iter)) {
		gtk_tree_model_get (model, &iter, FID_COL, &pfid, -1);
		sfid = e_mapi_util_mapi_id_to_string (pfid);
		e_source_set_property (source, "parent-fid", sfid);
		g_free (sfid);
	} else {
		e_source_set_property (source, "parent-fid", NULL);
	}
}

static GtkWidget *
e_mapi_create (GtkWidget *parent, ESource *source, EMapiFolderType folder_type)
{
	GtkWidget *table, *label, *scroll, *tv;
	gchar *uri_text, *profile = NULL;
	ESourceGroup *group;
	gint row;
	GtkCellRenderer *rcell;
	GtkTreeStore *ts;
	GtkTreeViewColumn *tvc;
	const gchar *acc;
	GSList *folders;
	EMapiConnection *conn;
	mapi_id_t fid = 0;

	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		return NULL;
	}

	folders = NULL;
	group = e_source_peek_group (source);
	profile = g_strdup (e_source_get_property (source, "profile"));
	if (profile == NULL) {
		profile = e_source_group_get_property (group, "profile");
		e_source_set_property (source, "profile", profile);
	}
	conn = e_mapi_connection_find (profile);
	g_free (profile);
	if (conn && e_mapi_connection_connected (conn))
		folders = e_mapi_connection_peek_folders_list (conn);
	acc = e_source_group_peek_name (group);
	ts = gtk_tree_store_new (NUM_COLS, G_TYPE_STRING, G_TYPE_INT64, G_TYPE_POINTER);

	add_folders (folders, ts, folder_type);

	if (conn)
		g_object_unref (conn);

	table = g_object_new (GTK_TYPE_TABLE, NULL);

	if (folder_type == MAPI_FOLDER_TYPE_CONTACT) {
		gtk_container_add (GTK_CONTAINER (parent), table);
	} else {
		g_object_get (parent, "n-rows", &row, NULL);
		gtk_table_attach (GTK_TABLE (parent), table, 0, 2, row, row + 1, GTK_FILL|GTK_EXPAND, 0, 0, 0);
	}

	label = gtk_label_new_with_mnemonic (_("_Location:"));
	gtk_widget_show (label);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_table_attach (GTK_TABLE (table), label, 0, 1, 0, 1, GTK_FILL | GTK_EXPAND, 0, 0, 0);

	rcell = gtk_cell_renderer_text_new ();
	tvc = gtk_tree_view_column_new_with_attributes (acc, rcell, "text", NAME_COL, NULL);
	tv = gtk_tree_view_new_with_model (GTK_TREE_MODEL (ts));
	gtk_tree_view_append_column (GTK_TREE_VIEW (tv), tvc);
	g_object_set (tv,"expander-column", tvc, "headers-visible", TRUE, NULL);
	gtk_tree_view_expand_all (GTK_TREE_VIEW (tv));

	if (e_source_get_property (source, "folder-id")) {
		e_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &fid);
		select_folder (GTK_TREE_MODEL (ts), fid, tv);
	}

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);
	g_object_set (scroll, "height-request", 150, NULL);
	gtk_container_add (GTK_CONTAINER (scroll), tv);
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), tv);
	g_signal_connect (G_OBJECT (tv), "cursor-changed", G_CALLBACK (e_mapi_cursor_change), source);
	gtk_widget_show_all (scroll);

	gtk_table_attach (GTK_TABLE (table), scroll, 0, 1, 1, 2, GTK_FILL | GTK_EXPAND, 0, 0, 0);

	gtk_widget_show_all (table);

	return table;
}

GtkWidget *
e_mapi_create_addressbook (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) data->target;

	return e_mapi_create (data->parent, t->source, MAPI_FOLDER_TYPE_CONTACT);
}

GtkWidget *
e_mapi_create_calendar (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	ECalConfigTargetSource *t = (ECalConfigTargetSource *) data->target;
	EMapiFolderType folder_type;

	switch (t->source_type) {
	case E_CAL_CLIENT_SOURCE_TYPE_EVENTS:
		folder_type = MAPI_FOLDER_TYPE_APPOINTMENT;
		break;
	case E_CAL_CLIENT_SOURCE_TYPE_TASKS:
		folder_type = MAPI_FOLDER_TYPE_TASK;
		break;
	case E_CAL_CLIENT_SOURCE_TYPE_MEMOS:
		folder_type = MAPI_FOLDER_TYPE_MEMO;
		break;
	default:
		g_return_val_if_reached (NULL);
	}

	return e_mapi_create (data->parent, t->source, folder_type);
}

gboolean
e_mapi_book_check (EPlugin *epl, EConfigHookPageCheckData *data)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) data->target;
	ESource *source = t->source;
	gchar *uri_text = e_source_get_uri (source);

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
e_mapi_book_commit (EPlugin *epl, EConfigTarget *target)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) target;
	ESource *source = t->source;
	gchar *uri_text, *r_uri, *sfid;
	const gchar *kerberos = NULL;
	ESourceGroup *grp;
	EMapiConnection *conn;
	mapi_id_t fid, pfid;
	GError *mapi_error = NULL;

	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH))
		return;

	e_mapi_util_mapi_id_from_string (e_source_get_property (source, "parent-fid"), &pfid);

	/* the profile should be already connected */
	conn = e_mapi_connection_find (e_source_get_property (source, "profile"));
	g_return_if_fail (conn != NULL);

	fid = e_mapi_connection_create_folder (conn, olFolderContacts, pfid, 0, e_source_peek_name (source), NULL, &mapi_error);
	g_object_unref (conn);

	if (!fid) {
		if (mapi_error) {
			e_notice (NULL, GTK_MESSAGE_ERROR, _("Failed to create address book '%s': %s"), e_source_peek_name (source), mapi_error->message);
			g_error_free (mapi_error);
		} else {
			e_notice (NULL, GTK_MESSAGE_ERROR, _("Failed to create address book '%s'"), e_source_peek_name (source));
		}

		return;
	}

	sfid = e_mapi_util_mapi_id_to_string (fid);
	r_uri = g_strconcat (";", sfid, NULL);
	e_source_set_relative_uri (source, r_uri);

	//FIXME: Offline handling
	grp = e_source_peek_group (source);
	e_source_set_property (source, "auth", "plain/password");
	e_source_set_property(source, "user", NULL);
	e_source_set_property(source, "username", e_source_group_get_property (grp, "username") ? e_source_group_get_property (grp, "username") : e_source_group_get_property (grp, "user"));
	e_source_set_property(source, "host", e_source_group_get_property (grp, "host"));
	e_source_set_property(source, "profile", e_source_group_get_property (grp, "profile"));
	e_source_set_property(source, "domain", e_source_group_get_property (grp, "domain"));
	e_source_set_property(source, "realm", e_source_group_get_property (grp, "realm"));
	kerberos = e_source_group_get_property (grp, "kerberos");
	e_source_set_property(source, "kerberos", kerberos);
	if (kerberos && g_str_equal (kerberos, "required")) {
		e_source_set_property (source, "auth", NULL);
		e_source_set_property (source, "auth-type", NULL);
	}
	e_source_set_relative_uri (source, g_strconcat (";",e_source_peek_name (source), NULL));

	e_source_set_property (source, "completion", "true");
	e_source_set_property (source, "public", "no");
	e_source_set_property (source, "folder-id", sfid);

	// Update the folder list in the plugin and EMapiFolder
	g_free (r_uri);
	g_free (sfid);

	return;
}

/* New calendar/task list/memo list */
gboolean
e_mapi_cal_check (EPlugin *epl, EConfigHookPageCheckData *data)
{
	ECalConfigTargetSource *t = (ECalConfigTargetSource *)(data->target);
	ESource *source = t->source;
	gchar *uri_text = e_source_get_uri (source);

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
e_mapi_cal_commit (EPlugin *epl, EConfigTarget *target)
{
	EMapiConnection *conn;
	ECalConfigTargetSource *t = (ECalConfigTargetSource *) target;
	ESourceGroup *group;
	ESource *source = t->source;
	gchar *tmp, *sfid;
	mapi_id_t fid, pfid;
	uint32_t type;
	gchar *uri_text = e_source_get_uri (source);
	GError *mapi_error = NULL;

	if (!uri_text || g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH))
		return;
	g_free (uri_text);

	switch (t->source_type) {
		case E_CAL_CLIENT_SOURCE_TYPE_EVENTS:
			type = olFolderCalendar;
			break;
		case E_CAL_CLIENT_SOURCE_TYPE_TASKS:
			type = olFolderTasks;
			break;
		case E_CAL_CLIENT_SOURCE_TYPE_MEMOS:
			type = olFolderNotes;
			break;
		default:
			g_warning ("%s: %s: Unknown EMapiFolderType\n", G_STRLOC, G_STRFUNC);
			return;
	}

	/* FIXME: Offline handling */

	e_mapi_util_mapi_id_from_string (e_source_get_property (source, "parent-fid"), &pfid);

	/* the profile should be already connected */
	conn = e_mapi_connection_find (e_source_get_property (source, "profile"));
	g_return_if_fail (conn != NULL);

	fid = e_mapi_connection_create_folder (conn, type, pfid, 0, e_source_peek_name (source), NULL, &mapi_error);
	g_object_unref (conn);

	if (!fid) {
		if (mapi_error) {
			e_notice (NULL, GTK_MESSAGE_ERROR, _("Failed to create calendar '%s': %s"), e_source_peek_name (source), mapi_error->message);
			g_error_free (mapi_error);
		} else {
			e_notice (NULL, GTK_MESSAGE_ERROR, _("Failed to create calendar '%s'"), e_source_peek_name (source));
		}

		return;
	}

	sfid = e_mapi_util_mapi_id_to_string (fid);
	tmp = g_strconcat (";", sfid, NULL);
	e_source_set_relative_uri (source, tmp);
	g_free (tmp);
	g_free (sfid);

	e_source_set_property (source, "auth", "1");
	e_source_set_property (source, "auth-type", "plain/password");
	e_source_set_property (source, "public", "no");

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

	tmp = e_source_group_get_property (group, "realm");
	e_source_set_property (source, "realm", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (group, "kerberos");
	e_source_set_property (source, "kerberos", tmp);
	if (tmp && g_str_equal (tmp, "required")) {
		e_source_set_property (source, "auth", NULL);
		e_source_set_property (source, "auth-type", NULL);
	}
	g_free (tmp);

	tmp = e_mapi_util_mapi_id_to_string (fid);
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

	// Update the folder list in the plugin and EMapiFolder
	return;
}