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
#include <libedataserver/e-flag.h>
#include <libedataserver/e-xml-hash-utils.h>
#include <libedataserver/e-credentials.h>
#include <libedataserverui/e-passwords.h>
#include <libedataserver/e-account.h>
#include <e-util/e-dialog-utils.h>
#include <e-util/e-plugin-util.h>
#include "mail/em-config.h"
#include <addressbook/gui/widgets/eab-config.h>
#include <calendar/gui/e-cal-config.h>
#include <shell/e-shell.h>

#include <e-mapi-folder.h>
#include <e-mapi-connection.h>
#include <e-mapi-utils.h>

#include "e-mapi-account-setup.h"

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

static gboolean
e_mapi_test_is_online (void)
{
	EShell *shell;

	shell = e_shell_get_default ();

	return shell && e_shell_get_online (shell);
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

struct ECreateProfileData
{
	const gchar *username;
	struct SRowSet *rowset;
	gint index;
	EFlag *flag;
};

static gboolean
create_profile_callback_in_main (gpointer user_data)
{
	struct ECreateProfileData *cpd = user_data;
	gint response;
	gint i, index = 0;
	GtkTreeIter iter;
	GtkListStore *store;
	GtkCellRenderer *renderer;
	GtkTreeSelection *selection;
	GtkWidget *dialog, *view;
	GtkBox *content_area;

	g_return_val_if_fail (cpd != NULL, FALSE);

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

	for (i = 0; i < cpd->rowset->cRows; i++) {
		const gchar *fullname = e_mapi_util_find_row_propval (&(cpd->rowset->aRow[i]), PidTagDisplayName);
		const gchar *account = e_mapi_util_find_row_propval (&(cpd->rowset->aRow[i]), PidTagAccount);

		if (fullname && account) {
			gtk_list_store_append (store, &iter);
			/* Preserve the index inside the store*/
			gtk_list_store_set (store, &iter,
					    COL_MAPI_FULL_NAME, fullname,
					    COL_MAPI_ACCOUNT, account,
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
			index = cpd->rowset->cRows + 1;
	} else /* If we return a value > available, we are canceling the login.*/
	       index = cpd->rowset->cRows + 1;

	gtk_widget_destroy (dialog);

	cpd->index = index;
	e_flag_set (cpd->flag);

	return FALSE;
}

/* Callback for ProcessNetworkProfile. If we have more than one username,
 we need to let the user select. */
static gint
create_profile_callback_in_thread (struct SRowSet *rowset,
				   gconstpointer data)
{
	struct ECreateProfileData cpd;
	const gchar *username = (const gchar *) data;
	gint i;

	/* If we can find the exact username, then find & return its index. */
	for (i = 0; i < rowset->cRows; i++) {
		const gchar *account = e_mapi_util_find_row_propval (&(rowset->aRow[i]), PidTagAccount);

		if (account && g_strcmp0 (username, account) == 0)
			return i;
	}

	cpd.username = username;
	cpd.rowset = rowset;
	cpd.index = -1;
	cpd.flag = e_flag_new ();

	g_timeout_add (100, create_profile_callback_in_main, &cpd);

	e_flag_wait (cpd.flag);
	e_flag_free (cpd.flag);

	return cpd.index;
}

static gchar *
prompt_password (const gchar *user,
		 const gchar *host,
		 const gchar *key)
{
	guint32 pw_flags = E_PASSWORDS_REMEMBER_FOREVER | E_PASSWORDS_SECRET;
	gchar *password, *title;
	gboolean save = TRUE;

	title = g_strdup_printf (_("Enter Password for %s@%s"), user, host);
	password = e_passwords_ask_password (title, NULL, key, title, pw_flags, &save, NULL);
	g_free (title);

	return password;
}

static GtkWindow *
get_widget_toplevel_window (GtkWidget *widget)
{
	if (!widget)
		return NULL;

	if (!GTK_IS_WINDOW (widget))
		widget = gtk_widget_get_toplevel (widget);

	if (GTK_IS_WINDOW (widget))
		return GTK_WINDOW (widget);

	return NULL;
}

struct EMapiValidateCredentialsData
{
	gchar *username;
	gchar *password;
	gchar *domain;
	gchar *server;
	gboolean use_ssl;
	gboolean krb_sso;
	gchar *krb_realm;
	gchar *key;
	CamelMapiSettings *mapi_settings;
	gboolean success;
};

static void
e_mapi_validate_credentials_data_free (gpointer ptr)
{
	struct EMapiValidateCredentialsData *vcd = ptr;

	if (!vcd)
		return;

	g_free (vcd->username);
	e_credentials_util_safe_free_string (vcd->password);
	g_free (vcd->domain);
	g_free (vcd->server);
	g_free (vcd->krb_realm);
	g_free (vcd->key);
	g_object_unref (vcd->mapi_settings);
	g_free (vcd);
}

static void
validate_credentials_idle (GObject *button,
			   gpointer user_data,
			   GCancellable *cancellable,
			   GError **perror)
{
	struct EMapiValidateCredentialsData *vcd = user_data;

	g_return_if_fail (vcd != NULL);

	if (vcd->success)
		e_notice (NULL, GTK_MESSAGE_INFO, "%s", _("Authentication finished successfully."));
	else
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Authentication failed."));
}

static void
validate_credentials_thread (GObject *button,
			     gpointer user_data,
			     GCancellable *cancellable,
			     GError **perror)
{
	struct EMapiValidateCredentialsData *vcd = user_data;
	EMapiProfileData empd;
	gboolean status;
	struct mapi_context *mapi_ctx = NULL;


	g_return_if_fail (vcd != NULL);

	empd.username = vcd->username;
	empd.password = vcd->password;
	empd.domain = vcd->domain;
	empd.server = vcd->server;
	empd.use_ssl = vcd->use_ssl;
	empd.krb_sso = vcd->krb_sso;
	empd.krb_realm = vcd->krb_realm;
	
	status = e_mapi_utils_create_mapi_context (&mapi_ctx, perror);
	status = status && e_mapi_create_profile (mapi_ctx, &empd, create_profile_callback_in_thread, empd.username, NULL, perror);
	if (status && !g_cancellable_is_cancelled (cancellable)) {
		/* profile was created, try to connect to the server */
		EMapiConnection *conn;
		gchar *profname;

		status = FALSE;
		profname = e_mapi_util_profile_name (mapi_ctx, &empd, FALSE);

		conn = e_mapi_connection_new (profname, empd.password, cancellable, perror);
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
		camel_mapi_settings_set_profile (vcd->mapi_settings, profname);
		g_free (profname);

		vcd->success = TRUE;
	} else {
		e_passwords_forget_password (NULL, vcd->key);
	}

	e_mapi_utils_destroy_mapi_context (mapi_ctx);
}

static void
validate_credentials_cb (GtkWidget *widget,
			 EConfig *config)
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

	if (!e_mapi_test_is_online ()) {
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Cannot authenticate MAPI accounts in offline mode"));
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

	url = camel_url_new ("dummy://", NULL);
	camel_settings_save_to_url (settings, url);
	key = camel_url_to_string (url, CAMEL_URL_HIDE_PARAMS);
	camel_url_free (url);

	if (empd.krb_sso) {
		e_mapi_util_trigger_krb_auth (&empd, &error);
	} else {
		empd.password = prompt_password (empd.username, empd.server, key);
	}

	if (COMPLETE_PROFILEDATA (&empd)) {
		struct EMapiValidateCredentialsData *vcd = g_new0 (struct EMapiValidateCredentialsData, 1);

		vcd->username = g_strdup (empd.username);
		vcd->password = g_strdup (empd.password);
		vcd->domain = g_strdup (empd.domain);
		vcd->server = g_strdup (empd.server);
		vcd->use_ssl = empd.use_ssl;
		vcd->krb_sso = empd.krb_sso;
		vcd->krb_realm = g_strdup (empd.krb_realm);
		vcd->key = g_strdup (key);
		vcd->mapi_settings = g_object_ref (vcd->mapi_settings);
		vcd->success = FALSE;

		e_mapi_run_in_thread_with_feedback_modal (get_widget_toplevel_window (widget),
			G_OBJECT (widget),
			_("Connecting to a server, please wait..."),
			validate_credentials_thread,
			validate_credentials_idle,
			vcd,
			e_mapi_validate_credentials_data_free);
	} else {
		e_passwords_forget_password (NULL, key);
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Authentication failed."));
	}

	if (error)
		g_error_free (error);

	e_credentials_util_safe_free_string (empd.password);
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
	g_signal_connect (auth_button, "clicked",  G_CALLBACK (validate_credentials_cb), data->config);

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
		if (folder && (e_mapi_folder_get_type (folder) == folder_type || (folder_type == E_MAPI_FOLDER_TYPE_MEMO && e_mapi_folder_get_type (folder) == E_MAPI_FOLDER_TYPE_JOURNAL))) {
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

static EMapiFolderCategory
e_mapi_source_to_folder_category (ESource *source)
{
	g_return_val_if_fail (source != NULL, E_MAPI_FOLDER_CATEGORY_UNKNOWN);

	if (e_source_get_property (source, "foreign-username"))
		return E_MAPI_FOLDER_CATEGORY_FOREIGN;

	if (g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0)
		return E_MAPI_FOLDER_CATEGORY_PUBLIC;

	return E_MAPI_FOLDER_CATEGORY_PERSONAL;
}

struct EMapiFolderStructureData
{
	EMapiFolderType folder_type;
	GSList *folders;
	GtkWidget *tree_view;
	ESource *source;
};

static void
e_mapi_folder_structure_data_free (gpointer ptr)
{
	struct EMapiFolderStructureData *fsd = ptr;

	if (!fsd)
		return;

	e_mapi_folder_free_list (fsd->folders);
	g_object_unref (fsd->tree_view);
	g_object_unref (fsd->source);
	g_free (fsd);
}

static void
e_mapi_download_folder_structure_idle (GObject *source_obj,
				       gpointer user_data,
				       GCancellable *cancellable,
				       GError **perror)
{
	struct EMapiFolderStructureData *fsd = user_data;
	GtkTreeStore *tree_store;
	ESource *source;

	g_return_if_fail (fsd != NULL);
	g_return_if_fail (fsd->tree_view != NULL);
	g_return_if_fail (source_obj != NULL);
	g_return_if_fail (E_IS_SOURCE (source_obj));

	source = E_SOURCE (source_obj);
	tree_store = GTK_TREE_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (fsd->tree_view)));
	g_return_if_fail (tree_store != NULL);

	add_folders (fsd->folders, tree_store, fsd->folder_type);
	gtk_tree_view_expand_all (GTK_TREE_VIEW (fsd->tree_view));

	if (e_source_get_property (source, "folder-id")) {
		mapi_id_t fid;

		e_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &fid);

		select_folder (GTK_TREE_MODEL (tree_store), fid, fsd->tree_view);
	}
}

static void
e_mapi_download_folder_structure_thread (GObject *source_obj,
					 gpointer user_data,
					 GCancellable *cancellable,
					 GError **perror)
{
	struct EMapiFolderStructureData *fsd = user_data;
	ESource *source;
	EMapiConnection *conn;

	g_return_if_fail (fsd != NULL);
	g_return_if_fail (fsd->tree_view != NULL);
	g_return_if_fail (source_obj != NULL);
	g_return_if_fail (E_IS_SOURCE (source_obj));

	source = E_SOURCE (source_obj);

	conn = e_mapi_account_open_connection_for (NULL,
		e_source_get_property (source, "profile"),
		e_source_get_property (source, "username"),
		e_source_get_property (source, "host"),
		cancellable,
		perror);

	if (!conn)
		return;

	if (conn && e_mapi_connection_connected (conn)) {
		fsd->folders = e_mapi_connection_peek_folders_list (conn);
		if (fsd->folders)
			fsd->folders = e_mapi_folder_copy_list (fsd->folders);
	}

	if (conn)
		g_object_unref (conn);
}

static gboolean
e_mapi_invoke_folder_structure_download_idle (gpointer user_data)
{
	struct EMapiFolderStructureData *fsd = user_data;

	g_return_val_if_fail (fsd != NULL, FALSE);

	e_mapi_run_in_thread_with_feedback (get_widget_toplevel_window (fsd->tree_view),
		G_OBJECT (fsd->source),
		_("Searching remote MAPI folder structure, please wait..."),
		e_mapi_download_folder_structure_thread,
		e_mapi_download_folder_structure_idle,
		fsd,
		e_mapi_folder_structure_data_free);

	return FALSE;
}

static GtkWidget *
e_mapi_create (GtkWidget *dialog,
	       GtkWidget *parent,
	       ESource *source,
	       EMapiFolderType folder_type)
{
	GtkWidget *table, *label, *scroll, *tv;
	gchar *uri_text, *profile = NULL;
	ESourceGroup *group;
	gint row;
	GtkCellRenderer *rcell;
	GtkTreeStore *ts;
	GtkTreeViewColumn *tvc;
	const gchar *acc;
	gboolean is_new_source;

	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		if (uri_text && g_ascii_strncasecmp (uri_text, "mapigal://", strlen ("mapigal://")) == 0) {
			e_plugin_util_add_check (parent, _("Allow _partial search results"), source, "allow-partial", "true", NULL);
		}

		return NULL;
	}

	e_plugin_util_add_check (parent, _("Lis_ten for server notifications"), source, "server-notification", "true", NULL);

	switch (e_mapi_source_to_folder_category (source)) {
	case E_MAPI_FOLDER_CATEGORY_FOREIGN:
	case E_MAPI_FOLDER_CATEGORY_PUBLIC:
		/* no extra options for subscribed folders */
		return NULL;
	default:
		break;
	}

	group = e_source_peek_group (source);
	profile = g_strdup (e_source_get_property (source, "profile"));
	is_new_source = e_source_get_property (source, "folder-id") == NULL;
	if (is_new_source) {
		gchar *tmp;

		g_free (profile);

		profile = e_source_group_get_property (group, "profile");
		e_source_set_property (source, "profile", profile);

		tmp = e_source_group_get_property (group, "username");
		e_source_set_property (source, "username", tmp);
		g_free (tmp);

		tmp = e_source_group_get_property (group, "host");
		e_source_set_property (source, "host", tmp);
		g_free (tmp);
	}
	g_free (profile);

	acc = e_source_group_peek_name (group);
	ts = gtk_tree_store_new (NUM_COLS, G_TYPE_STRING, G_TYPE_INT64, G_TYPE_POINTER);
	table = g_object_new (GTK_TYPE_TABLE, NULL);

	if (folder_type == E_MAPI_FOLDER_TYPE_CONTACT) {
		gtk_container_add (GTK_CONTAINER (parent), table);
	} else {
		g_object_get (parent, "n-rows", &row, NULL);
		gtk_table_attach (GTK_TABLE (parent), table, 0, 2, row, row + 1, GTK_FILL|GTK_EXPAND, 0, 0, 0);
	}

	if (is_new_source && !e_mapi_test_is_online ()) {
		const gchar *msg;

		switch (folder_type) {
		case E_MAPI_FOLDER_TYPE_APPOINTMENT:
			msg = _("Cannot create MAPI calendar in offline mode");
			break;
		case E_MAPI_FOLDER_TYPE_TASK:
			msg = _("Cannot create MAPI task list in offline mode");
			break;
		case E_MAPI_FOLDER_TYPE_MEMO:
			msg = _("Cannot create MAPI memo list in offline mode");
			break;
		case E_MAPI_FOLDER_TYPE_CONTACT:
			msg = _("Cannot create MAPI address book in offline mode");
			break;
		default:
			g_warn_if_reached ();
			msg = _("Cannot create MAPI source in offline mode");
			break;
		}

		label = gtk_label_new (msg);
		gtk_widget_show (label);
		gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
		gtk_table_attach (GTK_TABLE (table), label, 0, 1, 0, 1, GTK_FILL | GTK_EXPAND, 0, 0, 0);
	} else {
		label = gtk_label_new_with_mnemonic (_("_Location:"));
		gtk_widget_show (label);
		gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
		gtk_table_attach (GTK_TABLE (table), label, 0, 1, 0, 1, GTK_FILL | GTK_EXPAND, 0, 0, 0);

		rcell = gtk_cell_renderer_text_new ();
		tvc = gtk_tree_view_column_new_with_attributes (acc, rcell, "text", NAME_COL, NULL);
		tv = gtk_tree_view_new_with_model (GTK_TREE_MODEL (ts));
		gtk_tree_view_append_column (GTK_TREE_VIEW (tv), tvc);
		g_object_set (tv,"expander-column", tvc, "headers-visible", TRUE, NULL);
		gtk_widget_set_sensitive (tv, is_new_source);

		scroll = gtk_scrolled_window_new (NULL, NULL);
		gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
		gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);
		g_object_set (scroll, "height-request", 150, NULL);
		gtk_container_add (GTK_CONTAINER (scroll), tv);
		gtk_label_set_mnemonic_widget (GTK_LABEL (label), tv);
		g_signal_connect (G_OBJECT (tv), "cursor-changed", G_CALLBACK (e_mapi_cursor_change), source);
		gtk_widget_show_all (scroll);

		gtk_table_attach (GTK_TABLE (table), scroll, 0, 1, 1, 2, GTK_FILL | GTK_EXPAND, 0, 0, 0);

		if (e_mapi_test_is_online ()) {
			struct EMapiFolderStructureData *fsd;

			fsd = g_new0 (struct EMapiFolderStructureData, 1);
			fsd->folder_type = folder_type;
			fsd->folders = NULL;
			fsd->tree_view = g_object_ref (tv);
			fsd->source = g_object_ref (source);

			g_idle_add (e_mapi_invoke_folder_structure_download_idle, fsd);
		}
	}

	gtk_widget_show_all (table);

	return table;
}

GtkWidget *
e_mapi_create_addressbook (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) data->target;

	return e_mapi_create (data->target->widget, data->parent, t->source, E_MAPI_FOLDER_TYPE_CONTACT);
}

GtkWidget *
e_mapi_create_calendar (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	ECalConfigTargetSource *t = (ECalConfigTargetSource *) data->target;
	EMapiFolderType folder_type;

	switch (t->source_type) {
	case E_CAL_CLIENT_SOURCE_TYPE_EVENTS:
		folder_type = E_MAPI_FOLDER_TYPE_APPOINTMENT;
		break;
	case E_CAL_CLIENT_SOURCE_TYPE_TASKS:
		folder_type = E_MAPI_FOLDER_TYPE_TASK;
		break;
	case E_CAL_CLIENT_SOURCE_TYPE_MEMOS:
		folder_type = E_MAPI_FOLDER_TYPE_MEMO;
		break;
	default:
		g_return_val_if_reached (NULL);
	}

	return e_mapi_create (data->target->widget, data->parent, t->source, folder_type);
}

gboolean
e_mapi_book_check (EPlugin *epl, EConfigHookPageCheckData *data)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) data->target;
	ESource *source = t->source;
	gchar *uri_text = e_source_get_uri (source);

	if (!uri_text)
		return TRUE;

	/* not a MAPI account */
	if (g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		g_free (uri_text);
		return TRUE;
	}

	g_free (uri_text);

	if (!e_source_get_property (source, "folder-id") &&
	    !e_mapi_test_is_online ())
		return FALSE;

	/* does not have a parent-fid which is needed for folder creation on server */
	return e_source_get_property (source, "parent-fid") ||
		e_source_get_property (source, "foreign-username") ||
		g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0;
}

static gboolean
emas_open_folder (ESource *source,
		  EMapiConnection *conn,
		  mapi_id_t fid,
		  mapi_object_t *obj_folder,
		  GCancellable *cancellable,
		  GError **perror)
{
	gchar *foreign_username;
	gboolean is_public_folder;
	gboolean res;

	g_return_val_if_fail (source != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (obj_folder != NULL, FALSE);

	is_public_folder = g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0;
	foreign_username = e_source_get_duped_property (source, "foreign-username");

	if (foreign_username)
		res = e_mapi_connection_open_foreign_folder (conn, foreign_username, fid, obj_folder, cancellable, perror);
	else if (is_public_folder)
		res = e_mapi_connection_open_public_folder (conn, fid, obj_folder, cancellable, perror);
	else
		res = e_mapi_connection_open_personal_folder (conn, fid, obj_folder, cancellable, perror);

	g_free (foreign_username);

	return res;
}

struct EMapiCreateFolderData
{
	ESource *source;
	gchar *folder_name;
	gchar *folder_type;

	gchar * (* create_error_string) (const gchar *folder_name, const GError *error);
	mapi_id_t parent_fid;
	mapi_id_t *created_fid;
};

static void
e_mapi_create_folder_data_free (gpointer ptr)
{
	struct EMapiCreateFolderData *cfd = ptr;

	if (!cfd)
		return;

	g_object_unref (cfd->source);
	g_free (cfd->folder_name);
	g_free (cfd->folder_type);
	g_free (cfd);
}

static void
e_mapi_create_folder_thread (GObject *source_obj,
			     gpointer user_data,
			     GCancellable *cancellable,
			     GError **perror)
{
	struct EMapiCreateFolderData *cfd = user_data;
	EMapiConnection *conn;
	mapi_id_t fid, pfid;
	mapi_object_t obj_folder;
	ESource *source;
	GError *mapi_error = NULL;

	g_return_if_fail (cfd != NULL);
	g_return_if_fail (cfd->folder_name != NULL);
	g_return_if_fail (cfd->folder_type != NULL);
	g_return_if_fail (cfd->created_fid != NULL);
	g_return_if_fail (source_obj != NULL);

	source = E_SOURCE (source_obj);
	conn = e_mapi_account_open_connection_for (NULL,
		e_source_get_property (source, "profile"),
		e_source_get_property (source, "username"),
		e_source_get_property (source, "host"),
		cancellable,
		perror);

	if (!conn)
		return;

	e_mapi_util_mapi_id_from_string (e_source_get_property (source, "parent-fid"), &pfid);

	fid = 0;
	if (emas_open_folder (source, conn, pfid, &obj_folder, cancellable, &mapi_error)) {
		if (!e_mapi_connection_create_folder (conn, &obj_folder, cfd->folder_name, cfd->folder_type, &fid, cancellable, &mapi_error))
			fid = 0;
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	g_object_unref (conn);

	if (!fid) {
		gchar *error_str;

		if (cfd->create_error_string)
			error_str = cfd->create_error_string (cfd->folder_name, mapi_error);
		else if (mapi_error) {
			error_str = g_strdup_printf (_("Failed to create folder '%s': %s"), cfd->folder_name, mapi_error->message);
		} else {
			error_str = g_strdup_printf (_("Failed to create folder '%s'"), cfd->folder_name);
		}

		g_return_if_fail (error_str != NULL);

		g_set_error_literal (perror, E_MAPI_ERROR, mapi_error ? mapi_error->code : MAPI_E_CALL_FAILED, error_str);

		g_clear_error (&mapi_error);
		g_free (error_str);
	}

	*cfd->created_fid = fid;
}

static gchar *
create_book_error_string (const gchar *folder_name,
			  const GError *error)
{
	if (error)
		return g_strdup_printf (_("Failed to create address book '%s': %s"), folder_name, error->message);

	return g_strdup_printf (_("Failed to create address book '%s'"), folder_name);
}

void
e_mapi_book_commit (EPlugin *epl, EConfigTarget *target)
{
	EABConfigTargetSource *t = (EABConfigTargetSource *) target;
	ESource *source = t->source;
	gchar *uri_text, *tmp;
	ESourceGroup *grp;

	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH))
		return;

	switch (e_mapi_source_to_folder_category (source)) {
	case E_MAPI_FOLDER_CATEGORY_FOREIGN:
	case E_MAPI_FOLDER_CATEGORY_PUBLIC:
		/* no extra changes for subscribed folders */
		return;
	default:
		break;
	}

	grp = e_source_peek_group (source);
	e_source_set_property (source, "auth", "plain/password");
	e_source_set_property (source, "user", NULL);

	tmp = e_source_group_get_property (grp, "username");
	if (!tmp)
		tmp = e_source_group_get_property (grp, "user");
	e_source_set_property(source, "username", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (grp, "host");
	e_source_set_property(source, "host", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (grp, "profile");
	e_source_set_property(source, "profile", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (grp, "domain");
	e_source_set_property(source, "domain", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (grp, "realm");
	e_source_set_property(source, "realm", tmp);
	g_free (tmp);

	tmp = e_source_group_get_property (grp, "kerberos");
	e_source_set_property (source, "kerberos", tmp);
	if (tmp && g_str_equal (tmp, "required")) {
		e_source_set_property (source, "auth", NULL);
		e_source_set_property (source, "auth-type", NULL);
	}
	g_free (tmp);

	e_source_set_property (source, "completion", "true");
	e_source_set_property (source, "public", NULL);

	if (!e_source_get_property (source, "folder-id")) {
		struct EMapiCreateFolderData *cfd;
		gchar *r_uri, *sfid;
		mapi_id_t fid = 0;

		cfd = g_new0 (struct EMapiCreateFolderData, 1);
		cfd->source = g_object_ref (source);
		cfd->folder_name = g_strdup (e_source_peek_name (source));
		cfd->folder_type = g_strdup (IPF_CONTACT);
		cfd->create_error_string = create_book_error_string;
		cfd->created_fid = &fid;

		e_mapi_run_in_thread_with_feedback_modal (get_widget_toplevel_window (target->widget),
			G_OBJECT (source),
			_("Creating address book on a server, please wait..."),
			e_mapi_create_folder_thread,
			NULL,
			cfd,
			e_mapi_create_folder_data_free);

		if (!fid)
			return;

		sfid = e_mapi_util_mapi_id_to_string (fid);
		r_uri = g_strconcat (";", sfid, NULL);
		e_source_set_relative_uri (source, r_uri);
		e_source_set_property (source, "folder-id", sfid);
		g_free (r_uri);
		g_free (sfid);
	}
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

	/* not a MAPI account */
	if (g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		g_free (uri_text);
		return TRUE;
	}

	g_free (uri_text);

	if (!e_source_get_property (source, "folder-id") &&
	    !e_mapi_test_is_online ())
		return FALSE;

	return e_source_get_property (source, "parent-fid") ||
		e_source_get_property (source, "foreign-username") ||
		g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0;
}

static gchar *
create_cal_error_string (const gchar *folder_name,
			 const GError *error)
{
	if (error)
		return g_strdup_printf (_("Failed to create calendar '%s': %s"), folder_name, error->message);

	return g_strdup_printf (_("Failed to create calendar '%s'"), folder_name);
}

static gchar *
create_task_error_string (const gchar *folder_name,
			  const GError *error)
{
	if (error)
		return g_strdup_printf (_("Failed to create task list '%s': %s"), folder_name, error->message);

	return g_strdup_printf (_("Failed to create task list '%s'"), folder_name);
}

static gchar *
create_memo_error_string (const gchar *folder_name,
			  const GError *error)
{
	if (error)
		return g_strdup_printf (_("Failed to create memo list '%s': %s"), folder_name, error->message);

	return g_strdup_printf (_("Failed to create memo list '%s'"), folder_name);
}

void
e_mapi_cal_commit (EPlugin *epl, EConfigTarget *target)
{
	ECalConfigTargetSource *t = (ECalConfigTargetSource *) target;
	ESourceGroup *group;
	ESource *source = t->source;
	gchar *tmp;
	const gchar *type;
	gchar *uri_text = e_source_get_uri (source);

	if (!uri_text || g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH))
		return;
	g_free (uri_text);

	switch (e_mapi_source_to_folder_category (source)) {
	case E_MAPI_FOLDER_CATEGORY_FOREIGN:
	case E_MAPI_FOLDER_CATEGORY_PUBLIC:
		/* no extra changes for subscribed folders */
		return;
	default:
		break;
	}

	switch (t->source_type) {
		case E_CAL_CLIENT_SOURCE_TYPE_EVENTS:
			type = IPF_APPOINTMENT;
			break;
		case E_CAL_CLIENT_SOURCE_TYPE_TASKS:
			type = IPF_TASK;
			break;
		case E_CAL_CLIENT_SOURCE_TYPE_MEMOS:
			type = IPF_STICKYNOTE;
			break;
		default:
			g_warning ("%s: %s: Unknown EMapiFolderType\n", G_STRLOC, G_STRFUNC);
			return;
	}

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

	if (!e_source_get_property (source, "folder-id")) {
		struct EMapiCreateFolderData *cfd;
		const gchar *msg = NULL;
		gchar *r_uri, *sfid;
		mapi_id_t fid = 0;

		cfd = g_new0 (struct EMapiCreateFolderData, 1);
		cfd->source = g_object_ref (source);
		cfd->folder_name = g_strdup (e_source_peek_name (source));
		cfd->folder_type = g_strdup (type);
		switch (t->source_type) {
		case E_CAL_CLIENT_SOURCE_TYPE_EVENTS:
			cfd->create_error_string = create_cal_error_string;
			msg = _("Creating calendar on a server, please wait...");
			break;
		case E_CAL_CLIENT_SOURCE_TYPE_TASKS:
			cfd->create_error_string = create_task_error_string;
			msg = _("Creating task list on a server, please wait...");
			break;
		case E_CAL_CLIENT_SOURCE_TYPE_MEMOS:
			cfd->create_error_string = create_memo_error_string;
			msg = _("Creating memo list on a server, please wait...");
			break;
		default:
			g_warn_if_reached ();
			msg = "???";
			break;
		}
		cfd->created_fid = &fid;

		e_mapi_run_in_thread_with_feedback_modal (get_widget_toplevel_window (target->widget),
			G_OBJECT (source),
			msg,
			e_mapi_create_folder_thread,
			NULL,
			cfd,
			e_mapi_create_folder_data_free);

		if (!fid)
			return;

		sfid = e_mapi_util_mapi_id_to_string (fid);
		r_uri = g_strconcat (";", sfid, NULL);
		e_source_set_relative_uri (source, r_uri);
		e_source_set_property (source, "folder-id", sfid);

		g_free (r_uri);
		g_free (sfid);
	}
}

struct RunWithFeedbackData
{
	GtkWindow *parent;
	GtkWidget *dialog;
	GCancellable *cancellable;
	GObject *with_object;
	EMapiSetupFunc thread_func;
	EMapiSetupFunc idle_func;
	gpointer user_data;
	GDestroyNotify free_user_data;
	GError *error;
	gboolean run_modal;
};

static void
free_run_with_feedback_data (gpointer ptr)
{
	struct RunWithFeedbackData *rfd = ptr;

	if (!rfd)
		return;

	if (rfd->dialog)
		gtk_widget_destroy (rfd->dialog);

	g_object_unref (rfd->cancellable);
	g_object_unref (rfd->with_object);

	if (rfd->free_user_data)
		rfd->free_user_data (rfd->user_data);

	g_clear_error (&rfd->error);

	g_free (rfd);
}

static gboolean
run_with_feedback_idle (gpointer user_data)
{
	struct RunWithFeedbackData *rfd = user_data;
	gboolean was_cancelled = FALSE;

	g_return_val_if_fail (rfd != NULL, FALSE);

	if (!g_cancellable_is_cancelled (rfd->cancellable)) {
		if (rfd->idle_func && !rfd->error)
			rfd->idle_func (rfd->with_object, rfd->user_data, rfd->cancellable, &rfd->error);

		was_cancelled = g_cancellable_is_cancelled (rfd->cancellable);

		if (rfd->dialog) {
			gtk_widget_destroy (rfd->dialog);
			rfd->dialog = NULL;
		}
	} else {
		was_cancelled = TRUE;
	}

	if (!was_cancelled) {
		if (rfd->error)
			e_notice (rfd->parent, GTK_MESSAGE_ERROR, "%s", rfd->error->message);
	}

	free_run_with_feedback_data (rfd);

	return FALSE;
}

static gboolean
run_with_feedback_response_idle (gpointer user_data)
{
	struct RunWithFeedbackData *rfd = user_data;

	g_return_val_if_fail (rfd != NULL, FALSE);

	if (rfd->dialog)
		gtk_dialog_response (GTK_DIALOG (rfd->dialog), GTK_RESPONSE_CLOSE);

	return FALSE;
}

static gpointer
run_with_feedback_thread (gpointer user_data)
{
	struct RunWithFeedbackData *rfd = user_data;

	g_return_val_if_fail (rfd != NULL, NULL);
	g_return_val_if_fail (rfd->thread_func != NULL, NULL);

	if (!g_cancellable_is_cancelled (rfd->cancellable))
		rfd->thread_func (rfd->with_object, rfd->user_data, rfd->cancellable, &rfd->error);

	if (rfd->run_modal)
		g_idle_add (run_with_feedback_response_idle, rfd);
	else
		g_idle_add (run_with_feedback_idle, rfd);

	return NULL;
}

static void
run_with_feedback_response_cb (GtkWidget *dialog,
			       gint resonse_id,
			       struct RunWithFeedbackData *rfd)
{
	g_return_if_fail (rfd != NULL);

	if (!rfd->run_modal)
		rfd->dialog = NULL;

	g_cancellable_cancel (rfd->cancellable);

	if (!rfd->run_modal)
		gtk_widget_destroy (dialog);
}

static void
e_mapi_run_in_thread_with_feedback_general (GtkWindow *parent,
					    GObject *with_object,
					    const gchar *description,
					    EMapiSetupFunc thread_func,
					    EMapiSetupFunc idle_func,
					    gpointer user_data,
					    GDestroyNotify free_user_data,
					    gboolean run_modal)
{
	GtkWidget *dialog, *label, *content;
	struct RunWithFeedbackData *rfd;

	g_return_if_fail (with_object != NULL);
	g_return_if_fail (description != NULL);
	g_return_if_fail (thread_func != NULL);

	dialog = gtk_dialog_new_with_buttons ("",
		parent,
		GTK_DIALOG_MODAL,
		GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
		NULL);

	label = gtk_label_new (description);
	gtk_widget_show (label);

	content = gtk_dialog_get_content_area (GTK_DIALOG (dialog));

	gtk_container_add (GTK_CONTAINER (content), label);
	gtk_container_set_border_width (GTK_CONTAINER (content), 12);

	rfd = g_new0 (struct RunWithFeedbackData, 1);
	rfd->parent = parent;
	rfd->dialog = dialog;
	rfd->cancellable = g_cancellable_new ();
	rfd->with_object = g_object_ref (with_object);
	rfd->thread_func = thread_func;
	rfd->idle_func = idle_func;
	rfd->user_data = user_data;
	rfd->free_user_data = free_user_data;
	rfd->error = NULL;
	rfd->run_modal = run_modal;

	g_signal_connect (dialog, "response", G_CALLBACK (run_with_feedback_response_cb), rfd);

	if (run_modal) {
		g_return_if_fail (g_thread_create (run_with_feedback_thread, rfd, FALSE, NULL));

		gtk_dialog_run (GTK_DIALOG (dialog));

		run_with_feedback_idle (rfd);
	} else {
		gtk_widget_show (dialog);

		g_return_if_fail (g_thread_create (run_with_feedback_thread, rfd, FALSE, NULL));
	}
}

void
e_mapi_run_in_thread_with_feedback (GtkWindow *parent,
				    GObject *with_object,
				    const gchar *description,
				    EMapiSetupFunc thread_func,
				    EMapiSetupFunc idle_func,
				    gpointer user_data,
				    GDestroyNotify free_user_data)
{
	e_mapi_run_in_thread_with_feedback_general (parent, with_object, description, thread_func, idle_func, user_data, free_user_data, FALSE);
}

void
e_mapi_run_in_thread_with_feedback_modal (GtkWindow *parent,
					  GObject *with_object,
					  const gchar *description,
					  EMapiSetupFunc thread_func,
					  EMapiSetupFunc idle_func,
					  gpointer user_data,
					  GDestroyNotify free_user_data)
{
	e_mapi_run_in_thread_with_feedback_general (parent, with_object, description, thread_func, idle_func, user_data, free_user_data, TRUE);
}

EMapiConnection	*
e_mapi_account_open_connection_for (GtkWindow *parent,
				    const gchar *login_profile,
				    const gchar *login_username,
				    const gchar *login_url,
				    GCancellable *cancellable,
				    GError **perror)
{
	guint32 prompt_flags = E_PASSWORDS_SECRET | E_PASSWORDS_ONLINE | E_PASSWORDS_DISABLE_REMEMBER;
	EMapiConnection *conn = NULL;
	gchar *password = NULL;
	SoupURI *suri;
	gchar *key_str, *title;

	g_return_val_if_fail (login_profile != NULL, NULL);
	g_return_val_if_fail (login_username != NULL, NULL);
	g_return_val_if_fail (login_url != NULL, NULL);

	/* use the one from mailer, if there, otherwise open new */
	conn = e_mapi_connection_find (login_profile);
	if (conn)
		return conn;

	if (strchr (login_url, '/') != NULL) {
		suri = soup_uri_new (login_url);
	} else {
		gchar *url = g_strconcat ("http://", login_url, NULL);
		suri = soup_uri_new (url);
		g_free (url);
	}

	g_return_val_if_fail (suri != NULL, NULL);

	soup_uri_set_user (suri, login_username);
	soup_uri_set_password (suri, NULL);
	soup_uri_set_fragment (suri, NULL);

	key_str = soup_uri_to_string (suri, FALSE);
	title = g_strdup_printf (_("Enter Password for %s@%s"), soup_uri_get_user (suri), soup_uri_get_host (suri));

	soup_uri_free (suri);

	g_return_val_if_fail (key_str != NULL, NULL);

	password = e_passwords_get_password (NULL, key_str);
	if (!password)
		password = e_passwords_ask_password (title, NULL, key_str, NULL, prompt_flags, NULL, parent);

	prompt_flags |= E_PASSWORDS_REPROMPT;

	do {
		conn = e_mapi_connection_new (login_profile, password, cancellable, perror);

		if (!conn && !g_cancellable_is_cancelled (cancellable)) {
			e_credentials_util_safe_free_string (password);
			password = e_passwords_ask_password (title, NULL, key_str, NULL, prompt_flags, NULL, parent);
		}
	} while (!conn && !g_cancellable_is_cancelled (cancellable));

	e_credentials_util_safe_free_string (password);
	g_free (key_str);
	g_free (title);

	return conn;
}
