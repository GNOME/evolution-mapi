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
#include <libmapi/libmapi.h>
#include "mail/em-config.h"
#include "exchange-mapi-account-setup.h"
#include <addressbook/gui/widgets/eab-config.h>
#include <calendar/gui/e-cal-config.h>

#include <exchange-mapi-folder.h>
#include <exchange-mapi-connection.h>
#include <exchange-mapi-utils.h>

#define d(x) x

int e_plugin_lib_enable (EPluginLib *ep, int enable);

/* Account Setup */
GtkWidget *org_gnome_exchange_mapi_account_setup (EPlugin *epl, EConfigHookItemFactoryData *data);
gboolean org_gnome_exchange_mapi_check_options(EPlugin *epl, EConfigHookPageCheckData *data);

/* New Addressbook/CAL */
GtkWidget *exchange_mapi_create (EPlugin *epl, EConfigHookItemFactoryData *data);

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
e_plugin_lib_enable (EPluginLib *ep, int enable)
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

gboolean
exchange_mapi_delete_profile (const char *profile)
{
	enum MAPISTATUS	retval;
	gboolean result = FALSE; 
	gchar *profpath = NULL;

	profpath = g_build_filename (g_get_home_dir(), DEFAULT_PROF_PATH, NULL);
	if (!g_file_test (profpath, G_FILE_TEST_EXISTS)) {
		g_warning ("No need to delete profile. DB itself is missing \n");
		result = TRUE;
		goto cleanup; 
	}

	retval = MAPIInitialize(profpath); 
	if (retval == MAPI_E_SESSION_LIMIT)
	/* do nothing, the profile store is already initialized */
		; 
	else if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("MAPIInitialize", GetLastError());
		goto cleanup; 
	}

	g_debug ("Deleting profile %s ", profile); 
	retval = DeleteProfile(profile); 
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("DeleteProfile", GetLastError());
		goto cleanup; 
	}

	exchange_mapi_connection_close ();
	result = TRUE; 

cleanup: 
	g_free(profpath);

	return result;
}

gboolean 
exchange_mapi_create_profile(const char *username, const char *password, const char *domain, const char *server)
{
	enum MAPISTATUS	retval;
	gboolean result = FALSE; 
	const gchar *workstation = "localhost";
	gchar *profname = NULL, *profpath = NULL;
	struct mapi_session *session = NULL;

	/*We need all the params before proceeding.*/
	g_return_val_if_fail (username && *username && password && *password &&
			      domain && *domain && server && *server, FALSE);

	d(g_print ("Create profile with %s %s %s\n", username, domain, server));

	profpath = g_build_filename (g_get_home_dir(), DEFAULT_PROF_PATH, NULL);
	profname = g_strdup_printf("%s@%s", username, domain);

	if (!g_file_test (profpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		/* Create a ProfileStore */
		retval = CreateProfileStore (profpath, LIBMAPI_LDIF_DIR); 
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("CreateProfileStore", GetLastError());
			goto cleanup; 
		}
	}

	retval = MAPIInitialize(profpath); 
	if (retval == MAPI_E_SESSION_LIMIT)
	/* do nothing, the profile store is already initialized */
		mapi_errstr("MAPIInitialize", GetLastError()); 
	else if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("MAPIInitialize", GetLastError());
		goto cleanup; 
	}

	/* Delete any existing profiles with the same profilename */
	retval = DeleteProfile(profname); 
	/* don't bother to check error - it would be valid if we got an error */

	retval = CreateProfile(profname, username, password, 0); 
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("CreateProfile", GetLastError());
		goto cleanup; 
	}

	mapi_profile_add_string_attr(profname, "binding", server);
	mapi_profile_add_string_attr(profname, "workstation", workstation);
	mapi_profile_add_string_attr(profname, "domain", domain);
	
	/* This is only convenient here and should be replaced at some point */
	mapi_profile_add_string_attr(profname, "codepage", "0x4e4");
	mapi_profile_add_string_attr(profname, "language", "0x409");
	mapi_profile_add_string_attr(profname, "method", "0x409");
	
	/* Login now */
	d(g_print("Logging into the server... "));
	retval = MapiLogonProvider(&session, profname, password, PROVIDER_ID_NSPI); 
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("MapiLogonProvider", GetLastError());
		g_debug ("Deleting profile %s ", profname); 
		retval = DeleteProfile(profname); 
		if (retval != MAPI_E_SUCCESS)
			mapi_errstr("DeleteProfile", GetLastError());
		goto cleanup; 
	}
	d(g_print("succeeded \n"));

	retval = ProcessNetworkProfile(session, username, NULL, NULL); 
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("ProcessNetworkProfile", GetLastError());
		goto cleanup; 
	}

	/* Set it as the default profile. Is this needed? */
	retval = SetDefaultProfile(profname); 
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetDefaultProfile", GetLastError());
		goto cleanup; 
	}

	/* Close the connection, so that we can login with what we created */
	exchange_mapi_connection_close ();

	/* Initialize a global connection */
	if (exchange_mapi_connection_new (profname, password)) {
		result = TRUE;
		exchange_mapi_account_listener_get_folder_list ();
	}

cleanup: 
	if (!result)
		MAPIUninitialize ();

	g_free (profname);
	g_free (profpath);

	return result;
}


static void
validate_credentials (GtkWidget *widget, EConfig *config)
{
	EMConfigTargetAccount *target_account = (EMConfigTargetAccount *)(config->target);
	CamelURL *url = NULL;
 	gchar *key = NULL, *password = NULL;
	const gchar *domain_name = NULL; 
	url = camel_url_new (e_account_get_string (target_account->account, E_ACCOUNT_SOURCE_URL), NULL);
	key = camel_url_to_string (url, CAMEL_URL_HIDE_PASSWORD | CAMEL_URL_HIDE_PARAMS);
	password = e_passwords_get_password (EXCHANGE_MAPI_PASSWORD_COMPONENT, key);
	if (!password) {
		gboolean remember = FALSE;
		gchar *title;

		title = g_strdup_printf (_("Enter Password for %s@%s"), url->user, url->host);
		password = e_passwords_ask_password (title, EXCHANGE_MAPI_PASSWORD_COMPONENT, key, title,
						     E_PASSWORDS_REMEMBER_FOREVER|E_PASSWORDS_SECRET,
						     &remember, NULL);
		g_free (title);
	}

	domain_name = camel_url_get_param (url, "domain");

	/*Can there be a account without password ?*/
	if (password && *password && domain_name && *domain_name && *url->user && *url->host) {
		gboolean status = exchange_mapi_create_profile (url->user, password, domain_name, url->host);
		if (status) {
			/* Things are successful */
			gchar *profname = NULL, *uri = NULL; 

			profname = g_strdup_printf("%s@%s", url->user, domain_name);
			camel_url_set_param(url, "profile", profname);
			g_free (profname);

			uri = camel_url_to_string(url, 0);
			e_account_set_string(target_account->account, E_ACCOUNT_SOURCE_URL, uri);
			g_free (uri);
		} else {
			e_passwords_forget_password (EXCHANGE_MAPI_PASSWORD_COMPONENT, key);
			/* FIXME: Run an error dialog here */
		}
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
	CONTACTSNAME_COL,
	CONTACTSFID_COL,
	CONTACTSFOLDER_COL,
	NUM_COLS
};


static gboolean
check_node (GtkTreeStore *ts, ExchangeMAPIFolder *folder, GtkTreeIter *iter)
{
	GtkTreeModel *ts_model;
	mapi_id_t fid;
	gboolean status = FALSE;

	ts_model = GTK_TREE_MODEL (ts);
	
	gtk_tree_model_get (ts_model, iter, 1, &fid, -1);
	if (fid && folder->parent_folder_id == fid) {
		/* Do something */
		GtkTreeIter node;
		gtk_tree_store_append (ts, &node, iter);		
		gtk_tree_store_set (ts, &node, 0, folder->folder_name, 1, folder->folder_id, 2, folder,-1);		
		return TRUE;
	}

	if (gtk_tree_model_iter_has_child (ts_model, iter)) {
		GtkTreeIter child;
		gtk_tree_model_iter_children (ts_model, &child, iter);
		status = check_node (ts, folder, &child);
	}

	while (gtk_tree_model_iter_next (ts_model, iter) && !status) {
		status = check_node (ts, folder, iter);
	}

	return status;
}

static void
add_to_store (GtkTreeStore *ts, ExchangeMAPIFolder *folder)
{
	GtkTreeModel *ts_model;
	GtkTreeIter iter;

	ts_model = GTK_TREE_MODEL (ts);
	
	gtk_tree_model_get_iter_first (ts_model, &iter);
	if (!check_node (ts, folder, &iter)) {
		GtkTreeIter node;
		gtk_tree_store_append (ts, &node, &iter);		
		gtk_tree_store_set (ts, &node, 0, folder->folder_name, 1, folder->folder_id, -1);
		
	}
}

static void
add_folders (GSList *folders, GtkTreeStore *ts)
{
	GSList *tmp = folders;
	GtkTreeIter iter;
	char *node = _("Personal Folders");
	
	gtk_tree_store_append (ts, &iter, NULL);
	gtk_tree_store_set (ts, &iter, 0, node, -1);
	while (tmp) {
		ExchangeMAPIFolder *folder = tmp->data;
		g_print("%s\n", folder->folder_name);
		add_to_store (ts, folder);
		tmp = tmp->next;
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

	gtk_tree_model_get (model, &iter, CONTACTSFID_COL, &pfid, -1);
	sfid = exchange_mapi_util_mapi_id_to_string (pfid);
	e_source_set_property (source, "parent-fid", sfid); 
	g_free (sfid);
}

GtkWidget *
exchange_mapi_create (EPlugin *epl, EConfigHookItemFactoryData *data)
{
	GtkWidget *vbox, *label, *scroll, *tv;
	EABConfigTargetSource *t = (EABConfigTargetSource *) data->target;
	ESource *source = t->source;
	char *uri_text;
	GtkCellRenderer *rcell;
	GtkTreeStore *ts;
	GtkTreeViewColumn *tvc;
	const char *acc;
	GSList *folders = exchange_mapi_account_listener_peek_folder_list ();

	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH)) {
		return NULL;
	}

	acc = e_source_group_peek_name (e_source_peek_group (source));
	ts = gtk_tree_store_new (NUM_COLS, G_TYPE_STRING, G_TYPE_INT64, G_TYPE_POINTER);

	add_folders (folders, ts);
	
	vbox = gtk_vbox_new (FALSE, 6);

	if (!strcmp (data->config->id, "org.gnome.evolution.calendar.calendarProperties")) {
		int row = ((GtkTable*) data->parent)->nrows;
		gtk_table_attach (GTK_TABLE (data->parent), vbox, 0, 2, row+1, row+2, GTK_FILL|GTK_EXPAND, 0, 0, 0);
	} else if (!strcmp (data->config->id, "com.novell.evolution.addressbook.config.accountEditor")) {
		gtk_container_add (GTK_CONTAINER (data->parent), vbox);
	}

	label = gtk_label_new_with_mnemonic (_("_Location:"));
	gtk_widget_show (label);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
	
	rcell = gtk_cell_renderer_text_new ();
	tvc = gtk_tree_view_column_new_with_attributes (acc, rcell, "text", CONTACTSNAME_COL, NULL);
	tv = gtk_tree_view_new_with_model (GTK_TREE_MODEL (ts));
	gtk_tree_view_append_column (GTK_TREE_VIEW (tv), tvc);
	g_object_set (tv,"expander-column", tvc, "headers-visible", TRUE, NULL);
	gtk_tree_view_expand_all (GTK_TREE_VIEW (tv));
	
	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);
	g_object_set (scroll, "height-request", 150, NULL);
	gtk_container_add (GTK_CONTAINER (scroll), tv);
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), tv);
	g_signal_connect (G_OBJECT (tv), "cursor-changed", G_CALLBACK (exchange_mapi_cursor_change), t->source);
	gtk_widget_show_all (scroll);

	gtk_box_pack_start (GTK_BOX (vbox), scroll, FALSE, FALSE, 0);

	gtk_widget_show_all (vbox);
	return vbox;
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
	char *uri_text, *tmp;
	const char *sfid; 
	mapi_id_t fid, pfid;
	ESourceGroup *grp;
	
	uri_text = e_source_get_uri (source);
	if (uri_text && g_ascii_strncasecmp (uri_text, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH))
		return;
	
	//FIXME: Offline handling
	sfid = e_source_get_property (source, "parent-fid");
	exchange_mapi_util_mapi_id_from_string (sfid, &pfid);

	fid = exchange_mapi_create_folder (olFolderContacts, pfid, e_source_peek_name (source));
	g_print("Created %016llX\n", fid);
	grp = e_source_peek_group (source);
	e_source_set_property (source, "auth", "plain/password");
	e_source_set_property (source, "auth-domain", EXCHANGE_MAPI_PASSWORD_COMPONENT);
	e_source_set_property(source, "user", e_source_group_get_property (grp, "user"));
	e_source_set_property(source, "host", e_source_group_get_property (grp, "host"));
	e_source_set_property(source, "profile", e_source_group_get_property (grp, "profile"));
	e_source_set_property(source, "domain", e_source_group_get_property (grp, "domain"));
	e_source_set_relative_uri (source, g_strconcat (";",e_source_peek_name (source), NULL));

	tmp = exchange_mapi_util_mapi_id_to_string (fid);
	e_source_set_property(source, "folder-id", tmp);
	g_free (tmp);
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
			g_warning ("%s(%d): %s: Unknown ExchangeMAPIFolderType\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
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

