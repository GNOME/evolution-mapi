/*
 * e-mail-config-mapi-backend.c
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

#include <camel/camel.h>
#include <libebackend/libebackend.h>
#include <libedataserver/libedataserver.h>

#include <e-util/e-dialog-utils.h>
#include <mail/e-mail-config-auth-check.h>
#include <mail/e-mail-config-receiving-page.h>
#include <shell/e-shell.h>

#include "camel-mapi-settings.h"
#include "e-mapi-folder.h"
#include "e-mapi-connection.h"
#include "e-mapi-utils.h"
#include "e-mapi-config-utils.h"

#include "e-mail-config-mapi-backend.h"

#define E_MAIL_CONFIG_MAPI_BACKEND_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE \
	((obj), E_TYPE_MAIL_CONFIG_MAPI_BACKEND, EMailConfigMapiBackendPrivate))

struct _EMailConfigMapiBackendPrivate {
	gint unused;
};

G_DEFINE_DYNAMIC_TYPE (
	EMailConfigMapiBackend,
	e_mail_config_mapi_backend,
	E_TYPE_MAIL_CONFIG_SERVICE_BACKEND)

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

static gboolean
validate_credentials_test (ESourceRegistry *registry,
			   EMapiProfileData *empd,
			   CamelMapiSettings *mapi_settings,
			   GCancellable *cancellable,
			   GError **perror)
{
	gboolean status, success = FALSE;
	struct mapi_context *mapi_ctx = NULL;

	status = e_mapi_utils_create_mapi_context (&mapi_ctx, perror);
	status = status && e_mapi_create_profile (mapi_ctx, empd, create_profile_callback_in_thread, empd->username, NULL, perror);
	if (status && !g_cancellable_is_cancelled (cancellable)) {
		/* profile was created, try to connect to the server */
		EMapiConnection *conn;
		gchar *profname;

		status = FALSE;
		profname = e_mapi_util_profile_name (mapi_ctx, empd, FALSE);

		conn = e_mapi_connection_new (registry, profname, empd->password, cancellable, perror);
		if (conn) {
			status = e_mapi_connection_connected (conn);
			g_object_unref (conn);
		}

		g_free (profname);
	}

	if (status) {
		/* Things are successful */
		gchar *profname = NULL;

		profname = e_mapi_util_profile_name (mapi_ctx, empd, FALSE);
		camel_mapi_settings_set_profile (mapi_settings, profname);
		g_free (profname);

		success = TRUE;
	}

	e_mapi_utils_destroy_mapi_context (mapi_ctx);

	return success;
}

typedef struct _EMailConfigMapiAuthenticator EMailConfigMapiAuthenticator;
typedef struct _EMailConfigMapiAuthenticatorClass EMailConfigMapiAuthenticatorClass;

struct _EMailConfigMapiAuthenticator {
	GObject parent;

	gchar *username;
	gchar *domain;
	gchar *server;
	gboolean use_ssl;
	gboolean krb_sso;
	gchar *krb_realm;
	CamelMapiSettings *mapi_settings;
	EMailConfigServiceBackend *backend;
	gboolean success;
};

struct _EMailConfigMapiAuthenticatorClass {
	GObjectClass parent_class;
};

static ESourceAuthenticationResult
mail_config_mapi_authenticator_try_password_sync (ESourceAuthenticator *auth,
						  const GString *password,
						  GCancellable *cancellable,
						  GError **error)
{
	EMailConfigMapiAuthenticator *mapi_authenticator = (EMailConfigMapiAuthenticator *) auth;
	EMailConfigServicePage *page;
	ESourceRegistry *registry;
	EMapiProfileData empd = { 0 };
	GError *mapi_error = NULL;

	empd.username = mapi_authenticator->username;
	empd.domain = mapi_authenticator->domain;
	empd.server = mapi_authenticator->server;
	empd.password = (GString *) password;
	empd.use_ssl = mapi_authenticator->use_ssl;
	empd.krb_sso = mapi_authenticator->krb_sso;
	empd.krb_realm = mapi_authenticator->krb_realm;

	page = e_mail_config_service_backend_get_page (mapi_authenticator->backend);
	registry = e_mail_config_service_page_get_registry (page);

	mapi_authenticator->success = validate_credentials_test (
		registry,
		&empd, 
		mapi_authenticator->mapi_settings,
		cancellable,
		&mapi_error);

	if (mapi_error) {
		gboolean is_network_error = g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NETWORK_ERROR);

		g_warn_if_fail (!mapi_authenticator->success);
		mapi_authenticator->success = FALSE;

		if (is_network_error)
			g_propagate_error (error, mapi_error);
		else
			g_clear_error (&mapi_error);

		return is_network_error ? E_SOURCE_AUTHENTICATION_ERROR : E_SOURCE_AUTHENTICATION_REJECTED;
	}

	g_warn_if_fail (mapi_authenticator->success);

	return E_SOURCE_AUTHENTICATION_ACCEPTED;
}

#define E_TYPE_MAIL_CONFIG_MAPI_AUTHENTICATOR (e_mail_config_mapi_authenticator_get_type ())

GType e_mail_config_mapi_authenticator_get_type (void) G_GNUC_CONST;

static void e_mail_config_mapi_authenticator_authenticator_init (ESourceAuthenticatorInterface *interface);

G_DEFINE_TYPE_EXTENDED (EMailConfigMapiAuthenticator, e_mail_config_mapi_authenticator, G_TYPE_OBJECT, 0,
	G_IMPLEMENT_INTERFACE (E_TYPE_SOURCE_AUTHENTICATOR, e_mail_config_mapi_authenticator_authenticator_init))

static void
mail_config_mapi_authenticator_finalize (GObject *object)
{
	EMailConfigMapiAuthenticator *mapi_authenticator = (EMailConfigMapiAuthenticator *) object;

	g_free (mapi_authenticator->username);
	g_free (mapi_authenticator->domain);
	g_free (mapi_authenticator->server);
	g_free (mapi_authenticator->krb_realm);
	g_object_unref (mapi_authenticator->mapi_settings);
	g_object_unref (mapi_authenticator->backend);

	G_OBJECT_CLASS (e_mail_config_mapi_authenticator_parent_class)->finalize (object);
}

static void
e_mail_config_mapi_authenticator_class_init (EMailConfigMapiAuthenticatorClass *class)
{
	GObjectClass *object_class;

	object_class = G_OBJECT_CLASS (class);
	object_class->finalize = mail_config_mapi_authenticator_finalize;
}

static void
e_mail_config_mapi_authenticator_authenticator_init (ESourceAuthenticatorInterface *interface)
{
	interface->try_password_sync = mail_config_mapi_authenticator_try_password_sync;
}

static void
e_mail_config_mapi_authenticator_init (EMailConfigMapiAuthenticator *mapi_authenticator)
{
}

static void
validate_credentials_idle (GObject *button,
			   gpointer user_data,
			   GCancellable *cancellable,
			   GError **perror)
{
	EMailConfigMapiAuthenticator *mapi_authenticator = user_data;

	g_return_if_fail (mapi_authenticator != NULL);

	if (mapi_authenticator->success)
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
	EMailConfigMapiAuthenticator *mapi_authenticator = user_data;
	EMailConfigServicePage *page;
	ESourceRegistry *registry;

	g_return_if_fail (mapi_authenticator != NULL);

	page = e_mail_config_service_backend_get_page (mapi_authenticator->backend);
	registry = e_mail_config_service_page_get_registry (page);

	if (mapi_authenticator->krb_sso) {
		GError *error = NULL;
		EMapiProfileData empd = { 0 };

		empd.username = mapi_authenticator->username;
		empd.domain = mapi_authenticator->domain;
		empd.server = mapi_authenticator->server;
		empd.use_ssl = mapi_authenticator->use_ssl;
		empd.krb_sso = mapi_authenticator->krb_sso;
		empd.krb_realm = mapi_authenticator->krb_realm;

		e_mapi_util_trigger_krb_auth (&empd, &error);
		g_clear_error (&error);

		mapi_authenticator->success = validate_credentials_test (
			registry,
			&empd, 
			mapi_authenticator->mapi_settings,
			cancellable,
			perror);
	} else {
		ESource *source;

		source = e_mail_config_service_backend_get_source (mapi_authenticator->backend);

		e_source_registry_authenticate_sync (
			registry, source, E_SOURCE_AUTHENTICATOR (mapi_authenticator),
			cancellable, perror);
	}
}

static void
validate_credentials_cb (GtkWidget *widget,
			 EMailConfigServiceBackend *backend)
{
	EMapiProfileData empd = { 0 };
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	CamelNetworkSettings *network_settings;
	const gchar *host;
	const gchar *user;
	GError *error = NULL;

	if (!e_mapi_config_utils_is_online ()) {
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Cannot authenticate MAPI accounts in offline mode"));
		return;
	}

	settings = e_mail_config_service_backend_get_settings (backend);
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

	if (COMPLETE_PROFILEDATA (&empd)) {
		EMailConfigMapiAuthenticator *mapi_authenticator;

		mapi_authenticator = g_object_new (E_TYPE_MAIL_CONFIG_MAPI_AUTHENTICATOR, NULL);

		mapi_authenticator->username = g_strdup (empd.username);
		mapi_authenticator->domain = g_strdup (empd.domain);
		mapi_authenticator->server = g_strdup (empd.server);
		mapi_authenticator->use_ssl = empd.use_ssl;
		mapi_authenticator->krb_sso = empd.krb_sso;
		mapi_authenticator->krb_realm = g_strdup (empd.krb_realm);
		mapi_authenticator->mapi_settings = g_object_ref (mapi_settings);
		mapi_authenticator->backend = g_object_ref (backend);
		mapi_authenticator->success = FALSE;

		e_mapi_config_utils_run_in_thread_with_feedback_modal (e_mapi_config_utils_get_widget_toplevel_window (widget),
			G_OBJECT (widget),
			_("Connecting to the server, please wait..."),
			validate_credentials_thread,
			validate_credentials_idle,
			mapi_authenticator,
			g_object_unref);
	} else {
		e_notice (NULL, GTK_MESSAGE_ERROR, "%s", _("Authentication failed."));
	}

	if (error)
		g_error_free (error);

	if (empd.password) {
		memset (empd.password->str, 0, empd.password->len);
		g_string_free (empd.password, TRUE);
	}
}

static ESource *
mail_config_mapi_backend_new_collection (EMailConfigServiceBackend *backend)
{
	EMailConfigServiceBackendClass *class;
	ESourceBackend *extension;
	ESource *source;
	const gchar *extension_name;

	/* This backend serves double duty.  One instance holds the
	 * mail account source, another holds the mail transport source.
	 * We can differentiate by examining the EMailConfigServicePage
	 * the backend is associated with.  We return a new collection
	 * for both the Receiving Page and Sending Page.  Although the
	 * Sending Page instance ultimately gets discarded, it's still
	 * needed to avoid creating a [Mapi Backend] extension in the
	 * mail transport source. */

	class = E_MAIL_CONFIG_SERVICE_BACKEND_GET_CLASS (backend);

	source = e_source_new (NULL, NULL, NULL);
	extension_name = E_SOURCE_EXTENSION_COLLECTION;
	extension = e_source_get_extension (source, extension_name);
	e_source_backend_set_backend_name (extension, class->backend_name);

	return source;
}

static void
mail_config_mapi_backend_insert_widgets (EMailConfigServiceBackend *backend,
					 GtkBox *parent)
{
	EMailConfigServicePage *page;
	ESource *source;
	ESourceExtension *extension;
	CamelSettings *settings;
	GtkWidget *hgrid = NULL;
	GtkWidget *label, *entry;
	GtkWidget *auth_button;
	GtkWidget *secure_conn;
	GtkWidget *krb_sso;
	GtkGrid *content_grid;
	gchar *markup;
	gint irow;

	page = e_mail_config_service_backend_get_page (backend);

	/* This backend serves double duty.  One instance holds the
	 * mail account source, another holds the mail transport source.
	 * We can differentiate by examining the EMailConfigServicePage
	 * the backend is associated with.  This method only applies to
	 * the Receiving Page. */
	if (!E_IS_MAIL_CONFIG_RECEIVING_PAGE (page))
		return;

	/* This needs to come _after_ the page type check so we don't
	 * introduce a backend extension in the mail transport source. */
	settings = e_mail_config_service_backend_get_settings (backend);

	content_grid = GTK_GRID (gtk_grid_new ());
	gtk_widget_set_margin_left (GTK_WIDGET (content_grid), 12);
	gtk_grid_set_row_spacing (content_grid, 6);
	gtk_grid_set_column_spacing (content_grid, 6);
	gtk_box_pack_start (GTK_BOX (parent), GTK_WIDGET (content_grid), FALSE, FALSE, 0);

	irow = 0;

	markup = g_markup_printf_escaped ("<b>%s</b>", _("Configuration"));
	label = gtk_label_new (markup);
	gtk_label_set_use_markup (GTK_LABEL (label), TRUE);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	g_free (markup);

	gtk_grid_attach (content_grid, label, 0, irow, 2, 1);
	irow++;

	label = gtk_label_new_with_mnemonic (_("_Server:"));
	gtk_misc_set_alignment (GTK_MISC (label), 1.0, 0.5);

	entry = gtk_entry_new ();
	gtk_widget_set_hexpand (entry, TRUE);
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);

	g_object_bind_property (
		settings, "host",
		entry, "text",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	gtk_grid_attach (content_grid, label, 0, irow, 1, 1);
	gtk_grid_attach (content_grid, entry, 1, irow, 1, 1);
	irow++;

	label = gtk_label_new_with_mnemonic (_("User_name:"));
	gtk_misc_set_alignment (GTK_MISC (label), 1.0, 0.5);

	entry = gtk_entry_new ();
	gtk_widget_set_hexpand (entry, TRUE);
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);

	g_object_bind_property (
		settings, "user",
		entry, "text",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	gtk_grid_attach (content_grid, label, 0, irow, 1, 1);
	gtk_grid_attach (content_grid, entry, 1, irow, 1, 1);
	irow++;

	/* Domain name & Authenticate Button */
	hgrid = g_object_new (GTK_TYPE_GRID,
		"column-homogeneous", FALSE,
		"column-spacing", 6,
		"orientation", GTK_ORIENTATION_HORIZONTAL,
		NULL);
	gtk_widget_set_hexpand (hgrid, TRUE);

	label = gtk_label_new_with_mnemonic (_("_Domain name:"));
	gtk_misc_set_alignment (GTK_MISC (label), 1.0, 0.5);

	entry = gtk_entry_new ();
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);
	gtk_widget_set_hexpand (entry, TRUE);
	gtk_container_add (GTK_CONTAINER (hgrid), entry);
	g_object_bind_property (
		settings, "domain",
		entry, "text",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	auth_button = gtk_button_new_with_mnemonic (_("_Authenticate"));
	gtk_container_add (GTK_CONTAINER (hgrid), auth_button);
	g_signal_connect (auth_button, "clicked",  G_CALLBACK (validate_credentials_cb), backend);

	gtk_grid_attach (content_grid, label, 0, irow, 1, 1);
	gtk_grid_attach (content_grid, hgrid, 1, irow, 1, 1);
	irow++;

	secure_conn = gtk_check_button_new_with_mnemonic (_("_Use secure connection"));
	gtk_widget_set_hexpand (secure_conn, TRUE);
	
	gtk_grid_attach (content_grid, secure_conn, 1, irow, 1, 1);
	irow++;

	g_object_bind_property_full (
		settings, "security-method",
		secure_conn, "active",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE,
		transform_security_method_to_boolean,
		transform_boolean_to_security_method,
		NULL, (GDestroyNotify) NULL);

	krb_sso = gtk_check_button_new_with_mnemonic (_("_Kerberos authentication"));
	gtk_widget_set_hexpand (secure_conn, TRUE);

	g_object_bind_property (
		settings, "kerberos",
		krb_sso, "active",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	gtk_grid_attach (content_grid, krb_sso, 1, irow, 1, 1);
	irow++;

	label = gtk_label_new_with_mnemonic (_("_Realm name:"));
	gtk_misc_set_alignment (GTK_MISC (label), 1.0, 0.5);

	g_object_bind_property (
		settings, "kerberos",
		label, "sensitive",
		G_BINDING_SYNC_CREATE);

	entry = gtk_entry_new ();
	gtk_widget_set_hexpand (entry, TRUE);
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);

	g_object_bind_property (
		settings, "realm",
		entry, "text",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	g_object_bind_property (
		settings, "kerberos",
		entry, "sensitive",
		G_BINDING_SYNC_CREATE);

	gtk_grid_attach (content_grid, label, 0, irow, 1, 1);
	gtk_grid_attach (content_grid, entry, 1, irow, 1, 1);

	source = e_mail_config_service_backend_get_collection (backend);
	extension = e_source_get_extension (source, E_SOURCE_EXTENSION_COLLECTION);

	/* The collection identity is the user name. */
	g_object_bind_property (
		settings, "user",
		extension, "identity",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	gtk_widget_show_all (GTK_WIDGET (content_grid));
}

static void
mail_config_mapi_backend_setup_defaults (EMailConfigServiceBackend *backend)
{
	CamelSettings *settings;
	EMailConfigServicePage *page;
	const gchar *email_address;
	gchar **parts = NULL;

	page = e_mail_config_service_backend_get_page (backend);

	/* This backend serves double duty.  One instance holds the
	 * mail account source, another holds the mail transport source.
	 * We can differentiate by examining the EMailConfigServicePage
	 * the backend is associated with.  This method only applies to
	 * the Receiving Page. */
	if (!E_IS_MAIL_CONFIG_RECEIVING_PAGE (page))
		return;

	/* This needs to come _after_ the page type check so we don't
	 * introduce a backend extension in the mail transport source. */
	settings = e_mail_config_service_backend_get_settings (backend);

	email_address = e_mail_config_service_page_get_email_address (page);
	if (email_address != NULL)
		parts = g_strsplit (email_address, "@", 2);

	if (parts != NULL && g_strv_length (parts) >= 2) {
		CamelNetworkSettings *network_settings;
		gchar *host;

		g_strstrip (parts[0]);  /* user name */
		g_strstrip (parts[1]);  /* domain name */

		host = g_strdup_printf ("exchange.%s", parts[1]);

		network_settings = CAMEL_NETWORK_SETTINGS (settings);
		camel_network_settings_set_host (network_settings, host);
		camel_network_settings_set_user (network_settings, parts[0]);

		g_free (host);
	}

	g_strfreev (parts);
}

static gboolean
mail_config_mapi_backend_check_complete (EMailConfigServiceBackend *backend)
{
	EMailConfigServicePage *page;
	CamelSettings *settings;
	CamelMapiSettings *mapi_settings;
	const gchar *profile;

	page = e_mail_config_service_backend_get_page (backend);

	/* This backend serves double duty.  One instance holds the
	 * mail account source, another holds the mail transport source.
	 * We can differentiate by examining the EMailConfigServicePage
	 * the backend is associated with.  This method only applies to
	 * the Receiving Page. */
	if (!E_IS_MAIL_CONFIG_RECEIVING_PAGE (page))
		return TRUE;

	/* This needs to come _after_ the page type check so we don't
	 * introduce a backend extension in the mail transport source. */
	settings = e_mail_config_service_backend_get_settings (backend);
	mapi_settings = CAMEL_MAPI_SETTINGS (settings);

	/* We assume that if the profile is set, then the setting is valid. */
	profile = camel_mapi_settings_get_profile (mapi_settings);

	/* Profile not set. Do not proceed with account creation.*/
	return (profile != NULL && *profile != '\0');
}

static void
e_mail_config_mapi_backend_class_init (EMailConfigMapiBackendClass *class)
{
	EMailConfigServiceBackendClass *backend_class;

	g_type_class_add_private (
		class, sizeof (EMailConfigMapiBackendPrivate));

	backend_class = E_MAIL_CONFIG_SERVICE_BACKEND_CLASS (class);
	backend_class->backend_name = "mapi";
	backend_class->new_collection = mail_config_mapi_backend_new_collection;
	backend_class->insert_widgets = mail_config_mapi_backend_insert_widgets;
	backend_class->setup_defaults = mail_config_mapi_backend_setup_defaults;
	backend_class->check_complete = mail_config_mapi_backend_check_complete;
}

static void
e_mail_config_mapi_backend_class_finalize (EMailConfigMapiBackendClass *class)
{
}

static void
e_mail_config_mapi_backend_init (EMailConfigMapiBackend *backend)
{
	backend->priv = E_MAIL_CONFIG_MAPI_BACKEND_GET_PRIVATE (backend);
}

void
e_mail_config_mapi_backend_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_mail_config_mapi_backend_register_type (type_module);
}
