/*
 * e-mapi-config-utils.c
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

#include "evolution-mapi-config.h"

#include <string.h>
#include <unistd.h>
#include <glib/gi18n-lib.h>

#include <gtk/gtk.h>
#include <libedataserver/libedataserver.h>
#include <libedataserverui/libedataserverui.h>

#include <e-util/e-util.h>

#include <mail/em-folder-tree.h>
#include <shell/e-shell.h>
#include <shell/e-shell-sidebar.h>
#include <shell/e-shell-view.h>
#include <shell/e-shell-window.h>

#include "e-mapi-folder.h"
#include "e-mapi-connection.h"
#include "e-mapi-utils.h"
#include "e-source-mapi-folder.h"

#include "e-mapi-subscribe-foreign-folder.h"
#include "e-mapi-edit-folder-permissions.h"

#include "camel/camel-mapi-store.h"
#include "camel/camel-mapi-store-summary.h"

#include "e-mapi-config-utils.h"

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

static gpointer
run_with_feedback_thread (gpointer user_data)
{
	struct RunWithFeedbackData *rfd = user_data;

	g_return_val_if_fail (rfd != NULL, NULL);
	g_return_val_if_fail (rfd->thread_func != NULL, NULL);

	if (!g_cancellable_is_cancelled (rfd->cancellable))
		rfd->thread_func (rfd->with_object, rfd->user_data, rfd->cancellable, &rfd->error);

	g_idle_add (run_with_feedback_idle, rfd);

	return NULL;
}

static void
run_with_feedback_response_cb (GtkWidget *dialog,
			       gint resonse_id,
			       struct RunWithFeedbackData *rfd)
{
	g_return_if_fail (rfd != NULL);

	rfd->dialog = NULL;

	g_cancellable_cancel (rfd->cancellable);

	gtk_widget_destroy (dialog);
}

static void
e_mapi_config_utils_run_in_thread_with_feedback_general (GtkWindow *parent,
					    GObject *with_object,
					    const gchar *description,
					    EMapiSetupFunc thread_func,
					    EMapiSetupFunc idle_func,
					    gpointer user_data,
					    GDestroyNotify free_user_data,
					    gboolean run_modal)
{
	GtkWidget *dialog, *label, *content, *spinner, *box;
	struct RunWithFeedbackData *rfd;

	g_return_if_fail (with_object != NULL);
	g_return_if_fail (description != NULL);
	g_return_if_fail (thread_func != NULL);

	dialog = gtk_dialog_new_with_buttons ("",
		parent,
		GTK_DIALOG_MODAL,
		GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
		NULL);

	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

	spinner = e_spinner_new ();
	e_spinner_start (E_SPINNER (spinner));
	gtk_box_pack_start (GTK_BOX (box), spinner, FALSE, FALSE, 0);

	label = gtk_label_new (description);
	gtk_box_pack_start (GTK_BOX (box), label, TRUE, TRUE, 0);

	gtk_widget_show_all (box);

	content = gtk_dialog_get_content_area (GTK_DIALOG (dialog));

	gtk_container_add (GTK_CONTAINER (content), box);
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
		GThread *thread;
		GCancellable *cancellable;

		cancellable = g_object_ref (rfd->cancellable);

		thread = g_thread_new (NULL, run_with_feedback_thread, rfd);
		g_thread_unref (thread);

		gtk_dialog_run (GTK_DIALOG (dialog));

		g_cancellable_cancel (cancellable);
		g_object_unref (cancellable);
	} else {
		GThread *thread;

		gtk_widget_show (dialog);

		thread = g_thread_new (NULL, run_with_feedback_thread, rfd);
		g_thread_unref (thread);
	}
}

void
e_mapi_config_utils_run_in_thread_with_feedback (GtkWindow *parent,
				    GObject *with_object,
				    const gchar *description,
				    EMapiSetupFunc thread_func,
				    EMapiSetupFunc idle_func,
				    gpointer user_data,
				    GDestroyNotify free_user_data)
{
	e_mapi_config_utils_run_in_thread_with_feedback_general (parent, with_object, description, thread_func, idle_func, user_data, free_user_data, FALSE);
}

void
e_mapi_config_utils_run_in_thread_with_feedback_modal (GtkWindow *parent,
					  GObject *with_object,
					  const gchar *description,
					  EMapiSetupFunc thread_func,
					  EMapiSetupFunc idle_func,
					  gpointer user_data,
					  GDestroyNotify free_user_data)
{
	e_mapi_config_utils_run_in_thread_with_feedback_general (parent, with_object, description, thread_func, idle_func, user_data, free_user_data, TRUE);
}

typedef struct _TryCredentialsData {
	ESourceRegistry *registry;
	CamelMapiSettings *mapi_settings;
	EMapiConnection *conn;
} TryCredentialsData;

static gboolean
mapi_config_utils_try_credentials_sync (ECredentialsPrompter *prompter,
					ESource *source,
					const ENamedParameters *credentials,
					gboolean *out_authenticated,
					gpointer user_data,
					GCancellable *cancellable,
					GError **error)
{
	TryCredentialsData *data = user_data;
	EMapiProfileData empd = { 0 };
	CamelNetworkSettings *network_settings;
	GError *mapi_error = NULL;

	network_settings = CAMEL_NETWORK_SETTINGS (data->mapi_settings);

	empd.server = camel_network_settings_get_host (network_settings);
	empd.username = camel_network_settings_get_user (network_settings);
	e_mapi_util_profiledata_from_settings (&empd, data->mapi_settings);

	data->conn = e_mapi_connection_new (
		data->registry,
		camel_mapi_settings_get_profile (data->mapi_settings),
		credentials, cancellable, &mapi_error);

	if (mapi_error) {
		g_warn_if_fail (!data->conn);
		data->conn = NULL;

		g_propagate_error (error, mapi_error);

		return FALSE;
	}

	g_warn_if_fail (data->conn);
	*out_authenticated = TRUE;

	return TRUE;
}

EMapiConnection	*
e_mapi_config_utils_open_connection_for (GtkWindow *parent,
					 ESourceRegistry *registry,
					 ESource *source,
					 CamelMapiSettings *mapi_settings,
					 GCancellable *cancellable,
					 GError **perror)
{
	const gchar *profile;
	EMapiConnection *conn = NULL;
	EMapiProfileData empd = { 0 };
	CamelNetworkSettings *network_settings;
	GError *local_error = NULL;

	g_return_val_if_fail (registry != NULL, NULL);
	g_return_val_if_fail (source != NULL, NULL);
	g_return_val_if_fail (mapi_settings != NULL, NULL);

	profile = camel_mapi_settings_get_profile (mapi_settings);

	/* use the one from mailer, if there, otherwise open new */
	conn = e_mapi_connection_find (profile);
	if (conn)
		return conn;

	network_settings = CAMEL_NETWORK_SETTINGS (mapi_settings);

	empd.server = camel_network_settings_get_host (network_settings);
	empd.username = camel_network_settings_get_user (network_settings);
	e_mapi_util_profiledata_from_settings (&empd, mapi_settings);

	if (empd.krb_sso)
		conn = e_mapi_connection_new (registry, profile, NULL, cancellable, &local_error);

	while (!conn && !g_cancellable_is_cancelled (cancellable) && !local_error) {
		if (empd.krb_sso) {
			GError *krb_error = NULL;

			e_mapi_util_trigger_krb_auth (&empd, &krb_error);

			conn = e_mapi_connection_new (registry, profile, NULL, cancellable, &local_error);

			if (!conn && krb_error) {
				if (local_error) {
					GError *new_error = g_error_new (local_error->domain, local_error->code,
						/* Translators: the first '%s' is replaced with a generic error message,
						   the second '%s' is replaced with additional error information. */
						C_("gssapi_error", "%s (%s)"), local_error->message, krb_error->message);
					g_clear_error (&local_error);
					local_error = new_error;
				} else {
					local_error = krb_error;
					krb_error = NULL;
				}
			}

			g_clear_error (&krb_error);
		} else {
			EShell *shell;
			TryCredentialsData data;

			shell = e_shell_get_default ();

			data.mapi_settings = g_object_ref (mapi_settings);
			data.registry = g_object_ref (registry);
			data.conn = NULL;

			e_credentials_prompter_loop_prompt_sync (e_shell_get_credentials_prompter (shell),
				source, E_CREDENTIALS_PROMPTER_PROMPT_FLAG_ALLOW_SOURCE_SAVE,
				mapi_config_utils_try_credentials_sync, &data, cancellable, &local_error);

			if (data.conn)
				conn = g_object_ref (data.conn);

			g_clear_object (&data.mapi_settings);
			g_clear_object (&data.registry);
			g_clear_object (&data.conn);
		}
	}

	if (local_error)
		g_propagate_error (perror, local_error);

	return conn;
}

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

	ESourceRegistry *registry;
	ESource *source;
	CamelMapiSettings *mapi_settings;

	GSList *folder_list;
	GCancellable *cancellable;
	GError *error;
} FolderSizeDialogData;

static gboolean
mapi_settings_get_folder_size_idle (gpointer user_data)
{
	GtkWidget *widget;
	GtkCellRenderer *renderer;
	GtkListStore *store;
	GtkTreeIter iter;
	GtkBox *content_area;
	FolderSizeDialogData *fsd = user_data;

	g_return_val_if_fail (fsd != NULL, FALSE);

	if (g_cancellable_is_cancelled (fsd->cancellable))
		goto cleanup;

	/* Hide progress bar. Set status*/
	gtk_widget_destroy (GTK_WIDGET (fsd->spinner_grid));

	if (fsd->folder_list) {
		GtkWidget *scrolledwindow, *tree_view;
		GSList *fiter;

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
		for (fiter = fsd->folder_list; fiter;  fiter = fiter->next) {
			EMapiFolder *folder = fiter->data;
			gchar *folder_size = g_format_size (folder->size);

			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,
					    COL_FOLDERSIZE_NAME, folder->folder_name,
					    COL_FOLDERSIZE_SIZE, folder_size,
					    -1);

			g_free (folder_size);
		}

		gtk_container_add (GTK_CONTAINER (scrolledwindow), tree_view);
		widget = scrolledwindow;
	} else if (fsd->error) {
		gchar *msg = g_strconcat (_("Unable to retrieve folder size information"), "\n", fsd->error->message, NULL);
		widget = gtk_label_new (msg);
		g_free (msg);
	} else {
		widget = gtk_label_new (_("Unable to retrieve folder size information"));
	}

	gtk_widget_show_all (widget);

	/* Pack into content_area */
	content_area = GTK_BOX (gtk_dialog_get_content_area (fsd->dialog));
	gtk_box_pack_start (content_area, widget, TRUE, TRUE, 6);

 cleanup:
	e_mapi_folder_free_list (fsd->folder_list);
	g_object_unref (fsd->registry);
	g_object_unref (fsd->source);
	g_object_unref (fsd->mapi_settings);
	g_object_unref (fsd->cancellable);
	g_clear_error (&fsd->error);
	g_free (fsd);

	return FALSE;
}

static gpointer
mapi_settings_get_folder_size_thread (gpointer user_data)
{
	FolderSizeDialogData *fsd = user_data;
	EMapiConnection *conn;

	g_return_val_if_fail (fsd != NULL, NULL);

	fsd->folder_list = NULL;
	conn = e_mapi_config_utils_open_connection_for (GTK_WINDOW (fsd->dialog),
		fsd->registry,
		fsd->source,
		fsd->mapi_settings,
		fsd->cancellable,
		&fsd->error);

	if (conn && e_mapi_connection_connected (conn)) {
		fsd->folder_list = NULL;
		e_mapi_connection_get_folders_list (conn,
			&fsd->folder_list,
			NULL, NULL,
			fsd->cancellable, &fsd->error);
	}

	if (conn)
		g_object_unref (conn);

	g_idle_add (mapi_settings_get_folder_size_idle, fsd);

	return NULL;
}

void
e_mapi_config_utils_run_folder_size_dialog (ESourceRegistry *registry,
					    ESource *source,
					    CamelMapiSettings *mapi_settings)
{
	GtkBox *content_area;
	GtkWidget *spinner, *alignment, *dialog;
	GtkWidget *spinner_label;
	GCancellable *cancellable;
	GThread *thread;
	FolderSizeDialogData *fsd;

	g_return_if_fail (mapi_settings != NULL);

	dialog = gtk_dialog_new_with_buttons (_("Folder Size"), NULL,
		GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_CLOSE, GTK_RESPONSE_ACCEPT,
		NULL);

	fsd = g_new0 (FolderSizeDialogData, 1);
	fsd->dialog = GTK_DIALOG (dialog);

	gtk_window_set_default_size (GTK_WINDOW (fsd->dialog), 250, 300);

	content_area = GTK_BOX (gtk_dialog_get_content_area (fsd->dialog));

	spinner = e_spinner_new ();
	e_spinner_start (E_SPINNER (spinner));
	spinner_label = gtk_label_new (_("Fetching folder list…"));

	fsd->spinner_grid = GTK_GRID (gtk_grid_new ());
	gtk_grid_set_column_spacing (fsd->spinner_grid, 6);
	gtk_grid_set_column_homogeneous (fsd->spinner_grid, FALSE);
	gtk_orientable_set_orientation (GTK_ORIENTABLE (fsd->spinner_grid), GTK_ORIENTATION_HORIZONTAL);

	alignment = gtk_alignment_new (1.0, 0.5, 0.0, 1.0);
	gtk_container_add (GTK_CONTAINER (alignment), spinner);
	gtk_misc_set_alignment (GTK_MISC (spinner_label), 0.0, 0.5);

	gtk_container_add (GTK_CONTAINER (fsd->spinner_grid), alignment);
	gtk_container_add (GTK_CONTAINER (fsd->spinner_grid), spinner_label);

	/* Pack the TreeView into dialog's content area */
	gtk_box_pack_start (content_area, GTK_WIDGET (fsd->spinner_grid), TRUE, TRUE, 6);
	gtk_widget_show_all (GTK_WIDGET (fsd->dialog));

	cancellable = g_cancellable_new ();
	fsd->registry = g_object_ref (registry);
	fsd->source = g_object_ref (source);
	fsd->mapi_settings = g_object_ref (mapi_settings);
	fsd->cancellable = g_object_ref (cancellable);

	thread = g_thread_new (NULL, mapi_settings_get_folder_size_thread, fsd);
	g_thread_unref (thread);

	/* Start the dialog */
	gtk_dialog_run (GTK_DIALOG (dialog));

	g_cancellable_cancel (cancellable);
	g_object_unref (cancellable);
	gtk_widget_destroy (GTK_WIDGET (dialog));
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

				settings = camel_service_ref_settings (service);
				g_object_get (settings, "profile", &profile, NULL);
				g_object_unref (settings);

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
	CamelSession *session;
	CamelStore *store = NULL;

	profile = get_profile_name_from_folder_tree (shell_view, NULL, &store);
	if (profile && store) {
		CamelSettings *settings;
		ESourceRegistry *registry;
		ESource *source;

		session = camel_service_ref_session (CAMEL_SERVICE (store));
		registry = e_mail_session_get_registry (E_MAIL_SESSION (session));
		source = e_source_registry_ref_source (registry, camel_service_get_uid (CAMEL_SERVICE (store)));

		settings = camel_service_ref_settings (CAMEL_SERVICE (store));

		e_mapi_config_utils_run_folder_size_dialog (
			registry, source, CAMEL_MAPI_SETTINGS (settings));

		g_object_unref (settings);

		g_object_unref (source); 

		g_object_unref (session);
	}

	g_free (profile);
	if (store)
		g_object_unref (store);
}

static void
action_subscribe_foreign_folder_cb (GtkAction *action,
				    EShellView *shell_view)
{
	gchar *profile;
	GtkWindow *parent;
	EShell *shell;
	EShellBackend *backend;
	EClientCache *client_cache;
	CamelSession *session = NULL;
	CamelStore *store = NULL;

	profile = get_profile_name_from_folder_tree (shell_view, NULL, &store);
	if (!profile)
		return;

	parent = GTK_WINDOW (e_shell_view_get_shell_window (shell_view));
	backend = e_shell_view_get_shell_backend (shell_view);
	g_object_get (G_OBJECT (backend), "session", &session, NULL);

	shell = e_shell_backend_get_shell (backend);
	client_cache = e_shell_get_client_cache (shell);

	e_mapi_subscribe_foreign_folder (parent, session, store, client_cache);

	g_object_unref (session);
	g_object_unref (store);
	g_free (profile);
}

static void
action_folder_permissions_mail_cb (GtkAction *action,
				   EShellView *shell_view)
{
	gchar *profile, *folder_path = NULL;
	EShellWindow *shell_window;
	GtkWindow *parent;
	CamelStore *store = NULL;
	CamelMapiStore *mapi_store;
	CamelStoreInfo *si;

	profile = get_profile_name_from_folder_tree (shell_view, &folder_path, &store);
	if (!profile)
		return;

	mapi_store = CAMEL_MAPI_STORE (store);
	g_return_if_fail (mapi_store != NULL);
	g_return_if_fail (folder_path != NULL);

	shell_window = e_shell_view_get_shell_window (shell_view);
	parent = GTK_WINDOW (shell_window);

	si = camel_store_summary_path (mapi_store->summary, folder_path);
	if (!si) {
		e_notice (parent, GTK_MESSAGE_ERROR, _("Cannot edit permissions of folder “%s”, choose other folder."), folder_path);
	} else {
		CamelMapiStoreInfo *msi = (CamelMapiStoreInfo *) si;
		ESourceRegistry *registry = e_shell_get_registry (e_shell_window_get_shell (shell_window));
		ESource *source;
		CamelSettings *settings;

		source = e_source_registry_ref_source (registry, camel_service_get_uid (CAMEL_SERVICE (store)));
		g_return_if_fail (source != NULL);

		settings = camel_service_ref_settings (CAMEL_SERVICE (store));

		e_mapi_edit_folder_permissions (parent,
			registry,
			source,
			CAMEL_MAPI_SETTINGS (settings),
			camel_service_get_display_name (CAMEL_SERVICE (store)),
			folder_path,
			msi->folder_id,
			(msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_FOREIGN) != 0 ? E_MAPI_FOLDER_CATEGORY_FOREIGN :
			(msi->mapi_folder_flags & CAMEL_MAPI_STORE_FOLDER_FLAG_PUBLIC) != 0 ? E_MAPI_FOLDER_CATEGORY_PUBLIC :
			E_MAPI_FOLDER_CATEGORY_PERSONAL,
			msi->foreign_username,
			FALSE);

		g_object_unref (settings);

		g_object_unref (source);
	}

	g_object_unref (store);
	g_free (folder_path);
}

static void
mapi_ui_enable_actions (GtkActionGroup *action_group,
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
	  N_("Subscribe to folder of other user..."),
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

static const gchar *mapi_ui_mail_def =
	"<popup name=\"mail-folder-popup\">\n"
	"  <placeholder name=\"mail-folder-popup-actions\">\n"
	"    <menuitem action=\"mail-mapi-folder-size\"/>\n"
	"    <menuitem action=\"mail-mapi-subscribe-foreign-folder\"/>\n"
	"    <menuitem action=\"mail-mapi-folder-permissions\"/>\n"
	"  </placeholder>\n"
	"</popup>\n";

static void
mapi_ui_update_actions_mail_cb (EShellView *shell_view,
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

	mapi_ui_enable_actions (action_group, mail_account_context_entries, G_N_ELEMENTS (mail_account_context_entries), account_node, online);
	mapi_ui_enable_actions (action_group, mail_folder_context_entries, G_N_ELEMENTS (mail_folder_context_entries), folder_node, online);
}

static void
mapi_ui_init_mail (GtkUIManager *ui_manager,
                   EShellView *shell_view,
		   gchar **ui_definition)
{
	EShellWindow *shell_window;
	GtkActionGroup *action_group;

	g_return_if_fail (ui_definition != NULL);

	*ui_definition = g_strdup (mapi_ui_mail_def);

	shell_window = e_shell_view_get_shell_window (shell_view);
	action_group = e_shell_window_get_action_group (shell_window, "mail");

	/* Add actions to the "mail" action group. */
	e_action_group_add_actions_localized (action_group, GETTEXT_PACKAGE,
		mail_account_context_entries, G_N_ELEMENTS (mail_account_context_entries), shell_view);
	e_action_group_add_actions_localized (action_group, GETTEXT_PACKAGE,
		mail_folder_context_entries, G_N_ELEMENTS (mail_folder_context_entries), shell_view);

	/* Decide whether we want this option to be visible or not */
	g_signal_connect (shell_view, "update-actions",
			  G_CALLBACK (mapi_ui_update_actions_mail_cb),
			  shell_view);
}

static gboolean
get_selected_mapi_source (EShellView *shell_view,
			  ESource **selected_source,
			  ESourceRegistry **registry)
{
	ESource *source;
	EShellSidebar *shell_sidebar;
	ESourceSelector *selector = NULL;

	g_return_val_if_fail (shell_view != NULL, FALSE);

	shell_sidebar = e_shell_view_get_shell_sidebar (shell_view);
	g_return_val_if_fail (shell_sidebar != NULL, FALSE);

	g_object_get (shell_sidebar, "selector", &selector, NULL);
	g_return_val_if_fail (selector != NULL, FALSE);

	source = e_source_selector_ref_primary_selection (selector);
	if (source) {
		ESourceBackend *backend_ext = NULL;

		if (e_source_has_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK))
			backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
		else if (e_source_has_extension (source, E_SOURCE_EXTENSION_CALENDAR))
			backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_CALENDAR);
		else if (e_source_has_extension (source, E_SOURCE_EXTENSION_MEMO_LIST))
			backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MEMO_LIST);
		else if (e_source_has_extension (source, E_SOURCE_EXTENSION_TASK_LIST))
			backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_TASK_LIST);
		else if (e_source_has_extension (source, E_SOURCE_EXTENSION_MAIL_ACCOUNT))
			backend_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAIL_ACCOUNT);

		if (!backend_ext ||
		    g_strcmp0 (e_source_backend_get_backend_name (backend_ext), "mapi") != 0) {
			g_object_unref (source);
			source = NULL;
		}
	}

	if (source && registry)
		*registry = g_object_ref (e_source_selector_get_registry (selector));

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
	ESource *source = NULL;
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

	is_mapi_source = get_selected_mapi_source (shell_view, &source, NULL);

	if (is_mapi_source) {
		ESource *clicked_source = NULL;

		g_object_get (G_OBJECT (shell_view), "clicked-source", &clicked_source, NULL);

		if (clicked_source && clicked_source != source)
			is_mapi_source = FALSE;

		g_clear_object (&clicked_source);
	}

	g_clear_object (&source);

	shell_window = e_shell_view_get_shell_window (shell_view);
	shell = e_shell_window_get_shell (shell_window);

	is_online = shell && e_shell_get_online (shell);
	action_group = e_shell_window_get_action_group (shell_window, group);

	mapi_ui_enable_actions (action_group, entries, MAPI_ESOURCE_NUM_ENTRIES, is_mapi_source, is_online);
}

static void
setup_mapi_source_actions (EShellView *shell_view,
			   GtkUIManager *ui_manager,
			   GtkActionEntry *entries,
			   guint n_entries)
{
	EShellWindow *shell_window;
	const gchar *group;

	g_return_if_fail (shell_view != NULL);
	g_return_if_fail (ui_manager != NULL);
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
	ESourceRegistry *registry = NULL;
	ESource *source = NULL, *parent_source;
	ESourceMapiFolder *folder_ext;
	mapi_id_t folder_id = 0;
	const gchar *foreign_username;
	gboolean is_public;
	ESourceCamel *extension;
	CamelSettings *settings;
	const gchar *extension_name;

	g_return_if_fail (action != NULL);
	g_return_if_fail (shell_view != NULL);
	g_return_if_fail (get_selected_mapi_source (shell_view, &source, &registry));
	g_return_if_fail (source != NULL);
	g_return_if_fail (e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER));
	g_return_if_fail (gtk_action_get_name (action) != NULL);

	folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	folder_id = e_source_mapi_folder_get_id (folder_ext);
	g_return_if_fail (folder_id != 0);

	foreign_username = e_source_mapi_folder_get_foreign_username (folder_ext);
	is_public = !foreign_username && e_source_mapi_folder_is_public (folder_ext);

	parent_source = e_source_registry_ref_source (registry, e_source_get_parent (source));

	extension_name = e_source_camel_get_extension_name ("mapi");
	extension = e_source_get_extension (parent_source, extension_name);

	settings = e_source_camel_get_settings (extension);

	e_mapi_edit_folder_permissions (NULL,
		registry,
		source,
		CAMEL_MAPI_SETTINGS (settings),
		e_source_get_display_name (parent_source),
		e_source_get_display_name (source),
		folder_id,
		foreign_username ? E_MAPI_FOLDER_CATEGORY_FOREIGN :
		is_public ? E_MAPI_FOLDER_CATEGORY_PUBLIC :
		E_MAPI_FOLDER_CATEGORY_PERSONAL,
		foreign_username,
		strstr (gtk_action_get_name (action), "calendar") != NULL);

	g_object_unref (source);
	g_object_unref (parent_source);
	g_object_unref (registry);
}

static GtkActionEntry calendar_context_entries[] = {

	{ "calendar-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI calendar permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

static const gchar *mapi_ui_cal_def =
	"<popup name=\"calendar-popup\">\n"
	"  <placeholder name=\"calendar-popup-actions\">\n"
	"    <menuitem action=\"calendar-mapi-folder-permissions\"/>\n"
	"  </placeholder>\n"
	"</popup>\n";

static void
mapi_ui_init_calendar (GtkUIManager *ui_manager,
		       EShellView *shell_view,
		       gchar **ui_definition)
{
	g_return_if_fail (ui_definition != NULL);

	*ui_definition = g_strdup (mapi_ui_cal_def);

	setup_mapi_source_actions (shell_view, ui_manager,
		calendar_context_entries, G_N_ELEMENTS (calendar_context_entries));
}

static GtkActionEntry tasks_context_entries[] = {

	{ "tasks-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI tasks permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

static const gchar *mapi_ui_task_def =
	"<popup name=\"task-list-popup\">\n"
	"  <placeholder name=\"task-list-popup-actions\">\n"
	"    <menuitem action=\"tasks-mapi-folder-permissions\"/>\n"
	"  </placeholder>\n"
	"</popup>\n";

static void
mapi_ui_init_tasks (GtkUIManager *ui_manager,
		    EShellView *shell_view,
		    gchar **ui_definition)
{
	g_return_if_fail (ui_definition != NULL);

	*ui_definition = g_strdup (mapi_ui_task_def);

	setup_mapi_source_actions (shell_view, ui_manager,
		tasks_context_entries, G_N_ELEMENTS (tasks_context_entries));
}

static GtkActionEntry memos_context_entries[] = {

	{ "memos-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI memos permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

static const gchar *mapi_ui_memo_def =
	"<popup name=\"memo-list-popup\">\n"
	"  <placeholder name=\"memo-list-popup-actions\">\n"
	"    <menuitem action=\"memos-mapi-folder-permissions\"/>\n"
	"  </placeholder>\n"
	"</popup>\n";

static void
mapi_ui_init_memos (GtkUIManager *ui_manager,
		    EShellView *shell_view,
		    gchar **ui_definition)
{
	g_return_if_fail (ui_definition != NULL);

	*ui_definition = g_strdup (mapi_ui_memo_def);

	setup_mapi_source_actions (shell_view, ui_manager,
		memos_context_entries, G_N_ELEMENTS (memos_context_entries));
}

static GtkActionEntry contacts_context_entries[] = {

	{ "contacts-mapi-folder-permissions",
	  "folder-new",
	  N_("Permissions..."),
	  NULL,
	  N_("Edit MAPI contacts permissions"),
	  G_CALLBACK (action_folder_permissions_source_cb) }
};

static const gchar *mapi_ui_book_def =
	"<popup name=\"address-book-popup\">\n"
	"  <placeholder name=\"address-book-popup-actions\">\n"
	"    <menuitem action=\"contacts-mapi-folder-permissions\"/>\n"
	"  </placeholder>\n"
	"</popup>\n";

static void
mapi_ui_init_contacts (GtkUIManager *ui_manager,
		       EShellView *shell_view,
		       gchar **ui_definition)
{
	g_return_if_fail (ui_definition != NULL);

	*ui_definition = g_strdup (mapi_ui_book_def);

	setup_mapi_source_actions (shell_view, ui_manager,
		contacts_context_entries, G_N_ELEMENTS (contacts_context_entries));
}

void
e_mapi_config_utils_init_ui (EShellView *shell_view,
			     const gchar *ui_manager_id,
			     gchar **ui_definition)
{
	EShellWindow *shell_window;
	GtkUIManager *ui_manager;

	g_return_if_fail (shell_view != NULL);
	g_return_if_fail (ui_manager_id != NULL);
	g_return_if_fail (ui_definition != NULL);

	shell_window = e_shell_view_get_shell_window (shell_view);
	ui_manager = e_shell_window_get_ui_manager (shell_window);

	if (g_strcmp0 (ui_manager_id, "org.gnome.evolution.mail") == 0)
		mapi_ui_init_mail (ui_manager, shell_view, ui_definition);
	else if (g_strcmp0 (ui_manager_id, "org.gnome.evolution.calendars") == 0)
		mapi_ui_init_calendar (ui_manager, shell_view, ui_definition);
	else if (g_strcmp0 (ui_manager_id, "org.gnome.evolution.tasks") == 0)
		mapi_ui_init_tasks (ui_manager, shell_view, ui_definition);
	else if (g_strcmp0 (ui_manager_id, "org.gnome.evolution.memos") == 0)
		mapi_ui_init_memos (ui_manager, shell_view, ui_definition);
	else if (g_strcmp0 (ui_manager_id, "org.gnome.evolution.contacts") == 0)
		mapi_ui_init_contacts (ui_manager, shell_view, ui_definition);
}

gboolean
e_mapi_config_utils_is_online (void)
{
	EShell *shell;

	shell = e_shell_get_default ();

	return shell && e_shell_get_online (shell);
}

GtkWindow *
e_mapi_config_utils_get_widget_toplevel_window (GtkWidget *widget)
{
	if (!widget)
		return NULL;

	if (!GTK_IS_WINDOW (widget))
		widget = gtk_widget_get_toplevel (widget);

	if (GTK_IS_WINDOW (widget))
		return GTK_WINDOW (widget);

	return NULL;
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

	g_return_if_fail (gtk_tree_model_get_iter_first (ts_model, &iter));
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
	GtkTreeModel *model = GTK_TREE_MODEL (ts);
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
	if (gtk_tree_model_get_iter_first (model, &iter)) {
		traverse_tree (model, iter, folder_type, NULL);
	}
}

static void
select_folder (GtkTreeModel *model,
	       mapi_id_t fid,
	       GtkWidget *tree_view)
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

		if (folder && e_mapi_folder_get_id (folder) == fid) {
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
e_mapi_cursor_change (GtkTreeView *treeview,
		      ESource *source)
{
	ESourceMapiFolder *folder_ext;
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	mapi_id_t pfid;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview));
	if (!selection)
		return;

	if (gtk_tree_selection_get_selected (selection, &model, &iter)) {
		gtk_tree_model_get (model, &iter, FID_COL, &pfid, -1);
	} else {
		pfid = 0;
	}

	folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	e_source_mapi_folder_set_parent_id (folder_ext, pfid);
}

struct EMapiFolderStructureData
{
	EMapiFolderType folder_type;
	GSList *folders;
	GtkWidget *tree_view;
	ESource *source;
	ESource *child_source;
	ESourceRegistry *registry;
	ESourceConfig *config;
};

static void
e_mapi_folder_structure_data_free (gpointer ptr)
{
	struct EMapiFolderStructureData *fsd = ptr;

	if (!fsd)
		return;

	e_mapi_folder_free_list (fsd->folders);
	g_object_unref (fsd->tree_view);
	if (fsd->source)
		g_object_unref (fsd->source);
	if (fsd->config)
		g_object_unref (fsd->config);
	g_object_unref (fsd->child_source);
	g_object_unref (fsd->registry);
	g_free (fsd);
}

static void
e_mapi_download_folder_structure_idle (GObject *source_obj,
				       gpointer user_data,
				       GCancellable *cancellable,
				       GError **perror)
{
	struct EMapiFolderStructureData *fsd = user_data;
	ESourceMapiFolder *folder_ext;
	GtkTreeStore *tree_store;

	g_return_if_fail (fsd != NULL);
	g_return_if_fail (fsd->tree_view != NULL);
	g_return_if_fail (source_obj != NULL);
	g_return_if_fail (E_IS_SOURCE (source_obj));

	tree_store = GTK_TREE_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (fsd->tree_view)));
	g_return_if_fail (tree_store != NULL);

	add_folders (fsd->folders, tree_store, fsd->folder_type);
	gtk_tree_view_expand_all (GTK_TREE_VIEW (fsd->tree_view));

	folder_ext = e_source_get_extension (fsd->child_source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	if (e_source_mapi_folder_get_id (folder_ext)) {
		select_folder (GTK_TREE_MODEL (tree_store),
			e_source_mapi_folder_get_id (folder_ext),
			fsd->tree_view);
	}
}

static void
e_mapi_download_folder_structure_thread (GObject *source_obj,
					 gpointer user_data,
					 GCancellable *cancellable,
					 GError **perror)
{
	struct EMapiFolderStructureData *fsd = user_data;
	const gchar *extension_name;
	ESource *source;
	ESourceCamel *extension;
	EMapiConnection *conn;
	CamelSettings *settings;

	g_return_if_fail (fsd != NULL);
	g_return_if_fail (fsd->tree_view != NULL);
	g_return_if_fail (source_obj != NULL);
	g_return_if_fail (E_IS_SOURCE (source_obj));

	source = E_SOURCE (source_obj);

	extension_name = e_source_camel_get_extension_name ("mapi");
	g_return_if_fail (e_source_has_extension (source, extension_name));

	extension = e_source_get_extension (source, extension_name);

	settings = e_source_camel_get_settings (extension);

	conn = e_mapi_config_utils_open_connection_for (NULL,
		fsd->registry,
		source,
		CAMEL_MAPI_SETTINGS (settings),
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

static void
tree_view_mapped_cb (GObject *tree_view)
{
	const struct EMapiFolderStructureData *old_fsd = g_object_get_data (tree_view, "mapi-fsd-pointer");
	struct EMapiFolderStructureData *fsd;
	GtkTreeViewColumn *column;
	ESource *parent_source;

	g_return_if_fail (old_fsd != NULL);

	parent_source = e_source_config_get_collection_source (old_fsd->config);
	if (!parent_source)
		parent_source = e_source_registry_find_extension (
			old_fsd->registry, old_fsd->child_source, E_SOURCE_EXTENSION_COLLECTION);

	g_return_if_fail (parent_source != NULL);

	fsd = g_new0 (struct EMapiFolderStructureData, 1);
	fsd->folder_type = old_fsd->folder_type;
	fsd->folders = NULL;
	fsd->tree_view = g_object_ref (old_fsd->tree_view);
	fsd->source = g_object_ref (parent_source);
	fsd->child_source = g_object_ref (old_fsd->child_source);
	fsd->registry = g_object_ref (old_fsd->registry);

	column = gtk_tree_view_get_column (GTK_TREE_VIEW (tree_view), 0);
	gtk_tree_view_column_set_title (column, e_source_get_display_name (parent_source));

	e_mapi_config_utils_run_in_thread_with_feedback (e_mapi_config_utils_get_widget_toplevel_window (fsd->tree_view),
		G_OBJECT (fsd->source),
		_("Searching remote MAPI folder structure, please wait..."),
		e_mapi_download_folder_structure_thread,
		e_mapi_download_folder_structure_idle,
		fsd,
		e_mapi_folder_structure_data_free);
}

void
e_mapi_config_utils_insert_widgets (ESourceConfigBackend *backend,
				    ESource *scratch_source)
{
	ESourceBackend *backend_ext = NULL;
	ESourceMapiFolder *folder_ext;
	ESourceConfig *config;
	GtkWidget *widget;
	gboolean is_new_source;
	EMapiFolderType folder_type = E_MAPI_FOLDER_TYPE_UNKNOWN;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (scratch_source != NULL);

	if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_ADDRESS_BOOK)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
		folder_type = E_MAPI_FOLDER_TYPE_CONTACT;
	} else if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_CALENDAR)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_CALENDAR);
		folder_type = E_MAPI_FOLDER_TYPE_APPOINTMENT;
	} else if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_TASK_LIST)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_TASK_LIST);
		folder_type = E_MAPI_FOLDER_TYPE_TASK;
	} else if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_MEMO_LIST)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_MEMO_LIST);
		folder_type = E_MAPI_FOLDER_TYPE_MEMO;
	}

	if (!backend_ext || g_strcmp0 (e_source_backend_get_backend_name (backend_ext), "mapi") != 0)
		return;

	folder_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	g_return_if_fail (folder_ext != NULL);

	config = e_source_config_backend_get_config (backend);
	if (E_IS_BOOK_SOURCE_CONFIG (config))
		e_book_source_config_add_offline_toggle (E_BOOK_SOURCE_CONFIG (config), scratch_source);
	else if (E_IS_CAL_SOURCE_CONFIG (config))
		e_cal_source_config_add_offline_toggle (E_CAL_SOURCE_CONFIG (config), scratch_source);

	widget = gtk_check_button_new_with_mnemonic (_("Lis_ten for server notifications"));
	e_source_config_insert_widget (config, scratch_source, NULL, widget);
	gtk_widget_show (widget);

	e_binding_bind_property (
		folder_ext, "server-notification",
		widget, "active",
		G_BINDING_BIDIRECTIONAL |
		G_BINDING_SYNC_CREATE);

	/* no extra options for subscribed folders */
	if (e_source_mapi_folder_is_public (folder_ext) ||
	    e_source_mapi_folder_get_foreign_username (folder_ext))
		return;

	is_new_source = e_source_mapi_folder_get_id (folder_ext) == 0;
	if (is_new_source && !e_mapi_config_utils_is_online ()) {
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
		/* coverity[dead_error_begin] */
		default:
			g_warn_if_reached ();
			msg = _("Cannot create MAPI source in offline mode");
			break;
		}

		widget = gtk_label_new (msg);
		gtk_widget_show (widget);
		gtk_misc_set_alignment (GTK_MISC (widget), 0.0, 0.5);

		e_source_config_insert_widget (config, scratch_source, NULL, widget);
	} else {
		GtkGrid *content_grid;
		GtkCellRenderer *renderer;
		GtkTreeViewColumn *column;
		GtkTreeStore *tree_store;
		GtkWidget *tree_view, *scrolled_window;

		content_grid = GTK_GRID (gtk_grid_new ());
		gtk_grid_set_row_spacing (content_grid, 2);
		gtk_grid_set_column_spacing (content_grid, 6);

		widget = gtk_label_new_with_mnemonic (_("_Location:"));
		gtk_misc_set_alignment (GTK_MISC (widget), 0.0, 0.5);
		gtk_widget_set_hexpand (widget, TRUE);
		gtk_grid_attach (content_grid, widget, 0, 0, 1, 1);

		tree_store = gtk_tree_store_new (NUM_COLS, G_TYPE_STRING, G_TYPE_UINT64, G_TYPE_POINTER);

		renderer = gtk_cell_renderer_text_new ();
		column = gtk_tree_view_column_new_with_attributes ("", renderer, "text", NAME_COL, NULL);
		tree_view = gtk_tree_view_new_with_model (GTK_TREE_MODEL (tree_store));
		gtk_tree_view_append_column (GTK_TREE_VIEW (tree_view), column);
		g_object_set (tree_view, "expander-column", column, "headers-visible", TRUE, NULL);
		gtk_widget_set_sensitive (tree_view, is_new_source);

		scrolled_window = gtk_scrolled_window_new (NULL, NULL);
		gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
		gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scrolled_window), GTK_SHADOW_IN);
		g_object_set (scrolled_window, "height-request", 150, NULL);
		gtk_container_add (GTK_CONTAINER (scrolled_window), tree_view);
		gtk_label_set_mnemonic_widget (GTK_LABEL (widget), scrolled_window);
		g_signal_connect (G_OBJECT (tree_view), "cursor-changed", G_CALLBACK (e_mapi_cursor_change), scratch_source);
		gtk_widget_show_all (scrolled_window);

		gtk_grid_attach (content_grid, scrolled_window, 0, 1, 1, 1);

		if (e_mapi_config_utils_is_online ()) {
			struct EMapiFolderStructureData *fsd;

			fsd = g_new0 (struct EMapiFolderStructureData, 1);
			fsd->folder_type = folder_type;
			fsd->folders = NULL;
			fsd->tree_view = g_object_ref (tree_view);
			fsd->config = g_object_ref (config);
			fsd->child_source = g_object_ref (scratch_source);
			fsd->registry = g_object_ref (e_source_config_get_registry (config));

			g_signal_connect_after (tree_view, "map", G_CALLBACK (tree_view_mapped_cb), NULL);
			g_object_set_data_full (G_OBJECT (tree_view), "mapi-fsd-pointer", fsd, e_mapi_folder_structure_data_free);
		}

		gtk_widget_set_hexpand (GTK_WIDGET (content_grid), TRUE);
		gtk_widget_set_vexpand (GTK_WIDGET (content_grid), TRUE);
		gtk_widget_show_all (GTK_WIDGET (content_grid));

		e_source_config_insert_widget (config, scratch_source, NULL, GTK_WIDGET (content_grid));
	}
}

gboolean
e_mapi_config_utils_check_complete (ESource *scratch_source)
{
	ESourceBackend *backend_ext = NULL;
	ESourceMapiFolder *folder_ext;

	g_return_val_if_fail (scratch_source != NULL, FALSE);

	if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_ADDRESS_BOOK)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_ADDRESS_BOOK);
	} else if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_CALENDAR)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_CALENDAR);
	} else if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_TASK_LIST)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_TASK_LIST);
	} else if (e_source_has_extension (scratch_source, E_SOURCE_EXTENSION_MEMO_LIST)) {
		backend_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_MEMO_LIST);
	}

	if (!backend_ext || g_strcmp0 (e_source_backend_get_backend_name (backend_ext), "mapi") != 0)
		return TRUE;

	folder_ext = e_source_get_extension (scratch_source, E_SOURCE_EXTENSION_MAPI_FOLDER);
	if (!folder_ext)
		return FALSE;

	if (!e_source_mapi_folder_get_id (folder_ext) &&
	    !e_mapi_config_utils_is_online ())
		return FALSE;

	/* does not have a parent-fid which is needed for folder creation on server */
	return e_source_mapi_folder_get_parent_id (folder_ext) ||
		e_source_mapi_folder_get_foreign_username (folder_ext) ||
		e_source_mapi_folder_is_public (folder_ext);
}
