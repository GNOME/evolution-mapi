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

#include "e-mapi-config-utils.h"
#include "e-mapi-search-gal-user.h"
#include "e-mapi-utils.h"
#include "e-mapi-defs.h"

#define E_MAPI_SEARCH_DLG_DATA "e-mapi-search-dlg-data"

enum {
	COL_DISPLAY_NAME = 0,
	COL_EMAIL,
	COL_USER_DN,
	COL_ENTRY_ID,
	COL_USER_TYPE
};

struct EMapiSearchGalUserData
{
	EMapiConnection *conn;
	GCancellable *cancellable;
	gchar *search_text;
	guint32 search_extra;
	GtkWidget *tree_view;
	GtkWidget *info_label;
	guint schedule_search_id;
};

static void
e_mapi_search_gal_user_data_free (gpointer ptr)
{
	struct EMapiSearchGalUserData *pgu = ptr;

	if (!pgu)
		return;

	if (pgu->schedule_search_id) {
		g_source_remove (pgu->schedule_search_id);
		pgu->schedule_search_id = 0;
	}
	if (pgu->cancellable) {
		g_cancellable_cancel (pgu->cancellable);
		g_object_unref (pgu->cancellable);
		pgu->cancellable = NULL;
	}
	g_object_unref (pgu->conn);
	g_free (pgu->search_text);
	g_free (pgu);
}

struct EMapiGalSearchUser
{
	gchar *display_name;
	gchar *email;
	gchar *dn;
	struct SBinary_short *entry_id;
};

static void
e_mapi_search_gal_user_free (gpointer ptr)
{
	struct EMapiGalSearchUser *user = ptr;

	if (!user)
		return;

	g_free (user->display_name);
	g_free (user->email);
	g_free (user->dn);
	if (user->entry_id)
		g_free (user->entry_id->lpb);
	g_free (user->entry_id);
	g_free (user);
}

struct EMapiSearchIdleData
{
	EMapiConnection *conn;
	gchar *search_text;
	GCancellable *cancellable;

	GObject *dialog;
	GSList *found_users; /* struct EMapiGalSearchUser * */
	guint found_total;
};

static void
e_mapi_search_idle_data_free (gpointer ptr)
{
	struct EMapiSearchIdleData *sid = ptr;

	if (!sid)
		return;

	g_object_unref (sid->conn);
	g_object_unref (sid->cancellable);
	g_free (sid->search_text);
	g_slist_free_full (sid->found_users, e_mapi_search_gal_user_free);
	g_free (sid);
}

static void
empty_search_gal_tree_view (GtkWidget *tree_view)
{
	GtkListStore *store;
	GtkTreeModel *model;
	GtkTreeIter iter;
	struct SBinary_short *entry_id;

	g_return_if_fail (tree_view != NULL);

	model = gtk_tree_view_get_model (GTK_TREE_VIEW (tree_view));
	g_return_if_fail (model != NULL);

	store = GTK_LIST_STORE (model);
	g_return_if_fail (store != NULL);

	if (!gtk_tree_model_get_iter_first (model, &iter))
		return;

	do {
		entry_id = NULL;
		gtk_tree_model_get (model, &iter,
			COL_ENTRY_ID, &entry_id,
			-1);

		if (entry_id) {
			g_free (entry_id->lpb);
			g_free (entry_id);
		}
	} while (gtk_tree_model_iter_next (model, &iter));

	gtk_list_store_clear (store);
}

static void
search_gal_add_user (GtkListStore *store,
		     const gchar *display_name,
		     const gchar *email,
		     const gchar *user_dn,
		     struct SBinary_short *entry_id, /* takes ownership of the pointer */
		     EMapiGalUserType user_type)
{
	GtkTreeIter iter;

	g_return_if_fail (store != NULL);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_DISPLAY_NAME, display_name,
		COL_EMAIL, email,
		COL_USER_DN, user_dn,
		COL_ENTRY_ID, entry_id,
		COL_USER_TYPE, user_type,
		-1);
}

static gboolean
search_gal_finish_idle (gpointer user_data)
{
	struct EMapiSearchIdleData *sid = user_data;

	g_return_val_if_fail (sid != NULL, FALSE);
	g_return_val_if_fail (sid->dialog != NULL, FALSE);

	if (!g_cancellable_is_cancelled (sid->cancellable)) {
		struct EMapiSearchGalUserData *pgu;
		GtkListStore *store;
		guint added = 0;
		GSList *fu;

		pgu = g_object_get_data (sid->dialog, E_MAPI_SEARCH_DLG_DATA);
		g_return_val_if_fail (pgu != NULL, FALSE);
		g_return_val_if_fail (pgu->tree_view != NULL, FALSE);
		g_return_val_if_fail (pgu->info_label != NULL, FALSE);

		empty_search_gal_tree_view (pgu->tree_view);

		store = GTK_LIST_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (pgu->tree_view)));
		g_return_val_if_fail (store != NULL, FALSE);

		for (fu = sid->found_users; fu; fu = fu->next) {
			struct EMapiGalSearchUser *user = fu->data;

			if (!user)
				continue;

			search_gal_add_user (store, user->display_name, user->email, user->dn, user->entry_id, E_MAPI_GAL_USER_REGULAR);
			user->entry_id = NULL;

			added++;
		}

		if (!added) {
			gtk_label_set_text (GTK_LABEL (pgu->info_label), _("No users found"));
		} else if (added == sid->found_total) {
			gchar *str;
			str = g_strdup_printf (dngettext (GETTEXT_PACKAGE, "Found one user", "Found %d users", added), added);
			gtk_label_set_text (GTK_LABEL (pgu->info_label), str);
			g_free (str);
		} else {
			gchar *str;
			str = g_strdup_printf (dngettext (GETTEXT_PACKAGE, "Found %d user, but showing only first %d", "Found %d users, but showing only first %d", sid->found_total), sid->found_total, added);
			gtk_label_set_text (GTK_LABEL (pgu->info_label), str);
			g_free (str);
		}
	}

	e_mapi_search_idle_data_free (sid);

	return FALSE;
}

static gboolean
build_gal_search_restriction_cb (EMapiConnection *conn,
				 TALLOC_CTX *mem_ctx,
				 struct mapi_SRestriction **restrictions,
				 gpointer user_data,
				 GCancellable *cancellable,
				 GError **perror)
{
	const gchar *search_text = user_data;
	struct mapi_SRestriction *restriction;

	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (restrictions != NULL, FALSE);
	g_return_val_if_fail (search_text != NULL, FALSE);
	g_return_val_if_fail (*search_text, FALSE);

	restriction = talloc_zero (mem_ctx, struct mapi_SRestriction);
	g_return_val_if_fail (restriction != NULL, FALSE);

	restriction->rt = RES_OR;
	restriction->res.resOr.cRes = 2;
	restriction->res.resOr.res = talloc_zero_array (mem_ctx, struct mapi_SRestriction_or, restriction->res.resOr.cRes + 1);

	restriction->res.resOr.res[0].rt = RES_CONTENT;
	restriction->res.resOr.res[0].res.resContent.fuzzy = FL_SUBSTRING | FL_IGNORECASE;
	restriction->res.resOr.res[0].res.resContent.ulPropTag = PidTagDisplayName;
	restriction->res.resOr.res[0].res.resContent.lpProp.ulPropTag = PidTagDisplayName;
	restriction->res.resOr.res[0].res.resContent.lpProp.value.lpszW = talloc_strdup (mem_ctx, search_text);

	restriction->res.resOr.res[1].rt = RES_CONTENT;
	restriction->res.resOr.res[1].res.resContent.fuzzy = FL_SUBSTRING | FL_IGNORECASE;
	restriction->res.resOr.res[1].res.resContent.ulPropTag = PidTagSmtpAddress;
	restriction->res.resOr.res[1].res.resContent.lpProp.ulPropTag = PidTagSmtpAddress;
	restriction->res.resOr.res[1].res.resContent.lpProp.value.lpszW = talloc_strdup (mem_ctx, search_text);

	*restrictions = restriction;

	return TRUE;
}

static gboolean
list_gal_search_mids_cb (EMapiConnection *conn,
			 TALLOC_CTX *mem_ctx,
			 const ListObjectsData *object_data,
			 guint32 obj_index,
			 guint32 obj_total,
			 gpointer user_data,
			 GCancellable *cancellable,
			 GError **perror)
{
	GSList **pmids = user_data;
	mapi_id_t *mid;

	g_return_val_if_fail (object_data != NULL, FALSE);
	g_return_val_if_fail (user_data != NULL, FALSE);

	mid = g_new0 (mapi_id_t, 1);
	*mid = object_data->mid;

	*pmids = g_slist_prepend (*pmids, mid);

	return TRUE;
}

static gboolean
search_gal_build_properties_cb (EMapiConnection *conn,
				TALLOC_CTX *mem_ctx,
				struct SPropTagArray *props,
				gpointer data,
				GCancellable *cancellable,
				GError **perror)
{
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	SPropTagArray_add (mem_ctx, props, PidTagEntryId);
	SPropTagArray_add (mem_ctx, props, PidTagDisplayName);
	SPropTagArray_add (mem_ctx, props, PidTagSmtpAddress);
	SPropTagArray_add (mem_ctx, props, PidTagEmailAddress);

	return TRUE;
}

static gboolean
transfer_gal_search_objects_cb (EMapiConnection *conn,
				TALLOC_CTX *mem_ctx,
				/* const */ EMapiObject *object,
				guint32 obj_index,
				guint32 obj_total,
				gpointer user_data,
				GCancellable *cancellable,
				GError **perror)
{

	struct EMapiSearchIdleData *sid = user_data;
	const gchar *display_name, *email, *user_dn;
	const struct SBinary_short *entry_id;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (sid != NULL, FALSE);

	display_name = e_mapi_util_find_array_propval (&object->properties, PidTagDisplayName);
	email = e_mapi_util_find_array_propval (&object->properties, PidTagSmtpAddress);
	entry_id = e_mapi_util_find_array_propval (&object->properties, PidTagEntryId);
	user_dn = e_mapi_util_find_array_propval (&object->properties, PidTagEmailAddress);

	if (entry_id && (display_name || email)) {
		struct EMapiGalSearchUser *user;

		user = g_new0 (struct EMapiGalSearchUser, 1);
		user->display_name = g_strdup (display_name);
		user->email = g_strdup (email);
		user->dn = g_strdup (user_dn);
		user->entry_id = g_new0 (struct SBinary_short, 1);
		user->entry_id->cb = entry_id->cb;
		if (entry_id->cb > 0)
			user->entry_id->lpb = g_memdup (entry_id->lpb, entry_id->cb);

		sid->found_users = g_slist_prepend (sid->found_users, user);
	}

	return TRUE;
}

static gint
sort_mids_by_id (gconstpointer pmid1, gconstpointer pmid2)
{
	const mapi_id_t *mid1 = pmid1, *mid2 = pmid2;

	if (!mid1 && !mid2)
		return 0;

	if (!mid1)
		return -1;
	if (!mid2)
		return 1;

	/* simple subtract *mid1 - *mid2 may overflow gint */
	if (*mid1 < *mid2)
		return -1;
	if (*mid1 > *mid2)
		return 1;
	return 0;
}

static gpointer
search_gal_thread (gpointer user_data)
{
	struct EMapiSearchIdleData *sid = user_data;

	g_return_val_if_fail (sid != NULL, NULL);

	if (!g_cancellable_is_cancelled (sid->cancellable)) {
		GError *error = NULL;
		GSList *mids = NULL;

		if (e_mapi_connection_list_gal_objects (sid->conn,
			build_gal_search_restriction_cb, sid->search_text,
			list_gal_search_mids_cb, &mids,
			sid->cancellable, &error)) {
			mids = g_slist_sort (mids, sort_mids_by_id);
			sid->found_total = g_slist_length (mids);
			if (sid->found_total > 30) {
				GSList *tmp = mids, *iter;
				gint count;

				mids = NULL;
				for (iter = tmp, count = 0; iter && count < 30; iter = iter->next, count++) {
					mids = g_slist_prepend (mids, iter->data);
					iter->data = NULL;
				}

				g_slist_free_full (tmp, g_free);

				mids = g_slist_reverse (mids);
			}

			if (mids) {
				e_mapi_connection_transfer_gal_objects (sid->conn, mids,
					search_gal_build_properties_cb, NULL,
					transfer_gal_search_objects_cb, sid,
					sid->cancellable, &error);

				g_slist_free_full (mids, g_free);
			}

			sid->found_users = g_slist_reverse (sid->found_users);
		}

		if (error &&
		    !g_error_matches (error, E_MAPI_ERROR, MAPI_E_USER_CANCEL) &&
		    !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			g_warning ("%s: Failed to search GAL: %s", G_STRFUNC, error->message);
		}

		g_clear_error (&error);

		g_idle_add (search_gal_finish_idle, sid);
	} else {
		e_mapi_search_idle_data_free (sid);
	}

	return NULL;
}

static gboolean
schedule_search_cb (gpointer user_data)
{
	struct EMapiSearchIdleData *sid = user_data;

	g_return_val_if_fail (sid != NULL, FALSE);
	g_return_val_if_fail (sid->dialog != NULL, FALSE);

	if (!g_cancellable_is_cancelled (sid->cancellable)) {
		struct EMapiSearchGalUserData *pgu;
		GThread *thread;
		GError *error = NULL;

		pgu = g_object_get_data (sid->dialog, E_MAPI_SEARCH_DLG_DATA);
		g_return_val_if_fail (pgu != NULL, FALSE);
		g_return_val_if_fail (pgu->tree_view != NULL, FALSE);

		pgu->schedule_search_id = 0;
		sid->conn = g_object_ref (pgu->conn);
		sid->search_text = g_strdup (pgu->search_text);

		thread = g_thread_try_new (NULL, search_gal_thread, sid, &error);
		if (thread) {
			sid = NULL;
			g_thread_unref (thread);
		} else {
			g_object_unref (sid->conn);
			g_warning ("%s: Failed to create search thread: %s", G_STRFUNC, error ? error->message : "Unknown error");
		}

		g_clear_error (&error);
	}

	e_mapi_search_idle_data_free (sid);

	return FALSE;
}

static void
search_term_changed_cb (GtkEntry *entry,
			GObject *dialog)
{
	struct EMapiSearchGalUserData *pgu;

	g_return_if_fail (dialog != NULL);

	pgu = g_object_get_data (dialog, E_MAPI_SEARCH_DLG_DATA);
	g_return_if_fail (pgu != NULL);
	g_return_if_fail (pgu->tree_view != NULL);

	if (pgu->schedule_search_id) {
		g_source_remove (pgu->schedule_search_id);
		pgu->schedule_search_id = 0;
	}

	if (pgu->cancellable) {
		g_cancellable_cancel (pgu->cancellable);
		g_object_unref (pgu->cancellable);
	}

	pgu->cancellable = g_cancellable_new ();

	if (entry) {
		g_free (pgu->search_text);
		pgu->search_text = g_strdup (gtk_entry_get_text (entry));
	}

	empty_search_gal_tree_view (pgu->tree_view);

	if (!pgu->search_text || !*pgu->search_text) {
		GtkListStore *store;

		gtk_label_set_text (GTK_LABEL (pgu->info_label), _("Search for a user"));

		store = GTK_LIST_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (pgu->tree_view)));

		if ((pgu->search_extra & E_MAPI_GAL_USER_DEFAULT) != 0)
			search_gal_add_user (store, C_("User", "Default"), NULL, NULL, NULL, E_MAPI_GAL_USER_DEFAULT);

		if ((pgu->search_extra & E_MAPI_GAL_USER_ANONYMOUS) != 0)
			search_gal_add_user (store, C_("User", "Anonymous"), NULL, NULL, NULL, E_MAPI_GAL_USER_ANONYMOUS);
	} else {
		struct EMapiSearchIdleData *sid;

		sid = g_new0 (struct EMapiSearchIdleData, 1);
		sid->cancellable = g_object_ref (pgu->cancellable);
		sid->dialog = dialog;

		gtk_label_set_text (GTK_LABEL (pgu->info_label), _("Searching..."));
		pgu->schedule_search_id = g_timeout_add (333, schedule_search_cb, sid);
	}
}

static void
dialog_realized_cb (GObject *dialog)
{
	struct EMapiSearchGalUserData *pgu;

	g_return_if_fail (dialog != NULL);

	pgu = g_object_get_data (dialog, E_MAPI_SEARCH_DLG_DATA);
	g_return_if_fail (pgu != NULL);
	g_return_if_fail (pgu->tree_view != NULL);

	if (pgu->cancellable)
		return;

	search_term_changed_cb (NULL, dialog);
}

static void
search_gal_user_selection_changed_cb (GtkTreeSelection *selection,
				      GtkDialog *dialog)
{
	g_return_if_fail (selection != NULL);
	g_return_if_fail (dialog != NULL);

	gtk_dialog_set_response_sensitive (dialog,
		GTK_RESPONSE_OK,
		gtk_tree_selection_get_selected (selection, NULL, NULL));
}

static void
search_gal_user_row_activated_cb (GtkTreeView *tree_view,
				  GtkTreePath *path,
				  GtkTreeViewColumn *column,
				  GtkDialog *dialog)
{
	g_return_if_fail (tree_view != NULL);
	g_return_if_fail (dialog != NULL);

	if (path && column)
		gtk_dialog_response (dialog, GTK_RESPONSE_OK);
}

static GtkWidget *
create_users_tree_view (GtkWidget *dialog,
			struct EMapiSearchGalUserData *pgu)
{
	GtkTreeView *tree_view;
	GtkTreeSelection *selection;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	gint pos;

	g_return_val_if_fail (dialog != NULL, NULL);
	g_return_val_if_fail (pgu != NULL, NULL);

	tree_view = GTK_TREE_VIEW (gtk_tree_view_new_with_model (
		GTK_TREE_MODEL (gtk_list_store_new (5, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_UINT))));

	renderer = gtk_cell_renderer_text_new ();
	g_object_set (renderer, "editable", FALSE, NULL);
	pos = gtk_tree_view_insert_column_with_attributes (tree_view, -1, _("Name"), renderer, "text", COL_DISPLAY_NAME, NULL);
	column = gtk_tree_view_get_column (tree_view, pos - 1);
	gtk_tree_view_column_set_expand (column, TRUE);

	renderer = gtk_cell_renderer_text_new ();
	g_object_set (renderer, "editable", FALSE, NULL);
	gtk_tree_view_insert_column_with_attributes (tree_view, -1, _("E-mail"), renderer, "text", COL_EMAIL, NULL);

	selection = gtk_tree_view_get_selection (tree_view);
	gtk_tree_selection_set_mode (selection, GTK_SELECTION_SINGLE);
	search_gal_user_selection_changed_cb (selection, GTK_DIALOG (dialog));
	g_signal_connect (selection, "changed", G_CALLBACK (search_gal_user_selection_changed_cb), dialog);

	g_signal_connect (tree_view, "row-activated", G_CALLBACK (search_gal_user_row_activated_cb), dialog);

	pgu->tree_view = GTK_WIDGET (tree_view);

	return pgu->tree_view;
}

gboolean
e_mapi_search_gal_user_modal (GtkWindow *parent,
			      EMapiConnection *conn,
			      const gchar *search_this,
			      EMapiGalUserType *searched_type,
			      gchar **display_name,
			      gchar **email,
			      gchar **user_dn,
			      struct SBinary_short **entry_id)
{
	gboolean res = FALSE;
	struct EMapiSearchGalUserData *pgu;
	GtkWidget *dialog;
	GtkWidget *content, *label, *widget;
	GtkGrid *grid;
	GtkScrolledWindow *scrolled_window;
	gint row;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (searched_type != NULL, FALSE);
	g_return_val_if_fail (display_name || email || entry_id || user_dn, FALSE);

	pgu = g_new0 (struct EMapiSearchGalUserData, 1);
	pgu->conn = g_object_ref (conn);
	pgu->search_extra = 0; /* always none, as default/anonymous user cannot be added to permissions */

	dialog = gtk_dialog_new_with_buttons (
		_("Choose MAPI user..."),
		parent,
		GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_CLOSE, GTK_RESPONSE_CLOSE,
		GTK_STOCK_OK, GTK_RESPONSE_OK,
		NULL);

	g_object_set_data_full (G_OBJECT (dialog), E_MAPI_SEARCH_DLG_DATA, pgu, e_mapi_search_gal_user_data_free);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);

	content = gtk_dialog_get_content_area (GTK_DIALOG (dialog));

	grid = GTK_GRID (gtk_grid_new ());
	gtk_grid_set_row_homogeneous (grid, FALSE);
	gtk_grid_set_row_spacing (grid, 6);
	gtk_grid_set_column_homogeneous (grid, FALSE);
	gtk_grid_set_column_spacing (grid, 6);
	gtk_container_set_border_width (GTK_CONTAINER (grid), 12);
	gtk_container_add (GTK_CONTAINER (content), GTK_WIDGET (grid));

	row = 0;

	label = gtk_label_new_with_mnemonic (_("_Search:"));
	g_object_set (G_OBJECT (label),
		"hexpand", FALSE,
		"vexpand", FALSE,
		"xalign", 0.0,
		NULL);

	widget = gtk_entry_new ();
	g_object_set (G_OBJECT (widget),
		"hexpand", TRUE,
		"vexpand", FALSE,
		NULL);
	gtk_label_set_mnemonic_widget (GTK_LABEL (label), widget);
	if (search_this && *search_this) {
		gtk_entry_set_text (GTK_ENTRY (widget), search_this);
		pgu->search_text = g_strdup (search_this);
	}

	g_signal_connect (widget, "changed", G_CALLBACK (search_term_changed_cb), dialog);

	gtk_grid_attach (grid, label, 0, row, 1, 1);
	gtk_grid_attach (grid, widget, 1, row, 1, 1);

	row++;

	widget = gtk_scrolled_window_new (NULL, NULL);
	scrolled_window = GTK_SCROLLED_WINDOW (widget);
	gtk_scrolled_window_set_min_content_width (scrolled_window, 120);
	gtk_scrolled_window_set_min_content_height (scrolled_window, 120);
	gtk_container_add (GTK_CONTAINER (widget), create_users_tree_view (dialog, pgu));
	g_object_set (G_OBJECT (widget),
		"hexpand", TRUE,
		"vexpand", TRUE,
		"shadow-type", GTK_SHADOW_IN,
		NULL);

	gtk_grid_attach (grid, widget, 0, row, 2, 1);

	row++;

	label = gtk_label_new (_("Search for a user"));
	g_object_set (G_OBJECT (label),
		"hexpand", TRUE,
		"vexpand", FALSE,
		"xalign", 0.0,
		NULL);

	pgu->info_label = label;

	gtk_grid_attach (grid, label, 0, row, 2, 1);

	row++;

	gtk_widget_show_all (content);

	g_signal_connect (dialog, "realize", G_CALLBACK (dialog_realized_cb), NULL);

	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_OK) {
		GtkTreeSelection *selection;
		GtkTreeModel *model = NULL;
		GtkTreeIter iter;

		selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (pgu->tree_view));
		if (gtk_tree_selection_get_selected (selection, &model, &iter)) {
			guint ut = E_MAPI_GAL_USER_NONE;

			gtk_tree_model_get (model, &iter, COL_USER_TYPE, &ut, -1);
			
			*searched_type = ut;
			if (display_name)
				gtk_tree_model_get (model, &iter, COL_DISPLAY_NAME, display_name, -1);
			if (email)
				gtk_tree_model_get (model, &iter, COL_EMAIL, email, -1);
			if (user_dn)
				gtk_tree_model_get (model, &iter, COL_USER_DN, user_dn, -1);
			if (entry_id) {
				gtk_tree_model_get (model, &iter, COL_ENTRY_ID, entry_id, -1);
				gtk_list_store_set (GTK_LIST_STORE (model), &iter, COL_ENTRY_ID, NULL, -1);
			}

			res = TRUE;
		}			
	}

	gtk_widget_destroy (dialog);

	return res;
}
