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
 *    Bharath Acharya <abharath@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n-lib.h>

#include <sys/time.h>

#include <libedataserver/libedataserver.h>
#include <libedata-book/libedata-book.h>
#include <libebook/libebook.h>

#include "e-book-backend-mapi-gal.h"
#include "e-source-mapi-folder.h"

/* default value for "partial-count", upper bound of objects to download during partial search */
#define DEFAULT_PARTIAL_COUNT 50

G_DEFINE_TYPE (EBookBackendMAPIGAL, e_book_backend_mapi_gal, E_TYPE_BOOK_BACKEND_MAPI)

struct _EBookBackendMAPIGALPrivate
{
	/* nothing to store locally at the moment,
	   but keep it ready for any later need */

	gint32 unused;
};

struct TransferGalData
{
	EBookBackendMAPI *ebma;
	EDataBookView *book_view;
	gpointer notify_contact_data;
};

static gboolean
transfer_gal_cb (EMapiConnection *conn,
		 TALLOC_CTX *mem_ctx,
		 /* const */ EMapiObject *object,
		 guint32 obj_index,
		 guint32 obj_total,
		 gpointer user_data,
		 GCancellable *cancellable,
		 GError **perror)
{
	struct TransferGalData *tg = user_data;
	EContact *contact;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (tg != NULL, FALSE);

	contact = e_mapi_book_utils_contact_from_object (conn, object, e_book_backend_mapi_get_book_uid (tg->ebma));
	if (!contact) {
		/* this is GAL, just ignore them */
		return TRUE;
	}

	if (!e_book_backend_mapi_notify_contact_update (tg->ebma, tg->book_view, contact, obj_index, obj_total, FALSE, tg->notify_contact_data)) {
		g_object_unref (contact);
		return FALSE;
	}

	g_object_unref (contact);

	return TRUE;
}

static gboolean
list_gal_uids_cb (EMapiConnection *conn,
		  TALLOC_CTX *mem_ctx,
		  const ListObjectsData *object_data,
		  guint32 obj_index,
		  guint32 obj_total,
		  gpointer user_data,
		  GCancellable *cancellable,
		  GError **perror)
{
	gchar *uid;
	struct ListKnownUidsData *lku = user_data;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (object_data != NULL, FALSE);
	g_return_val_if_fail (lku != NULL, FALSE);

	uid = e_mapi_util_mapi_id_to_string (object_data->mid);
	if (uid) {
		if (lku->latest_last_modify < object_data->last_modified)
			lku->latest_last_modify = object_data->last_modified;

		g_hash_table_insert (lku->uid_to_rev, uid, e_mapi_book_utils_timet_to_string (object_data->last_modified));
	}

	return TRUE;
}

static void
ebbm_gal_create_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **added_contacts, GError **error)
{
	g_propagate_error (error, EDB_ERROR (PERMISSION_DENIED));
}

static void
ebbm_gal_remove_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *ids, GSList **removed_ids, GError **error)
{
	g_propagate_error (error, EDB_ERROR (PERMISSION_DENIED));
}

static void
ebbm_gal_modify_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **modified_contacts, GError **error)
{
	g_propagate_error (error, EDB_ERROR (PERMISSION_DENIED));
}

static gchar *
ebbm_gal_get_status_message (EBookBackendMAPI *ebma, gint index, gint total)
{
	if (index <= 0)
		return NULL;

	return g_strdup_printf (
		total <= 0 ?
			/* Translators : This is used to cache the downloaded contacts from GAL.
			   %d is an index of the GAL entry. */
			_("Caching GAL contact %d") :
			/* Translators : This is used to cache the downloaded contacts from GAL.
			   The first %d is an index of the GAL entry,
			   the second %d is total count of entries in GAL. */
			_("Caching GAL contact %d/%d"),
		index, total);
}

static void
ebbm_gal_transfer_contacts (EBookBackendMAPI *ebma,
			    const GSList *uids,
			    EDataBookView *book_view,
			    gpointer notify_contact_data,
			    GCancellable *cancellable,
			    GError **error)
{
	GError *mapi_error = NULL;
	struct TransferGalData tg = { 0 };
	EMapiConnection *conn;
	ESource *source;
	ESourceMapiFolder *ext_mapi_folder;
	GSList *get_mids = NULL;
	const GSList *iter;
	gint partial_count = -1;
	gboolean status;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma, cancellable, &mapi_error);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);

		if (!mapi_error)
			g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		else
			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_REPOSITORY_OFFLINE, NULL);
		g_clear_error (&mapi_error);

		return;
	}

	source = e_backend_get_source (E_BACKEND (ebma));
	ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

	if (ext_mapi_folder &&
	    !e_book_backend_mapi_is_marked_for_offline (ebma) &&
	    e_source_mapi_folder_get_allow_partial (ext_mapi_folder)) {
		partial_count = e_source_mapi_folder_get_partial_count (ext_mapi_folder);

		if (partial_count <= 0)
			partial_count = DEFAULT_PARTIAL_COUNT;
	}

	for (iter = uids; iter && (partial_count == -1 || partial_count > 0); iter = iter->next) {
		mapi_id_t *pmid, mid;

		if (e_mapi_util_mapi_id_from_string  (iter->data, &mid)) {
			pmid = g_new0 (mapi_id_t, 1);
			*pmid = mid;

			get_mids = g_slist_prepend (get_mids, pmid);

			if (partial_count > 0)
				partial_count--;
		}
	}

	tg.ebma = ebma;
	tg.book_view = book_view;
	tg.notify_contact_data = notify_contact_data;

	status = e_mapi_connection_transfer_gal_objects	(conn, get_mids, NULL, NULL, transfer_gal_cb, &tg, cancellable, &mapi_error);

	if (mapi_error) {
		e_book_backend_mapi_maybe_disconnect (ebma, mapi_error);

		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch GAL entries"));
		g_error_free (mapi_error);
	} else if (!status) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled");
	}

	g_slist_free_full (get_mids, g_free);

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_gal_get_contacts_count (EBookBackendMAPI *ebma,
			     guint32 *obj_total,
			     GCancellable *cancellable,
			     GError **error)
{
	EMapiConnection *conn;
	GError *mapi_error = NULL;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma, cancellable, &mapi_error);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);

		if (!mapi_error)
			g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		else
			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_REPOSITORY_OFFLINE, NULL);
		g_clear_error (&mapi_error);

		return;
	}

	if (!e_mapi_connection_count_gal_objects (conn, obj_total, cancellable, &mapi_error))
		*obj_total = -1;

	e_book_backend_mapi_maybe_disconnect (ebma, mapi_error);
	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);
		g_clear_error (&mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_gal_list_known_uids (EBookBackendMAPI *ebma,
			  BuildRestrictionsCB build_rs_cb,
			  gpointer build_rs_cb_data,
			  struct ListKnownUidsData *lku,
			  GCancellable *cancellable,
			  GError **error)
{
	EMapiConnection *conn;
	GError *mapi_error = NULL;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (lku != NULL);
	g_return_if_fail (lku->uid_to_rev != NULL);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma, cancellable, &mapi_error);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);

		if (!mapi_error)
			g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		else
			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_REPOSITORY_OFFLINE, NULL);
		g_clear_error (&mapi_error);

		return;
	}

	e_mapi_connection_list_gal_objects (conn, build_rs_cb, build_rs_cb_data, list_gal_uids_cb, lku, cancellable, &mapi_error);

	if (mapi_error) {
		e_book_backend_mapi_maybe_disconnect (ebma, mapi_error);
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch GAL entries"));
		g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
e_book_backend_mapi_gal_init (EBookBackendMAPIGAL *backend)
{
	backend->priv = G_TYPE_INSTANCE_GET_PRIVATE (backend, E_TYPE_BOOK_BACKEND_MAPI_GAL, EBookBackendMAPIGALPrivate);
}

static void
e_book_backend_mapi_gal_class_init (EBookBackendMAPIGALClass *klass)
{
	EBookBackendMAPIClass *parent_class;

	g_type_class_add_private (klass, sizeof (EBookBackendMAPIGALPrivate));

	parent_class = E_BOOK_BACKEND_MAPI_CLASS (klass);

	/* Set the virtual methods. */
	parent_class->op_create_contacts	= ebbm_gal_create_contacts;
	parent_class->op_remove_contacts	= ebbm_gal_remove_contacts;
	parent_class->op_modify_contacts	= ebbm_gal_modify_contacts;

	parent_class->op_get_status_message	= ebbm_gal_get_status_message;
	parent_class->op_get_contacts_count	= ebbm_gal_get_contacts_count;
	parent_class->op_list_known_uids	= ebbm_gal_list_known_uids;
	parent_class->op_transfer_contacts	= ebbm_gal_transfer_contacts;
}

/**
 * e_book_backend_mapi_gal_new:
 */
EBookBackend *
e_book_backend_mapi_gal_new (void)
{
	EBookBackendMAPIGAL *backend;

	backend = g_object_new (E_TYPE_BOOK_BACKEND_MAPI_GAL, NULL);

	return E_BOOK_BACKEND (backend);
}
