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
 *    Srinivasa Ragavan <sragavan@novell.com>
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
/*
** #include <glib/gi18n-lib.h>
*/

#include <libedataserver/e-sexp.h>
#include "libedataserver/e-flag.h"
#include <libebook/e-contact.h>
#include <camel/camel.h>

#include <libedata-book/e-book-backend-sexp.h>
#include <libedata-book/e-data-book.h>
#include <libedata-book/e-data-book-view.h>

#include "e-book-backend-mapi-contacts.h"

G_DEFINE_TYPE (EBookBackendMAPIContacts, e_book_backend_mapi_contacts, E_TYPE_BOOK_BACKEND_MAPI)

struct _EBookBackendMAPIContactsPrivate
{
	mapi_id_t fid;
	gboolean is_public_folder;
	gchar *foreign_username; /* NULL, if not a foreign folder */
};

static gboolean
ebbm_contacts_open_folder (EBookBackendMAPIContacts *ebmac,
			   EMapiConnection *conn,
			   mapi_object_t *obj_folder,
			   GCancellable *cancellable,
			   GError **perror)
{
	gboolean res;

	g_return_val_if_fail (ebmac != NULL, FALSE);
	g_return_val_if_fail (ebmac->priv != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (obj_folder != NULL, FALSE);

	if (ebmac->priv->foreign_username)
		res = e_mapi_connection_open_foreign_folder (conn, ebmac->priv->foreign_username, ebmac->priv->fid, obj_folder, cancellable, perror);
	else if (ebmac->priv->is_public_folder)
		res = e_mapi_connection_open_public_folder (conn, ebmac->priv->fid, obj_folder, cancellable, perror);
	else
		res = e_mapi_connection_open_personal_folder (conn, ebmac->priv->fid, obj_folder, cancellable, perror);

	return res;
}

typedef struct {
	EContact *contact;
	EBookBackendSqliteDB *db;
} EMapiCreateitemData;

static gboolean
ebbm_contact_to_object (EMapiConnection *conn,
			TALLOC_CTX *mem_ctx,
			EMapiObject **pobject, /* out */
			gpointer user_data,
			GCancellable *cancellable,
			GError **perror)
{
	EMapiCreateitemData *mcd = user_data;
	const gchar *uid = NULL;
	EContact *old_contact = NULL;
	gboolean res;
	GError *error = NULL;

	g_return_val_if_fail (mcd != NULL, FALSE);
	g_return_val_if_fail (mcd->contact != NULL, FALSE);
	g_return_val_if_fail (mcd->db != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (pobject != NULL, FALSE);

	uid = e_contact_get_const (mcd->contact, E_CONTACT_UID);
	if (uid)
		old_contact = e_book_backend_sqlitedb_get_contact (mcd->db, EMA_EBB_CACHE_FOLDERID, uid, NULL, NULL, &error);

	if (error) {
		old_contact = NULL;
		g_clear_error (&error);
	}

	res = e_mapi_book_utils_contact_to_object (mcd->contact, old_contact, pobject, mem_ctx, cancellable, perror);

	if (old_contact)
		g_object_unref (old_contact);

	return res;
}

struct TransferContactData
{
	EBookBackendMAPI *ebma;
	EContact *contact; /* out */
};

static gboolean
transfer_contact_cb (EMapiConnection *conn,
		     TALLOC_CTX *mem_ctx,
		     /* const */ EMapiObject *object,
		     guint32 obj_index,
		     guint32 obj_total,
		     gpointer user_data,
		     GCancellable *cancellable,
		     GError **perror)
{
	struct TransferContactData *tc = user_data;

	g_return_val_if_fail (tc != NULL, FALSE);
	g_return_val_if_fail (tc->ebma != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);

	tc->contact = e_mapi_book_utils_contact_from_object (conn, object, e_book_backend_mapi_get_book_uri (tc->ebma));
	if (tc->contact)
		return e_book_backend_mapi_notify_contact_update (tc->ebma, NULL, tc->contact, obj_index, obj_total, NULL);

	return TRUE;
}

static gboolean
gather_contact_mids_cb (EMapiConnection *conn,
			TALLOC_CTX *mem_ctx,
			const ListObjectsData *object_data,
			guint32 obj_index,
			guint32 obj_total,
			gpointer user_data,
			GCancellable *cancellable,
			GError **perror)
{
	GSList **pmids = user_data;
	mapi_id_t *pmid;

	g_return_val_if_fail (object_data != NULL, FALSE);
	g_return_val_if_fail (pmids != NULL, FALSE);

	pmid = g_new0 (mapi_id_t, 1);
	*pmid = object_data->mid;

	*pmids = g_slist_prepend (*pmids, pmid);

	return TRUE;
}

struct TransferContactsData
{
	EBookBackendMAPI *ebma;
	EDataBookView *book_view;
	gpointer notify_contact_data;
	GSList **cards;
};

static gboolean
transfer_contacts_cb (EMapiConnection *conn,
		      TALLOC_CTX *mem_ctx,
		      /* const */ EMapiObject *object,
		      guint32 obj_index,
		      guint32 obj_total,
		      gpointer user_data,
		      GCancellable *cancellable,
		      GError **perror)
{
	struct TransferContactsData *tcd = user_data;
	EContact *contact;

	g_return_val_if_fail (tcd != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (tcd->ebma != NULL, FALSE);

	contact = e_mapi_book_utils_contact_from_object (conn, object, e_book_backend_mapi_get_book_uri (tcd->ebma));
	if (contact) {
		if (tcd->cards)
			*tcd->cards = g_slist_prepend (*tcd->cards, e_vcard_to_string (E_VCARD (contact), EVC_FORMAT_VCARD_30));

		if (!e_book_backend_mapi_notify_contact_update (tcd->ebma, tcd->book_view, contact, obj_index, obj_total, tcd->notify_contact_data)) {
			g_object_unref (contact);
			return FALSE;
		}

		g_object_unref (contact);
	} else {
		g_debug ("%s: [%d/%d] Failed to transform to contact", G_STRFUNC, obj_index, obj_total);
	}

	return TRUE;
}

static gboolean
gather_known_uids_cb (EMapiConnection *conn,
		      TALLOC_CTX *mem_ctx,
		      const ListObjectsData *object_data,
		      guint32 obj_index,
		      guint32 obj_total,
		      gpointer user_data,
		      GCancellable *cancellable,
		      GError **perror)
{
	struct ListKnownUidsData *lku = user_data;
	gchar *suid;

	g_return_val_if_fail (lku != NULL, FALSE);
	g_return_val_if_fail (lku->uid_to_rev != NULL, FALSE);

	suid = e_mapi_util_mapi_id_to_string (object_data->mid);
	if (suid) {
		g_hash_table_insert (lku->uid_to_rev, suid, e_mapi_book_utils_timet_to_string (object_data->last_modified));
		if (lku->latest_last_modify < object_data->last_modified)
			lku->latest_last_modify = object_data->last_modified;
	}

	return TRUE;
}

static void
ebbmc_server_notification_cb (EMapiConnection *conn,
			      guint event_mask,
			      gpointer event_data,
			      gpointer user_data)
{
	EBookBackendMAPI *ebma = user_data;
	EBookBackendMAPIContactsPrivate *priv;
	mapi_id_t update_folder1 = 0, update_folder2 = 0;

	g_return_if_fail (ebma != NULL);

	switch (event_mask) {
	case fnevNewMail:
	case fnevNewMail | fnevMbit: {
		struct NewMailNotification *newmail = event_data;

		if (newmail)
			update_folder1 = newmail->FID;
		} break;
	case fnevObjectCreated:
	case fnevMbit | fnevObjectCreated: {
		struct MessageCreatedNotification *msgcreated = event_data;

		if (msgcreated)
			update_folder1 = msgcreated->FID;
		} break;
	case fnevObjectModified:
	case fnevMbit | fnevObjectModified: {
		struct MessageModifiedNotification *msgmodified = event_data;

		if (msgmodified)
			update_folder1 = msgmodified->FID;
		} break;
	case fnevObjectDeleted:
	case fnevMbit | fnevObjectDeleted: {
		struct MessageDeletedNotification *msgdeleted = event_data;

		if (msgdeleted)
			update_folder1 = msgdeleted->FID;
		} break;
	case fnevObjectMoved:
	case fnevMbit | fnevObjectMoved: {
		struct MessageMoveCopyNotification *msgmoved = event_data;

		if (msgmoved) {
			update_folder1 = msgmoved->OldFID;
			update_folder2 = msgmoved->FID;
		}
		} break;
	case fnevObjectCopied:
	case fnevMbit | fnevObjectCopied: {
		struct MessageMoveCopyNotification *msgcopied = event_data;

		if (msgcopied) {
			update_folder1 = msgcopied->OldFID;
			update_folder2 = msgcopied->FID;
		}
		} break;
	default:
		break;
	}

	priv = ((EBookBackendMAPIContacts *) ebma)->priv;
	if ((priv->fid == update_folder1 || priv->fid == update_folder2) &&
	    e_book_backend_mapi_is_marked_for_offline (ebma))
		e_book_backend_mapi_refresh_cache (ebma);
}

static void
ebbm_contacts_open (EBookBackendMAPI *ebma, GCancellable *cancellable, gboolean only_if_exists, GError **perror)
{
	ESource *source = e_backend_get_source (E_BACKEND (ebma));
	EBookBackendMAPIContactsPrivate *priv = ((EBookBackendMAPIContacts *) ebma)->priv;
	GError *err = NULL;

	if (e_book_backend_is_opened (E_BOOK_BACKEND (ebma))) {
		if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open)
			E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open (ebma, cancellable, only_if_exists, perror);
		return;
	}

	priv->fid = 0;
	priv->is_public_folder = g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0;
	priv->foreign_username = e_source_get_duped_property (source, "foreign-username");
	e_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &priv->fid);

	if (priv->foreign_username && !*priv->foreign_username) {
		g_free (priv->foreign_username);
		priv->foreign_username = NULL;
	}

	/* Chain up to parent's op_load_source() method. */
	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open (ebma, cancellable, only_if_exists, &err);

	if (err)
		g_propagate_error (perror, err);
}

static void
ebbm_contacts_connection_status_changed (EBookBackendMAPI *ebma, gboolean is_online)
{
	ESource *source;

	e_book_backend_notify_readonly (E_BOOK_BACKEND (ebma), !is_online);

	if (!is_online)
		return;

	source = e_backend_get_source (E_BACKEND (ebma));
	if (source && g_strcmp0 (e_source_get_property (source, "server-notification"), "true") == 0) {
		EMapiConnection *conn;
		mapi_object_t obj_folder;
		gboolean status;

		e_book_backend_mapi_lock_connection (ebma);

		conn = e_book_backend_mapi_get_connection (ebma);
		if (!conn) {
			e_book_backend_mapi_unlock_connection (ebma);
			return;
		}

		status = ebbm_contacts_open_folder (E_BOOK_BACKEND_MAPI_CONTACTS (ebma), conn, &obj_folder, NULL, NULL);

		if (status) {
			e_mapi_connection_enable_notifications (conn, &obj_folder,
				fnevObjectCreated | fnevObjectModified | fnevObjectDeleted | fnevObjectMoved | fnevObjectCopied,
				NULL, NULL);

			e_mapi_connection_close_folder (conn, &obj_folder, NULL, NULL);
		}

		g_signal_connect (conn, "server-notification", G_CALLBACK (ebbmc_server_notification_cb), ebma);

		e_book_backend_mapi_unlock_connection (ebma);
	}
}

static void
ebbm_contacts_remove (EBookBackendMAPI *ebma, GCancellable *cancellable, GError **error)
{
	EBookBackendMAPIContactsPrivate *priv;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = E_BOOK_BACKEND_MAPI_CONTACTS (ebma)->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_remove)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_remove (ebma, cancellable, &mapi_error);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);
		g_error_free (mapi_error);
		return;
	}

	if (!priv->is_public_folder && !priv->foreign_username) {
		EMapiConnection *conn;

		e_book_backend_mapi_lock_connection (ebma);

		conn = e_book_backend_mapi_get_connection (ebma);
		if (!conn) {
			g_propagate_error (error, EDB_ERROR (OFFLINE_UNAVAILABLE));
		} else {
			mapi_object_t *obj_store = NULL;

			if (e_mapi_connection_peek_store (conn, priv->foreign_username ? FALSE : priv->is_public_folder, priv->foreign_username, &obj_store, cancellable, &mapi_error))
				e_mapi_connection_remove_folder (conn, obj_store, priv->fid, cancellable, &mapi_error);

			if (mapi_error) {
				mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to remove public folder"));
				g_error_free (mapi_error);
			}
		}

		e_book_backend_mapi_unlock_connection (ebma);
	}
}

static void
ebbm_contacts_create_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **added_contacts, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	EMapiCreateitemData mcd;
	GError *mapi_error = NULL;
	mapi_id_t mid = 0;
	mapi_object_t obj_folder;
	gboolean status;
	gchar *id;
	EContact *contact;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcards != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (added_contacts != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (vcards->next) {
		g_propagate_error (error, EDB_ERROR_EX (NOT_SUPPORTED, _("The backend does not support bulk additions")));
		return;
	}

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	contact = e_contact_new_from_vcard (vcards->data);
	if (!contact) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	e_book_backend_mapi_get_db (ebma, &mcd.db);
	mcd.contact = contact;

	status = ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error);

	if (status) {
		e_mapi_connection_create_object (conn, &obj_folder, E_MAPI_CREATE_FLAG_NONE,
						 ebbm_contact_to_object, &mcd,
						 &mid, cancellable, &mapi_error);
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);

	if (!mid) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to create item on a server"));

		if (mapi_error)
			g_error_free (mapi_error);

		g_object_unref (contact);
		return;
	}

	id = e_mapi_util_mapi_id_to_string (mid);

	/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
	e_contact_set (contact, E_CONTACT_UID, id);
	e_contact_set (contact, E_CONTACT_BOOK_URI, e_book_backend_mapi_get_book_uri (ebma));

	g_free (id);

	*added_contacts = g_slist_append (NULL, contact);
}

static void
ebbm_contacts_remove_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *id_list, GSList **removed_ids, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	GError *mapi_error = NULL;
	GSList *to_remove;
	const GSList *l;
	mapi_object_t obj_folder;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (id_list != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (removed_ids != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	to_remove = NULL;
	for (l = id_list; l; l = l->next) {
		const gchar *uid = l->data;
		mapi_id_t *pmid = g_new0 (mapi_id_t, 1);

		if (e_mapi_util_mapi_id_from_string (uid, pmid)) {
			to_remove = g_slist_prepend (to_remove, pmid);

			*removed_ids = g_slist_prepend (*removed_ids, g_strdup (uid));
		} else {
			g_debug ("%s: Failed to decode MID from '%s'", G_STRFUNC, uid);
			g_free (pmid);
		}
	}

	if (ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error)) {
		e_mapi_connection_remove_items (conn, &obj_folder, to_remove, cancellable, &mapi_error);
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);

		g_error_free (mapi_error);

		g_slist_foreach (*removed_ids, (GFunc) g_free, NULL);
		g_slist_free (*removed_ids);
		*removed_ids = NULL;
	}

	g_slist_foreach (to_remove, (GFunc) g_free, NULL);
	g_slist_free (to_remove);
}

static void
ebbm_contacts_modify_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **modified_contacts, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	EMapiCreateitemData mcd;
	EContact *contact;
	GError *mapi_error = NULL;
	mapi_id_t mid;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcards != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (modified_contacts != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (vcards->next != NULL) {
		g_propagate_error (error, EDB_ERROR_EX (NOT_SUPPORTED, _("The backend does not support bulk modifications")));
		return;
	}

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	contact = e_contact_new_from_vcard (vcards->data);
	if (!contact) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	e_book_backend_mapi_get_db (ebma, &mcd.db);
	mcd.contact = contact;

	if (e_mapi_util_mapi_id_from_string (e_contact_get_const (contact, E_CONTACT_UID), &mid)) {
		mapi_object_t obj_folder;
		gboolean status;

		status = ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error);

		if (status) {
			status = e_mapi_connection_modify_object (conn, &obj_folder, mid,
								  ebbm_contact_to_object, &mcd,
								  cancellable, &mapi_error);

			e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
		}

		if (!status) {
			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to modify item on a server"));
			if (mapi_error)
				g_error_free (mapi_error);

			g_object_unref (contact);
		} else {
			*modified_contacts = g_slist_append (NULL, contact);
		}
	} else {
		g_debug ("%s: Failed to decode MID from '%s'", G_STRFUNC, (const gchar *) e_contact_get_const (contact, E_CONTACT_UID));
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_get_contact (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *id, gchar **vcard, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	mapi_id_t mid;
	mapi_object_t obj_folder;
	struct TransferContactData tc = { 0 };
	gboolean status, has_obj_folder;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (id != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcard != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact (ebma, cancellable, id, vcard, &mapi_error);

	if (mapi_error) {
		g_propagate_error (error, mapi_error);
		return;
	}

	/* found in a cache */
	if (*vcard)
		return;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	status = ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error);
	has_obj_folder = status;

	if (status) {
		status = e_mapi_util_mapi_id_from_string (id, &mid);
		if (!status) {
			g_debug ("%s: Failed to decode MID from '%s'", G_STRFUNC, id);
		}
	}

	if (status) {
		tc.ebma = ebma;
		tc.contact = NULL;

		e_mapi_connection_transfer_object (conn, &obj_folder, mid, transfer_contact_cb, &tc, cancellable, &mapi_error);
	}

	if (has_obj_folder)
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

	if (tc.contact) {
		*vcard =  e_vcard_to_string (E_VCARD (tc.contact), EVC_FORMAT_VCARD_30);
		g_object_unref (tc.contact);
	} else {
		if (!mapi_error || mapi_error->code == MAPI_E_NOT_FOUND) {
			g_propagate_error (error, EDB_ERROR (CONTACT_NOT_FOUND));
		} else {
			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_CONTACT_NOT_FOUND, NULL);
		}

		if (mapi_error)
			g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_get_contact_list (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *query, GSList **vCards, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	GError *mapi_error = NULL;
	gboolean status;
	mapi_object_t obj_folder;
	GSList *mids = NULL;
	struct TransferContactsData tcd = { 0 };

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (query != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vCards != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact_list)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact_list (ebma, cancellable, query, vCards, &mapi_error);

	if (mapi_error) {
		g_propagate_error (error, mapi_error);
		return;
	}

	/* found some in cache, thus use them */
	if (*vCards)
		return;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));

		return;
	}

	tcd.ebma = ebma;
	tcd.cards = vCards;

	status = ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error);

	if (status) {
		status = e_mapi_connection_list_objects (conn, &obj_folder,
							 e_mapi_book_utils_build_sexp_restriction, (gpointer) query,
							 gather_contact_mids_cb, &mids,
							 cancellable, &mapi_error);

		if (mids)
			status = e_mapi_connection_transfer_objects (conn, &obj_folder, mids, transfer_contacts_cb, &tcd, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

		g_slist_free_full (mids, g_free);
	}

	if (!status) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch items from a server"));
		if (mapi_error)
			g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static gchar *
ebbm_contacts_get_status_message (EBookBackendMAPI *ebma, gint index, gint total)
{
	if (index <= 0)
		return NULL;

	return g_strdup_printf (
		total <= 0 ?
			/* Translators : This is used to cache the downloaded contacts from a server.
			   %d is an index of the contact. */
			_("Caching contact %d") :
			/* Translators : This is used to cache the downloaded contacts from a server.
			   The first %d is an index of the contact,
			   the second %d is total count of conacts on the server. */
			_("Caching contact %d/%d"),
		index, total);
}

static void
ebbm_contacts_get_contacts_count (EBookBackendMAPI *ebma,
				  guint32 *obj_total,
				  GCancellable *cancellable,
				  GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EMapiConnection *conn;
	gboolean status;
	mapi_object_t obj_folder;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (obj_total != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (ebmac->priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	status = ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error);

	if (status) {
		struct FolderBasicPropertiesData fbp = { 0 };

		status = e_mapi_connection_get_folder_properties (conn, &obj_folder, NULL, NULL,
			e_mapi_utils_get_folder_basic_properties_cb, &fbp,
			cancellable, &mapi_error);
		if (status)
			*obj_total = fbp.obj_total;
		
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to count server contacts"));
		g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_list_known_uids (EBookBackendMAPI *ebma,
			       BuildRestrictionsCB build_rs_cb,
			       gpointer build_rs_cb_data,
			       struct ListKnownUidsData *lku,
			       GCancellable *cancellable,
			       GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EMapiConnection *conn;
	gboolean status;
	mapi_object_t obj_folder;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (lku != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (lku->uid_to_rev != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (ebmac->priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	status = ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error);

	if (status) {
		status = e_mapi_connection_list_objects (conn, &obj_folder, build_rs_cb, build_rs_cb_data,
							 gather_known_uids_cb, lku,
							 cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to list items from a server"));
		g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_transfer_contacts (EBookBackendMAPI *ebma,
				 const GSList *uids,
				 EDataBookView *book_view,
				 gpointer notify_contact_data,
				 GCancellable *cancellable,
				 GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	struct TransferContactsData tcd = { 0 };
	mapi_object_t obj_folder;
	gboolean status;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));

		return;
	}

	tcd.ebma = ebma;
	tcd.book_view = book_view;
	tcd.notify_contact_data = notify_contact_data;

	status = ebbm_contacts_open_folder (ebmac, conn, &obj_folder, cancellable, &mapi_error);

	if (status) {
		GSList *mids = NULL;
		const GSList *iter;

		for (iter = uids; iter; iter = iter->next) {
			const gchar *uid_str = iter->data;
			mapi_id_t mid, *pmid;

			if (!uid_str || !e_mapi_util_mapi_id_from_string (uid_str, &mid))
				continue;

			pmid = g_new0 (mapi_id_t, 1);
			*pmid = mid;

			mids = g_slist_prepend (mids, pmid);
		}

		if (mids)
			status = e_mapi_connection_transfer_objects (conn, &obj_folder, mids, transfer_contacts_cb, &tcd, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

		g_slist_free_full (mids, g_free);
	}

	if (!status) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to transfer contacts from a server"));

		if (mapi_error)
			g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
e_book_backend_mapi_contacts_init (EBookBackendMAPIContacts *backend)
{
	backend->priv = G_TYPE_INSTANCE_GET_PRIVATE (backend, E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, EBookBackendMAPIContactsPrivate);

	backend->priv->foreign_username = NULL;
}

static void
ebbm_contacts_finalize (GObject *object)
{
	EBookBackendMAPIContactsPrivate *priv;

	priv = E_BOOK_BACKEND_MAPI_CONTACTS (object)->priv;

	g_free (priv->foreign_username);
	priv->foreign_username = NULL;

	G_OBJECT_CLASS (e_book_backend_mapi_contacts_parent_class)->finalize (object);
}

static void
e_book_backend_mapi_contacts_class_init (EBookBackendMAPIContactsClass *klass)
{
	EBookBackendMAPIClass *parent_class;
	GObjectClass *object_class;

	g_type_class_add_private (klass, sizeof (EBookBackendMAPIContactsPrivate));

	object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = ebbm_contacts_finalize;

	parent_class = E_BOOK_BACKEND_MAPI_CLASS (klass);

	/* Set the virtual methods. */
	parent_class->op_open				= ebbm_contacts_open;
	parent_class->op_remove				= ebbm_contacts_remove;
	parent_class->op_create_contacts		= ebbm_contacts_create_contacts;
	parent_class->op_remove_contacts		= ebbm_contacts_remove_contacts;
	parent_class->op_modify_contacts		= ebbm_contacts_modify_contacts;
	parent_class->op_get_contact			= ebbm_contacts_get_contact;
	parent_class->op_get_contact_list		= ebbm_contacts_get_contact_list;

	parent_class->op_connection_status_changed	= ebbm_contacts_connection_status_changed;
	parent_class->op_get_status_message		= ebbm_contacts_get_status_message;
	parent_class->op_get_contacts_count		= ebbm_contacts_get_contacts_count;
	parent_class->op_list_known_uids		= ebbm_contacts_list_known_uids;
	parent_class->op_transfer_contacts		= ebbm_contacts_transfer_contacts;
}

EBookBackend *
e_book_backend_mapi_contacts_new (void)
{
	return g_object_new (E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, NULL);
}
