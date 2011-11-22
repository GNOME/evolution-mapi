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

#include <libedataserver/e-sexp.h>
#include "libedataserver/e-flag.h"
#include <libebook/e-contact.h>

#include <libedata-book/e-book-backend-sexp.h>
#include <libedata-book/e-data-book.h>
#include <libedata-book/e-data-book-view.h>

#include "e-book-backend-mapi-gal.h"

G_DEFINE_TYPE (EBookBackendMAPIGAL, e_book_backend_mapi_gal, E_TYPE_BOOK_BACKEND_MAPI)

struct _EBookBackendMAPIGALPrivate
{
	/* nothing to store locally at the moment,
	   but keep it ready for any later need */

	gint32 unused;
};

static gchar *
get_uid_from_row (struct SRow *aRow, uint32_t row_index)
{
	gchar *suid = NULL;
	const gchar *str;

	g_return_val_if_fail (aRow != NULL, NULL);

	str = e_mapi_util_find_row_propval (aRow, PR_EMAIL_ADDRESS_UNICODE);
	if (str && *str)
		suid = g_strdup (str);

	if (!suid) {
		const mapi_id_t *midptr;

		midptr = e_mapi_util_find_row_propval (aRow, PR_MID);

		suid = e_mapi_util_mapi_id_to_string (midptr ? *midptr : row_index);
	}

	return suid;
}

struct FetchGalData
{
	EBookBackendMAPI *ebma;
	EDataBookView *book_view;
	gpointer notify_contact_data;
	mapi_id_t fid; /* folder ID of contacts, for named IDs */
};

static gboolean
fetch_gal_cb (EMapiConnection *conn,
	      uint32_t row_index,
	      uint32_t n_rows,
	      struct SRow *aRow,
	      gpointer data,
	      GCancellable *cancellable,
	      GError **perror)
{
	struct FetchGalData *fgd = data;
	EContact *contact;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (aRow != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);

	contact = mapi_book_utils_contact_from_props (conn, fgd->fid, e_book_backend_mapi_get_book_uri (fgd->ebma), NULL, aRow);
	if (!contact) {
		/* just ignore them */
		return TRUE;
	}

	if (!e_contact_get_const (contact, E_CONTACT_UID)) {
		gchar *suid;

		suid = get_uid_from_row (aRow, row_index);
		e_contact_set (contact, E_CONTACT_UID, suid);
		g_free (suid);
	}

	if (!e_book_backend_mapi_notify_contact_update (fgd->ebma, fgd->book_view, contact, row_index, n_rows, fgd->notify_contact_data)) {
		g_object_unref (contact);
		return FALSE;
	}

	g_object_unref (contact);

	return TRUE;
}

static gboolean
list_gal_uids_cb (EMapiConnection *conn,
		  uint32_t row_index,
		  uint32_t n_rows,
		  struct SRow *aRow,
		  gpointer user_data,
		  GCancellable *cancellable,
		  GError **perror)
{
	gchar *uid;
	struct ListKnownUidsData *lku = user_data;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (aRow != NULL, FALSE);
	g_return_val_if_fail (lku != NULL, FALSE);

	uid = get_uid_from_row (aRow, row_index);
	if (uid) {
		const struct FILETIME *ft;
		time_t tt;

		ft = e_mapi_util_find_row_propval (aRow, PidTagLastModificationTime);
		tt = ft ? e_mapi_util_filetime_to_time_t (ft) : 1;

		if (lku->latest_last_modify < tt)
			lku->latest_last_modify = tt;

		g_hash_table_insert (lku->uid_to_rev, uid, mapi_book_utils_timet_to_string (tt));
	}

	return !g_cancellable_is_cancelled (cancellable);
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
	struct FetchGalData fgd = { 0 };
	EMapiConnection *conn;
	gchar *last_fetch;
	gboolean fetch_successful;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	/* GAL doesn't use restrictions yet, thus just fetches all items always */
	last_fetch = e_book_backend_mapi_cache_get (ebma, "gal-last-update");
	if (last_fetch) {
		GTimeVal last_tv = { 0 }, now = { 0 };

		g_get_current_time (&now);

		/* refetch gal only once per week */
		if (g_time_val_from_iso8601 (last_fetch, &last_tv) && now.tv_sec - last_tv.tv_sec <= 60 * 60 * 24 * 7) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled");
			g_free (last_fetch);
			e_book_backend_mapi_unlock_connection (ebma);
			return;
		}

		g_free (last_fetch);
	}

	fgd.ebma = ebma;
	fgd.book_view = book_view;
	fgd.notify_contact_data = notify_contact_data;
	fgd.fid = e_mapi_connection_get_default_folder_id (conn, olFolderContacts, NULL, NULL);

	fetch_successful = e_mapi_connection_fetch_gal (conn, NULL, NULL,
		mapi_book_utils_get_prop_list, GET_ALL_KNOWN_IDS,
		fetch_gal_cb, &fgd, NULL, &mapi_error);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch GAL entries"));
		g_error_free (mapi_error);
	} else if (!fetch_successful) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled");
	} else {
		GTimeVal now = { 0 };

		g_get_current_time (&now);

		last_fetch = g_time_val_to_iso8601 (&now);
		if (last_fetch && *last_fetch)
			e_book_backend_mapi_cache_set (ebma, "gal-last-update", last_fetch);

		g_free (last_fetch);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_gal_get_contacts_count (EBookBackendMAPI *ebma,
			     guint32 *obj_total,
			     GCancellable *cancellable,
			     GError **error)
{
	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (obj_total != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	/* just a fake value, to check by ids */
	*obj_total = -1;
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

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	e_mapi_connection_fetch_gal (conn, NULL, NULL,
		mapi_book_utils_get_prop_list, GET_UIDS_ONLY,
		list_gal_uids_cb, lku, cancellable, &mapi_error);

	if (mapi_error) {
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
