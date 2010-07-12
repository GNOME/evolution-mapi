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
#include <libedata-book/e-book-backend-cache.h>
#include <libedata-book/e-book-backend-summary.h>

#include "e-book-backend-mapi-gal.h"
#include "e-book-backend-mapi-utils.h"

G_DEFINE_TYPE (EBookBackendMAPIGAL, e_book_backend_mapi_gal, E_TYPE_BOOK_BACKEND)

static gboolean enable_debug = TRUE;

struct _EBookBackendMAPIGALPrivate
{
	gchar *profile;
	ExchangeMapiConnection *conn;

	mapi_id_t fid;
	gint mode;
	gboolean marked_for_offline;
	GThread *build_cache_thread;
	gboolean kill_cache_build;
	gboolean is_cache_ready;
	gboolean is_summary_ready;
	gboolean is_writable;
	gchar *uri;

	GMutex *lock;
	gchar *summary_file_name;
	EBookBackendSummary *summary;
	EBookBackendCache *cache;

	GStaticMutex running_mutex;
	GHashTable *view_to_closure_hash; /* EDataBookView -> BESearchClosure */
};

#define SUMMARY_FLUSH_TIMEOUT 5000

static gchar *
e_book_backend_mapi_gal_get_static_capabilities (EBookBackend *backend)
{
	if (enable_debug)
		printf("mapi get_static_capabilities\n");
	//FIXME: Implement this.

	return g_strdup ("net,bulk-removes,do-initial-query,contact-lists");
}

static EDataBookView *
find_book_view (EBookBackendMAPIGAL *ebmapi)
{
	EList *views = e_book_backend_get_book_views (E_BOOK_BACKEND (ebmapi));
	EIterator *iter;
	EDataBookView *rv = NULL;
	gint test;

	if (!views)
		return NULL;

	test = e_list_length (views);

	iter = e_list_get_iterator (views);

	if (!iter) {
		g_object_unref (views);
		return NULL;
	}

	if (e_iterator_is_valid (iter)) {
		/* just always use the first book view */
		EDataBookView *v = (EDataBookView*)e_iterator_get(iter);
		if (v)
			rv = v;
	}

	g_object_unref (iter);
	g_object_unref (views);

	return rv;
}

static void
book_view_notify_status (EDataBookView *view, const gchar *status)
{
	if (!view)
		return;
	e_data_book_view_notify_status_message (view, status);
}

static guint32
current_time_ms (void)
{
	GTimeVal tv;

	g_get_current_time (&tv);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

struct fetch_gal_data
{
	EBookBackendMAPIGAL *ebmapi;
	EDataBookView *book_view;
	mapi_id_t fid; /* folder ID of contacts, for named IDs */
	guint32 last_update; /* when in micro-seconds was done last notification about progress */
};

static gboolean
fetch_gal_cb (ExchangeMapiConnection *conn, uint32_t row_index, uint32_t n_rows, struct SRow *aRow, gpointer data)
{
	EBookBackendMAPIGALPrivate *priv;
	struct fetch_gal_data *fgd = data;
	EContact *contact;
	gchar *uid;
	guint32 current_time;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (aRow != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);

	priv = fgd->ebmapi->priv;
	if (priv->kill_cache_build)
		return FALSE;

	contact = mapi_book_utils_contact_from_props (conn, fgd->fid, NULL, aRow);
	if (!contact) {
		/* just ignore them */
		return TRUE;
	}

	uid = g_strdup_printf ("%d", row_index);
	e_contact_set (contact, E_CONTACT_UID, uid);
	g_free (uid);

	e_book_backend_cache_add_contact (priv->cache, contact);
	e_book_backend_summary_add_contact (priv->summary, contact);

	if (!fgd->book_view)
		fgd->book_view = find_book_view (fgd->ebmapi);

	if (fgd->book_view)
		e_data_book_view_notify_update (fgd->book_view, contact);

	current_time = current_time_ms ();
	if (fgd->book_view && current_time - fgd->last_update >= 333) {
		gchar *status_msg;

		if (n_rows > 0) {
			/* To translators : This is used to cache the downloaded contacts from GAL.
			   The first %d is an index of the GAL entry,
			   the second %d is total count of entries in GAL. */
			status_msg = g_strdup_printf (_("Caching GAL entry %d/%d"), row_index, n_rows);
		} else {
			/* To translators : This is used to cache the downloaded contacts from GAL.
			   %d is an index of the GAL entry. */
			status_msg = g_strdup_printf (_("Caching GAL entry %d"), row_index);
		}
		book_view_notify_status (fgd->book_view, status_msg);
		g_free (status_msg);
		fgd->last_update = current_time;
	}

	g_object_unref (contact);

	return TRUE;
}

static gpointer
build_cache (EBookBackendMAPIGAL *ebmapi)
{
	EBookBackendMAPIGALPrivate *priv = ebmapi->priv;
	GError *mapi_error = NULL;
	gchar *tmp;
	struct fetch_gal_data fgd = { 0 };

	//FIXME: What if book view is NULL? Can it be? Check that.
	if (!priv->cache) {
		printf("Caching for the first time\n");
		priv->cache = e_book_backend_cache_new (priv->uri);
	}

	fgd.ebmapi = ebmapi;
	fgd.book_view = find_book_view (ebmapi);
	fgd.fid = exchange_mapi_connection_get_default_folder_id (priv->conn, olFolderContacts, NULL);
	fgd.last_update = current_time_ms ();

	e_file_cache_freeze_changes (E_FILE_CACHE (priv->cache));
	exchange_mapi_connection_fetch_gal (priv->conn,
					mapi_book_utils_get_prop_list, GET_ALL_KNOWN_IDS,
					fetch_gal_cb, &fgd, &mapi_error);

	if (fgd.book_view) {
		GError *error = NULL;

		if (mapi_error) {
			mapi_error_to_edb_error (&error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch GAL entries"));
			g_error_free (mapi_error);
		}

		e_data_book_view_notify_complete (fgd.book_view, error);
		e_data_book_view_unref (fgd.book_view);

		if (error)
			g_error_free (error);
	}

	tmp = g_strdup_printf("%d", priv->kill_cache_build ? 0 : (gint)time (NULL));
	e_book_backend_cache_set_time (priv->cache, tmp);
	printf("setting time  %s\n", tmp);
	g_free (tmp);

	e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));

	e_book_backend_summary_save (priv->summary);

	priv->is_cache_ready = !priv->kill_cache_build;
	priv->is_summary_ready = !priv->kill_cache_build;

	return NULL;
}

static void
e_book_backend_mapi_gal_get_supported_fields (EBookBackend *backend,
		      EDataBook    *book,
		      guint32	    opid)

{
	GList *fields;

	fields = mapi_book_utils_get_supported_fields ();
	e_data_book_respond_get_supported_fields (book,
						  opid,
						  NULL /* Success */,
						  fields);
	g_list_free (fields);
}

static void
e_book_backend_mapi_gal_get_required_fields (EBookBackend *backend,
		     EDataBook *book,
		     guint32 opid)
{
	GList *fields = NULL;

	fields = g_list_append (fields, (gchar *) e_contact_field_name (E_CONTACT_FILE_AS));
	e_data_book_respond_get_required_fields (book,
						  opid,
						  NULL /* Success */,
						  fields);
	g_list_free (fields);
}

static void
e_book_backend_mapi_gal_authenticate_user (EBookBackend *backend,
					    EDataBook    *book,
					    guint32       opid,
					    const gchar *user,
					    const gchar *passwd,
					    const gchar *auth_method)
{
	EBookBackendMAPIGAL *ebmapi = (EBookBackendMAPIGAL *) backend;
	EBookBackendMAPIGALPrivate *priv = ebmapi->priv;
	GError *mapi_error = NULL;

	if (enable_debug) {
		printf ("mapi: authenticate user\n");
	}

	switch (priv->mode) {
	case E_DATA_BOOK_MODE_LOCAL:
		e_book_backend_notify_writable (backend, FALSE);
		e_book_backend_set_is_writable (E_BOOK_BACKEND(backend), FALSE);
		e_book_backend_notify_connection_status (backend, FALSE);
		e_data_book_respond_authenticate_user (book, opid, NULL /* Success */);
		return;

	case E_DATA_BOOK_MODE_REMOTE:
		g_static_mutex_lock (&priv->running_mutex);

		/* rather reuse already established connection */
		priv->conn = exchange_mapi_connection_find (priv->profile);
		if (priv->conn && !exchange_mapi_connection_connected (priv->conn))
			exchange_mapi_connection_reconnect (priv->conn, passwd, &mapi_error);
		else if (!priv->conn)
			priv->conn = exchange_mapi_connection_new (priv->profile, passwd, &mapi_error);

		if (!priv->conn || mapi_error) {
			GError *err = NULL;

			if (priv->conn) {
				g_object_unref (priv->conn);
				priv->conn = NULL;
			}
				
			mapi_error_to_edb_error (&err, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Cannot connect"));
			e_data_book_respond_authenticate_user (book, opid, err);
			g_static_mutex_unlock (&priv->running_mutex);

			if (mapi_error)
				g_error_free (mapi_error);
			return;
		}

		if (priv->cache && priv->is_cache_ready) {
			printf("FIXME: Should check for an update in the cache\n");
//			g_thread_create ((GThreadFunc) update_cache,
	//					  backend, FALSE, backend);
		} else if (priv->marked_for_offline && !priv->is_cache_ready) {
			if (!priv->build_cache_thread) {
				/* Means we dont have a cache. Lets build that first */
				printf("Preparing to build cache\n");
				priv->kill_cache_build = FALSE;
				priv->build_cache_thread = g_thread_create ((GThreadFunc) build_cache, ebmapi, TRUE, NULL);
			}
		}
		e_book_backend_set_is_writable (backend, FALSE);
		e_data_book_respond_authenticate_user (book, opid, NULL /* Success */);
		g_static_mutex_unlock (&priv->running_mutex);
		return;

	default :
		break;
	}
}

static gchar *
get_filename_from_uri (const gchar *uri, const gchar *file)
{
	gchar *mangled_uri, *filename;
	gint i;

	/* mangle the URI to not contain invalid characters */
	mangled_uri = g_strdup (uri);
	for (i = 0; i < strlen (mangled_uri); i++) {
		switch (mangled_uri[i]) {
		case ':' :
		case '/' :
			mangled_uri[i] = '_';
		}
	}

	/* generate the file name */
	filename = g_build_filename (g_get_home_dir (), ".evolution/cache/addressbook",
				     mangled_uri, file, NULL);

	/* free memory */
	g_free (mangled_uri);

	return filename;
}

static void
e_book_backend_mapi_gal_create_contact (EBookBackend *backend,
		EDataBook    *book,
		guint32       opid,
		const gchar   *vcard)
{
	e_data_book_respond_create (book, opid,
				    EDB_ERROR (PERMISSION_DENIED),
				    NULL);
}

static void
e_book_backend_mapi_gal_remove_contacts (EBookBackend *backend,
		 EDataBook    *book,
		 guint32       opid,
		 GList        *ids)
{
	e_data_book_respond_remove_contacts (book, opid,
					     EDB_ERROR (PERMISSION_DENIED),
					     NULL);
}

static void
e_book_backend_mapi_gal_modify_contact (EBookBackend *backend,
		EDataBook    *book,
		guint32       opid,
		const gchar   *vcard)
{
	e_data_book_respond_modify (book, opid,
				    EDB_ERROR (PERMISSION_DENIED),
				    NULL);
}

static void
e_book_backend_mapi_gal_load_source (EBookBackend *backend,
				 ESource      *source,
				 gboolean     only_if_exists,
				 GError **perror)
{
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;
	const gchar *offline, *tmp;

	if (enable_debug)
		printf("MAPI load source\n");

	if (e_book_backend_is_loaded (backend))
		return /* Success */;

	offline = e_source_get_property (source, "offline_sync");
	if (offline  && g_str_equal (offline, "1"))
		priv->marked_for_offline = TRUE;

	/* Either we are in Online mode or this is marked for offline */

	priv->uri = e_source_get_uri (source);

	if (priv->mode ==  E_DATA_BOOK_MODE_LOCAL &&
	    !priv->marked_for_offline ) {
		g_propagate_error (perror, EDB_ERROR (OFFLINE_UNAVAILABLE));
		return;
	}

	g_free (priv->summary_file_name);
	priv->summary_file_name = get_filename_from_uri (priv->uri, "cache.summary");
	if (priv->summary) g_object_unref (priv->summary);
	priv->summary = e_book_backend_summary_new (priv->summary_file_name, SUMMARY_FLUSH_TIMEOUT);

	if (priv->marked_for_offline) {
		if (g_file_test (priv->summary_file_name, G_FILE_TEST_EXISTS)) {
			e_book_backend_summary_load (priv->summary);
			priv->is_summary_ready = TRUE;
		}

		/* Load the cache as well.*/
		if (e_book_backend_cache_exists (priv->uri)) {
			gchar *last_time;

			priv->cache = e_book_backend_cache_new (priv->uri);

			last_time = e_book_backend_cache_get_time (priv->cache);
			priv->is_cache_ready = last_time && !g_str_equal (last_time, "0");
			g_free (last_time);
		}
		//FIXME: We may have to do a time based reload. Or deltas should upload.
	}

	e_book_backend_set_is_loaded (E_BOOK_BACKEND (backend), TRUE);
	e_book_backend_set_is_writable (backend, FALSE);
	if (priv->mode ==  E_DATA_BOOK_MODE_LOCAL) {
		e_book_backend_set_is_writable (backend, FALSE);
		e_book_backend_notify_writable (backend, FALSE);
		e_book_backend_notify_connection_status (backend, FALSE);
		if (!priv->cache) {
			printf("Unfortunately the cache is not yet created\n");
			g_propagate_error (perror, EDB_ERROR (OFFLINE_UNAVAILABLE));
			return;
		}
	} else {
		e_book_backend_notify_connection_status (backend, TRUE);
	}

	priv->profile = g_strdup (e_source_get_property (source, "profile"));
	exchange_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &priv->fid);

	tmp = e_source_get_property (source, "folder-id");

	/* Once aunthentication in address book works this can be removed */
	if (priv->mode == E_DATA_BOOK_MODE_LOCAL) {
		return /* Success */;
	}

	// writable property will be set in authenticate_user callback
	e_book_backend_set_is_loaded (E_BOOK_BACKEND (backend), TRUE);
	e_book_backend_notify_connection_status (E_BOOK_BACKEND (backend), TRUE);

	if (enable_debug)
		printf("For profile %s and folder %s - %016" G_GINT64_MODIFIER "X\n", priv->profile, tmp, priv->fid);
}

static void
e_book_backend_mapi_gal_set_mode (EBookBackend *backend, EDataBookMode mode)
{
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;

	if (enable_debug)
		printf("mapi: set_mode \n");

	priv->mode = mode;
	if (e_book_backend_is_loaded (backend)) {
		if (mode == E_DATA_BOOK_MODE_LOCAL) {
			e_book_backend_notify_writable (backend, FALSE);
			e_book_backend_set_is_writable (backend, FALSE);
			e_book_backend_notify_connection_status (backend, FALSE);
			/* FIXME: Uninitialize mapi here. may be.*/
		}
		else if (mode == E_DATA_BOOK_MODE_REMOTE) {
			e_book_backend_notify_writable (backend, FALSE);
			e_book_backend_set_is_writable (backend, FALSE);
			e_book_backend_notify_connection_status (backend, TRUE);
//			e_book_backend_notify_auth_required (backend); //FIXME: WTH is this required.
		}
	}
}

typedef struct {
	EBookBackendMAPIGAL *bg;
	EDataBookView *book_view;
	gboolean stop;
} BESearchClosure;

static BESearchClosure*
init_closure (EDataBookView *book_view, EBookBackendMAPIGAL *bg)
{
	BESearchClosure *closure;

	g_return_val_if_fail (bg != NULL, NULL);
	g_return_val_if_fail (bg->priv != NULL, NULL);
	g_return_val_if_fail (bg->priv->view_to_closure_hash != NULL, NULL);
	
	closure = g_new0 (BESearchClosure, 1);
	closure->bg = bg;
	closure->book_view = book_view;
	closure->stop = FALSE;

	g_hash_table_insert (bg->priv->view_to_closure_hash, g_object_ref (book_view), closure);

	return closure;
}

static void
destroy_closure (BESearchClosure *closure)
{
	g_return_if_fail (closure != NULL);

	if (closure->book_view)
		g_object_unref (closure->book_view);
	g_free (closure);
}

static void
stop_book_view (EDataBookView *book_view, BESearchClosure *closure, EBookBackendMAPIGAL *mapi_backend)
{
	g_return_if_fail (closure != NULL);

	closure->stop = TRUE;
}

static void
untrack_book_view (EBookBackendMAPIGAL *mapi_backend, EDataBookView *book_view)
{
	g_return_if_fail (mapi_backend != NULL);
	g_return_if_fail (mapi_backend->priv != NULL);
	g_return_if_fail (mapi_backend->priv->view_to_closure_hash != NULL);
	g_return_if_fail (book_view != NULL);

	g_hash_table_remove (mapi_backend->priv->view_to_closure_hash, book_view);
}

static void
get_contacts_from_cache (EBookBackendMAPIGAL *ebmapi,
			 const gchar *query,
			 GPtrArray *ids,
			 EDataBookView *book_view,
			 BESearchClosure *closure)
{
	gint i;

	for (i = 0; i < ids->len; i ++) {
		gchar *uid;
		EContact *contact;

                if (closure->stop)
                        break;

		uid = g_ptr_array_index (ids, i);
		contact = e_book_backend_cache_get_contact (ebmapi->priv->cache, uid);
		if (contact) {
			e_data_book_view_notify_update (book_view, contact);
			g_object_unref (contact);
		}
	}
}
#if 0
static gboolean
build_restriction_emails_contains (struct mapi_SRestriction *res,
				   const gchar *query)
{
	gchar *email=NULL, *tmp, *tmp1;

	/* This currently supports "email foo@bar.soo" */
	tmp = strdup (query);

	tmp = strstr (tmp, "email");
	if (tmp ) {
		tmp = strchr (tmp, '\"');
		if (tmp && ++tmp) {
			tmp = strchr (tmp, '\"');
			if (tmp && ++tmp) {
				tmp1 = tmp;
				tmp1 = strchr (tmp1, '\"');
				if (tmp1) {
					*tmp1 = 0;
					email = tmp;
				}
			}
		}
	}

	if (email==NULL || !strchr (email, '@'))
		return FALSE;

	res->rt = RES_PROPERTY;
	res->res.resProperty.relop = RES_PROPERTY;
	res->res.resProperty.ulPropTag = PROP_TAG(PT_UNICODE, 0x801f); /* EMAIL */
	res->res.resProperty.lpProp.ulPropTag = PROP_TAG(PT_UNICODE, 0x801f); /* EMAIL*/
	res->res.resProperty.lpProp.value.lpszA = email;

	return TRUE;
}
#endif

static void
book_view_thread (gpointer data)
{
	BESearchClosure *closure = data;
	EDataBookView *book_view = closure->book_view;
	EBookBackendMAPIGAL *backend = closure->bg;
	EBookBackendMAPIGALPrivate *priv = backend->priv;
	const gchar *query = NULL;
	GPtrArray *ids = NULL;
	GList *contacts = NULL, *temp_list = NULL;

	if (enable_debug)
		printf("mapi: book view\n");

	book_view_notify_status (book_view, _("Searching"));
	query = e_data_book_view_get_card_query (book_view);

	if (!find_book_view (backend))
		e_book_backend_add_book_view (E_BOOK_BACKEND (backend), book_view);

	switch (priv->mode) {
		case E_DATA_BOOK_MODE_REMOTE:
			if (!priv->conn) {
				GError *err = EDB_ERROR (AUTHENTICATION_REQUIRED);
				e_book_backend_notify_auth_required (E_BOOK_BACKEND (backend));
				e_data_book_view_notify_complete (book_view, err);
				g_error_free (err);
				untrack_book_view (backend, book_view);
				destroy_closure (closure);
				return;
			}

			if (priv->marked_for_offline && !priv->is_cache_ready) {
				/* To translators : Here Evolution MAPI downloads the entries from the GAL server */
				book_view_notify_status (book_view, _("Downloading GAL entries from server…"));
				untrack_book_view (backend, book_view);
				destroy_closure (closure);
				return;
			}

			if (priv->marked_for_offline && priv->cache && priv->is_cache_ready) {
				if (priv->is_summary_ready &&
				    e_book_backend_summary_is_summary_query (priv->summary, query)) {
					if (enable_debug)
						printf ("reading the contacts from summary \n");
					ids = e_book_backend_summary_search (priv->summary, query);
					if (ids && ids->len > 0)
						get_contacts_from_cache (backend, query, ids, book_view, closure);
					if (ids)
						g_ptr_array_free (ids, TRUE);
					break;
				}

				printf("Summary seems to be not there or not a summary query, lets fetch from cache directly\n");

				/* We are already cached. Lets return from there. */
				contacts = e_book_backend_cache_get_contacts (priv->cache,
								      query);
				temp_list = contacts;
				for (; contacts != NULL; contacts = g_list_next(contacts)) {
					if (closure->stop) {
						for (;contacts != NULL; contacts = g_list_next (contacts))
							g_object_unref (contacts->data);
						break;
					}
					e_data_book_view_notify_update (book_view,
									E_CONTACT(contacts->data));
					g_object_unref (contacts->data);
				}
				if (temp_list)
					g_list_free (temp_list);
				break;
			}

			if (e_book_backend_summary_is_summary_query (priv->summary, query)) {
				ids = e_book_backend_summary_search (priv->summary, query);
				if (ids && ids->len > 0)
					get_contacts_from_cache (backend, query, ids, book_view, closure);
				if (ids)
					g_ptr_array_free (ids, TRUE);
				break;
			}

			break;
	}

	e_data_book_view_notify_complete (book_view, NULL /* Success */);
	untrack_book_view (backend, book_view);
	destroy_closure (closure);
}

static void
e_book_backend_mapi_gal_get_contact (EBookBackend *backend,
				     EDataBook    *book,
				     guint32       opid,
				     const gchar   *id)
{
	if (enable_debug)
		printf ("mapi: get contact %s\n", id);

	e_data_book_respond_get_contact (book, opid, EDB_ERROR (NOT_SUPPORTED), NULL);
}

static void
e_book_backend_mapi_gal_get_contact_list (EBookBackend *backend,
					    EDataBook    *book,
					    guint32       opid,
					    const gchar   *query )
{
	/*EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;*/

	if (enable_debug)
		printf("mapi: get contact list %s\n", query);

	e_data_book_respond_get_contact_list (book, opid, EDB_ERROR (NOT_SUPPORTED), NULL);
}

static void
e_book_backend_mapi_gal_start_book_view (EBookBackend  *backend,
					   EDataBookView *book_view)
{
	BESearchClosure *closure = init_closure (book_view, E_BOOK_BACKEND_MAPIGAL (backend));

	g_return_if_fail (closure != NULL);

	if (enable_debug)
		printf ("mapi: start_book_view...\n");

	g_thread_create ((GThreadFunc) book_view_thread, closure, FALSE, NULL);
}

static void
e_book_backend_mapi_gal_stop_book_view (EBookBackend  *backend,
					  EDataBookView *book_view)
{
	if (enable_debug)
		printf("mapi: stop book view\n");

	untrack_book_view (E_BOOK_BACKEND_MAPIGAL (backend), book_view);
}

static void
e_book_backend_mapi_gal_get_changes (EBookBackend *backend, EDataBook *book, guint32 opid, const gchar *change_id)
{
	if (enable_debug)
		printf ("mapi: get changes\n");

	e_data_book_respond_get_changes (book, opid, EDB_ERROR (NOT_SUPPORTED), NULL);
}

static void
e_book_backend_mapi_gal_get_supported_auth_methods (EBookBackend *backend, EDataBook *book, guint32 opid)
{
	GList *auth_methods = NULL;
	gchar *auth_method;

	if (enable_debug)
		printf ("mapi get_supported_auth_methods...\n");

	auth_method =  g_strdup_printf ("plain/password");
	auth_methods = g_list_append (auth_methods, auth_method);
	e_data_book_respond_get_supported_auth_methods (book,
							opid,
							NULL /* Success */,
							auth_methods);
	g_free (auth_method);
	g_list_free (auth_methods);
}

static void
e_book_backend_mapi_gal_cancel_operation (EBookBackend *backend, EDataBook *book, GError **perror)
{
	if (enable_debug)
		printf ("mapi cancel_operation...\n");
	g_propagate_error (perror, EDB_ERROR (COULD_NOT_CANCEL));
}

static void
e_book_backend_mapi_gal_remove (EBookBackend *backend, EDataBook *book, guint32 opid)
{
	e_data_book_respond_remove (book, opid, EDB_ERROR (PERMISSION_DENIED));
}

static void
e_book_backend_mapi_gal_init (EBookBackendMAPIGAL *backend)
{
	EBookBackendMAPIGALPrivate *priv;

	priv = g_new0 (EBookBackendMAPIGALPrivate, 1);
	/* Priv Struct init */
	backend->priv = priv;

	priv->build_cache_thread = NULL;
	priv->view_to_closure_hash = g_hash_table_new (g_direct_hash, g_direct_equal);
	g_static_mutex_init (&priv->running_mutex);

/*	priv->marked_for_offline = FALSE;
	priv->uri = NULL;
	priv->cache = NULL;
	priv->is_summary_ready = FALSE;
	priv->is_cache_ready = FALSE;

*/	if (g_getenv ("MAPI_DEBUG"))
		enable_debug = TRUE;
	else
		enable_debug = FALSE;
}

static void
e_book_backend_mapi_gal_dispose (GObject *object)
{
	EBookBackendMAPIGAL *mapi_backend = E_BOOK_BACKEND_MAPIGAL (object);
	EBookBackendMAPIGALPrivate *priv = mapi_backend->priv;

	if (priv) {
		if (priv->view_to_closure_hash) {
			g_hash_table_foreach (priv->view_to_closure_hash, (GHFunc) stop_book_view, mapi_backend);
			g_hash_table_destroy (priv->view_to_closure_hash);
			priv->view_to_closure_hash = NULL;
		}

		if (priv->build_cache_thread) {
			priv->kill_cache_build = TRUE;
			g_thread_join (priv->build_cache_thread);
			priv->build_cache_thread = NULL;
		}

		#define FREE(x) if (x) { g_free (x); x = NULL; }
		#define UNREF(x) if (x) { g_object_unref (x); x = NULL; }

		/* this will also ensure any pending authentication
		   request is finished and it's safe to free memory */
		g_static_mutex_lock (&priv->running_mutex);

		UNREF (priv->conn);
		UNREF (priv->cache);
		UNREF (priv->summary);

		FREE (priv->profile);
		FREE (priv->uri);
		FREE (priv->summary_file_name);

		g_static_mutex_unlock (&priv->running_mutex);
		g_static_mutex_free (&priv->running_mutex);

		FREE (mapi_backend->priv);

		#undef UNREF
		#undef FREE
	}

	/* Chain up to parent's dispose() method. */
	if (G_OBJECT_CLASS (e_book_backend_mapi_gal_parent_class)->dispose)
		G_OBJECT_CLASS (e_book_backend_mapi_gal_parent_class)->dispose (object);
}

static void
e_book_backend_mapi_gal_class_init (EBookBackendMAPIGALClass *klass)
{
	GObjectClass  *object_class = G_OBJECT_CLASS (klass);
	EBookBackendClass *parent_class;

	parent_class = E_BOOK_BACKEND_CLASS (klass);

	/* Set the virtual methods. */
	parent_class->create_contact		 = e_book_backend_mapi_gal_create_contact;
	parent_class->remove_contacts		 = e_book_backend_mapi_gal_remove_contacts;
	parent_class->modify_contact		 = e_book_backend_mapi_gal_modify_contact;
	parent_class->load_source		 = e_book_backend_mapi_gal_load_source;
	parent_class->get_static_capabilities    = e_book_backend_mapi_gal_get_static_capabilities;

	parent_class->get_contact                = e_book_backend_mapi_gal_get_contact;
	parent_class->get_contact_list           = e_book_backend_mapi_gal_get_contact_list;
	parent_class->start_book_view            = e_book_backend_mapi_gal_start_book_view;
	parent_class->stop_book_view             = e_book_backend_mapi_gal_stop_book_view;
	parent_class->get_changes                = e_book_backend_mapi_gal_get_changes;
	parent_class->authenticate_user          = e_book_backend_mapi_gal_authenticate_user;
	parent_class->get_supported_fields	 = e_book_backend_mapi_gal_get_supported_fields;
	parent_class->get_required_fields	 = e_book_backend_mapi_gal_get_required_fields;
	parent_class->get_supported_auth_methods = e_book_backend_mapi_gal_get_supported_auth_methods;
	parent_class->cancel_operation		 = e_book_backend_mapi_gal_cancel_operation;
	parent_class->set_mode                   = e_book_backend_mapi_gal_set_mode;
	parent_class->remove			 = e_book_backend_mapi_gal_remove;

	object_class->dispose                    = e_book_backend_mapi_gal_dispose;
}

/**
 * e_book_backend_mapi_gal_new:
 */
EBookBackend *
e_book_backend_mapi_gal_new (void)
{
	EBookBackendMAPIGAL *backend;

	if (enable_debug)
		printf ("\ne_book_backend_mapi_gal_new...\n");

	backend = g_object_new (E_TYPE_BOOK_BACKEND_MAPIGAL, NULL);

	return E_BOOK_BACKEND (backend);
}
