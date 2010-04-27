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

#include "e-book-backend-mapi.h"
#include "e-book-backend-mapi-gal.h"

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
	gchar *book_name;

	GMutex *lock;
	gchar *summary_file_name;
	EBookBackendSummary *summary;
	EBookBackendCache *cache;
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

	contact = mapi_book_contact_from_props (conn, fgd->fid, NULL, aRow);
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
	gchar *tmp;
	struct fetch_gal_data fgd = { 0 };

	//FIXME: What if book view is NULL? Can it be? Check that.
	if (!priv->cache) {
		printf("Caching for the first time\n");
		priv->cache = e_book_backend_cache_new (priv->uri);
	}

	if (!priv->summary) {
		priv->summary = e_book_backend_summary_new (priv->summary_file_name,
							    SUMMARY_FLUSH_TIMEOUT);
		printf("Summary file name is %s\n", priv->summary_file_name);
	}

	fgd.ebmapi = ebmapi;
	fgd.book_view = find_book_view (ebmapi);
	fgd.fid = exchange_mapi_connection_get_default_folder_id (priv->conn, olFolderContacts);
	fgd.last_update = current_time_ms ();

	e_file_cache_freeze_changes (E_FILE_CACHE (priv->cache));
	exchange_mapi_connection_fetch_gal (priv->conn,
					mapi_book_get_prop_list, GET_ALL_KNOWN_IDS,
					fetch_gal_cb, &fgd);

	if (fgd.book_view) {
		e_data_book_view_notify_complete (fgd.book_view, GNOME_Evolution_Addressbook_Success);
		e_data_book_view_unref (fgd.book_view);
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

	fields = mapi_book_get_supported_fields ();
	e_data_book_respond_get_supported_fields (book,
						  opid,
						  GNOME_Evolution_Addressbook_Success,
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
						  GNOME_Evolution_Addressbook_Success,
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

	if (enable_debug) {
		printf ("mapi: authenticate user\n");
	}

	switch (priv->mode) {
	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		e_book_backend_notify_writable (backend, FALSE);
		e_book_backend_set_is_writable (E_BOOK_BACKEND(backend), FALSE);
		e_book_backend_notify_connection_status (backend, FALSE);
		e_data_book_respond_authenticate_user (book, opid, GNOME_Evolution_Addressbook_Success);
		return;

	case GNOME_Evolution_Addressbook_MODE_REMOTE:

		priv->conn = exchange_mapi_connection_new (priv->profile, passwd);
		if (!priv->conn) {
			priv->conn = exchange_mapi_connection_find (priv->profile);
			if (priv->conn && !exchange_mapi_connection_connected (priv->conn))
				exchange_mapi_connection_reconnect (priv->conn, passwd);
		}
		if (!priv->conn)
			return e_data_book_respond_authenticate_user (book, opid,GNOME_Evolution_Addressbook_OtherError);

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
		e_data_book_respond_authenticate_user (book, opid, GNOME_Evolution_Addressbook_Success);
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
				    GNOME_Evolution_Addressbook_PermissionDenied,
				    NULL);
}

static void
e_book_backend_mapi_gal_remove_contacts (EBookBackend *backend,
		 EDataBook    *book,
		 guint32       opid,
		 GList        *ids)
{
	e_data_book_respond_remove_contacts (book, opid,
					     GNOME_Evolution_Addressbook_PermissionDenied,
					     NULL);
}

static void
e_book_backend_mapi_gal_modify_contact (EBookBackend *backend,
		EDataBook    *book,
		guint32       opid,
		const gchar   *vcard)
{
	e_data_book_respond_modify (book, opid,
				    GNOME_Evolution_Addressbook_PermissionDenied,
				    NULL);
}

static GNOME_Evolution_Addressbook_CallStatus
e_book_backend_mapi_gal_load_source (EBookBackend *backend,
				 ESource      *source,
				 gboolean     only_if_exists)
{
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;
	const gchar *offline, *tmp;
	gchar **tokens;
	gchar *uri = NULL;
	if (enable_debug)
		printf("MAPI load source\n");
	offline = e_source_get_property (source, "offline_sync");
	if (offline  && g_str_equal (offline, "1"))
		priv->marked_for_offline = TRUE;

	/* Either we are in Online mode or this is marked for offline */

	priv->uri = g_strdup (e_source_get_uri (source));

	tokens = g_strsplit (priv->uri, ";", 2);
	if (tokens[0])
		uri = g_strdup (tokens [0]);
	priv->book_name  = g_strdup (tokens[1]);
	if (priv->book_name == NULL) {
		g_warning ("Bookname is null for %s\n", uri);
		return GNOME_Evolution_Addressbook_OtherError;
	}
	g_strfreev (tokens);

	if (priv->mode ==  GNOME_Evolution_Addressbook_MODE_LOCAL &&
	    !priv->marked_for_offline ) {
		return GNOME_Evolution_Addressbook_OfflineUnavailable;
	}

	if (priv->marked_for_offline) {
		priv->summary_file_name = get_filename_from_uri (priv->uri, "cache.summary");
		if (g_file_test (priv->summary_file_name, G_FILE_TEST_EXISTS)) {
			printf("Loading the summary\n");
			priv->summary = e_book_backend_summary_new (priv->summary_file_name,
								    SUMMARY_FLUSH_TIMEOUT);
			e_book_backend_summary_load (priv->summary);
			priv->is_summary_ready = TRUE;
		}

		/* Load the cache as well.*/
		if (e_book_backend_cache_exists (priv->uri)) {
			gchar *last_time;

			printf("Loading the cache\n");
			priv->cache = e_book_backend_cache_new (priv->uri);

			last_time = e_book_backend_cache_get_time (priv->cache);
			priv->is_cache_ready = last_time && !g_str_equal (last_time, "0");
			g_free (last_time);
		}
		//FIXME: We may have to do a time based reload. Or deltas should upload.
	} else {
		priv->summary = e_book_backend_summary_new (NULL,SUMMARY_FLUSH_TIMEOUT);
	}

	g_free (uri);
	e_book_backend_set_is_loaded (E_BOOK_BACKEND (backend), TRUE);
	e_book_backend_set_is_writable (backend, FALSE);
	if (priv->mode ==  GNOME_Evolution_Addressbook_MODE_LOCAL) {
		e_book_backend_set_is_writable (backend, FALSE);
		e_book_backend_notify_writable (backend, FALSE);
		e_book_backend_notify_connection_status (backend, FALSE);
		if (!priv->cache) {
			printf("Unfortunately the cache is not yet created\n");
			return GNOME_Evolution_Addressbook_OfflineUnavailable;
		}
	} else {
		e_book_backend_notify_connection_status (backend, TRUE);
	}

	priv->profile = g_strdup (e_source_get_property (source, "profile"));
	exchange_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &priv->fid);

	tmp = e_source_get_property (source, "folder-id");

	/* Once aunthentication in address book works this can be removed */
	if (priv->mode == GNOME_Evolution_Addressbook_MODE_LOCAL) {
		return GNOME_Evolution_Addressbook_Success;
	}

	// writable property will be set in authenticate_user callback
	e_book_backend_set_is_loaded (E_BOOK_BACKEND (backend), TRUE);
	e_book_backend_notify_connection_status (E_BOOK_BACKEND (backend), TRUE);

	if (enable_debug)
		printf("For profile %s and folder %s - %016" G_GINT64_MODIFIER "X\n", priv->profile, tmp, priv->fid);

	return GNOME_Evolution_Addressbook_Success;
}

static void
e_book_backend_mapi_gal_set_mode (EBookBackend *backend, GNOME_Evolution_Addressbook_BookMode mode)
{
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;

	if (enable_debug)
		printf("mapi: set_mode \n");

	priv->mode = mode;
	if (e_book_backend_is_loaded (backend)) {
		if (mode == GNOME_Evolution_Addressbook_MODE_LOCAL) {
			e_book_backend_notify_writable (backend, FALSE);
			e_book_backend_set_is_writable (backend, FALSE);
			e_book_backend_notify_connection_status (backend, FALSE);
			/* FIXME: Uninitialize mapi here. may be.*/
		}
		else if (mode == GNOME_Evolution_Addressbook_MODE_REMOTE) {
			e_book_backend_notify_writable (backend, FALSE);
			e_book_backend_set_is_writable (backend, FALSE);
			e_book_backend_notify_connection_status (backend, TRUE);
//			e_book_backend_notify_auth_required (backend); //FIXME: WTH is this required.
		}
	}
}

static void
e_book_backend_mapi_gal_dispose (GObject *object)
{
	/* FIXME : provide implmentation */
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) object)->priv;

	if (priv->profile) {
		g_free (priv->profile);
		priv->profile = NULL;
	}
	if (priv->conn) {
		g_object_unref (priv->conn);
		priv->conn = NULL;
	}
	if (priv->uri) {
		g_free (priv->uri);
		priv->uri = NULL;
	}

	if (priv->build_cache_thread) {
		priv->kill_cache_build = TRUE;
		g_thread_join (priv->build_cache_thread);
		priv->build_cache_thread = NULL;
	}
}

typedef struct {
	EBookBackendMAPIGAL *bg;
	GThread *thread;
	EFlag *running;
} BESearchClosure;

static BESearchClosure*
get_closure (EDataBookView *book_view)
{
	return g_object_get_data (G_OBJECT (book_view), "closure");
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

                if (!e_flag_is_set (closure->running))
                        break;

		uid = g_ptr_array_index (ids, i);
		contact = e_book_backend_cache_get_contact (ebmapi->priv->cache, uid);
		if (contact) {
			e_data_book_view_notify_update (book_view, contact);
			g_object_unref (contact);
		}
	}
	if (e_flag_is_set (closure->running))
		e_data_book_view_notify_complete (book_view,
						  GNOME_Evolution_Addressbook_Success);
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

static gboolean
build_multiple_restriction_emails_contains (struct mapi_SRestriction *res,
					    struct mapi_SRestriction_or *or_res,
					    const gchar *query)
{
	gchar *email=NULL, *tmp, *tmp1;
	//Number of restriction to apply
	guint res_count = 6;

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

	or_res[0].rt = RES_CONTENT;
	or_res[0].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[0].res.resContent.ulPropTag = PR_EMS_AB_MANAGER_T_UNICODE;
	or_res[0].res.resContent.lpProp.value.lpszA = email;

	or_res[1].rt = RES_CONTENT;
	or_res[1].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[1].res.resContent.ulPropTag = PR_DISPLAY_NAME_UNICODE;
	or_res[1].res.resContent.lpProp.value.lpszA = email;

	or_res[2].rt = RES_CONTENT;
	or_res[2].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[2].res.resContent.ulPropTag = PR_GIVEN_NAME_UNICODE;
	or_res[2].res.resContent.lpProp.value.lpszA = email;

	or_res[3].rt = RES_CONTENT;
	or_res[3].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[3].res.resContent.ulPropTag = PROP_TAG(PT_UNICODE, 0x8084);
	or_res[3].res.resContent.lpProp.value.lpszA = email;

	or_res[4].rt = RES_CONTENT;
	or_res[4].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[4].res.resContent.ulPropTag = PROP_TAG(PT_UNICODE, 0x8094);
	or_res[4].res.resContent.lpProp.value.lpszA = email;

	or_res[5].rt = RES_CONTENT;
	or_res[5].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[5].res.resContent.ulPropTag = PROP_TAG(PT_UNICODE, 0x80a4);
	or_res[5].res.resContent.lpProp.value.lpszA = email;

	res = g_new0 (struct mapi_SRestriction, 1);

	res->rt = RES_OR;
	res->res.resOr.cRes = res_count;
	res->res.resOr.res = or_res;

	return TRUE;
}

static void
book_view_thread (gpointer data)
{
	struct mapi_SRestriction res;
	struct mapi_SRestriction_or *or_res = NULL;
	EDataBookView *book_view = data;
	BESearchClosure *closure = get_closure (book_view);
	EBookBackendMAPIGAL *backend = closure->bg;
	EBookBackendMAPIGALPrivate *priv = backend->priv;
	const gchar *query = NULL;
	GPtrArray *ids = NULL;
	GList *contacts = NULL, *temp_list = NULL;
	//Number of multiple restriction to apply
	guint res_count = 6;

	if (enable_debug)
		printf("mapi: book view\n");

	g_object_ref (book_view);
	e_flag_set (closure->running);

	book_view_notify_status (book_view, _("Searching"));
	query = e_data_book_view_get_card_query (book_view);

	if (!find_book_view (backend))
		e_book_backend_add_book_view (E_BOOK_BACKEND (backend), book_view);

	switch (priv->mode) {
		case GNOME_Evolution_Addressbook_MODE_REMOTE:
			if (!priv->conn) {
				e_book_backend_notify_auth_required (E_BOOK_BACKEND (backend));
				e_data_book_view_notify_complete (book_view,
							GNOME_Evolution_Addressbook_AuthenticationRequired);
				g_object_unref (book_view);
				return;
			}

			if (priv->marked_for_offline && !priv->is_cache_ready) {
				/* To translators : Here Evolution MAPI downloads the entries from the GAL server */
				book_view_notify_status (book_view, _("Downloading GAL entries from server…"));
				return;
			}

			if (priv->marked_for_offline && priv->cache && priv->is_cache_ready) {
				if (priv->is_summary_ready &&
				    e_book_backend_summary_is_summary_query (priv->summary, query)) {
					if (enable_debug)
						printf ("reading the contacts from summary \n");
					ids = e_book_backend_summary_search (priv->summary, query);
					if (ids && ids->len > 0) {
						get_contacts_from_cache (backend, query, ids, book_view, closure);
						g_ptr_array_free (ids, TRUE);
					}
					g_object_unref (book_view);
					break;
				}

				printf("Summary seems to be not there or not a summary query, lets fetch from cache directly\n");

				/* We are already cached. Lets return from there. */
				contacts = e_book_backend_cache_get_contacts (priv->cache,
								      query);
				temp_list = contacts;
				for (; contacts != NULL; contacts = g_list_next(contacts)) {
					if (!e_flag_is_set (closure->running)) {
						for (;contacts != NULL; contacts = g_list_next (contacts))
							g_object_unref (contacts->data);
						break;
					}
					e_data_book_view_notify_update (book_view,
									E_CONTACT(contacts->data));
					g_object_unref (contacts->data);
				}
				if (e_flag_is_set (closure->running))
					e_data_book_view_notify_complete (book_view,
									  GNOME_Evolution_Addressbook_Success);
				if (temp_list)
					 g_list_free (temp_list);
				g_object_unref (book_view);
				break;
			}

			if (e_book_backend_summary_is_summary_query (priv->summary, query)) {
				or_res = g_new (struct mapi_SRestriction_or, res_count);

				if (!build_multiple_restriction_emails_contains (&res, or_res, query)) {
					e_data_book_view_notify_complete (book_view,
								  GNOME_Evolution_Addressbook_OtherError);
					return;
				}

			if (e_flag_is_set (closure->running))
				e_data_book_view_notify_complete (book_view,
								  GNOME_Evolution_Addressbook_Success);
			g_object_unref (book_view);
			break;
		}
	}

	if (book_view)
		e_data_book_view_notify_complete (book_view,
						  GNOME_Evolution_Addressbook_Success);
	return;
}

static void
closure_destroy (BESearchClosure *closure)
{
	e_flag_free (closure->running);
	g_free (closure);
}

static BESearchClosure*
init_closure (EDataBookView *book_view, EBookBackendMAPIGAL *bg)
{
	BESearchClosure *closure = g_new (BESearchClosure, 1);

	closure->bg = bg;
	closure->thread = NULL;
	closure->running = e_flag_new ();

	g_object_set_data_full (G_OBJECT (book_view), "closure",
				closure, (GDestroyNotify)closure_destroy);

	return closure;
}

static void
e_book_backend_mapi_gal_get_contact (EBookBackend *backend,
				     EDataBook    *book,
				     guint32       opid,
				     const gchar   *id)
{
	if (enable_debug)
		printf ("mapi: get contact %s\n", id);

	e_data_book_respond_get_contact (book, opid, GNOME_Evolution_Addressbook_RepositoryOffline, NULL);
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

	e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_RepositoryOffline,
						      NULL);

	return;
}

static void
e_book_backend_mapi_gal_start_book_view (EBookBackend  *backend,
					   EDataBookView *book_view)
{
	BESearchClosure *closure = init_closure (book_view, E_BOOK_BACKEND_MAPIGAL (backend));

	if (enable_debug)
		printf ("mapi: start_book_view...\n");
	closure->thread = g_thread_create ((GThreadFunc) book_view_thread, book_view, FALSE, NULL);
	e_flag_wait (closure->running);

	/* at this point we know the book view thread is actually running */
}

static void
e_book_backend_mapi_gal_stop_book_view (EBookBackend  *backend,
					  EDataBookView *book_view)
{
	if (enable_debug)
		printf("mapi: stop book view\n");
	/* FIXME : provide implmentation */
}

static void
e_book_backend_mapi_gal_get_changes (EBookBackend *backend, EDataBook *book, guint32 opid, const gchar *change_id)
{
	if (enable_debug)
		printf ("mapi: get changes\n");

	e_data_book_respond_get_changes (book, opid, GNOME_Evolution_Addressbook_RepositoryOffline, NULL);
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
							GNOME_Evolution_Addressbook_Success,
							auth_methods);
	g_free (auth_method);
	g_list_free (auth_methods);
}

static GNOME_Evolution_Addressbook_CallStatus
e_book_backend_mapi_gal_cancel_operation (EBookBackend *backend, EDataBook *book)
{
	if (enable_debug)
		printf ("mapi cancel_operation...\n");
	return GNOME_Evolution_Addressbook_CouldNotCancel;
}

static void
e_book_backend_mapi_gal_remove (EBookBackend *backend, EDataBook *book, guint32 opid)
{
	e_data_book_respond_remove (book, opid, GNOME_Evolution_Addressbook_PermissionDenied);
}

static void e_book_backend_mapi_gal_class_init (EBookBackendMAPIGALClass *klass)
{
	GObjectClass  *object_class = G_OBJECT_CLASS (klass);
	EBookBackendClass *parent_class;

	e_book_backend_mapi_gal_parent_class = g_type_class_peek_parent (klass);

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

//	if (enable_debug)
		printf ("\ne_book_backend_mapi_gal_new...\n");

	backend = g_object_new (E_TYPE_BOOK_BACKEND_MAPIGAL, NULL);

	return E_BOOK_BACKEND (backend);
}

static void	e_book_backend_mapi_gal_init (EBookBackendMAPIGAL *backend)
{
	EBookBackendMAPIGALPrivate *priv;

	priv= g_new0 (EBookBackendMAPIGALPrivate, 1);
	/* Priv Struct init */
	backend->priv = priv;

	priv->build_cache_thread = NULL;

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
