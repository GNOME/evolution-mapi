#ifdef HAVE_CONFIG_H
#include <config.h>  
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>

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

static EBookBackendClass *e_book_backend_mapi_gal_parent_class;
static gboolean enable_debug = TRUE;

#define ELEMENT_TYPE_SIMPLE 0x01
#define ELEMENT_TYPE_COMPLEX 0x02

static const struct field_element_mapping {
		EContactField field_id;
		int element_type;
	        int mapi_id;
	        int contact_type;
//		char *element_name;
//		void (*populate_contact_func)(EContact *contact,    gpointer data);
//		void (*set_value_in_gw_item) (EGwItem *item, gpointer data);
//		void (*set_changes) (EGwItem *new_item, EGwItem *old_item);

	} mappings [] = { 

	{ E_CONTACT_UID, PT_STRING8, 0, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_REV, PT_SYSTIME, PR_LAST_MODIFICATION_TIME, ELEMENT_TYPE_SIMPLE},
		
	{ E_CONTACT_FILE_AS, PT_STRING8, PR_EMS_AB_MANAGER_T, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FULL_NAME, PT_STRING8, PR_DISPLAY_NAME, ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_GIVEN_NAME, PT_STRING8, PR_GIVEN_NAME, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FAMILY_NAME, PT_STRING8, PR_SURNAME , ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_NICKNAME, PT_STRING8, PR_NICKNAME, ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_EMAIL_1, PT_STRING8, PROP_TAG(PT_UNICODE, 0x8084), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_EMAIL_2, PT_STRING8, PROP_TAG(PT_UNICODE, 0x8094), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_EMAIL_3, PT_STRING8, PROP_TAG(PT_UNICODE, 0x80a4), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_IM_AIM,  PT_STRING8, PROP_TAG(PT_UNICODE, 0x8062), ELEMENT_TYPE_COMPLEX},	
		
	{ E_CONTACT_PHONE_BUSINESS, PT_STRING8, PR_OFFICE_TELEPHONE_NUMBER, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME, PT_STRING8, PR_HOME_TELEPHONE_NUMBER, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_MOBILE, PT_STRING8, PR_MOBILE_TELEPHONE_NUMBER, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME_FAX, PT_STRING8, PR_HOME_FAX_NUMBER ,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_BUSINESS_FAX, PT_STRING8, PR_BUSINESS_FAX_NUMBER,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_PAGER, PT_STRING8, PR_PAGER_TELEPHONE_NUMBER,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_ASSISTANT, PT_STRING8, PR_ASSISTANT_TELEPHONE_NUMBER ,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_COMPANY, PT_STRING8, PR_COMPANY_MAIN_PHONE_NUMBER ,ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_HOMEPAGE_URL, PT_STRING8, 0x802b001e, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FREEBUSY_URL, PT_STRING8, 0x80d8001e, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_ROLE, PT_STRING8, PR_PROFESSION, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_TITLE, PT_STRING8, PR_TITLE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG, PT_STRING8, PR_COMPANY_NAME, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG_UNIT, PT_STRING8, PR_DEPARTMENT_NAME,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_MANAGER, PT_STRING8, PR_MANAGER_NAME, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ASSISTANT, PT_STRING8, PR_ASSISTANT, ELEMENT_TYPE_SIMPLE},
		
	{ E_CONTACT_OFFICE, PT_STRING8, PR_OFFICE_LOCATION, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_SPOUSE, PT_STRING8, PR_SPOUSE_NAME, ELEMENT_TYPE_SIMPLE},
		
	{ E_CONTACT_BIRTH_DATE,  PT_SYSTIME, PR_BIRTHDAY, ELEMENT_TYPE_COMPLEX},
	{ E_CONTACT_ANNIVERSARY, PT_SYSTIME, PR_WEDDING_ANNIVERSARY, ELEMENT_TYPE_COMPLEX},
		  
	{ E_CONTACT_NOTE, PT_STRING8, PR_BODY, ELEMENT_TYPE_SIMPLE},
		

	{ E_CONTACT_ADDRESS_HOME, PT_STRING8, 0x801a001e, ELEMENT_TYPE_COMPLEX},
	{ E_CONTACT_ADDRESS_WORK, PT_STRING8, 0x801c001e, ELEMENT_TYPE_COMPLEX},
//		{ E_CONTACT_BOOK_URI, ELEMENT_TYPE_SIMPLE, "book_uri"}
//		{ E_CONTACT_EMAIL, PT_STRING8, 0x8084001e},
//		{ E_CONTACT_CATEGORIES, },		
	};

static int maplen = G_N_ELEMENTS(mappings);

struct _EBookBackendMAPIGALPrivate
{
	char *profile;
	mapi_id_t fid;
	int mode;
	gboolean marked_for_offline;
	gboolean is_cache_ready;
	gboolean is_summary_ready;
	gboolean is_writable;
	char *uri;
	char *book_name;
	
	GMutex *lock;
	char *summary_file_name;
	EBookBackendSummary *summary;
	EBookBackendCache *cache;

};

#define SUMMARY_FLUSH_TIMEOUT 5000

static char *
e_book_backend_mapi_gal_get_static_capabilities (EBookBackend *backend)
{
	if(enable_debug)
		printf("mapi get_static_capabilities\n");
	//FIXME: Implement this.
	
	return g_strdup ("net,bulk-removes,do-initial-query,contact-lists");
}

static void
e_book_backend_mapi_gal_authenticate_user (EBookBackend *backend,
					    EDataBook    *book,
					    guint32       opid,
					    const char *user,
					    const char *passwd,
					    const char *auth_method)
{
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;
	
	if (enable_debug) {
		printf ("mapi: authenticate user\n");
	}	

	
	switch (priv->mode) {
	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		e_book_backend_notify_writable (backend, FALSE);
		e_book_backend_notify_connection_status (backend, FALSE); 
		e_data_book_respond_authenticate_user (book, opid, GNOME_Evolution_Addressbook_Success); 
		return;
		
	case GNOME_Evolution_Addressbook_MODE_REMOTE:
		
		if (!exchange_mapi_connection_new (priv->profile, NULL))
			return e_data_book_respond_authenticate_user (book, opid,GNOME_Evolution_Addressbook_OtherError);

		if (priv->cache && priv->is_cache_ready) {
			printf("FIXME: Should check for an update in the cache\n");
//			g_thread_create ((GThreadFunc) update_cache, 
	//					  backend, FALSE, backend);
		} else if (priv->marked_for_offline && !priv->is_cache_ready) {
			/* Means we dont have a cache. Lets build that first */
			printf("Preparing to build cache\n");
	//		g_thread_create ((GThreadFunc) build_cache, backend, FALSE, NULL);
		} 
		e_book_backend_set_is_writable (backend, TRUE);
		e_data_book_respond_authenticate_user (book, opid, GNOME_Evolution_Addressbook_Success);
		return;
		
	default :
		break;
	}	
}

static char *
get_filename_from_uri (const char *uri, const char *file)
{
	char *mangled_uri, *filename;
	int i;

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

static GNOME_Evolution_Addressbook_CallStatus
e_book_backend_mapi_gal_load_source (EBookBackend *backend,
				 ESource      *source,
				 gboolean     only_if_exists)
{
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;
	const gchar *offline, *tmp;
	char **tokens;
	char *uri = NULL;
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
			printf("Loading the cache\n");
			priv->cache = e_book_backend_cache_new (priv->uri);
			priv->is_cache_ready = TRUE;
		}
		//FIXME: We may have to do a time based reload. Or deltas should upload.
	} else {
		priv->summary = e_book_backend_summary_new (NULL,SUMMARY_FLUSH_TIMEOUT);
	}

	g_free (uri);
	e_book_backend_set_is_loaded (E_BOOK_BACKEND (backend), TRUE);
	e_book_backend_set_is_writable (backend, TRUE);	
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
e_book_backend_mapi_gal_set_mode (EBookBackend *backend, int mode)
{
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) backend)->priv;

	if(enable_debug)
		printf("mapi: set_mode \n");
	
	priv->mode = mode;
	if (e_book_backend_is_loaded (backend)) {
		if (mode == GNOME_Evolution_Addressbook_MODE_LOCAL) {
			e_book_backend_notify_writable (backend, FALSE);
			e_book_backend_notify_connection_status (backend, FALSE);
			/* FIXME: Uninitialize mapi here. may be.*/
		}
		else if (mode == GNOME_Evolution_Addressbook_MODE_REMOTE) {
			e_book_backend_notify_writable (backend, TRUE);
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
	if (priv->uri) {
		g_free (priv->uri);
		priv->uri = NULL;
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

static EContact *
emapidump_gal (struct SRow *gal_entry)
{
	EContact *contact = e_contact_new ();
	int i;
	
//	exchange_mapi_debug_property_dump (properties);
	for (i=1; i<maplen; i++) {
		gpointer value;

		/* can cast it, no writing to the value; and it'll be freed not before the end of this function */
		value = (gpointer) find_SPropValue_data (gal_entry, mappings[i].mapi_id);
		if (mappings[i].element_type == PT_STRING8 && mappings[i].contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value)
				e_contact_set (contact, mappings[i].field_id, value);
		} else if (mappings[i].contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value && mappings[i].element_type == PT_SYSTIME) {
				struct FILETIME *t = value;
				time_t time;
				NTTIME nt;
				char buff[129];

				nt = t->dwHighDateTime;
				nt = nt << 32;
				nt |= t->dwLowDateTime;
				time = nt_time_to_unix (nt);
				e_contact_set (contact, mappings[i].field_id, ctime_r (&time, buff));
			} else
				printf("Nothing is printed\n");
		}
	}
}

static gboolean
create_gal_contact_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	EDataBookView *book_view = data;
	BESearchClosure *closure = get_closure (book_view);
	EBookBackendMAPIGAL *be = closure->bg;
	EContact *contact;
	EBookBackendMAPIGALPrivate *priv = ((EBookBackendMAPIGAL *) be)->priv;
	char *suid;
	GSList *l;
	int counter;
	
	if (!e_flag_is_set (closure->running)) {
		printf("Might be that the operation is cancelled. Lets ask our parent also to do.\n");
		return FALSE;
	}
	
//	contact = emapidump_contact (item_data->properties);
	for (l=item_data->gallist; l; l=l->next) {
		struct SRow *SRow = (struct SRow *) (l->data);
		counter++;
		contact = emapidump_gal (SRow);
		suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);
	
		if (contact) {
			/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
			e_contact_set (contact, E_CONTACT_UID, suid);		
			e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);
			e_data_book_view_notify_update (book_view, contact);
			g_object_unref(contact);
		}

		g_free (suid);
	}
	g_print ("\n The counter for the above data is %d\n", counter);
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
	const char *query = NULL;
	GPtrArray *ids = NULL;
	GList *contacts = NULL, *temp_list = NULL;
	//Number of multiple restriction to apply
	unsigned int res_count = 6;
	
	if (enable_debug)
		printf("mapi: book view\n");
	
	bonobo_object_ref (book_view);
	e_flag_set (closure->running);
						
	e_data_book_view_notify_status_message (book_view, "Searching...");
	query = e_data_book_view_get_card_query (book_view);
						
	switch (priv->mode) {
		case GNOME_Evolution_Addressbook_MODE_REMOTE:
			if (!exchange_mapi_connection_fetch_items (priv->fid, NULL, NULL,
							NULL, 0, 
							NULL, NULL, 
							create_gal_contact_cb, book_view, 
							MAPI_OPTIONS_FETCH_GAL)) {
				if (e_flag_is_set (closure->running))
					e_data_book_view_notify_complete (book_view, 
									  GNOME_Evolution_Addressbook_OtherError);      
				bonobo_object_unref (book_view);
				return;
			}
		
			if (e_flag_is_set (closure->running))
				e_data_book_view_notify_complete (book_view,
								  GNOME_Evolution_Addressbook_Success);
			bonobo_object_unref (book_view);
			break;

	}
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
	if(enable_debug)
		printf("mapi: stop book view\n");	
	/* FIXME : provide implmentation */
}

static void e_book_backend_mapi_gal_class_init (EBookBackendMAPIGALClass *klass)
{
	GObjectClass  *object_class = G_OBJECT_CLASS (klass);
	EBookBackendClass *parent_class;
	
	e_book_backend_mapi_gal_parent_class = g_type_class_peek_parent (klass);
	
	parent_class = E_BOOK_BACKEND_CLASS (klass);

	/* Set the virtual methods. */
	parent_class->load_source		 = e_book_backend_mapi_gal_load_source;
	parent_class->get_static_capabilities    = e_book_backend_mapi_gal_get_static_capabilities;

	parent_class->start_book_view            = e_book_backend_mapi_gal_start_book_view;
	parent_class->stop_book_view             = e_book_backend_mapi_gal_stop_book_view;
	parent_class->authenticate_user          = e_book_backend_mapi_gal_authenticate_user;
	parent_class->set_mode                   = e_book_backend_mapi_gal_set_mode;
	object_class->dispose                    = e_book_backend_mapi_gal_dispose;
}

/**
 * e_book_backend_mapigal_new:
 */
EBookBackend *
e_book_backend_mapigal_new (void)
{
	EBookBackendMAPIGAL *backend;

//	if (enable_debug)
		printf ("\ne_book_backend_mapigal_new...\n");

	backend = g_object_new (E_TYPE_BOOK_BACKEND_MAPIGAL, NULL);

	return E_BOOK_BACKEND (backend);
}

static void	e_book_backend_mapi_gal_init (EBookBackendMAPIGAL *backend)
{
	EBookBackendMAPIGALPrivate *priv;
  
	priv= g_new0 (EBookBackendMAPIGALPrivate, 1);
	/* Priv Struct init */
	backend->priv = priv;

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

GType	e_book_backend_mapigal_get_type (void)
{
	static GType type = 0;
	
	if (! type) {
		GTypeInfo info = {
			sizeof (EBookBackendMAPIGALClass),
			NULL, /* base_class_init */
			NULL, /* base_class_finalize */
			(GClassInitFunc)  e_book_backend_mapi_gal_class_init,
			NULL, /* class_finalize */
			NULL, /* class_data */
			sizeof (EBookBackendMAPIGAL),
			0,    /* n_preallocs */
			(GInstanceInitFunc) e_book_backend_mapi_gal_init
		};
		
		type = g_type_register_static (E_TYPE_BOOK_BACKEND, "EBookBackendMAPIGAL", &info, 0);
	}
	
	return type;
}
