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
 *    Suman Manjunath <msuman@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#include <glib/gi18n.h>
#include <gio/gio.h>

#include "e-cal-backend-mapi.h"

#include <libedata-cal/e-cal-backend-cache.h>
#include <libedataserver/e-xml-hash-utils.h>

#include <exchange-mapi-connection.h>
#include <exchange-mapi-cal-utils.h>
#include <exchange-mapi-utils.h>

#define d(x) x

#ifdef G_OS_WIN32
/* Undef the similar macro from pthread.h, it doesn't check if
 * gmtime() returns NULL.
 */
#undef gmtime_r

/* The gmtime() in Microsoft's C library is MT-safe */
#define gmtime_r(tp,tmp) (gmtime(tp)?(*(tmp)=*gmtime(tp),(tmp)):0)
#endif

typedef struct {
	GCond *cond;
	GMutex *mutex;
	gboolean exit;
} SyncDelta;

/* Private part of the CalBackendMAPI structure */
struct _ECalBackendMAPIPrivate {
	mapi_id_t 		fid;
	uint32_t 		olFolder;
	gchar 			*profile; 

	/* These fields are entirely for access rights */
	gchar 			*owner_name;
	gchar 			*owner_email;	
	gchar			*user_name;
	gchar			*user_email;

	/* A mutex to control access to the private structure */
	GMutex			*mutex;
	ECalBackendCache	*cache;
	gboolean		read_only;
	gchar			*uri;
	gchar			*username;
	gchar			*password;
	CalMode			mode;
	gboolean		mode_changed;
	icaltimezone		*default_zone;

	/* timeout handler for syncing sendoptions */
	guint			sendoptions_sync_timeout;
	
	gchar			*local_attachments_store;

	/* used exclusively for delta fetching */
	guint 			timeout_id;
	GThread 		*dthread;
	SyncDelta 		*dlock;
	GSList 			*cache_keys;
};

#define PARENT_TYPE E_TYPE_CAL_BACKEND_SYNC
static ECalBackendClass *parent_class = NULL;

#define CACHE_REFRESH_INTERVAL 600000

static gboolean authenticated = FALSE;
static GStaticMutex auth_mutex = G_STATIC_MUTEX_INIT;

static ECalBackendSyncStatus
e_cal_backend_mapi_authenticate (ECalBackend *backend)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	if (authenticated || exchange_mapi_connection_exists () || exchange_mapi_connection_new (priv->profile, priv->password)) {
		authenticated = TRUE;
		return GNOME_Evolution_Calendar_Success;
	} else { 
		authenticated = FALSE;
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Authentication failed"));
		return GNOME_Evolution_Calendar_AuthenticationFailed;
	}
}

/***** OBJECT CLASS FUNCTIONS *****/
static void 
e_cal_backend_mapi_dispose (GObject *object)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (object);
	priv = cbmapi->priv;

	if (G_OBJECT_CLASS (parent_class)->dispose)
		(* G_OBJECT_CLASS (parent_class)->dispose) (object);
}

static void 
e_cal_backend_mapi_finalize (GObject *object)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (object != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (object));

	cbmapi = E_CAL_BACKEND_MAPI (object);
	priv = cbmapi->priv;

	/* Clean up */
	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}

	if (priv->dlock) {
		g_mutex_lock (priv->dlock->mutex);
		priv->dlock->exit = TRUE;
		g_mutex_unlock (priv->dlock->mutex);
		
		g_cond_signal (priv->dlock->cond);

		if (priv->dthread)
			g_thread_join (priv->dthread);
		
		g_mutex_free (priv->dlock->mutex);
		g_cond_free (priv->dlock->cond);
		g_free (priv->dlock);
		priv->dthread = NULL;
	}

	if (priv->mutex) {
		g_mutex_free (priv->mutex);
		priv->mutex = NULL;
	}

	if (priv->cache) {
		g_object_unref (priv->cache);
		priv->cache = NULL;
	}

	if (priv->username) {
		g_free (priv->username);
		priv->username = NULL;
	}

	if (priv->password) {
		g_free (priv->password);
		priv->password = NULL;
	}

	if (priv->profile) {
		g_free (priv->profile);
		priv->profile = NULL;
	}

	if (priv->user_name) {
		g_free (priv->user_name);
		priv->user_name = NULL;
	}

	if (priv->user_email) {
		g_free (priv->user_email);
		priv->user_email = NULL;
	}

	if (priv->owner_name) {
		g_free (priv->owner_name);
		priv->owner_name = NULL;
	}

	if (priv->owner_email) {
		g_free (priv->owner_email);
		priv->owner_email = NULL;
	}

	if (priv->local_attachments_store) {
		g_free (priv->local_attachments_store);
		priv->local_attachments_store = NULL;
	}

	if (priv->sendoptions_sync_timeout) {
		g_source_remove (priv->sendoptions_sync_timeout);
		priv->sendoptions_sync_timeout = 0;
	}

	if (priv->default_zone) {
		icaltimezone_free (priv->default_zone, 1);
		priv->default_zone = NULL;
	}

	g_free (priv);
	cbmapi->priv = NULL;

	if (G_OBJECT_CLASS (parent_class)->finalize)
		(* G_OBJECT_CLASS (parent_class)->finalize) (object);
}


/***** SYNC CLASS FUNCTIONS *****/
static ECalBackendSyncStatus 
e_cal_backend_mapi_is_read_only (ECalBackendSync *backend, EDataCal *cal, gboolean *read_only)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	*read_only = priv->read_only;

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_cal_address (ECalBackendSync *backend, EDataCal *cal, char **address)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	*address = g_strdup (priv->user_email);

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_alarm_email_address (ECalBackendSync *backend, EDataCal *cal, char **address)
{
	/* We don't support email alarms. This should not have been called. */

	*address = NULL;

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_ldap_attribute (ECalBackendSync *backend, EDataCal *cal, char **attribute)
{
	/* This is just a hack for SunONE */
	*attribute = NULL;

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_static_capabilities (ECalBackendSync *backend, EDataCal *cal, char **capabilities)
{
	/* FIXME: what else ? */

	*capabilities = g_strdup (
				CAL_STATIC_CAPABILITY_NO_ALARM_REPEAT ","
				CAL_STATIC_CAPABILITY_NO_AUDIO_ALARMS ","
//				CAL_STATIC_CAPABILITY_NO_DISPLAY_ALARMS ","
				CAL_STATIC_CAPABILITY_NO_EMAIL_ALARMS ","
				CAL_STATIC_CAPABILITY_NO_PROCEDURE_ALARMS ","
				CAL_STATIC_CAPABILITY_ONE_ALARM_ONLY ","
				CAL_STATIC_CAPABILITY_REMOVE_ALARMS ","

//				CAL_STATIC_CAPABILITY_NO_SHARED_MEMOS ","
//				CAL_STATIC_CAPABILITY_NO_TASK_ASSIGNMENT ","
				CAL_STATIC_CAPABILITY_NO_THISANDFUTURE ","
				CAL_STATIC_CAPABILITY_NO_THISANDPRIOR ","
//				CAL_STATIC_CAPABILITY_NO_TRANSPARENCY ","
//				CAL_STATIC_CAPABILITY_ORGANIZER_MUST_ATTEND ","
//				CAL_STATIC_CAPABILITY_ORGANIZER_NOT_EMAIL_ADDRESS ","
				CAL_STATIC_CAPABILITY_CREATE_MESSAGES ","
//				CAL_STATIC_CAPABILITY_SAVE_SCHEDULES ","
				CAL_STATIC_CAPABILITY_NO_CONV_TO_ASSIGN_TASK ","
				CAL_STATIC_CAPABILITY_NO_CONV_TO_RECUR ","
//				CAL_STATIC_CAPABILITY_NO_GEN_OPTIONS ","
//				CAL_STATIC_CAPABILITY_REQ_SEND_OPTIONS ","
//				CAL_STATIC_CAPABILITY_RECURRENCES_NO_MASTER ","
//				CAL_STATIC_CAPABILITY_ORGANIZER_MUST_ACCEPT ","
//				CAL_STATIC_CAPABILITY_DELEGATE_SUPPORTED ","
//				CAL_STATIC_CAPABILITY_NO_ORGANIZER ","
//				CAL_STATIC_CAPABILITY_DELEGATE_TO_MANY ","
				CAL_STATIC_CAPABILITY_HAS_UNACCEPTED_MEETING
				  );

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 	
e_cal_backend_mapi_remove (ECalBackendSync *backend, EDataCal *cal)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	gboolean status = FALSE;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	if (priv->mode == CAL_MODE_LOCAL)
		return GNOME_Evolution_Calendar_RepositoryOffline;

	/* FIXME: check for return status and respond */
	if (!authenticated) {
		g_static_mutex_lock (&auth_mutex); 
		e_cal_backend_mapi_authenticate (E_CAL_BACKEND (cbmapi));
		g_static_mutex_unlock (&auth_mutex);
	}

	if (!authenticated)
		return GNOME_Evolution_Calendar_AuthenticationFailed;

	status = exchange_mapi_remove_folder (priv->olFolder, priv->fid);
	if (!status)
		return GNOME_Evolution_Calendar_OtherError;

	g_mutex_lock (priv->mutex);

	/* remove the cache */
	if (priv->cache)
		e_file_cache_remove (E_FILE_CACHE (priv->cache));

	g_mutex_unlock (priv->mutex);

	/* anything else ? */

	return GNOME_Evolution_Calendar_Success;
}

static const char *
get_element_type (icalcomponent_kind kind)
{

	const char *type = "";

	if (kind == ICAL_VEVENT_COMPONENT)
		type = "Appointment";
	else if (kind == ICAL_VTODO_COMPONENT)
		type = "Task";
	else if (kind == ICAL_VJOURNAL_COMPONENT)
		type = "Note";

	return type;

}

static void 
notify_progress (ECalBackendMAPI *cbmapi, guint64 index, guint64 total)
{
	guint percent = ((float)index/total) * 100 ;
	if (percent > 100)
		percent = 99; 

	gchar *progress_string = g_strdup_printf (_("Loading %s items"), get_element_type (e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi)))); 

	e_cal_backend_notify_view_progress (E_CAL_BACKEND (cbmapi), progress_string, percent);

	g_free (progress_string); 
}

static gboolean
mapi_cal_get_changes_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct mapi_SPropValue_array *array = item_data->properties; 
	const mapi_id_t mid = item_data->mid; 
	GSList *streams = item_data->streams; 
	GSList *recipients = item_data->recipients; 
	GSList *attachments = item_data->attachments; 
	ECalBackendMAPI *cbmapi	= data;
	ECalBackendMAPIPrivate *priv = cbmapi->priv;
	icalcomponent_kind kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
	gchar *tmp = NULL;
	ECalComponent *cache_comp = NULL;
	const bool *recurring;

//	exchange_mapi_debug_property_dump (array);

	recurring = NULL;
	/* FIXME: Evolution does not support recurring tasks */
	recurring = (const bool *)find_mapi_SPropValue_data(array, PROP_TAG(PT_BOOLEAN, 0x8126));
	if (recurring && *recurring) {
		g_warning ("Encountered a recurring task.");
		exchange_mapi_util_free_stream_list (&streams);
		exchange_mapi_util_free_recipient_list (&recipients);
		exchange_mapi_util_free_attachment_list (&attachments);
		return TRUE;
	}

	tmp = exchange_mapi_util_mapi_id_to_string (mid);
	cache_comp = e_cal_backend_cache_get_component (priv->cache, tmp, NULL);

	if (cache_comp == NULL) {
		ECalComponent *comp = exchange_mapi_cal_util_mapi_props_to_comp (kind, tmp, array, 
									streams, recipients, attachments, 
									priv->local_attachments_store, priv->default_zone);

		if (E_IS_CAL_COMPONENT (comp)) {
			char *comp_str;

			e_cal_component_commit_sequence (comp);
			comp_str = e_cal_component_get_as_string (comp);	

			e_cal_backend_notify_object_created (E_CAL_BACKEND (cbmapi), (const char *) comp_str);
			e_cal_backend_cache_put_component (priv->cache, comp);

			g_free (comp_str);
		}
		g_object_unref (comp);
	} else {
		struct timeval t;

		if (get_mapi_SPropValue_array_date_timeval (&t, array, PR_LAST_MODIFICATION_TIME) == MAPI_E_SUCCESS) {
			struct icaltimetype itt, *cache_comp_lm = NULL;

			itt = icaltime_from_timet_with_zone (t.tv_sec, 0, 0);
			icaltime_set_timezone (&itt, icaltimezone_get_utc_timezone ());

			e_cal_component_get_last_modified (cache_comp, &cache_comp_lm);
			if (!cache_comp_lm || (icaltime_compare (itt, *cache_comp_lm) != 0)) {
				ECalComponent *comp;
				char *cache_comp_str = NULL, *modif_comp_str = NULL;

				e_cal_component_commit_sequence (cache_comp);
				cache_comp_str = e_cal_component_get_as_string (cache_comp);

				comp = exchange_mapi_cal_util_mapi_props_to_comp (kind, tmp, array, 
									streams, recipients, attachments, 
									priv->local_attachments_store, priv->default_zone);

				e_cal_component_commit_sequence (comp);
				modif_comp_str = e_cal_component_get_as_string (comp);

				e_cal_backend_notify_object_modified (E_CAL_BACKEND (cbmapi), cache_comp_str, modif_comp_str);
				e_cal_backend_cache_put_component (priv->cache, comp);

				g_object_unref (comp);
				g_free (cache_comp_str); 
				g_free (modif_comp_str);
			}
			g_object_unref (cache_comp);
			g_free (cache_comp_lm);
		}
	}

	g_free (tmp);
	exchange_mapi_util_free_stream_list (&streams);
	exchange_mapi_util_free_recipient_list (&recipients);
	exchange_mapi_util_free_attachment_list (&attachments);

	notify_progress (cbmapi, item_data->index, item_data->total);

	return TRUE;
}

static gboolean
handle_deleted_items_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	const mapi_id_t mid = item_data->mid; 
	ECalBackendMAPI *cbmapi	= data;
	ECalBackendMAPIPrivate *priv = cbmapi->priv;
	gchar *tmp = NULL;
	GSList *cache_comp_uid = NULL;

	tmp = exchange_mapi_util_mapi_id_to_string (mid);
	cache_comp_uid = g_slist_find_custom (priv->cache_keys, tmp, (GCompareFunc) (g_ascii_strcasecmp));
	if (cache_comp_uid != NULL)
		priv->cache_keys = g_slist_remove_link (priv->cache_keys, cache_comp_uid);

	g_free (tmp);
	return TRUE;
}

/* Simple workflow for fetching deltas: 
 * Poke cache for server_utc_time -> if exists, fetch all items modified after that time, 
 * note current time before fetching and update cache with the same after fetching. 
 * If server_utc_time does not exist OR is invalid, fetch all items 
 * (we anyway process the results only if last_modified has changed).
 */

static gboolean
get_deltas (gpointer handle)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	static GStaticMutex updating = G_STATIC_MUTEX_INIT;
	icaltimetype itt_current, itt_cache = icaltime_null_time(); 
	time_t current_time;
	struct tm tm;
	gchar *time_string = NULL;
	gchar t_str [26]; 
	const char *serv_time;
	struct mapi_SRestriction res;
	gboolean use_restriction = FALSE;
	GSList *ls = NULL;

	if (!handle)
		return FALSE;

	cbmapi = (ECalBackendMAPI *) handle;
	priv= cbmapi->priv;
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));

	if (priv->mode == CAL_MODE_LOCAL)
		return FALSE;

	g_static_mutex_lock (&updating);

	serv_time = e_cal_backend_cache_get_server_utc_time (priv->cache);
	if (serv_time)
		itt_cache = icaltime_from_string (serv_time); 
	if (!icaltime_is_null_time (itt_cache)) {
		struct SPropValue sprop;
		struct timeval t;

		use_restriction = TRUE;
		res.rt = RES_PROPERTY;
		res.res.resProperty.relop = RELOP_GE;
		res.res.resProperty.ulPropTag = PR_LAST_MODIFICATION_TIME;

		t.tv_sec = icaltime_as_timet_with_zone (itt_cache, icaltimezone_get_utc_timezone ());
		t.tv_usec = 0;
		set_SPropValue_proptag_date_timeval (&sprop, PR_LAST_MODIFICATION_TIME, &t);
		cast_mapi_SPropValue (&(res.res.resProperty.lpProp), &sprop);
	} else
		g_warning ("Cache time-stamp not found."); 

	itt_current = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
	current_time = icaltime_as_timet_with_zone (itt_current, icaltimezone_get_utc_timezone ());
	gmtime_r (&current_time, &tm);
	strftime (t_str, 26, "%Y-%m-%dT%H:%M:%SZ", &tm);

	e_cal_backend_notify_view_progress_start (E_CAL_BACKEND (cbmapi));

//	e_file_cache_freeze_changes (E_FILE_CACHE (priv->cache));
	/* FIXME: GetProps does not seem to work for tasks :-( */
	if (kind == ICAL_VTODO_COMPONENT) {
		if (!exchange_mapi_connection_fetch_items (priv->fid, use_restriction ? &res : NULL, NULL,
						NULL, 0, NULL, NULL, 
						mapi_cal_get_changes_cb, cbmapi, 
						MAPI_OPTIONS_FETCH_ALL)) {
			/* FIXME: better string please... */
			e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Error fetching changes from the server. Removing the cache might help."));
//			e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
			g_static_mutex_unlock (&updating);
			return FALSE;
		}
	} else if (!exchange_mapi_connection_fetch_items (priv->fid, use_restriction ? &res : NULL, NULL,
						cal_GetPropsList, G_N_ELEMENTS (cal_GetPropsList), 
						exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER(kind), 
						mapi_cal_get_changes_cb, cbmapi, 
						MAPI_OPTIONS_FETCH_ALL)) {
		/* FIXME: better string please... */
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Error fetching changes from the server. Removing the cache might help."));
//		e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
		g_static_mutex_unlock (&updating);
		return FALSE;
	}
//	e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));

	e_cal_backend_notify_view_done (E_CAL_BACKEND (cbmapi), GNOME_Evolution_Calendar_Success);

	time_string = g_strdup (t_str);
	e_cal_backend_cache_put_server_utc_time (priv->cache, time_string);
	g_free (time_string);

	/* handle deleted items here by going over the entire cache and
	 * checking for deleted items.*/

	/* e_cal_backend_cache_get_keys returns a list of all the keys. 
	 * The items in the list are pointers to internal data, 
	 * so should not be freed, only the list should. */
	priv->cache_keys = e_cal_backend_cache_get_keys (priv->cache);
	if (!exchange_mapi_connection_fetch_items (priv->fid, NULL, NULL,
						cal_IDList, G_N_ELEMENTS (cal_IDList), 
						NULL, NULL, 
						handle_deleted_items_cb, cbmapi, 
						0)) {
		/* FIXME: better string please... */
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Error fetching changes from the server. Removing the cache might help."));
		priv->cache_keys = NULL;
		g_static_mutex_unlock (&updating);
		return FALSE;
	}

	e_file_cache_freeze_changes (E_FILE_CACHE (priv->cache));
	for (ls = priv->cache_keys; ls ; ls = g_slist_next (ls)) {
		ECalComponent *comp = NULL;
		icalcomponent *icalcomp = NULL;

		comp = e_cal_backend_cache_get_component (priv->cache, (const char *) ls->data, NULL);

		if (!comp)
			continue;

		icalcomp = e_cal_component_get_icalcomponent (comp);
		if (kind == icalcomponent_isa (icalcomp)) {
			char *comp_str = NULL;
			ECalComponentId *id = e_cal_component_get_id (comp);
			
			comp_str = e_cal_component_get_as_string (comp);
			e_cal_backend_notify_object_removed (E_CAL_BACKEND (cbmapi), 
					id, comp_str, NULL);
			e_cal_backend_cache_remove_component (priv->cache, (const char *) id->uid, id->rid);

			e_cal_component_free_id (id);
			g_free (comp_str);
		}
		g_object_unref (comp);
	}
	e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));

//	g_slist_free (priv->cache_keys); 
	priv->cache_keys = NULL;

	g_static_mutex_unlock (&updating);
	return TRUE;        
}

static ECalBackendSyncStatus
e_cal_backend_mapi_get_default_object (ECalBackendSync *backend, EDataCal *cal, char **object)
{
	ECalComponent *comp;

        comp = e_cal_component_new ();

	switch (e_cal_backend_get_kind (E_CAL_BACKEND (backend))) {
	case ICAL_VEVENT_COMPONENT:
        	e_cal_component_set_new_vtype (comp, E_CAL_COMPONENT_EVENT);
		break;
	case ICAL_VTODO_COMPONENT:
		e_cal_component_set_new_vtype (comp, E_CAL_COMPONENT_TODO);
		break;
	case ICAL_VJOURNAL_COMPONENT:
		e_cal_component_set_new_vtype (comp, E_CAL_COMPONENT_JOURNAL);
		break;
	default:
		g_object_unref (comp);
		return GNOME_Evolution_Calendar_ObjectNotFound;
	}

	*object = e_cal_component_get_as_string (comp);
	g_object_unref (comp);

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_object (ECalBackendSync *backend, EDataCal *cal, const char *uid, const char *rid, char **object)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	ECalComponent *comp;

	cbmapi = (ECalBackendMAPI *)(backend);
	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_OtherError);

	priv = cbmapi->priv;

	g_mutex_lock (priv->mutex);

	/* search the object in the cache */
	comp = e_cal_backend_cache_get_component (priv->cache, uid, rid);

	if (comp) {
		g_mutex_unlock (priv->mutex);
		if (e_cal_backend_get_kind (E_CAL_BACKEND (backend)) ==
		    icalcomponent_isa (e_cal_component_get_icalcomponent (comp)))
			*object = e_cal_component_get_as_string (comp);
		else
			*object = NULL;

		g_object_unref (comp);

		return *object ? GNOME_Evolution_Calendar_Success : GNOME_Evolution_Calendar_ObjectNotFound;
	}

	g_mutex_unlock (priv->mutex);

	/* callers will never have a uid that is in server but not in cache */
	return GNOME_Evolution_Calendar_ObjectNotFound;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_object_list (ECalBackendSync *backend, EDataCal *cal, const char *sexp, GList **objects)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	GList *components, *l;
	ECalBackendSExp *cbsexp;
	gboolean search_needed = TRUE;

	cbmapi = E_CAL_BACKEND_MAPI (backend);	
	priv = cbmapi->priv;

	g_mutex_lock (priv->mutex);

//	d(g_message (G_STRLOC ": Getting object list (%s)", sexp));

	if (!strcmp (sexp, "#t"))
		search_needed = FALSE;

	cbsexp = e_cal_backend_sexp_new (sexp);

	if (!cbsexp) {
		g_mutex_unlock (priv->mutex);
		return GNOME_Evolution_Calendar_InvalidQuery;
	}

	*objects = NULL;
	components = e_cal_backend_cache_get_components (priv->cache);

	for (l = components; l != NULL; l = l->next) {
		ECalComponent *comp = E_CAL_COMPONENT (l->data);
		if (e_cal_backend_get_kind (E_CAL_BACKEND (backend)) ==
				icalcomponent_isa (e_cal_component_get_icalcomponent (comp))) {
			if ((!search_needed) ||
					(e_cal_backend_sexp_match_comp (cbsexp, comp, E_CAL_BACKEND (backend)))) {
				*objects = g_list_append (*objects, e_cal_component_get_as_string (comp));
			} 
		}  
	}	

	g_object_unref (cbsexp);
	g_list_foreach (components, (GFunc) g_object_unref, NULL);
	g_list_free (components);
	g_mutex_unlock (priv->mutex);

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_attachment_list (ECalBackendSync *backend, EDataCal *cal, const char *uid, const char *rid, GSList **list)
{
	/* TODO implement the function */
	return GNOME_Evolution_Calendar_Success;
}

static guint
get_cache_refresh_interval (void)
{
	guint time_interval;
	const char *time_interval_string = NULL;
	
	time_interval = CACHE_REFRESH_INTERVAL;
	time_interval_string = g_getenv ("GETQM_TIME_INTERVAL");
	if (time_interval_string) {
		time_interval = g_ascii_strtod (time_interval_string, NULL);
		time_interval *= (60*1000);
	}
		
	return time_interval;
}

static gpointer
delta_thread (gpointer data)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	GTimeVal timeout;

	cbmapi = (ECalBackendMAPI *)(data);
	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GINT_TO_POINTER (GNOME_Evolution_Calendar_OtherError));

	priv = cbmapi->priv;

	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	while (TRUE)	{
		gboolean succeeded = get_deltas (cbmapi);

		g_mutex_lock (priv->dlock->mutex);

		if (!succeeded || priv->dlock->exit) 
			break;

		g_get_current_time (&timeout);
		g_time_val_add (&timeout, get_cache_refresh_interval () * 1000);
		g_cond_timed_wait (priv->dlock->cond, priv->dlock->mutex, &timeout);
		
		if (priv->dlock->exit) 
			break;	
		
		g_mutex_unlock (priv->dlock->mutex);
	}

	g_mutex_unlock (priv->dlock->mutex);
	priv->dthread = NULL;	
	return NULL;
}

static gboolean
fetch_deltas (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_OtherError);

	priv = cbmapi->priv;

	/* If the thread is already running just return back */	
	if (priv->dthread) 
		return FALSE;
	
	if (!priv->dlock) {
		priv->dlock = g_new0 (SyncDelta, 1);
		priv->dlock->mutex = g_mutex_new ();
		priv->dlock->cond = g_cond_new ();
	}
	
	priv->dlock->exit = FALSE;
	priv->dthread = g_thread_create ((GThreadFunc) delta_thread, cbmapi, TRUE, &error);
	if (!priv->dthread) {
		g_warning (G_STRLOC ": %s", error->message);
		g_error_free (error);
	}

	return TRUE;
}


static gboolean
start_fetch_deltas (gpointer data)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = (ECalBackendMAPI *)(data);
	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_OtherError);

	priv = cbmapi->priv;

	fetch_deltas (cbmapi);

	priv->timeout_id = 0;

	return FALSE;
}

static gboolean
mapi_cal_cache_create_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct mapi_SPropValue_array *properties = item_data->properties; 
	const mapi_id_t mid = item_data->mid; 
	GSList *streams = item_data->streams; 
	GSList *recipients = item_data->recipients; 
	GSList *attachments = item_data->attachments; 	
	ECalBackendMAPI *cbmapi	= E_CAL_BACKEND_MAPI (data);
	ECalBackendMAPIPrivate *priv = cbmapi->priv;
	icalcomponent_kind kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
        ECalComponent *comp = NULL;
	gchar *tmp = NULL;
	const bool *recurring = NULL;

//	exchange_mapi_debug_property_dump (properties);

	switch (kind) {
		case ICAL_VTODO_COMPONENT:
			/* FIXME: Evolution does not support recurring tasks */
			recurring = (const bool *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BOOLEAN, 0x8126));
			if (recurring && *recurring) {
				g_warning ("Encountered a recurring task.");
				exchange_mapi_util_free_stream_list (&streams);
				exchange_mapi_util_free_recipient_list (&recipients);
				exchange_mapi_util_free_attachment_list (&attachments);
				return TRUE;
			}
			break;
		case ICAL_VEVENT_COMPONENT  :
		case ICAL_VJOURNAL_COMPONENT:
			break;
		default:
			return FALSE; 
	}
	
	tmp = exchange_mapi_util_mapi_id_to_string (mid);
	comp = exchange_mapi_cal_util_mapi_props_to_comp (kind, tmp, properties, 
							streams, recipients, attachments, 
							priv->local_attachments_store, priv->default_zone);
	g_free (tmp);

	if (E_IS_CAL_COMPONENT (comp)) {
		gchar *comp_str;
		e_cal_component_commit_sequence (comp);
		comp_str = e_cal_component_get_as_string (comp);	
		e_cal_backend_notify_object_created (E_CAL_BACKEND (cbmapi), (const char *) comp_str);
		g_free (comp_str);
		e_cal_backend_cache_put_component (priv->cache, comp);
		g_object_unref (comp);
	}

	exchange_mapi_util_free_stream_list (&streams);
	exchange_mapi_util_free_recipient_list (&recipients);
	exchange_mapi_util_free_attachment_list (&attachments);

	notify_progress (cbmapi, item_data->index, item_data->total);

	return TRUE;
}

static ECalBackendSyncStatus
populate_cache (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;
	ESource *source = NULL;
	icalcomponent_kind kind;
	icaltimetype itt_current; 
	time_t current_time;
	struct tm tm;
	gchar *time_string = NULL;
	gchar t_str [26]; 

	priv = cbmapi->priv;
	source = e_cal_backend_get_source (E_CAL_BACKEND (cbmapi));
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));

	g_mutex_lock (priv->mutex);

	itt_current = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
	current_time = icaltime_as_timet_with_zone (itt_current, icaltimezone_get_utc_timezone ());
	gmtime_r (&current_time, &tm);
	strftime (t_str, 26, "%Y-%m-%dT%H:%M:%SZ", &tm);

	e_cal_backend_notify_view_progress_start (E_CAL_BACKEND (cbmapi));

//	e_file_cache_freeze_changes (E_FILE_CACHE (priv->cache));
	/* FIXME: GetProps does not seem to work for tasks :-( */
	if (kind == ICAL_VTODO_COMPONENT) {
		if (!exchange_mapi_connection_fetch_items (priv->fid, NULL, NULL,
						NULL, 0, NULL, NULL, 
						mapi_cal_cache_create_cb, cbmapi, 
						MAPI_OPTIONS_FETCH_ALL)) {
			e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Could not create cache file"));
			e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
			g_mutex_unlock (priv->mutex);
			return GNOME_Evolution_Calendar_OtherError;
		}
	} else if (!exchange_mapi_connection_fetch_items (priv->fid, NULL, NULL,
						cal_GetPropsList, G_N_ELEMENTS (cal_GetPropsList), 
						exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER(kind), 
						mapi_cal_cache_create_cb, cbmapi, 
						MAPI_OPTIONS_FETCH_ALL)) {
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Could not create cache file"));
		e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
		g_mutex_unlock (priv->mutex);
		return GNOME_Evolution_Calendar_OtherError;
	}
//	e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));

	e_cal_backend_notify_view_done (E_CAL_BACKEND (cbmapi), GNOME_Evolution_Calendar_Success);

	time_string = g_strdup (t_str);
	e_cal_backend_cache_put_server_utc_time (priv->cache, time_string);
	g_free (time_string);

	e_cal_backend_cache_set_marker (priv->cache);

	g_mutex_unlock (priv->mutex);

	return GNOME_Evolution_Calendar_Success;
}

static gpointer
cache_init (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv = cbmapi->priv;
	icalcomponent_kind kind;
	ECalBackendSyncStatus status; 

	kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));

	priv->mode = CAL_MODE_REMOTE;

	if (!e_cal_backend_cache_get_marker (priv->cache)) {
		/* Populate the cache for the first time.*/
		status = populate_cache (cbmapi);
		if (status != GNOME_Evolution_Calendar_Success) {
			g_warning (G_STRLOC ": Could not populate the cache");
			/*FIXME  why dont we do a notify here */
			return GINT_TO_POINTER(GNOME_Evolution_Calendar_PermissionDenied);
		} else {
			/*  Set delta fetch timeout */
			priv->timeout_id = g_timeout_add (get_cache_refresh_interval (), start_fetch_deltas, (gpointer) cbmapi);

			return NULL;
		}
	}

	g_mutex_lock (priv->mutex);
	fetch_deltas (cbmapi);
	g_mutex_unlock (priv->mutex);

	return NULL;
}

static ECalBackendSyncStatus
e_cal_backend_mapi_connect (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;
	ESource *source;
	ECalSourceType source_type;
	GThread *thread;
	GError *error = NULL;

	priv = cbmapi->priv;

	if (!priv->fid)
		return GNOME_Evolution_Calendar_OtherError;

	source = e_cal_backend_get_source (E_CAL_BACKEND (cbmapi));

	if (!authenticated) {
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Authentication failed"));
		return GNOME_Evolution_Calendar_AuthenticationFailed; 
	}

	/* We have established a connection */
	if (priv->cache && priv->fid) {
		priv->mode = CAL_MODE_REMOTE;
		if (priv->mode_changed && !priv->dthread) {
			priv->mode_changed = FALSE;
			fetch_deltas (cbmapi);
		}

		/* FIXME: put server UTC time in cache */
		return GNOME_Evolution_Calendar_Success;
	}

	priv->mode_changed = FALSE;

	switch (e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi))) {
	case ICAL_VEVENT_COMPONENT:
		source_type = E_CAL_SOURCE_TYPE_EVENT;
		break;
	case ICAL_VTODO_COMPONENT:
		source_type = E_CAL_SOURCE_TYPE_TODO;
		break;
	case ICAL_VJOURNAL_COMPONENT:
		source_type = E_CAL_SOURCE_TYPE_JOURNAL;
		break;
	default:
		source_type = E_CAL_SOURCE_TYPE_EVENT;
		break;
	}

	priv->cache = e_cal_backend_cache_new (e_cal_backend_get_uri (E_CAL_BACKEND (cbmapi)), source_type);
	if (!priv->cache) {
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Could not create cache file"));
		return GNOME_Evolution_Calendar_OtherError;
	}

	e_cal_backend_cache_put_default_timezone (priv->cache, priv->default_zone);

	/* spawn a new thread for caching the calendar items */
	thread = g_thread_create ((GThreadFunc) cache_init, cbmapi, FALSE, &error);
	if (!thread) {
		g_warning (G_STRLOC ": %s", error->message);
		g_error_free (error);
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Could not create thread for populating cache"));
		return GNOME_Evolution_Calendar_OtherError;
	} 

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_open (ECalBackendSync *backend, EDataCal *cal, gboolean only_if_exists, const char *username, const char *password)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	ECalBackendSyncStatus status;
	ECalSourceType source_type;
	ESource *esource;
	const char *source = NULL, *fid = NULL;
	char *filename;
	char *mangled_uri;
	int i;
	uint32_t olFolder = 0;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	esource = e_cal_backend_get_source (E_CAL_BACKEND (cbmapi));
	fid = e_source_get_property (esource, "folder-id");
	if (!(fid && *fid))
		return GNOME_Evolution_Calendar_OtherError;

	g_mutex_lock (priv->mutex);

	cbmapi->priv->read_only = FALSE;

	switch (e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi))) {
	case ICAL_VEVENT_COMPONENT:
		source_type = E_CAL_SOURCE_TYPE_EVENT;
		source = "calendar";
		olFolder = olFolderCalendar;
		break;
	case ICAL_VTODO_COMPONENT:
		source_type = E_CAL_SOURCE_TYPE_TODO;
		source = "tasks";
		olFolder = olFolderTasks;
		break;
	case ICAL_VJOURNAL_COMPONENT:
		source_type = E_CAL_SOURCE_TYPE_JOURNAL;
		source = "journal";
		olFolder = olFolderNotes;
		break;
	default:
		source_type = E_CAL_SOURCE_TYPE_EVENT;
		break;
	}

	/* Not for remote */	
	if (priv->mode == CAL_MODE_LOCAL) {
		const gchar *display_contents = NULL;

		cbmapi->priv->read_only = TRUE;				
		display_contents = e_source_get_property (esource, "offline_sync");
		
		if (!display_contents || !g_str_equal (display_contents, "1")) {
			g_mutex_unlock (priv->mutex);	
			return GNOME_Evolution_Calendar_RepositoryOffline;
		}

		/* Cache created here for the first time */
		if (!priv->cache) {
			priv->cache = e_cal_backend_cache_new (e_cal_backend_get_uri (E_CAL_BACKEND (cbmapi)), source_type);
			if (!priv->cache) {
				g_mutex_unlock (priv->mutex);
				e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Could not create cache file"));
				return GNOME_Evolution_Calendar_OtherError;
			}
		}
		e_cal_backend_cache_put_default_timezone (priv->cache, priv->default_zone);
		g_mutex_unlock (priv->mutex);	
		return GNOME_Evolution_Calendar_Success;
	}

	priv->username = g_strdup (username);
	priv->password = g_strdup (password);

	priv->profile = g_strdup (e_source_get_property (esource, "profile"));
	priv->user_name = g_strdup (e_source_get_property (esource, "acl-user-name"));
	priv->user_email = g_strdup (e_source_get_property (esource, "acl-user-email"));
	priv->owner_name = g_strdup (e_source_get_property (esource, "acl-owner-name"));
	priv->owner_email = g_strdup (e_source_get_property (esource, "acl-owner-email"));

	exchange_mapi_util_mapi_id_from_string (fid, &priv->fid);
	priv->olFolder = olFolder;

	/* Set the local attachment store */
	mangled_uri = g_strdup (e_cal_backend_get_uri (E_CAL_BACKEND (cbmapi)));
	/* mangle the URI to not contain invalid characters */
	for (i = 0; i < strlen (mangled_uri); i++) {
		switch (mangled_uri[i]) {
		case ':' :
		case '/' :
			mangled_uri[i] = '_';
		}
	}

	filename = g_build_filename (g_get_home_dir (),
				     ".evolution/cache/", source,
				     mangled_uri,
				     G_DIR_SEPARATOR_S, 
				     NULL);

	g_free (mangled_uri);
	priv->local_attachments_store = 
		g_filename_to_uri (filename, NULL, NULL);
	g_free (filename);

	g_mutex_unlock (priv->mutex);

	g_static_mutex_lock (&auth_mutex);
	status = e_cal_backend_mapi_authenticate (E_CAL_BACKEND (cbmapi));
	g_static_mutex_unlock (&auth_mutex); 

	if (status == GNOME_Evolution_Calendar_Success)
		return e_cal_backend_mapi_connect (cbmapi);
	else
		return status;
}

static gboolean 
capture_req_props (FetchItemsCallbackData *item_data, gpointer data)
{
	struct mapi_SPropValue_array *properties = item_data->properties; 
	struct cbdata *cbdata = (struct cbdata *) data;
	const uint32_t *ui32;

	ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PR_OWNER_APPT_ID);
	if (ui32)
		cbdata->appt_id = *ui32;
	ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_LONG, 0x8201));
	if (ui32)
		cbdata->appt_seq = *ui32;
	cbdata->cleanglobalid = (const struct Binary_r *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BINARY, 0x0023));
	cbdata->globalid = (const struct Binary_r *)find_mapi_SPropValue_data(properties, PROP_TAG(PT_BINARY, 0x0003));
	cbdata->username = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_NAME);
	cbdata->useridtype = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE);
	cbdata->userid = exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	cbdata->ownername = exchange_mapi_util_find_array_propval (properties, PR_SENDER_NAME);
	cbdata->owneridtype = exchange_mapi_util_find_array_propval (properties, PR_SENDER_ADDRTYPE);
	cbdata->ownerid = exchange_mapi_util_find_array_propval (properties, PR_SENDER_EMAIL_ADDRESS);

	return TRUE;
}

static void
get_server_data (ECalBackendMAPI *cbmapi, icalcomponent *comp, struct cbdata *cbdata)
{
	ECalBackendMAPIPrivate *priv = cbmapi->priv;
	const char *uid;
	mapi_id_t mid;
	struct mapi_SRestriction res;
	struct SPropValue sprop;
	struct Binary_r sb;
	uint32_t proptag = 0x0;
	struct SPropTagArray *array;

	uid = icalcomponent_get_uid (comp);
	exchange_mapi_util_mapi_id_from_string (uid, &mid);
	if (exchange_mapi_connection_fetch_item (priv->fid, mid, 
					NULL, 0, 
					NULL, NULL, 
					capture_req_props, cbdata, 
					MAPI_OPTIONS_FETCH_GENERIC_STREAMS))

		return;

	array = exchange_mapi_util_resolve_named_prop (priv->olFolder, priv->fid, 0x0023, PSETID_Meeting);
	proptag = array->aulPropTag[0];

	res.rt = RES_PROPERTY;
	res.res.resProperty.relop = RELOP_EQ;
	res.res.resProperty.ulPropTag = proptag;

	exchange_mapi_cal_util_generate_globalobjectid (TRUE, uid, &sb);

	set_SPropValue_proptag (&sprop, proptag, (const void *) &sb);
	cast_mapi_SPropValue (&(res.res.resProperty.lpProp), &sprop);

	exchange_mapi_connection_fetch_items (priv->fid, &res, NULL,
					NULL, 0, 
					NULL, NULL, 
					capture_req_props, cbdata, 
					MAPI_OPTIONS_FETCH_GENERIC_STREAMS);
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_create_object (ECalBackendSync *backend, EDataCal *cal, char **calobj, char **uid)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;
	ECalComponent *comp;
	const char *compuid;
	mapi_id_t mid = 0;
	gchar *tmp = NULL;
	GSList *recipients = NULL;
	GSList *attachments = NULL;
	GSList *streams = NULL;
	struct cbdata cbdata;
	struct Binary_r globalid;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (backend));

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_InvalidObject);
	g_return_val_if_fail (calobj != NULL && *calobj != NULL, GNOME_Evolution_Calendar_InvalidObject);

	if (priv->mode == CAL_MODE_LOCAL)
		return GNOME_Evolution_Calendar_RepositoryOffline;

	/* check the component for validity */
	icalcomp = icalparser_parse_string (*calobj);
	if (!icalcomp)
		return GNOME_Evolution_Calendar_InvalidObject;

	if (kind != icalcomponent_isa (icalcomp)) {
		icalcomponent_free (icalcomp);
		return GNOME_Evolution_Calendar_InvalidObject;
	}

	comp = e_cal_component_new ();
	e_cal_component_set_icalcomponent (comp, icalcomp);

	/* FIXME: [WIP] Add support for recurrences */
	if (e_cal_component_has_recurrences (comp)) {
		GByteArray *ba = exchange_mapi_cal_util_rrule_to_bin (comp, NULL); 
		if (ba) {
			struct SPropTagArray *tag_array; 
			ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1); 
			stream->value = ba; 
			tag_array = exchange_mapi_util_resolve_named_prop (priv->olFolder, priv->fid, 0x8216, PSETID_Appointment); 
			if (tag_array) {
				stream->proptag = tag_array->aulPropTag[0];
				streams = g_slist_append (streams, stream); 

				g_free (tag_array->aulPropTag); 
				g_free (tag_array);
			}
		}
	}

	/* FIXME: [WIP] Add support for meetings/assigned tasks */
	if (e_cal_component_has_attendees (comp)) 
		exchange_mapi_cal_util_fetch_recipients (comp, &recipients);

	if (e_cal_component_has_attachments (comp))
		exchange_mapi_cal_util_fetch_attachments (comp, &attachments, priv->local_attachments_store);

	cbdata.username = e_cal_backend_mapi_get_user_name (cbmapi);
	cbdata.useridtype = "SMTP";
	cbdata.userid = e_cal_backend_mapi_get_user_email (cbmapi);
	cbdata.ownername = e_cal_backend_mapi_get_owner_name (cbmapi);
	cbdata.owneridtype = "SMTP";
	cbdata.ownerid = e_cal_backend_mapi_get_owner_email (cbmapi);

	/* Check if object exists */
	switch (priv->mode) {
		case CAL_MODE_ANY:
		case CAL_MODE_REMOTE:
			/* Create an appointment */
			cbdata.comp = comp;
			cbdata.is_modify = FALSE;
			cbdata.msgflags = MSGFLAG_READ;
			cbdata.meeting_type = (recipients != NULL) ? MEETING_OBJECT : NOT_A_MEETING;
			cbdata.resp = (recipients != NULL) ? olResponseOrganized : olResponseNone;
			cbdata.appt_id = exchange_mapi_cal_util_get_new_appt_id (priv->fid);
			cbdata.appt_seq = 0;
			e_cal_component_get_uid (comp, &compuid);
			exchange_mapi_cal_util_generate_globalobjectid (TRUE, compuid, &globalid);
			cbdata.globalid = &globalid;
			cbdata.cleanglobalid = &globalid;

			mid = exchange_mapi_create_item (priv->olFolder, priv->fid, 
							exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER(kind), 
							exchange_mapi_cal_util_build_props, &cbdata, 
							recipients, attachments, streams, MAPI_OPTIONS_DONT_SUBMIT);
			g_free (cbdata.props);
//			g_free (globalid.lpb);
			if (!mid) {
				g_object_unref (comp);
				exchange_mapi_util_free_recipient_list (&recipients);
				exchange_mapi_util_free_stream_list (&streams);
				exchange_mapi_util_free_attachment_list (&attachments);
				return GNOME_Evolution_Calendar_OtherError;
			}

			tmp = exchange_mapi_util_mapi_id_to_string (mid);
			e_cal_component_set_uid (comp, tmp);
			g_free (tmp);

			e_cal_component_commit_sequence (comp);
			e_cal_backend_cache_put_component (priv->cache, comp);
			*calobj = e_cal_component_get_as_string (comp);
			e_cal_backend_notify_object_created (E_CAL_BACKEND (cbmapi), *calobj);
			break;
		default:
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_stream_list (&streams);
			exchange_mapi_util_free_attachment_list (&attachments);
			return GNOME_Evolution_Calendar_CalListener_MODE_NOT_SUPPORTED;
	}

	/* blatant HACK /me blames some stupid design in e-d-s */
	if (e_cal_component_has_attachments (comp) && !fetch_deltas(cbmapi))
		g_cond_signal (priv->dlock->cond);

	g_object_unref (comp);
	exchange_mapi_util_free_recipient_list (&recipients);
	exchange_mapi_util_free_stream_list (&streams);
	exchange_mapi_util_free_attachment_list (&attachments);

	return GNOME_Evolution_Calendar_Success;
}

static gboolean
modifier_is_organizer (ECalBackendMAPI *cbmapi, ECalComponent *comp)
{
	ECalComponentOrganizer org; 
	const char *ownerid, *orgid; 

	if (!e_cal_component_has_organizer(comp))
		return TRUE;

	e_cal_component_get_organizer (comp, &org);
	if (!g_ascii_strncasecmp (org.value, "mailto:", 7))
		orgid = (org.value) + 7;
	else 
		orgid = org.value;
	ownerid = e_cal_backend_mapi_get_owner_email (cbmapi);

	return (!g_ascii_strcasecmp(orgid, ownerid) ? TRUE : FALSE);
}

static OlResponseStatus 
get_trackstatus_from_partstat (icalparameter_partstat partstat)
{
	switch (partstat) {
		case ICAL_PARTSTAT_ACCEPTED 	: return olResponseAccepted;
		case ICAL_PARTSTAT_TENTATIVE 	: return olResponseTentative;
		case ICAL_PARTSTAT_DECLINED 	: return olResponseDeclined;
		default 			: return olResponseTentative;
	}
}

static OlResponseStatus
find_my_response (ECalBackendMAPI *cbmapi, ECalComponent *comp)
{
	icalcomponent *icalcomp = e_cal_component_get_icalcomponent (comp);
	icalproperty *attendee; 
	gchar *att = NULL;
	OlResponseStatus val = olResponseTentative; 

	att = g_strdup_printf ("MAILTO:%s", e_cal_backend_mapi_get_owner_email (cbmapi));
	attendee = icalcomponent_get_first_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	while (attendee) {
		const char *value = icalproperty_get_attendee (attendee);
		if (!g_ascii_strcasecmp (value, att)) {
			icalparameter *param = icalproperty_get_first_parameter (attendee, ICAL_PARTSTAT_PARAMETER);
			val = get_trackstatus_from_partstat (icalparameter_get_partstat(param));
			break;
		}
		attendee = icalcomponent_get_next_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	}
	g_free (att);

	return val;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_modify_object (ECalBackendSync *backend, EDataCal *cal, const char *calobj, 
				  CalObjModType mod, char **old_object, char **new_object)
{
	ECalBackendMAPI *cbmapi;
        ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;
	ECalComponent *comp, *cache_comp = NULL;
	gboolean status;
	mapi_id_t mid;
	const char *uid = NULL, *rid = NULL;
	GSList *recipients = NULL;
	GSList *streams = NULL;
	GSList *attachments = NULL;
	struct cbdata cbdata;
	gboolean no_increment = FALSE;
	icalproperty *prop; 

	*old_object = *new_object = NULL;
	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (backend));

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_InvalidObject);
	g_return_val_if_fail (calobj != NULL, GNOME_Evolution_Calendar_InvalidObject);

	if (priv->mode == CAL_MODE_LOCAL)
		return GNOME_Evolution_Calendar_RepositoryOffline;

	if (mod != CALOBJ_MOD_ALL) {
		e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Support for modifying single instances of a recurring appointment is not yet implemented. No change was made to the appointment on the server.")); 
		return GNOME_Evolution_Calendar_Success;
	}

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp)
		return GNOME_Evolution_Calendar_InvalidObject;

	prop = icalcomponent_get_first_property (icalcomp, ICAL_X_PROPERTY);
	while (prop) {
		const char *name = icalproperty_get_x_name (prop);
		if (!g_ascii_strcasecmp (name, "X-EVOLUTION-IS-REPLY")) {
			no_increment = TRUE; 
			icalcomponent_remove_property (icalcomp, prop);
		}
		prop = icalcomponent_get_next_property (icalcomp, ICAL_X_PROPERTY);
	}

	comp = e_cal_component_new ();
	e_cal_component_set_icalcomponent (comp, icalcomp);

	/* FIXME: [WIP] Add support for recurrences */
	if (e_cal_component_has_recurrences (comp)) {
		GByteArray *ba = exchange_mapi_cal_util_rrule_to_bin (comp, NULL); 
		if (ba) {
			struct SPropTagArray *tag_array; 
			ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1); 
			stream->value = ba; 
			tag_array = exchange_mapi_util_resolve_named_prop (priv->olFolder, priv->fid, 0x8216, PSETID_Appointment); 
			if (tag_array) {
				stream->proptag = tag_array->aulPropTag[0];
				streams = g_slist_append (streams, stream); 
			}
		}
	}

	if (e_cal_component_has_attendees (comp)) 
		exchange_mapi_cal_util_fetch_recipients (comp, &recipients);

	if (e_cal_component_has_attachments (comp))
		exchange_mapi_cal_util_fetch_attachments (comp, &attachments, priv->local_attachments_store);

	e_cal_component_get_uid (comp, &uid);
//	rid = e_cal_component_get_recurid_as_string (comp);

	switch (priv->mode) {
	case CAL_MODE_ANY :
	case CAL_MODE_REMOTE :	/* when online, send the item to the server */
		/* check if the object exists */
		cache_comp = e_cal_backend_cache_get_component (priv->cache, uid, rid);
		if (!cache_comp) {
			get_deltas (cbmapi);
			cache_comp = e_cal_backend_cache_get_component (priv->cache, uid, rid);
		}

		if (!cache_comp) {
			g_message ("CRITICAL : Could not find the object in cache");
			g_object_unref (comp);
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_stream_list (&streams);
			exchange_mapi_util_free_attachment_list (&attachments);
			return GNOME_Evolution_Calendar_ObjectNotFound;
		}
		exchange_mapi_util_mapi_id_from_string (uid, &mid);

		cbdata.comp = comp;
		cbdata.msgflags = MSGFLAG_READ;
		cbdata.is_modify = TRUE;

		get_server_data (cbmapi, icalcomp, &cbdata);
		if (modifier_is_organizer(cbmapi, comp)) {
			cbdata.meeting_type = (recipients != NULL) ? MEETING_OBJECT : NOT_A_MEETING; 
			cbdata.resp = (recipients != NULL) ? olResponseOrganized : olResponseNone;
			if (!no_increment)
				cbdata.appt_seq += 1;
			cbdata.username = e_cal_backend_mapi_get_user_name (cbmapi);
			cbdata.useridtype = "SMTP";
			cbdata.userid = e_cal_backend_mapi_get_user_email (cbmapi);
			cbdata.ownername = e_cal_backend_mapi_get_owner_name (cbmapi);
			cbdata.owneridtype = "SMTP";
			cbdata.ownerid = e_cal_backend_mapi_get_owner_email (cbmapi);
		} else {
			cbdata.resp = (recipients != NULL) ? find_my_response(cbmapi, comp) : olResponseNone;
			cbdata.meeting_type = (recipients != NULL) ? MEETING_OBJECT_RCVD : NOT_A_MEETING; 
		}

		status = exchange_mapi_modify_item (priv->olFolder, priv->fid, mid, 
						exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER(kind), 
						exchange_mapi_cal_util_build_props, &cbdata, 
						recipients, attachments, streams, MAPI_OPTIONS_DONT_SUBMIT);
		g_free (cbdata.props);
		if (!status) {
			g_object_unref (comp);
			g_object_unref (cache_comp);
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_stream_list (&streams);
			exchange_mapi_util_free_attachment_list (&attachments);
			return GNOME_Evolution_Calendar_OtherError;
		}
		break;
	default : 
		g_object_unref (comp);
		g_object_unref (cache_comp);
		exchange_mapi_util_free_recipient_list (&recipients);
		exchange_mapi_util_free_stream_list (&streams);
		exchange_mapi_util_free_attachment_list (&attachments);
		return GNOME_Evolution_Calendar_CalListener_MODE_NOT_SUPPORTED;
	}

	*old_object = e_cal_component_get_as_string (cache_comp);
	*new_object = e_cal_component_get_as_string (comp);

	g_object_unref (comp);
	g_object_unref (cache_comp);
	exchange_mapi_util_free_recipient_list (&recipients);
	exchange_mapi_util_free_stream_list (&streams);
	exchange_mapi_util_free_attachment_list (&attachments);

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_remove_object (ECalBackendSync *backend, EDataCal *cal,
				  const char *uid, const char *rid, CalObjModType mod, 
				  char **old_object, char **object)
{
	ECalBackendMAPI *cbmapi;
        ECalBackendMAPIPrivate *priv;
	icalcomponent *icalcomp;
	ECalBackendSyncStatus status;
	char *calobj = NULL;
	mapi_id_t mid;

	*old_object = *object = NULL;
	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_InvalidObject);

	if (priv->mode == CAL_MODE_LOCAL)
		return GNOME_Evolution_Calendar_RepositoryOffline;

	switch (priv->mode) {
	case CAL_MODE_ANY :
	case CAL_MODE_REMOTE : 	/* when online, modify/delete the item from the server */
		/* check if the object exists */
		/* FIXME: we may have detached instances which need to be removed */
		status = e_cal_backend_mapi_get_object (backend, cal, uid, NULL, &calobj);
		if (status != GNOME_Evolution_Calendar_Success)
			return status;

		/* check the component for validity */
		icalcomp = icalparser_parse_string (calobj);
		if (!icalcomp) {
			g_free (calobj);
			return GNOME_Evolution_Calendar_InvalidObject;
		}

		exchange_mapi_util_mapi_id_from_string (uid, &mid);

		if (mod == CALOBJ_MOD_THIS && rid && *rid) {
			char *obj = NULL, *new_object = NULL, *new_calobj = NULL;
			struct icaltimetype time_rid;

			/*remove a single instance of a recurring event and modify */
			time_rid = icaltime_from_string (rid);
			e_cal_util_remove_instances (icalcomp, time_rid, mod);
			new_calobj  = (char *) icalcomponent_as_ical_string (icalcomp);
			status = e_cal_backend_mapi_modify_object (backend, cal, new_calobj, CALOBJ_MOD_ALL, &obj, &new_object);
			if (status == GNOME_Evolution_Calendar_Success) {
				*old_object = obj;
				*object = new_object;
			}
			g_free (new_calobj);
		} else {
			GSList *list=NULL, *l, *comp_list = e_cal_backend_cache_get_components_by_uid (priv->cache, uid);

//			if (e_cal_component_has_attendees (E_CAL_COMPONENT (comp_list->data))) { 
//			} else { 
				struct id_list *data = g_new (struct id_list, 1);
				data->id = mid;
				list = g_slist_prepend (list, (gpointer) data);
//			}

			if (exchange_mapi_remove_items (priv->olFolder, priv->fid, list)) {
				for (l = comp_list; l; l = l->next) {
					ECalComponent *comp = E_CAL_COMPONENT (l->data);
					ECalComponentId *id = e_cal_component_get_id (comp);

					e_cal_backend_cache_remove_component (priv->cache, id->uid, id->rid);
					if (!id->rid || !g_str_equal (id->rid, rid))
						e_cal_backend_notify_object_removed (E_CAL_BACKEND (cbmapi), id, e_cal_component_get_as_string (comp), NULL);
					e_cal_component_free_id (id);

					g_object_unref (comp);
				}
				*old_object = g_strdup (calobj);
				*object = NULL;
				status = GNOME_Evolution_Calendar_Success;
			} else
				status = GNOME_Evolution_Calendar_OtherError;

			g_slist_free (list);
			g_slist_free (comp_list);
		} 
		g_free (calobj);
		break; 
	default :
		status = GNOME_Evolution_Calendar_CalListener_MODE_NOT_SUPPORTED;
		break; 
	}

	return status;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_discard_alarm (ECalBackendSync *backend, EDataCal *cal, const char *uid, const char *auid)
{

	return GNOME_Evolution_Calendar_Success;
	
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_send_objects (ECalBackendSync *backend, EDataCal *cal, const char *calobj, 
				 GList **users, char **modified_calobj)
{
	ECalBackendSyncStatus status = GNOME_Evolution_Calendar_OtherError;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (backend));

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_InvalidObject);
	g_return_val_if_fail (calobj != NULL, GNOME_Evolution_Calendar_InvalidObject);

	if (priv->mode == CAL_MODE_LOCAL)
		return GNOME_Evolution_Calendar_RepositoryOffline;

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp)
		return GNOME_Evolution_Calendar_InvalidObject;

	*modified_calobj = NULL;
	*users = NULL;

	if (icalcomponent_isa (icalcomp) == ICAL_VCALENDAR_COMPONENT) {
		icalproperty_method method = icalcomponent_get_method (icalcomp);
		icalcomponent *subcomp = icalcomponent_get_first_component (icalcomp, kind);
		while (subcomp) {
			ECalComponent *comp = e_cal_component_new ();
			struct cbdata cbdata;
			mapi_id_t mid = 0;
			GSList *recipients = NULL;
			GSList *attachments = NULL;
			GSList *streams = NULL;

			e_cal_component_set_icalcomponent (comp, icalcomponent_new_clone (subcomp));

			/* FIXME: Add support for recurrences */
			if (e_cal_component_has_recurrences (comp)) {
				GByteArray *ba = exchange_mapi_cal_util_rrule_to_bin (comp, NULL); 
				if (ba) {
					struct SPropTagArray *tag_array; 
					ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1); 
					stream->value = ba; 
					tag_array = exchange_mapi_util_resolve_named_prop (priv->olFolder, priv->fid, 0x8216, PSETID_Appointment); 
					if (tag_array) {
						stream->proptag = tag_array->aulPropTag[0];
						streams = g_slist_append (streams, stream); 

						g_free (tag_array->aulPropTag); 
						g_free (tag_array);
					}
				}
			}

			if (e_cal_component_has_attachments (comp))
				exchange_mapi_cal_util_fetch_attachments (comp, &attachments, priv->local_attachments_store);

			cbdata.comp = comp;
			cbdata.is_modify = TRUE;
			cbdata.msgflags = MSGFLAG_READ | MSGFLAG_SUBMIT | MSGFLAG_UNSENT;

			switch (method) {
			case ICAL_METHOD_REQUEST : 
				cbdata.meeting_type = MEETING_REQUEST;
				cbdata.resp = olResponseNotResponded;
				if (e_cal_component_has_attendees (comp))
					exchange_mapi_cal_util_fetch_recipients (comp, &recipients);
				break;
			case ICAL_METHOD_CANCEL : 
				cbdata.meeting_type = MEETING_CANCEL;
				cbdata.resp = olResponseNotResponded;
				if (e_cal_component_has_attendees (comp))
					exchange_mapi_cal_util_fetch_recipients (comp, &recipients);
				break;
			case ICAL_METHOD_RESPONSE : 
				cbdata.meeting_type = MEETING_RESPONSE;
				cbdata.resp = find_my_response (cbmapi, comp);
				if (e_cal_component_has_organizer (comp))
					exchange_mapi_cal_util_fetch_organizer (comp, &recipients);
				break;
			default :
				cbdata.meeting_type = NOT_A_MEETING;
				cbdata.resp = olResponseNone;
				if (e_cal_component_has_attendees (comp))
					exchange_mapi_cal_util_fetch_recipients (comp, &recipients);
				break;
			}

			get_server_data (cbmapi, subcomp, &cbdata);
			cbdata.username = e_cal_backend_mapi_get_user_name (cbmapi);
			cbdata.useridtype = "SMTP";
			cbdata.userid = e_cal_backend_mapi_get_user_email (cbmapi);
			cbdata.ownername = e_cal_backend_mapi_get_owner_name (cbmapi);
			cbdata.owneridtype = "SMTP";
			cbdata.ownerid = e_cal_backend_mapi_get_owner_email (cbmapi);

			mid = exchange_mapi_create_item (olFolderOutbox, 0, 
							exchange_mapi_cal_util_build_name_id, GINT_TO_POINTER(kind), 
							exchange_mapi_cal_util_build_props, &cbdata, 
							recipients, attachments, streams, 0);
			g_free (cbdata.props);
			if (!mid) {
				g_object_unref (comp);
				exchange_mapi_util_free_recipient_list (&recipients);
				exchange_mapi_util_free_attachment_list (&attachments);
				return GNOME_Evolution_Calendar_OtherError;
			} else 
				status = GNOME_Evolution_Calendar_Success;

			g_object_unref (comp);
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_attachment_list (&attachments);

			subcomp = icalcomponent_get_next_component (icalcomp,
								    e_cal_backend_get_kind (E_CAL_BACKEND (backend)));
		}
	}

	if (status == GNOME_Evolution_Calendar_Success)
		*modified_calobj = g_strdup (calobj);

	icalcomponent_free (icalcomp);

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_receive_objects (ECalBackendSync *backend, EDataCal *cal, const char *calobj)
{
	ECalBackendSyncStatus status = GNOME_Evolution_Calendar_OtherError;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (backend));

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_InvalidObject);
	g_return_val_if_fail (calobj != NULL, GNOME_Evolution_Calendar_InvalidObject);

	if (priv->mode == CAL_MODE_LOCAL)
		return GNOME_Evolution_Calendar_RepositoryOffline;

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp)
		return GNOME_Evolution_Calendar_InvalidObject;

	if (icalcomponent_isa (icalcomp) == ICAL_VCALENDAR_COMPONENT) {
		gboolean stop = FALSE;
		icalproperty_method method = icalcomponent_get_method (icalcomp);
		icalcomponent *subcomp = icalcomponent_get_first_component (icalcomp, kind);
		while (subcomp && !stop) {
			ECalComponent *comp = e_cal_component_new ();
			gchar *rid = NULL; 
			const char *uid;
			gchar *old_object = NULL, *new_object = NULL, *comp_str; 

			e_cal_component_set_icalcomponent (comp, icalcomponent_new_clone (subcomp));

			/* FIXME: Add support for recurrences */
			if (e_cal_component_has_recurrences (comp)) {
				g_object_unref (comp);
				return GNOME_Evolution_Calendar_OtherError;
			}

			e_cal_component_get_uid (comp, &uid);
			rid = e_cal_component_get_recurid_as_string (comp);

			switch (method) {
			case ICAL_METHOD_REQUEST :
				comp_str = e_cal_component_get_as_string (comp);
				status = e_cal_backend_mapi_modify_object (backend, cal, comp_str, CALOBJ_MOD_THIS, &old_object, &new_object);
				g_free (comp_str);
				g_free (old_object);
				g_free (new_object);
				if (status == GNOME_Evolution_Calendar_Success) {
					GList *users = NULL, *l;
					icalcomponent *resp_comp = e_cal_util_new_top_level ();
					icalcomponent_set_method (resp_comp, ICAL_METHOD_RESPONSE);
					icalcomponent_add_component (resp_comp, 
						icalcomponent_new_clone(e_cal_component_get_icalcomponent(comp)));
					comp_str = icalcomponent_as_ical_string (resp_comp);
					status = e_cal_backend_mapi_send_objects (backend, cal, comp_str, &users, &new_object);
					g_free (comp_str);
					g_free (new_object);
					for (l = users; l; l = l->next)
						g_free (l->data);
					g_list_free (users);
					icalcomponent_free (resp_comp);
				}

				if (status != GNOME_Evolution_Calendar_Success)
					stop = TRUE;
				break;
			case ICAL_METHOD_CANCEL :
				status = e_cal_backend_mapi_remove_object (backend, cal, uid, rid, CALOBJ_MOD_THIS, &old_object, &new_object);
				if (status != GNOME_Evolution_Calendar_Success)
					stop = TRUE;
				g_free (old_object);
				g_free (new_object);
				break;
			case ICAL_METHOD_REPLY :
				/* responses are automatically updated even as they are rendered (just like in Outlook) */
				status = GNOME_Evolution_Calendar_Success;
				break; 
			default :
				break;
			}

			g_free (rid);
			g_object_unref (comp);

			subcomp = icalcomponent_get_next_component (icalcomp,
								    e_cal_backend_get_kind (E_CAL_BACKEND (backend)));
		}
	}

	return status;
}


static ECalBackendSyncStatus 
e_cal_backend_mapi_get_timezone (ECalBackendSync *backend, EDataCal *cal, const char *tzid, char **object)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	icaltimezone *zone;
	icalcomponent *icalcomp;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	g_return_val_if_fail (tzid != NULL, GNOME_Evolution_Calendar_ObjectNotFound);

	if (!strcmp (tzid, "UTC")) {
		zone = icaltimezone_get_utc_timezone ();
	} else {
		zone = icaltimezone_get_builtin_timezone_from_tzid (tzid);
		if (!zone)
			return GNOME_Evolution_Calendar_ObjectNotFound;
	}

	icalcomp = icaltimezone_get_component (zone);
	if (!icalcomp)
		return GNOME_Evolution_Calendar_InvalidObject;

	*object = icalcomponent_as_ical_string (icalcomp);

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_add_timezone (ECalBackendSync *backend, EDataCal *cal, const char *tzobj)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent *tz_comp;

	cbmapi = (ECalBackendMAPI *) backend;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_OtherError);
	g_return_val_if_fail (tzobj != NULL, GNOME_Evolution_Calendar_OtherError);

	priv = cbmapi->priv;

	tz_comp = icalparser_parse_string (tzobj);
	if (!tz_comp)
		return GNOME_Evolution_Calendar_InvalidObject;

	if (icalcomponent_isa (tz_comp) == ICAL_VTIMEZONE_COMPONENT) {
		icaltimezone *zone;
		zone = icaltimezone_new ();
		icaltimezone_set_component (zone, tz_comp);

		if (e_cal_backend_cache_put_timezone (priv->cache, zone) == FALSE) {
			icaltimezone_free (zone, 1);
			return GNOME_Evolution_Calendar_OtherError;
		}
		icaltimezone_free (zone, 1);
	}

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_set_default_zone (ECalBackendSync *backend, EDataCal *cal, const char *tzobj)
{
	icalcomponent *tz_comp;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icaltimezone *zone;

	cbmapi = (ECalBackendMAPI *) backend;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_OtherError);
	g_return_val_if_fail (tzobj != NULL, GNOME_Evolution_Calendar_OtherError);

	priv = cbmapi->priv;

	tz_comp = icalparser_parse_string (tzobj);
	if (!tz_comp)
		return GNOME_Evolution_Calendar_InvalidObject;

	zone = icaltimezone_new ();
	icaltimezone_set_component (zone, tz_comp);

	if (priv->default_zone)
		icaltimezone_free (priv->default_zone, 1);

	/* Set the default timezone to it. */
	priv->default_zone = zone;

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus 
e_cal_backend_mapi_get_free_busy (ECalBackendSync *backend, EDataCal *cal, 
				  GList *users, time_t start, time_t end, GList **freebusy)
{

	return GNOME_Evolution_Calendar_Success;	

}

typedef struct {
	ECalBackendMAPI *backend;
	icalcomponent_kind kind;
	GList *deletes;
	EXmlHash *ehash;
} ECalBackendMAPIComputeChangesData;

static void
e_cal_backend_mapi_compute_changes_foreach_key (const char *key, const char *value, gpointer data)
{
	ECalBackendMAPIComputeChangesData *be_data = data;

	if (!e_cal_backend_cache_get_component (be_data->backend->priv->cache, key, NULL)) {
		ECalComponent *comp;

		comp = e_cal_component_new ();
		if (be_data->kind == ICAL_VTODO_COMPONENT)
			e_cal_component_set_new_vtype (comp, E_CAL_COMPONENT_TODO);
		else
			e_cal_component_set_new_vtype (comp, E_CAL_COMPONENT_EVENT);

		e_cal_component_set_uid (comp, key);
		be_data->deletes = g_list_prepend (be_data->deletes, e_cal_component_get_as_string (comp));

		e_xmlhash_remove (be_data->ehash, key);
		g_object_unref (comp);
 	}
}

static ECalBackendSyncStatus
e_cal_backend_mapi_compute_changes (ECalBackendMAPI *cbmapi, const char *change_id,
				    GList **adds, GList **modifies, GList **deletes)
{
	ECalBackendSyncStatus status;
	ECalBackendCache *cache;
	gchar *filename;
	EXmlHash *ehash;
	ECalBackendMAPIComputeChangesData be_data;
	GList *i, *list = NULL;
	gchar *unescaped_uri;

	cache = cbmapi->priv->cache;

	/* FIXME Will this always work? */
	unescaped_uri = g_uri_unescape_string (cbmapi->priv->uri, "");
	filename = g_strdup_printf ("%s-%s.db", unescaped_uri, change_id);
	ehash = e_xmlhash_new (filename);
	g_free (filename);
	g_free (unescaped_uri);

        status = e_cal_backend_mapi_get_object_list (E_CAL_BACKEND_SYNC (cbmapi), NULL, "#t", &list);
        if (status != GNOME_Evolution_Calendar_Success)
                return status;

        /* Calculate adds and modifies */
	for (i = list; i != NULL; i = g_list_next (i)) {
		const char *uid;
		char *calobj;
		ECalComponent *comp;

		comp = e_cal_component_new_from_string (i->data);
		e_cal_component_get_uid (comp, &uid);
		calobj = i->data;

		g_assert (calobj != NULL);

		/* check what type of change has occurred, if any */
		switch (e_xmlhash_compare (ehash, uid, calobj)) {
		case E_XMLHASH_STATUS_SAME:
			break;
		case E_XMLHASH_STATUS_NOT_FOUND:
			*adds = g_list_prepend (*adds, g_strdup (calobj));
			e_xmlhash_add (ehash, uid, calobj);
			break;
		case E_XMLHASH_STATUS_DIFFERENT:
			*modifies = g_list_prepend (*modifies, g_strdup (calobj));
			e_xmlhash_add (ehash, uid, calobj);
			break;
		}

		g_free (calobj);
		g_object_unref (comp);
	}
	g_list_free (list);

	/* Calculate deletions */
	be_data.backend = cbmapi;
	be_data.kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
	be_data.deletes = NULL;
	be_data.ehash = ehash;
   	e_xmlhash_foreach_key (ehash, (EXmlHashFunc)e_cal_backend_mapi_compute_changes_foreach_key, &be_data);

	*deletes = be_data.deletes;

	e_xmlhash_write (ehash);
  	e_xmlhash_destroy (ehash);

	return GNOME_Evolution_Calendar_Success;
}

static ECalBackendSyncStatus
e_cal_backend_mapi_get_changes (ECalBackendSync *backend, EDataCal *cal, const char *change_id,
				GList **adds, GList **modifies, GList **deletes)
{
	ECalBackendMAPI *cbmapi;

	cbmapi = E_CAL_BACKEND_MAPI (backend);

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), GNOME_Evolution_Calendar_InvalidObject);
	g_return_val_if_fail (change_id != NULL, GNOME_Evolution_Calendar_ObjectNotFound);

	return e_cal_backend_mapi_compute_changes (cbmapi, change_id, adds, modifies, deletes);

}


/***** BACKEND CLASS FUNCTIONS *****/
static gboolean	
e_cal_backend_mapi_is_loaded (ECalBackend *backend)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	return priv->cache ? TRUE : FALSE;
}

static void 
e_cal_backend_mapi_start_query (ECalBackend *backend, EDataCalView *query)
{
        ECalBackendSyncStatus status;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
        GList *objects = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

        status = e_cal_backend_mapi_get_object_list (E_CAL_BACKEND_SYNC (backend), NULL,
						     e_data_cal_view_get_text (query), &objects);
        if (status != GNOME_Evolution_Calendar_Success) {
		e_data_cal_view_notify_done (query, status);
                return;
	}

       	/* notify listeners of all objects */
	if (objects) {
		e_data_cal_view_notify_objects_added (query, (const GList *) objects);
		/* free memory */
		g_list_foreach (objects, (GFunc) g_free, NULL);
		g_list_free (objects);
	}

	e_data_cal_view_notify_done (query, GNOME_Evolution_Calendar_Success);
}

static CalMode 
e_cal_backend_mapi_get_mode (ECalBackend *backend)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	return priv->mode;
}

static void 
e_cal_backend_mapi_set_mode (ECalBackend *backend, CalMode mode)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	if (!priv->mode && priv->mode == mode) {
		e_cal_backend_notify_mode (backend, GNOME_Evolution_Calendar_CalListener_MODE_SET,
				  	   cal_mode_to_corba (mode));
		return;
	}	

	g_mutex_lock (priv->mutex);

	priv->mode_changed = TRUE;
	switch (mode) {
		case CAL_MODE_REMOTE:
			priv->mode = CAL_MODE_REMOTE;
			priv->read_only = FALSE;
			e_cal_backend_notify_mode (backend, GNOME_Evolution_Calendar_CalListener_MODE_SET,
					GNOME_Evolution_Calendar_MODE_REMOTE);
			e_cal_backend_notify_readonly (backend, priv->read_only);
			if (e_cal_backend_mapi_is_loaded (backend))
		              e_cal_backend_notify_auth_required(backend);
			break;
		case CAL_MODE_LOCAL:
			priv->mode = CAL_MODE_LOCAL;
			priv->read_only = TRUE;
			/* do we have to close the connection here ? */
			e_cal_backend_notify_mode (backend, GNOME_Evolution_Calendar_CalListener_MODE_SET,
					GNOME_Evolution_Calendar_MODE_REMOTE);
			e_cal_backend_notify_readonly (backend, priv->read_only);
			break;
		default:
			e_cal_backend_notify_mode (backend, GNOME_Evolution_Calendar_CalListener_MODE_NOT_SUPPORTED,
					cal_mode_to_corba (mode));
	}	

	g_mutex_unlock (priv->mutex);
}

static icaltimezone * 
e_cal_backend_mapi_internal_get_default_timezone (ECalBackend *backend)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	return priv->default_zone;
}

static icaltimezone *
e_cal_backend_mapi_internal_get_timezone (ECalBackend *backend, const char *tzid)
{
	icaltimezone *zone;

	zone = icaltimezone_get_builtin_timezone_from_tzid (tzid);

	if (!zone && E_CAL_BACKEND_CLASS (parent_class)->internal_get_timezone)
		zone = E_CAL_BACKEND_CLASS (parent_class)->internal_get_timezone (backend, tzid);

	if (!zone)
		return icaltimezone_get_utc_timezone ();

	return zone;
}


/* MAPI CLASS INIT */
static void 
e_cal_backend_mapi_class_init (ECalBackendMAPIClass *class)
{
	GObjectClass *object_class;
	ECalBackendSyncClass *sync_class;
	ECalBackendClass *backend_class;
	
	object_class = (GObjectClass *) class;
	sync_class = (ECalBackendSyncClass *) class;
	backend_class = (ECalBackendClass *) class;
	
	parent_class = g_type_class_peek_parent (class);

	object_class->dispose = e_cal_backend_mapi_dispose;
	object_class->finalize = e_cal_backend_mapi_finalize;

	sync_class->is_read_only_sync = e_cal_backend_mapi_is_read_only;
	sync_class->get_cal_address_sync = e_cal_backend_mapi_get_cal_address;
	sync_class->get_alarm_email_address_sync = e_cal_backend_mapi_get_alarm_email_address;
	sync_class->get_ldap_attribute_sync = e_cal_backend_mapi_get_ldap_attribute;
	sync_class->get_static_capabilities_sync = e_cal_backend_mapi_get_static_capabilities;
	sync_class->open_sync = e_cal_backend_mapi_open;
	sync_class->remove_sync = e_cal_backend_mapi_remove;
	sync_class->get_default_object_sync = e_cal_backend_mapi_get_default_object;
	sync_class->get_object_sync = e_cal_backend_mapi_get_object;
	sync_class->get_object_list_sync = e_cal_backend_mapi_get_object_list;
	sync_class->get_attachment_list_sync = e_cal_backend_mapi_get_attachment_list;
	sync_class->create_object_sync = e_cal_backend_mapi_create_object;
	sync_class->modify_object_sync = e_cal_backend_mapi_modify_object;
	sync_class->remove_object_sync = e_cal_backend_mapi_remove_object;
	sync_class->discard_alarm_sync = e_cal_backend_mapi_discard_alarm;
	sync_class->receive_objects_sync = e_cal_backend_mapi_receive_objects;
	sync_class->send_objects_sync = e_cal_backend_mapi_send_objects;
	sync_class->get_timezone_sync = e_cal_backend_mapi_get_timezone;
	sync_class->add_timezone_sync = e_cal_backend_mapi_add_timezone;
	sync_class->set_default_zone_sync = e_cal_backend_mapi_set_default_zone;
	sync_class->get_freebusy_sync = e_cal_backend_mapi_get_free_busy;
	sync_class->get_changes_sync = e_cal_backend_mapi_get_changes;

	backend_class->is_loaded = e_cal_backend_mapi_is_loaded;
	backend_class->start_query = e_cal_backend_mapi_start_query;
	backend_class->get_mode = e_cal_backend_mapi_get_mode;
	backend_class->set_mode = e_cal_backend_mapi_set_mode;
	backend_class->internal_get_default_timezone = e_cal_backend_mapi_internal_get_default_timezone;
	backend_class->internal_get_timezone = e_cal_backend_mapi_internal_get_timezone;
}


static void
e_cal_backend_mapi_init (ECalBackendMAPI *cbmapi, ECalBackendMAPIClass *class)
{
	ECalBackendMAPIPrivate *priv;
	
	priv = g_new0 (ECalBackendMAPIPrivate, 1);

	priv->timeout_id = 0;
	priv->sendoptions_sync_timeout = 0;

	/* create the mutex for thread safety */
	priv->mutex = g_mutex_new ();

	cbmapi->priv = priv;

	e_cal_backend_sync_set_lock (E_CAL_BACKEND_SYNC (cbmapi), TRUE);
}

GType
e_cal_backend_mapi_get_type (void)
{
	static GType e_cal_backend_mapi_type = 0;

	if (!e_cal_backend_mapi_type) {
		static GTypeInfo info = {
                        sizeof (ECalBackendMAPIClass),
                        (GBaseInitFunc) NULL,
                        (GBaseFinalizeFunc) NULL,
                        (GClassInitFunc) e_cal_backend_mapi_class_init,
                        NULL, NULL,
                        sizeof (ECalBackendMAPI),
                        0,
                        (GInstanceInitFunc) e_cal_backend_mapi_init
                };
		e_cal_backend_mapi_type = g_type_register_static (E_TYPE_CAL_BACKEND_SYNC,
								  "ECalBackendMAPI", &info, 0);
	}

	return e_cal_backend_mapi_type;
}


/***** UTILITY FUNCTIONS *****/
const char *	
e_cal_backend_mapi_get_local_attachments_store (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->local_attachments_store;
}

const char *	
e_cal_backend_mapi_get_owner_name (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->owner_name;
}

const char *	
e_cal_backend_mapi_get_owner_email (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->owner_email;
}

const char *	
e_cal_backend_mapi_get_user_name (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->user_name;
}

const char *	
e_cal_backend_mapi_get_user_email (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->user_email;
}
