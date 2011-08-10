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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <gio/gio.h>

#include <libical/icaltz-util.h>

#include <libedata-cal/e-cal-backend-file-store.h>
#include <libedataserver/e-xml-hash-utils.h>

#include <exchange-mapi-connection.h>
#include <exchange-mapi-cal-utils.h>
#include <exchange-mapi-utils.h>
#include <em-operation-queue.h>

#include "e-cal-backend-mapi.h"

#define d(x)

#ifdef G_OS_WIN32
/* Undef the similar macro from pthread.h, it doesn't check if
 * gmtime() returns NULL.
 */
#undef gmtime_r

/* The gmtime() in Microsoft's C library is MT-safe */
#define gmtime_r(tp,tmp) (gmtime(tp)?(*(tmp)=*gmtime(tp),(tmp)):0)
#endif

#define EDC_ERROR(_code) e_data_cal_create_error (_code, NULL)
#define EDC_ERROR_EX(_code, _msg) e_data_cal_create_error (_code, _msg)

#define SERVER_UTC_TIME "server_utc_time"
#define CACHE_MARKER "populated"

G_DEFINE_TYPE (ECalBackendMAPI, e_cal_backend_mapi, E_TYPE_CAL_BACKEND)

typedef struct {
	GCond *cond;
	GMutex *mutex;
	gboolean exit;
} SyncDelta;

/* Private part of the CalBackendMAPI structure */
struct _ECalBackendMAPIPrivate {
	EMOperationQueue *op_queue;

	mapi_id_t		fid;
	uint32_t		olFolder;
	gchar			*profile;
	ExchangeMapiConnection  *conn;

	/* These fields are entirely for access rights */
	gchar			*owner_name;
	gchar			*owner_email;
	gchar			*user_name;
	gchar			*user_email;

	/* A mutex to control access to the private structure */
	GMutex			*mutex;
	ECalBackendStore	*store;
	gboolean		read_only;
	gchar			*uri;
	gboolean		mode_changed;
	gboolean		populating_cache; /* whether in populate_cache */
	GMutex			*updating_mutex;

	/* timeout handler for syncing sendoptions */
	guint			sendoptions_sync_timeout;

	/* used exclusively for delta fetching */
	guint			timeout_id;
	GThread			*dthread;
	SyncDelta		*dlock;
};

#define CACHE_REFRESH_INTERVAL 600000

static GStaticMutex auth_mutex = G_STATIC_MUTEX_INIT;

static void
mapi_error_to_edc_error (GError **perror, const GError *mapi_error, EDataCalCallStatus code, const gchar *context)
{
	gchar *err_msg = NULL;

	if (!perror)
		return;

	if (code == OtherError && mapi_error) {
		/* Change error to more accurate only with OtherError */
		switch (mapi_error->code) {
		case MAPI_E_PASSWORD_CHANGE_REQUIRED:
		case MAPI_E_PASSWORD_EXPIRED:
			code = AuthenticationRequired;
			break;
		default:
			break;
		}
	}

	if (context)
		err_msg = g_strconcat (context, mapi_error ? ": " : NULL, mapi_error ? mapi_error->message : NULL, NULL);
	else if (!mapi_error)
		err_msg = g_strdup (_("Unknown error"));

	g_propagate_error (perror, EDC_ERROR_EX (code, err_msg ? err_msg : mapi_error->message));

	g_free (err_msg);
}

/* **** UTILITY FUNCTIONS **** */

static const gchar *
ecbm_get_owner_name (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->owner_name;
}

static const gchar *
ecbm_get_owner_email (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->owner_email;
}

static const gchar *
ecbm_get_user_name (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->user_name;
}

static const gchar *
ecbm_get_user_email (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	return priv->user_email;
}

static gboolean
ecbm_get_backend_property (ECalBackend *backend, EDataCal *cal, const gchar *prop_name, gchar **prop_value, GError **perror)
{
	gboolean processed = TRUE;

	g_return_val_if_fail (backend != NULL, FALSE);
	g_return_val_if_fail (prop_name != NULL, FALSE);
	g_return_val_if_fail (prop_value != NULL, FALSE);

	if (g_str_equal (prop_name, CLIENT_BACKEND_PROPERTY_CAPABILITIES)) {
		*prop_value = g_strdup (
				CAL_STATIC_CAPABILITY_NO_ALARM_REPEAT ","
				CAL_STATIC_CAPABILITY_NO_AUDIO_ALARMS ","
				CAL_STATIC_CAPABILITY_NO_EMAIL_ALARMS ","
				CAL_STATIC_CAPABILITY_NO_PROCEDURE_ALARMS ","
				CAL_STATIC_CAPABILITY_ONE_ALARM_ONLY ","
				CAL_STATIC_CAPABILITY_REMOVE_ALARMS ","
				CAL_STATIC_CAPABILITY_NO_THISANDFUTURE ","
				CAL_STATIC_CAPABILITY_NO_THISANDPRIOR ","
				CAL_STATIC_CAPABILITY_CREATE_MESSAGES ","
				CAL_STATIC_CAPABILITY_NO_CONV_TO_ASSIGN_TASK ","
				CAL_STATIC_CAPABILITY_NO_CONV_TO_RECUR ","
				CAL_STATIC_CAPABILITY_HAS_UNACCEPTED_MEETING ","
				CAL_STATIC_CAPABILITY_REFRESH_SUPPORTED
				  );
	} else if (g_str_equal (prop_name, CAL_BACKEND_PROPERTY_CAL_EMAIL_ADDRESS)) {
		ECalBackendMAPI *cbmapi;
		ECalBackendMAPIPrivate *priv;

		cbmapi = E_CAL_BACKEND_MAPI (backend);
		priv = cbmapi->priv;

		*prop_value = g_strdup (priv->user_email);
	} else if (g_str_equal (prop_name, CAL_BACKEND_PROPERTY_ALARM_EMAIL_ADDRESS)) {
		/* We don't support email alarms. This should not have been called. */
		*prop_value = NULL;
	} else if (g_str_equal (prop_name, CAL_BACKEND_PROPERTY_DEFAULT_OBJECT)) {
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
			g_propagate_error (perror, EDC_ERROR (ObjectNotFound));
			return TRUE;
		}

		*prop_value = e_cal_component_get_as_string (comp);
		g_object_unref (comp);
	} else {
		processed = FALSE;
	}

	return processed;
}

static void
ecbm_refresh (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, GError **perror)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	if (priv && priv->dlock && priv->dlock->cond)
		g_cond_signal (priv->dlock->cond);
}

static void
ecbm_remove (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, GError **perror)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	ESource *source = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	source = e_cal_backend_get_source (E_CAL_BACKEND (cbmapi));

	if (!e_cal_backend_is_online (backend) || !priv->conn || !exchange_mapi_connection_connected (priv->conn)) {
		g_propagate_error (perror, EDC_ERROR (RepositoryOffline));
		return;
	}
	if (g_strcmp0 (e_source_get_property (source, "public"), "yes") != 0) {
		GError *mapi_error = NULL;

		if (!exchange_mapi_connection_remove_folder (priv->conn, priv->fid, 0, &mapi_error)) {
			mapi_error_to_edc_error (perror, mapi_error, OtherError, _("Failed to remove public folder"));
			if (mapi_error)
				g_error_free (mapi_error);
			return;
		}
	}

	g_mutex_lock (priv->mutex);

	/* remove the cache */
	if (priv->store)
		e_cal_backend_store_remove (priv->store);

	g_mutex_unlock (priv->mutex);
}

#if 0
static const gchar *
get_element_type (icalcomponent_kind kind)
{

	const gchar *type = "";

	if (kind == ICAL_VEVENT_COMPONENT)
		type = "Appointment";
	else if (kind == ICAL_VTODO_COMPONENT)
		type = "Task";
	else if (kind == ICAL_VJOURNAL_COMPONENT)
		type = "Note";

	return type;

}
#endif

struct EMAPIProgressData
{
	gint percent;
	const gchar *msg;
};

static gboolean
view_progress_cb (EDataCalView *view, gpointer user_data)
{
	struct EMAPIProgressData *pd = user_data;

	g_return_val_if_fail (pd != NULL, FALSE);

	if (!e_data_cal_view_is_completed (view) && !e_data_cal_view_is_stopped (view))
		e_data_cal_view_notify_progress (view, pd->percent, pd->msg);

	/* continue with the next */
	return TRUE;
}

static void
notify_view_progress (ECalBackendMAPI *cbmapi, guint64 index, guint64 total)
{
	struct EMAPIProgressData pd = { 0 };
	gchar *progress_string;

	pd.percent = ((gfloat) index/total) * 100;
	if (pd.percent > 100)
		pd.percent = 99;

	/* To translators: This message is displayed on the status bar when calendar/tasks/memo items are being fetched from the server. */
	progress_string = g_strdup_printf (_("Loading items in folder %s"),
				e_source_peek_name (e_cal_backend_get_source (E_CAL_BACKEND (cbmapi))));

	pd.msg = progress_string;

	e_cal_backend_foreach_view (E_CAL_BACKEND (cbmapi), view_progress_cb, &pd);

	g_free (progress_string);
}

static gboolean
view_completed_cb (EDataCalView *view, gpointer user_data)
{
	if (!e_data_cal_view_is_completed (view) && !e_data_cal_view_is_stopped (view))
		e_data_cal_view_notify_complete (view, NULL);

	return TRUE;
}

static void
notify_view_completed (ECalBackendMAPI *cbmapi)
{
	e_cal_backend_foreach_view (E_CAL_BACKEND (cbmapi), view_completed_cb, NULL);
}

static icaltimezone *
resolve_tzid (const char *tzid, gpointer user_data)
{
	icaltimezone *zone;

	zone = (!strcmp (tzid, "UTC"))
		? icaltimezone_get_utc_timezone ()
		: icaltimezone_get_builtin_timezone_from_tzid (tzid);

	if (!zone)
		zone = e_cal_backend_internal_get_timezone (E_CAL_BACKEND (user_data), tzid);

	return zone;
}

static void
put_component_to_store (ECalBackendMAPI *cbmapi,
			ECalComponent *comp)
{
	time_t time_start, time_end;
	ECalBackendMAPIPrivate *priv;

	priv = cbmapi->priv;

	e_cal_util_get_component_occur_times (comp, &time_start, &time_end,
						resolve_tzid, cbmapi, icaltimezone_get_utc_timezone (),
						e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi)));

	e_cal_backend_store_put_component_with_time_range (priv->store, comp, time_start, time_end);
}

static gboolean
mapi_cal_get_changes_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct mapi_SPropValue_array *array = item_data->properties;
	const mapi_id_t mid = item_data->mid;
	GSList *streams = item_data->streams;
	GSList *recipients = item_data->recipients;
	GSList *attachments = item_data->attachments;
	GSList *detached = NULL, *d_i = NULL;
	ECalBackendMAPI *cbmapi	= data;
	ECalBackendMAPIPrivate *priv = cbmapi->priv;
	icalcomponent_kind kind;
	gchar *tmp = NULL;
	ECalComponent *cache_comp = NULL;
	const gchar *cache_dir;
	const bool *recurring;

	kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
	cache_dir = e_cal_backend_get_cache_dir (E_CAL_BACKEND (cbmapi));

	recurring = exchange_mapi_util_find_array_namedid (array, item_data->conn, item_data->fid, PidLidTaskFRecurring);
	if (recurring && *recurring) {
		g_warning ("Encountered a recurring task.");
		exchange_mapi_util_free_stream_list (&streams);
		exchange_mapi_util_free_recipient_list (&recipients);
		exchange_mapi_util_free_attachment_list (&attachments);
		return TRUE;
	}

	tmp = exchange_mapi_util_mapi_id_to_string (mid);
	cache_comp = e_cal_backend_store_get_component (priv->store, tmp, NULL);

	if (cache_comp == NULL) {
		ECalComponent *comp = exchange_mapi_cal_util_mapi_props_to_comp (item_data->conn, item_data->fid, kind, tmp, array,
									streams, recipients, attachments,
									cache_dir, icaltimezone_get_utc_timezone (), FALSE, &detached);

		detached = g_slist_prepend (detached, comp);

		for (d_i = detached; d_i; d_i = g_slist_next (d_i)) {
			comp = d_i->data;

			if (E_IS_CAL_COMPONENT (comp)) {
				gchar *comp_str;

				e_cal_component_commit_sequence (comp);
				put_component_to_store (cbmapi, comp);

				comp_str = e_cal_component_get_as_string (comp);
				e_cal_backend_notify_object_created (E_CAL_BACKEND (cbmapi), comp_str);
				g_free (comp_str);
			}

			g_object_unref (comp);
		}
		g_slist_free (detached);
	} else {
		struct timeval t;

		if (get_mapi_SPropValue_array_date_timeval (&t, array, PR_LAST_MODIFICATION_TIME) == MAPI_E_SUCCESS) {
			struct icaltimetype itt, *cache_comp_lm = NULL;

			itt = icaltime_from_timet_with_zone (t.tv_sec, 0, 0);
			icaltime_set_timezone (&itt, icaltimezone_get_utc_timezone ());

			e_cal_component_get_last_modified (cache_comp, &cache_comp_lm);
			if (!cache_comp_lm || (icaltime_compare (itt, *cache_comp_lm) != 0)) {
				ECalComponent *comp;
				gchar *cache_comp_str = NULL, *modif_comp_str = NULL;

				e_cal_component_commit_sequence (cache_comp);
				cache_comp_str = e_cal_component_get_as_string (cache_comp);

				comp = exchange_mapi_cal_util_mapi_props_to_comp (item_data->conn, item_data->fid, kind, tmp, array,
									streams, recipients, attachments,
									cache_dir, icaltimezone_get_utc_timezone (), FALSE, NULL);

				e_cal_component_commit_sequence (comp);
				modif_comp_str = e_cal_component_get_as_string (comp);

				put_component_to_store (cbmapi, comp);
				e_cal_backend_notify_object_modified (E_CAL_BACKEND (cbmapi), cache_comp_str, modif_comp_str);

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

	notify_view_progress (cbmapi, item_data->index, item_data->total);

	return TRUE;
}

static void
copy_strings_in_slist (GSList *slist)
{
	GSList *l;

	for (l = slist; l; l = l->next) {
		l->data = g_strdup (l->data);
	}
}

struct deleted_items_data {
	ECalBackendMAPI *cbmapi;
	GSList *cache_ids;
	GSList *unknown_mids; /* MIDs of items not in the cache */
};

static gboolean
handle_deleted_items_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	const mapi_id_t mid = item_data->mid;
	struct deleted_items_data *did = data;
	gchar *tmp = NULL;
	GSList *cache_comp_uid = NULL;
	gboolean need_refetch = FALSE;

	g_return_val_if_fail (did != NULL, FALSE);

	tmp = exchange_mapi_util_mapi_id_to_string (mid);
	cache_comp_uid = g_slist_find_custom (did->cache_ids, tmp, (GCompareFunc) (g_ascii_strcasecmp));
	if (cache_comp_uid != NULL) {
		ECalBackendMAPIPrivate *priv = did->cbmapi->priv;
		ECalComponent *comp;

		comp = e_cal_backend_store_get_component (priv->store, cache_comp_uid->data, NULL);
		if (comp) {
			struct icaltimetype *last_mod = NULL;
			struct timeval t;

			e_cal_component_get_last_modified (comp, &last_mod);
			if (!last_mod) {
				need_refetch = TRUE;
			} else if (get_mapi_SPropValue_array_date_timeval (&t, item_data->properties, PR_LAST_MODIFICATION_TIME) == MAPI_E_SUCCESS
			    && icaltime_compare (icaltime_from_timet_with_zone (t.tv_sec, 0, icaltimezone_get_utc_timezone ()), *last_mod) != 0) {
				need_refetch = TRUE;
			}

			if (last_mod)
				e_cal_component_free_icaltimetype (last_mod);

			g_object_unref (comp);
		}

		g_free (cache_comp_uid->data);
		did->cache_ids = g_slist_remove_link (did->cache_ids, cache_comp_uid);
	} else {
		/* fetch it, as it is not in the cache */
		need_refetch = TRUE;
	}

	if (need_refetch) {
		mapi_id_t *nmid = g_new (mapi_id_t, 1);

		*nmid = mid;
		did->unknown_mids = g_slist_prepend (did->unknown_mids, nmid);
	}

	g_free (tmp);
	return TRUE;
}

static gboolean
mapi_cal_get_idlist (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
{
	static const uint32_t cal_IDList[] = {
		PR_FID,
		PR_MID,
		PR_LAST_MODIFICATION_TIME
	};

	g_return_val_if_fail (props != NULL, FALSE);

	return exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, cal_IDList, G_N_ELEMENTS (cal_IDList));
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
	icaltimetype itt_current, itt_cache = icaltime_null_time();
	time_t current_time;
	struct tm tm;
	gchar *time_string = NULL;
	gchar t_str [26];
	const gchar *serv_time;
	struct mapi_SRestriction res;
	gboolean use_restriction = FALSE;
	GSList *ls = NULL;
	struct deleted_items_data did;
	ESource *source = NULL;
	guint32 options= MAPI_OPTIONS_FETCH_ALL;
	gboolean is_public = FALSE;
	TALLOC_CTX *mem_ctx = NULL;
	GError *mapi_error = NULL;

	if (!handle)
		return FALSE;

	cbmapi = (ECalBackendMAPI *) handle;
	priv= cbmapi->priv;
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
	source = e_cal_backend_get_source (E_CAL_BACKEND (cbmapi));
	if (!e_cal_backend_is_online (E_CAL_BACKEND (cbmapi)))
		return FALSE;

	g_mutex_lock (priv->updating_mutex);

	serv_time = e_cal_backend_store_get_key_value (priv->store, SERVER_UTC_TIME);
	if (serv_time)
		itt_cache = icaltime_from_string (serv_time);

	if (!icaltime_is_null_time (itt_cache)) {
		struct SPropValue sprop;
		struct timeval t;

		mem_ctx = talloc_init ("ExchangeMAPI_get_deltas_cal");
		use_restriction = TRUE;
		res.rt = RES_PROPERTY;
		res.res.resProperty.relop = RELOP_GE;
		res.res.resProperty.ulPropTag = PR_LAST_MODIFICATION_TIME;

		t.tv_sec = icaltime_as_timet_with_zone (itt_cache, icaltimezone_get_utc_timezone ());
		t.tv_usec = 0;
		set_SPropValue_proptag_date_timeval (&sprop, PR_LAST_MODIFICATION_TIME, &t);
		cast_mapi_SPropValue (mem_ctx, &(res.res.resProperty.lpProp),
				      &sprop);
	}

	itt_current = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
	current_time = icaltime_as_timet_with_zone (itt_current, icaltimezone_get_utc_timezone ());
	gmtime_r (&current_time, &tm);
	strftime (t_str, 26, "%Y-%m-%dT%H:%M:%SZ", &tm);

	if (g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0) {
		options |= MAPI_OPTIONS_USE_PFSTORE;
		is_public = TRUE;
		use_restriction = FALSE;
	}

	if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, use_restriction ? &res : NULL, NULL,
					is_public ? NULL : exchange_mapi_cal_utils_get_props_cb, GINT_TO_POINTER (kind),
					mapi_cal_get_changes_cb, cbmapi,
					options, &mapi_error)) {
		if (mapi_error) {
			gchar *msg = g_strdup_printf (_("Failed to fetch changes from a server: %s"), mapi_error->message);
			e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), msg);
			g_free (msg);
			g_error_free (mapi_error);
		} else {
			e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Failed to fetch changes from a server"));
		}

		g_mutex_unlock (priv->updating_mutex);
		if (mem_ctx)
			talloc_free (mem_ctx);
		return FALSE;
	}

	notify_view_completed (cbmapi);

	time_string = g_strdup (t_str);
	e_cal_backend_store_put_key_value (priv->store, SERVER_UTC_TIME, time_string);
	g_free (time_string);

	if (mem_ctx) {
		talloc_free (mem_ctx);
		mem_ctx = NULL;
	}
	/* handle deleted items here by going over the entire cache and
	 * checking for deleted items.*/

	/* e_cal_backend_cache_get_keys returns a list of all the keys.
	 * The items in the list are pointers to internal data,
	 * so should not be freed, only the list should. */
	did.cbmapi = cbmapi;
	did.cache_ids = e_cal_backend_store_get_component_ids (priv->store);
	did.unknown_mids = NULL;
	copy_strings_in_slist (did.cache_ids);
	options = 0;

	if (g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0)
		options = MAPI_OPTIONS_USE_PFSTORE;

	if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, NULL, NULL,
						mapi_cal_get_idlist, NULL,
						handle_deleted_items_cb, &did,
						options, &mapi_error)) {
		if (mapi_error) {
			gchar *msg = g_strdup_printf (_("Failed to fetch changes from a server: %s"), mapi_error->message);
			e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), msg);
			g_free (msg);
			g_error_free (mapi_error);
		} else {
			e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Failed to fetch changes from a server"));
		}

		g_slist_foreach (did.cache_ids, (GFunc) g_free, NULL);
		g_slist_free (did.cache_ids);
		g_mutex_unlock (priv->updating_mutex);
		return FALSE;
	}

	options = MAPI_OPTIONS_FETCH_ALL;
	e_cal_backend_store_freeze_changes (priv->store);
	for (ls = did.cache_ids; ls; ls = g_slist_next (ls)) {
		ECalComponent *comp = NULL;
		icalcomponent *icalcomp = NULL;

		comp = e_cal_backend_store_get_component (priv->store, (const gchar *) ls->data, NULL);

		if (!comp)
			continue;

		icalcomp = e_cal_component_get_icalcomponent (comp);
		if (kind == icalcomponent_isa (icalcomp)) {
			gchar *comp_str = NULL;
			ECalComponentId *id = e_cal_component_get_id (comp);

			comp_str = e_cal_component_get_as_string (comp);
			e_cal_backend_notify_object_removed (E_CAL_BACKEND (cbmapi),
					id, comp_str, NULL);
			e_cal_backend_store_remove_component (priv->store, (const gchar *) id->uid, id->rid);

			e_cal_component_free_id (id);
			g_free (comp_str);
		}
		g_object_unref (comp);
	}
	e_cal_backend_store_thaw_changes (priv->store);

	g_slist_foreach (did.cache_ids, (GFunc) g_free, NULL);
	g_slist_free (did.cache_ids);

	if (did.unknown_mids) {
		gint i;
		struct mapi_SRestriction_or *or_res = g_new0 (struct mapi_SRestriction_or, g_slist_length (did.unknown_mids));

		for (i = 0, ls = did.unknown_mids; ls; i++, ls = ls->next) {
			mapi_id_t *pmid = ls->data;

			or_res[i].rt = RES_PROPERTY;
			or_res[i].res.resProperty.relop = RELOP_EQ;
			or_res[i].res.resProperty.ulPropTag = PR_MID;
			or_res[i].res.resProperty.lpProp.ulPropTag = PR_MID;
			or_res[i].res.resProperty.lpProp.value.dbl = *pmid;
		}

		memset (&res, 0, sizeof (struct mapi_SRestriction));
		res.rt = RES_OR;
		res.res.resOr.cRes = g_slist_length (did.unknown_mids);
		res.res.resOr.res = or_res;

		g_slist_foreach (did.unknown_mids, (GFunc) g_free, NULL);
		g_slist_free (did.unknown_mids);

		if (g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0) {
			options |= MAPI_OPTIONS_USE_PFSTORE;
			is_public = TRUE;
		}

		if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, &res, NULL,
					is_public ? NULL : exchange_mapi_cal_utils_get_props_cb, GINT_TO_POINTER (kind),
					mapi_cal_get_changes_cb, cbmapi,
					options, &mapi_error)) {
			if (mapi_error) {
				gchar *msg = g_strdup_printf (_("Failed to fetch changes from a server: %s"), mapi_error->message);
				e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), msg);
				g_free (msg);
				g_error_free (mapi_error);
			} else {
				e_cal_backend_notify_error (E_CAL_BACKEND (cbmapi), _("Failed to fetch changes from a server"));
			}

			g_free (or_res);
			g_mutex_unlock (priv->updating_mutex);
			return FALSE;
		}
		g_free (or_res);
	}

	g_mutex_unlock (priv->updating_mutex);
	return TRUE;
}

static void
ecbm_get_object (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *uid, const gchar *rid, gchar **object, GError **error)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	ECalComponent *comp;

	cbmapi = (ECalBackendMAPI *)(backend);
	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);

	priv = cbmapi->priv;

	g_mutex_lock (priv->mutex);

	/* search the object in the cache */
	comp = e_cal_backend_store_get_component (priv->store, uid, rid);

	if (!comp) {
		/* the object is not in the backend store, double check that it's
		 * also not on the server to prevent for a race condition where we
		 * might otherwise mistakenly generate a new UID */
		g_mutex_unlock (priv->mutex);
		get_deltas (cbmapi);
		g_mutex_lock (priv->mutex);
		comp = e_cal_backend_store_get_component (priv->store, uid, rid);
	}

	if (comp) {
		g_mutex_unlock (priv->mutex);
		if (e_cal_backend_get_kind (E_CAL_BACKEND (backend)) ==
		    icalcomponent_isa (e_cal_component_get_icalcomponent (comp)))
			*object = e_cal_component_get_as_string (comp);
		else
			*object = NULL;

		g_object_unref (comp);

	} else {
		g_mutex_unlock (priv->mutex);
	}

	if (!object || !*object)
		g_propagate_error (error, EDC_ERROR (ObjectNotFound));
}

static void
ecbm_get_object_list (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *sexp, GSList **objects, GError **perror)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	GSList *components, *l;
	ECalBackendSExp *cbsexp;
	gboolean search_needed = TRUE;
	time_t occur_start = -1, occur_end = -1;
	gboolean prunning_by_time;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	g_mutex_lock (priv->mutex);

//	d(g_message (G_STRLOC ": Getting object list (%s)", sexp));

	if (!strcmp (sexp, "#t"))
		search_needed = FALSE;

	cbsexp = e_cal_backend_sexp_new (sexp);

	if (!cbsexp) {
		g_mutex_unlock (priv->mutex);
		g_propagate_error (perror, EDC_ERROR (InvalidQuery));
		return;
	}

	*objects = NULL;
	prunning_by_time = e_cal_backend_sexp_evaluate_occur_times(cbsexp, &occur_start, &occur_end);

	components = prunning_by_time ?
		e_cal_backend_store_get_components_occuring_in_range (priv->store, occur_start, occur_end)
		: e_cal_backend_store_get_components (priv->store);

	for (l = components; l != NULL; l = l->next) {
		ECalComponent *comp = E_CAL_COMPONENT (l->data);
		if (e_cal_backend_get_kind (E_CAL_BACKEND (backend)) ==
				icalcomponent_isa (e_cal_component_get_icalcomponent (comp))) {
			if ((!search_needed) ||
					(e_cal_backend_sexp_match_comp (cbsexp, comp, E_CAL_BACKEND (backend)))) {
				*objects = g_slist_append (*objects, e_cal_component_get_as_string (comp));
			}
		}
	}

	g_object_unref (cbsexp);
	g_slist_foreach (components, (GFunc) g_object_unref, NULL);
	g_slist_free (components);
	g_mutex_unlock (priv->mutex);
}

static void
ecbm_get_attachment_uris (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *uid, const gchar *rid, GSList **list, GError **perror)
{
	/* TODO implement the function */
	g_propagate_error (perror, EDC_ERROR (NotSupported));
}

static guint
get_cache_refresh_interval (void)
{
	guint time_interval;
	const gchar *time_interval_string = NULL;

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
	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), NULL);

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

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), FALSE);

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
	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), FALSE);

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
	GSList *detached = NULL, *d_i = NULL;
	ECalBackendMAPI *cbmapi	= E_CAL_BACKEND_MAPI (data);
	icalcomponent_kind kind;
        ECalComponent *comp = NULL;
	gchar *tmp = NULL;
	const bool *recurring = NULL;
	const gchar *cache_dir;

	kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
	cache_dir = e_cal_backend_get_cache_dir (E_CAL_BACKEND (cbmapi));

//	exchange_mapi_debug_property_dump (properties);

	switch (kind) {
		case ICAL_VTODO_COMPONENT:
			/* FIXME: Evolution does not support recurring tasks */
			recurring = exchange_mapi_util_find_array_namedid (properties, item_data->conn, item_data->fid, PidLidTaskFRecurring);
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
	comp = exchange_mapi_cal_util_mapi_props_to_comp (item_data->conn, item_data->fid, kind, tmp, properties,
							streams, recipients, attachments,
							cache_dir, icaltimezone_get_utc_timezone (), FALSE, &detached);
	g_free (tmp);

	detached = g_slist_prepend (detached, comp);
	for (d_i = detached; d_i; d_i = g_slist_next (d_i)) {
		comp = d_i->data;

		if (E_IS_CAL_COMPONENT (comp)) {
			gchar *comp_str;

			e_cal_component_commit_sequence (comp);
			put_component_to_store (cbmapi, comp);

			comp_str = e_cal_component_get_as_string (comp);
			e_cal_backend_notify_object_created (E_CAL_BACKEND (cbmapi), comp_str);
			g_free (comp_str);
		}

		g_object_unref (comp);
	}
	g_slist_free (detached);

	exchange_mapi_util_free_stream_list (&streams);
	exchange_mapi_util_free_recipient_list (&recipients);
	exchange_mapi_util_free_attachment_list (&attachments);

	notify_view_progress (cbmapi, item_data->index, item_data->total);

	return TRUE;
}

static gboolean
populate_cache (ECalBackendMAPI *cbmapi, GError **perror)
{
	ECalBackendMAPIPrivate *priv;
	ESource *source = NULL;
	icalcomponent_kind kind;
	icaltimetype itt_current;
	time_t current_time;
	struct tm tm;
	gchar *time_string = NULL;
	gchar t_str [26];
	guint32 options= MAPI_OPTIONS_FETCH_ALL;
	gboolean is_public = FALSE;
	GError *mapi_error = NULL;

	priv = cbmapi->priv;

	g_mutex_lock (priv->mutex);
	if (priv->populating_cache) {
		g_mutex_unlock (priv->mutex);
		return TRUE; /* Success */
	}
	priv->populating_cache = TRUE;
	g_mutex_unlock (priv->mutex);

	source = e_cal_backend_get_source (E_CAL_BACKEND (cbmapi));
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));

	itt_current = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
	current_time = icaltime_as_timet_with_zone (itt_current, icaltimezone_get_utc_timezone ());
	gmtime_r (&current_time, &tm);
	strftime (t_str, 26, "%Y-%m-%dT%H:%M:%SZ", &tm);

	if (g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0) {
		options |= MAPI_OPTIONS_USE_PFSTORE;
		is_public = TRUE;
	}

	if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, NULL, NULL,
					is_public ? NULL : exchange_mapi_cal_utils_get_props_cb, GINT_TO_POINTER (kind),
					mapi_cal_cache_create_cb, cbmapi,
					options, &mapi_error)) {
		e_cal_backend_store_thaw_changes (priv->store);
		g_mutex_lock (priv->mutex);
		priv->populating_cache = FALSE;
		g_mutex_unlock (priv->mutex);

		mapi_error_to_edc_error (perror, mapi_error, OtherError, _("Failed to fetch items from a server"));
		if (mapi_error)
			g_error_free (mapi_error);

		return FALSE;
	}

	notify_view_completed (cbmapi);

	time_string = g_strdup (t_str);
	e_cal_backend_store_put_key_value (priv->store, SERVER_UTC_TIME, time_string);

	g_free (time_string);

	e_cal_backend_store_put_key_value (priv->store, CACHE_MARKER, "1");

	g_mutex_lock (priv->mutex);
	priv->populating_cache = FALSE;
	g_mutex_unlock (priv->mutex);

	return TRUE;
}

static gpointer
cache_init (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv = cbmapi->priv;

	if (!e_cal_backend_store_get_key_value (priv->store, CACHE_MARKER)) {
		/* Populate the cache for the first time.*/
		if (!populate_cache (cbmapi, NULL)) {
			g_warning (G_STRLOC ": Could not populate the cache");
			/*FIXME  why dont we do a notify here */
			return NULL;
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

static void
ecbm_connect (ECalBackendMAPI *cbmapi, GError **perror)
{
	ECalBackendMAPIPrivate *priv;
	GThread *thread;
	GError *error = NULL;

	priv = cbmapi->priv;

	if (!priv->fid) {
		g_propagate_error (perror, EDC_ERROR_EX (OtherError, "No folder ID set"));
		return;
	}

	if (!priv->conn || !exchange_mapi_connection_connected (priv->conn)) {
		g_propagate_error (perror, EDC_ERROR (AuthenticationFailed));
		return;
	}

	/* We have established a connection */
	if (priv->store && priv->fid && e_cal_backend_store_put_key_value (priv->store, CACHE_MARKER, "1")) {
		e_cal_backend_notify_online (E_CAL_BACKEND (cbmapi), TRUE);

		if (priv->mode_changed && !priv->dthread) {
			priv->mode_changed = FALSE;
			fetch_deltas (cbmapi);
		}

		/* FIXME: put server UTC time in cache */
		return /* Success */;
	}

	priv->mode_changed = FALSE;

	/* spawn a new thread for caching the calendar items */
	thread = g_thread_create ((GThreadFunc) cache_init, cbmapi, FALSE, &error);
	if (!thread) {
		g_warning (G_STRLOC ": %s", error->message);
		g_error_free (error);
		g_propagate_error (perror, EDC_ERROR_EX (OtherError, _("Could not create thread for populating cache")));
	}
}

static void
ecbm_open (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, gboolean only_if_exists, GError **perror)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	ESource *esource;
	const gchar *fid = NULL;
	const gchar *cache_dir;
	uint32_t olFolder = 0;

	if (e_cal_backend_is_opened (E_CAL_BACKEND (backend))) {
		e_cal_backend_notify_opened (backend, NULL);
		return /* Success */;
	}

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	esource = e_cal_backend_get_source (E_CAL_BACKEND (cbmapi));
	fid = e_source_get_property (esource, "folder-id");
	if (!(fid && *fid)) {
		g_propagate_error (perror, EDC_ERROR_EX (OtherError, "No folder ID set"));
		e_cal_backend_notify_opened (backend, EDC_ERROR_EX (OtherError, "No folder ID set"));
		return;
	}

	g_mutex_lock (priv->mutex);

	cbmapi->priv->read_only = FALSE;

	switch (e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi))) {
	default:
	case ICAL_VEVENT_COMPONENT:
		olFolder = olFolderCalendar;
		break;
	case ICAL_VTODO_COMPONENT:
		olFolder = olFolderTasks;
		break;
	case ICAL_VJOURNAL_COMPONENT:
		olFolder = olFolderNotes;
		break;
	}

	if (priv->store) {
		g_object_unref (priv->store);
		priv->store = NULL;
	}

	/* Always create cache here */
	cache_dir = e_cal_backend_get_cache_dir (backend);
	priv->store = e_cal_backend_file_store_new (cache_dir);

	if (!priv->store) {
		g_mutex_unlock (priv->mutex);
		g_propagate_error (perror, EDC_ERROR_EX (OtherError, _("Could not create cache file")));
		e_cal_backend_notify_opened (backend, EDC_ERROR_EX (OtherError, _("Could not create cache file")));
		return;
	}

	e_cal_backend_store_load (priv->store);

	/* Not for remote */
	if (!e_cal_backend_is_online (backend)) {
		const gchar *display_contents = NULL;

		cbmapi->priv->read_only = TRUE;

		display_contents = e_source_get_property (esource, "offline_sync");

		if (!display_contents || !g_str_equal (display_contents, "1")) {
			g_mutex_unlock (priv->mutex);
			g_propagate_error (perror, EDC_ERROR (RepositoryOffline));
			e_cal_backend_notify_opened (backend, EDC_ERROR (RepositoryOffline));
			return;
		}

		g_mutex_unlock (priv->mutex);
		e_cal_backend_notify_online (backend, FALSE);
		e_cal_backend_notify_readonly (backend, priv->read_only);
		e_cal_backend_notify_opened (backend, NULL);
		return /* Success */;
	}

	priv->profile = g_strdup (e_source_get_property (esource, "profile"));
	priv->user_name = g_strdup (e_source_get_property (esource, "acl-user-name"));
	priv->user_email = g_strdup (e_source_get_property (esource, "acl-user-email"));
	priv->owner_name = g_strdup (e_source_get_property (esource, "acl-owner-name"));
	priv->owner_email = g_strdup (e_source_get_property (esource, "acl-owner-email"));

	exchange_mapi_util_mapi_id_from_string (fid, &priv->fid);
	priv->olFolder = olFolder;

	g_mutex_unlock (priv->mutex);

	e_cal_backend_notify_online (backend, TRUE);
	e_cal_backend_notify_readonly (backend, priv->read_only);
	e_cal_backend_notify_auth_required (backend, TRUE, NULL);
}

static void
ecbm_authenticate_user (ECalBackend *backend, GCancellable *cancellable, ECredentials *credentials, GError **perror)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	ExchangeMapiConnection *old_conn;
	GError *mapi_error = NULL;

	g_static_mutex_lock (&auth_mutex);

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	old_conn = priv->conn;

	priv->conn = exchange_mapi_connection_new (priv->profile, e_credentials_peek (credentials, E_CREDENTIALS_KEY_PASSWORD), &mapi_error);
	if (!priv->conn) {
		priv->conn = exchange_mapi_connection_find (priv->profile);
		if (priv->conn && !exchange_mapi_connection_connected (priv->conn))
			exchange_mapi_connection_reconnect (priv->conn, e_credentials_peek (credentials, E_CREDENTIALS_KEY_PASSWORD), &mapi_error);
	}

	if (old_conn)
		g_object_unref (old_conn);

	if (priv->conn && exchange_mapi_connection_connected (priv->conn)) {
		/* Success */;
	} else {
		mapi_error_to_edc_error (perror, mapi_error, AuthenticationFailed, NULL);
		if (mapi_error)
			g_error_free (mapi_error);
		g_static_mutex_unlock (&auth_mutex);
		return;
	}

	if (mapi_error) {
		mapi_error_to_edc_error (perror, mapi_error, AuthenticationFailed, NULL);
		g_error_free (mapi_error);
		g_static_mutex_unlock (&auth_mutex);
		return;
	}

	g_static_mutex_unlock (&auth_mutex);

	ecbm_connect (cbmapi, perror);
}

static gboolean
mapi_cal_get_required_props (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
{
	static uint32_t req_props_list[] = {
		PR_OWNER_APPT_ID,
		PR_SENT_REPRESENTING_NAME_UNICODE,
		PR_SENT_REPRESENTING_ADDRTYPE_UNICODE,
		PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE,
		PR_SENDER_NAME_UNICODE,
		PR_SENDER_ADDRTYPE_UNICODE,
		PR_SENDER_EMAIL_ADDRESS_UNICODE
	};

	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData nids[] = {
		{ PidLidGlobalObjectId, 0 },
		{ PidLidCleanGlobalObjectId, 0 },
		{ PidLidAppointmentSequence, 0 }
	};

	g_return_val_if_fail (props != NULL, FALSE);

	if (!exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids)))
		return FALSE;

	return exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, req_props_list, G_N_ELEMENTS (req_props_list));
}

static gboolean
capture_req_props (FetchItemsCallbackData *item_data, gpointer data)
{
	struct mapi_SPropValue_array *properties = item_data->properties;
	struct cal_cbdata *cbdata = (struct cal_cbdata *) data;
	const uint32_t *ui32;

	ui32 = (const uint32_t *)find_mapi_SPropValue_data(properties, PR_OWNER_APPT_ID);
	if (ui32)
		cbdata->appt_id = *ui32;
	ui32 = exchange_mapi_util_find_array_namedid (properties, item_data->conn, item_data->fid, PidLidAppointmentSequence);
	if (ui32)
		cbdata->appt_seq = *ui32;
	cbdata->cleanglobalid = exchange_mapi_util_copy_binary_r (exchange_mapi_util_find_array_namedid (properties, item_data->conn, item_data->fid, PidLidCleanGlobalObjectId));
	cbdata->globalid = exchange_mapi_util_copy_binary_r (exchange_mapi_util_find_array_namedid (properties, item_data->conn, item_data->fid, PidLidGlobalObjectId));
	cbdata->username = g_strdup (exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_NAME_UNICODE));
	cbdata->useridtype = g_strdup (exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_ADDRTYPE_UNICODE));
	cbdata->userid = g_strdup (exchange_mapi_util_find_array_propval (properties, PR_SENT_REPRESENTING_EMAIL_ADDRESS_UNICODE));
	cbdata->ownername = g_strdup (exchange_mapi_util_find_array_propval (properties, PR_SENDER_NAME_UNICODE));
	cbdata->owneridtype = g_strdup (exchange_mapi_util_find_array_propval (properties, PR_SENDER_ADDRTYPE_UNICODE));
	cbdata->ownerid = g_strdup (exchange_mapi_util_find_array_propval (properties, PR_SENDER_EMAIL_ADDRESS_UNICODE));

	return TRUE;
}

static void
get_comp_mid (icalcomponent *icalcomp, mapi_id_t *mid)
{
	gchar *x_mid;

	g_return_if_fail (icalcomp != NULL);
	g_return_if_fail (mid != NULL);

	x_mid = exchange_mapi_cal_utils_get_icomp_x_prop (icalcomp, "X-EVOLUTION-MAPI-MID");
	if (x_mid) {
		exchange_mapi_util_mapi_id_from_string (x_mid, mid);
		g_free (x_mid);
	} else {
		exchange_mapi_util_mapi_id_from_string (icalcomponent_get_uid (icalcomp), mid);
	}
}

/* should call free_server_data() before done with cbdata */
static void
get_server_data (ECalBackendMAPI *cbmapi, ECalComponent *comp, struct cal_cbdata *cbdata)
{
	ECalBackendMAPIPrivate *priv = cbmapi->priv;
	icalcomponent *icalcomp;
	const gchar *uid;
	mapi_id_t mid;
	struct mapi_SRestriction res;
	struct SPropValue sprop;
	struct Binary_r sb;
	uint32_t proptag = 0x0;
	gchar *propval;
	TALLOC_CTX *mem_ctx;

	icalcomp = e_cal_component_get_icalcomponent (comp);
	uid = icalcomponent_get_uid (icalcomp);
	get_comp_mid (icalcomp, &mid);
	if (exchange_mapi_connection_fetch_item (priv->conn, priv->fid, mid,
					mapi_cal_get_required_props, NULL,
					capture_req_props, cbdata,
					MAPI_OPTIONS_FETCH_GENERIC_STREAMS, NULL))

		return;

	proptag = exchange_mapi_connection_resolve_named_prop (priv->conn, priv->fid, PidLidCleanGlobalObjectId, NULL);
	if (proptag == MAPI_E_RESERVED) proptag = PidLidCleanGlobalObjectId;

	res.rt = RES_PROPERTY;
	res.res.resProperty.relop = RELOP_EQ;
	res.res.resProperty.ulPropTag = proptag;

	propval = exchange_mapi_cal_utils_get_icomp_x_prop (icalcomp, "X-EVOLUTION-MAPI-GLOBALID");
	if (propval && *propval) {
		gsize len = 0;

		sb.lpb = g_base64_decode (propval, &len);
		sb.cb = len;
	} else {
		struct icaltimetype ical_creation_time = { 0 };
		struct FILETIME creation_time = { 0 };

		e_cal_component_get_dtstamp (comp, &ical_creation_time);

		exchange_mapi_util_time_t_to_filetime (icaltime_as_timet (ical_creation_time), &creation_time);
		exchange_mapi_cal_util_generate_globalobjectid (TRUE, uid, NULL, ical_creation_time.year ? &creation_time : NULL, &sb);
	}
	g_free (propval);

	mem_ctx = talloc_init ("ExchangeMAPI_cal_get_server_data");
	set_SPropValue_proptag (&sprop, proptag, (gconstpointer ) &sb);
	cast_mapi_SPropValue (mem_ctx, &(res.res.resProperty.lpProp), &sprop);

	exchange_mapi_connection_fetch_items (priv->conn, priv->fid, &res, NULL,
					mapi_cal_get_required_props, NULL,
					capture_req_props, cbdata,
					MAPI_OPTIONS_FETCH_GENERIC_STREAMS, NULL);

	talloc_free (mem_ctx);
}

/* frees data members allocated in get_server_data(), not the cbdata itself */
static void
free_server_data (struct cal_cbdata *cbdata)
{
	if (!cbdata)
		return;

	#define do_free(_func, _val) _func (_val); _val = NULL

	do_free (exchange_mapi_util_free_binary_r, cbdata->cleanglobalid);
	do_free (exchange_mapi_util_free_binary_r, cbdata->globalid);
	do_free (g_free, cbdata->username);
	do_free (g_free, cbdata->useridtype);
	do_free (g_free, cbdata->userid);
	do_free (g_free, cbdata->ownername);
	do_free (g_free, cbdata->owneridtype);
	do_free (g_free, cbdata->ownerid);

	#undef do_free
}

#define free_and_dupe_str(_des, _new) G_STMT_START {	\
	g_free (_des);					\
	_des = g_strdup (_new);				\
	} G_STMT_END

static icaltimezone *ecbm_internal_get_timezone (ECalBackend *backend, const gchar *tzid);

static void
ecbm_create_object (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *calobj, gchar **uid, gchar **new_object, GError **error)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;
	ECalComponent *comp;
	mapi_id_t mid = 0;
	gchar *tmp = NULL;
	GSList *recipients = NULL;
	GSList *attachments = NULL;
	GSList *streams = NULL;
	struct cal_cbdata cbdata = { 0 };
	struct icaltimetype current;
	const gchar *cache_dir;
	GError *mapi_error = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	kind = e_cal_backend_get_kind (E_CAL_BACKEND (backend));
	cache_dir = e_cal_backend_get_cache_dir (E_CAL_BACKEND (backend));

	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);
	e_return_data_cal_error_if_fail (calobj != NULL, InvalidArg);
	e_return_data_cal_error_if_fail (new_object != NULL, InvalidArg);

	if (!e_cal_backend_is_online (backend)) {
		g_propagate_error (error, EDC_ERROR (RepositoryOffline));
		return;
	}

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp) {
		g_propagate_error (error, EDC_ERROR (InvalidObject));
		return;
	}

	if (kind != icalcomponent_isa (icalcomp)) {
		icalcomponent_free (icalcomp);
		g_propagate_error (error, EDC_ERROR (InvalidObject));
		return;
	}

	comp = e_cal_component_new ();
	e_cal_component_set_icalcomponent (comp, icalcomp);

	current = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
	e_cal_component_set_created (comp, &current);
	e_cal_component_set_last_modified (comp, &current);

	/* FIXME: [WIP] Add support for recurrences */
	if (e_cal_component_has_recurrences (comp)) {
		GByteArray *ba = exchange_mapi_cal_util_rrule_to_bin (comp, NULL);
		if (ba) {
			ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1);
			stream->value = ba;
			stream->proptag = exchange_mapi_connection_resolve_named_prop (priv->conn, priv->fid, PidLidAppointmentRecur, NULL);
			if (stream->proptag != MAPI_E_RESERVED)
				streams = g_slist_append (streams, stream);
		}
	}

	/* FIXME: [WIP] Add support for meetings/assigned tasks */
	if (e_cal_component_has_attendees (comp))
		exchange_mapi_cal_util_fetch_recipients (comp, &recipients);

	if (e_cal_component_has_attachments (comp))
		exchange_mapi_cal_util_fetch_attachments (comp, &attachments, cache_dir);

	cbdata.kind = kind;
	cbdata.username = (gchar *) ecbm_get_user_name (cbmapi);
	cbdata.useridtype = (gchar *) "SMTP";
	cbdata.userid = (gchar *) ecbm_get_user_email (cbmapi);
	cbdata.ownername = (gchar *) ecbm_get_owner_name (cbmapi);
	cbdata.owneridtype = (gchar *) "SMTP";
	cbdata.ownerid = (gchar *) ecbm_get_owner_email (cbmapi);
	cbdata.get_timezone = (icaltimezone * (*)(gpointer data, const gchar *tzid)) ecbm_internal_get_timezone;
	cbdata.get_tz_data = cbmapi;

	/* Check if object exists */
	if (e_cal_backend_is_online (backend)) {
		/* Create an appointment */
		cbdata.comp = comp;
		cbdata.is_modify = FALSE;
		cbdata.msgflags = MSGFLAG_READ;
		cbdata.meeting_type = (recipients != NULL) ? MEETING_OBJECT : NOT_A_MEETING;
		cbdata.resp = (recipients != NULL) ? olResponseOrganized : olResponseNone;
		cbdata.appt_id = exchange_mapi_cal_util_get_new_appt_id (priv->conn, priv->fid);
		cbdata.appt_seq = 0;
		cbdata.globalid = NULL;
		cbdata.cleanglobalid = NULL;

		mid = exchange_mapi_connection_create_item (priv->conn, priv->olFolder, priv->fid,
						exchange_mapi_cal_utils_write_props_cb, &cbdata,
						recipients, attachments, streams, MAPI_OPTIONS_DONT_SUBMIT, &mapi_error);
		g_free (cbdata.props);
		if (!mid) {
			g_object_unref (comp);
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_stream_list (&streams);
			exchange_mapi_util_free_attachment_list (&attachments);
			mapi_error_to_edc_error (error, mapi_error, OtherError, _("Failed to create item on a server"));
			if (mapi_error)
				g_error_free (mapi_error);
			return;
		}

		tmp = exchange_mapi_util_mapi_id_to_string (mid);
		e_cal_component_set_uid (comp, tmp);
		if (uid)
			*uid = tmp;
		else
			g_free (tmp);

		e_cal_component_commit_sequence (comp);
		put_component_to_store (cbmapi, comp);
		*new_object = e_cal_component_get_as_string (comp);
		e_cal_backend_notify_object_created (E_CAL_BACKEND (cbmapi), *new_object);
	} else {
		exchange_mapi_util_free_recipient_list (&recipients);
		exchange_mapi_util_free_stream_list (&streams);
		exchange_mapi_util_free_attachment_list (&attachments);
		g_propagate_error (error, EDC_ERROR (UnsupportedMethod));
		return;
	}

	if (!fetch_deltas(cbmapi))
		g_cond_signal (priv->dlock->cond);

	g_object_unref (comp);
	exchange_mapi_util_free_recipient_list (&recipients);
	exchange_mapi_util_free_stream_list (&streams);
	exchange_mapi_util_free_attachment_list (&attachments);
}

static gboolean
modifier_is_organizer (ECalBackendMAPI *cbmapi, ECalComponent *comp)
{
	ECalComponentOrganizer org;
	const gchar *ownerid, *orgid;

	if (!e_cal_component_has_organizer(comp))
		return TRUE;

	e_cal_component_get_organizer (comp, &org);
	if (!g_ascii_strncasecmp (org.value, "mailto:", 7))
		orgid = (org.value) + 7;
	else
		orgid = org.value;
	ownerid = ecbm_get_owner_email (cbmapi);

	return (!g_ascii_strcasecmp(orgid, ownerid) ? TRUE : FALSE);
}

static OlResponseStatus
get_trackstatus_from_partstat (icalparameter_partstat partstat)
{
	switch (partstat) {
		case ICAL_PARTSTAT_ACCEPTED	: return olResponseAccepted;
		case ICAL_PARTSTAT_TENTATIVE	: return olResponseTentative;
		case ICAL_PARTSTAT_DECLINED	: return olResponseDeclined;
		default				: return olResponseTentative;
	}
}

static OlResponseStatus
find_my_response (ECalBackendMAPI *cbmapi, ECalComponent *comp)
{
	icalcomponent *icalcomp = e_cal_component_get_icalcomponent (comp);
	icalproperty *attendee;
	gchar *att = NULL;
	OlResponseStatus val = olResponseTentative;

	att = g_strdup_printf ("MAILTO:%s", ecbm_get_owner_email (cbmapi));
	attendee = icalcomponent_get_first_property (icalcomp, ICAL_ATTENDEE_PROPERTY);
	while (attendee) {
		const gchar *value = icalproperty_get_attendee (attendee);
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

static void
ecbm_modify_object (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *calobj, CalObjModType mod, gchar **old_object, gchar **new_object, GError **error)
{
	ECalBackendMAPI *cbmapi;
        ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;
	ECalComponent *comp, *cache_comp = NULL;
	gboolean status;
	mapi_id_t mid;
	const gchar *uid = NULL, *rid = NULL;
	GSList *recipients = NULL;
	GSList *streams = NULL;
	GSList *attachments = NULL;
	struct cal_cbdata cbdata = { 0 };
	gboolean no_increment = FALSE;
	icalproperty *prop;
	struct icaltimetype current;
	const gchar *cache_dir;
	GError *mapi_error = NULL;

	*old_object = *new_object = NULL;
	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	kind = e_cal_backend_get_kind (backend);
	cache_dir = e_cal_backend_get_cache_dir (backend);

	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);
	e_return_data_cal_error_if_fail (calobj != NULL, InvalidArg);

	if (!e_cal_backend_is_online (backend)) {
		g_propagate_error (error, EDC_ERROR (RepositoryOffline));
		return;
	}

	if (mod != CALOBJ_MOD_ALL) {
		g_propagate_error (error, EDC_ERROR_EX (OtherError, _("Support for modifying single instances of a recurring appointment is not yet implemented. No change was made to the appointment on the server.")));
		return;
	}

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp) {
		g_propagate_error (error, EDC_ERROR (InvalidObject));
		return;
	}

	prop = icalcomponent_get_first_property (icalcomp, ICAL_X_PROPERTY);
	while (prop) {
		const gchar *name = icalproperty_get_x_name (prop);
		if (!g_ascii_strcasecmp (name, "X-EVOLUTION-IS-REPLY")) {
			no_increment = TRUE;
			icalcomponent_remove_property (icalcomp, prop);
		}
		prop = icalcomponent_get_next_property (icalcomp, ICAL_X_PROPERTY);
	}

	comp = e_cal_component_new ();
	e_cal_component_set_icalcomponent (comp, icalcomp);

	current = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
	e_cal_component_set_last_modified (comp, &current);

	/* FIXME: [WIP] Add support for recurrences */
	if (e_cal_component_has_recurrences (comp)) {
		GByteArray *ba = exchange_mapi_cal_util_rrule_to_bin (comp, NULL);
		if (ba) {
			ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1);
			stream->value = ba;
			stream->proptag = exchange_mapi_connection_resolve_named_prop (priv->conn, priv->fid, PidLidAppointmentRecur, NULL);
			if (stream->proptag != MAPI_E_RESERVED)
				streams = g_slist_append (streams, stream);
		}
	}

	if (e_cal_component_has_attendees (comp))
		exchange_mapi_cal_util_fetch_recipients (comp, &recipients);

	if (e_cal_component_has_attachments (comp))
		exchange_mapi_cal_util_fetch_attachments (comp, &attachments, cache_dir);

	e_cal_component_get_uid (comp, &uid);
//	rid = e_cal_component_get_recurid_as_string (comp);

	cbdata.kind = kind;
	cbdata.get_timezone = (icaltimezone * (*)(gpointer data, const gchar *tzid)) ecbm_internal_get_timezone;
	cbdata.get_tz_data = cbmapi;

	if (e_cal_backend_is_online (backend)) {
		/* when online, send the item to the server */
		/* check if the object exists */
		cache_comp = e_cal_backend_store_get_component (priv->store, uid, rid);
		if (!cache_comp) {
			get_deltas (cbmapi);
			cache_comp = e_cal_backend_store_get_component (priv->store, uid, rid);
		}

		if (!cache_comp) {
			g_message ("CRITICAL : Could not find the object in cache");
			g_object_unref (comp);
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_stream_list (&streams);
			exchange_mapi_util_free_attachment_list (&attachments);
			g_propagate_error (error, EDC_ERROR (ObjectNotFound));
			return;
		}

		get_comp_mid (e_cal_component_get_icalcomponent (cache_comp), &mid);

		cbdata.comp = comp;
		cbdata.msgflags = MSGFLAG_READ;
		cbdata.is_modify = TRUE;

		get_server_data (cbmapi, comp, &cbdata);
		if (modifier_is_organizer(cbmapi, comp)) {
			cbdata.meeting_type = (recipients != NULL) ? MEETING_OBJECT : NOT_A_MEETING;
			cbdata.resp = (recipients != NULL) ? olResponseOrganized : olResponseNone;
			if (!no_increment)
				cbdata.appt_seq += 1;
			free_and_dupe_str (cbdata.username, ecbm_get_user_name (cbmapi));
			free_and_dupe_str (cbdata.useridtype, "SMTP");
			free_and_dupe_str (cbdata.userid, ecbm_get_user_email (cbmapi));
			free_and_dupe_str (cbdata.ownername, ecbm_get_owner_name (cbmapi));
			free_and_dupe_str (cbdata.owneridtype, "SMTP");
			free_and_dupe_str (cbdata.ownerid, ecbm_get_owner_email (cbmapi));
		} else {
			cbdata.resp = (recipients != NULL) ? find_my_response(cbmapi, comp) : olResponseNone;
			cbdata.meeting_type = (recipients != NULL) ? MEETING_OBJECT_RCVD : NOT_A_MEETING;
		}

		status = exchange_mapi_connection_modify_item (priv->conn, priv->olFolder, priv->fid, mid,
						exchange_mapi_cal_utils_write_props_cb, &cbdata,
						recipients, attachments, streams, MAPI_OPTIONS_DONT_SUBMIT, &mapi_error);
		g_free (cbdata.props);
		free_server_data (&cbdata);
		if (!status) {
			g_object_unref (comp);
			g_object_unref (cache_comp);
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_stream_list (&streams);
			exchange_mapi_util_free_attachment_list (&attachments);

			mapi_error_to_edc_error (error, mapi_error, OtherError, _("Failed to modify item on a server"));
			if (mapi_error)
				g_error_free (mapi_error);
			return;
		}
	} else {
		g_object_unref (comp);
		g_object_unref (cache_comp);
		exchange_mapi_util_free_recipient_list (&recipients);
		exchange_mapi_util_free_stream_list (&streams);
		exchange_mapi_util_free_attachment_list (&attachments);
		g_propagate_error (error, EDC_ERROR (UnsupportedMethod));
		return;
	}

	*old_object = e_cal_component_get_as_string (cache_comp);
	*new_object = e_cal_component_get_as_string (comp);

	put_component_to_store (cbmapi, comp);
	e_cal_backend_notify_object_modified (E_CAL_BACKEND (cbmapi), *old_object, *new_object);

	g_object_unref (comp);
	g_object_unref (cache_comp);
	exchange_mapi_util_free_recipient_list (&recipients);
	exchange_mapi_util_free_stream_list (&streams);
	exchange_mapi_util_free_attachment_list (&attachments);
}

static void
ecbm_remove_object (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable,
				  const gchar *uid, const gchar *rid, CalObjModType mod,
				  gchar **old_object, gchar **object, GError **error)
{
	ECalBackendMAPI *cbmapi;
        ECalBackendMAPIPrivate *priv;
	icalcomponent *icalcomp;
	gchar *calobj = NULL;
	mapi_id_t mid;
	GError *err = NULL;

	*old_object = *object = NULL;
	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);

	if (!e_cal_backend_is_online (backend)) {
		g_propagate_error (error, EDC_ERROR (RepositoryOffline));
		return;
	}

	/* when online, modify/delete the item from the server */
	/* check if the object exists */
	/* FIXME: we may have detached instances which need to be removed */
	ecbm_get_object (backend, cal, NULL, uid, NULL, &calobj, &err);
	if (err) {
		g_propagate_error (error, err);
		return;
	}

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp) {
		g_free (calobj);
		g_propagate_error (error, EDC_ERROR (InvalidObject));
		return;
	}

	get_comp_mid (icalcomp, &mid);

	if (mod == CALOBJ_MOD_THIS && rid && *rid) {
		gchar *obj = NULL, *new_object = NULL, *new_calobj = NULL;
		struct icaltimetype time_rid;

		/*remove a single instance of a recurring event and modify */
		time_rid = icaltime_from_string (rid);
		e_cal_util_remove_instances (icalcomp, time_rid, mod);
		new_calobj  = (gchar *) icalcomponent_as_ical_string_r (icalcomp);
		ecbm_modify_object (backend, cal, cancellable, new_calobj, CALOBJ_MOD_ALL, &obj, &new_object, &err);
		if (!err) {
			*old_object = obj;
			*object = new_object;
		}
		g_free (new_calobj);
	} else {
		GSList *list=NULL, *l, *comp_list = e_cal_backend_store_get_components_by_uid (priv->store, uid);
		GError *ri_error = NULL;

		/*if (e_cal_component_has_attendees (E_CAL_COMPONENT (comp_list->data))) {
		} else {*/
				struct id_list *data = g_new (struct id_list, 1);
				data->id = mid;
				list = g_slist_prepend (list, (gpointer) data);
		/* } */

		if (exchange_mapi_connection_remove_items (priv->conn, priv->olFolder, priv->fid, 0, list, &ri_error)) {
			for (l = comp_list; l; l = l->next) {
				ECalComponent *comp = E_CAL_COMPONENT (l->data);
				ECalComponentId *id = e_cal_component_get_id (comp);

				e_cal_backend_store_remove_component (priv->store, id->uid, id->rid);
				if (!id->rid || !g_str_equal (id->rid, rid))
					e_cal_backend_notify_object_removed (E_CAL_BACKEND (cbmapi), id, e_cal_component_get_as_string (comp), NULL);
				e_cal_component_free_id (id);

				g_object_unref (comp);
			}
			*old_object = g_strdup (calobj);
			*object = NULL;
			err = NULL; /* Success */
		} else
			mapi_error_to_edc_error (&err, ri_error, OtherError, "Cannot remove items from a server");

		g_slist_free (list);
		g_slist_free (comp_list);
	}
	g_free (calobj);

	if (err)
		g_propagate_error (error, err);
}

static void
ecbm_discard_alarm (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *uid, const gchar *rid, const gchar *auid, GError **perror)
{
	g_propagate_error (perror, EDC_ERROR (NotSupported));
}

static void
ecbm_send_objects (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *calobj, GSList **users, gchar **modified_calobj, GError **error)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;
	const gchar *cache_dir;
	GError *mapi_error = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	kind = e_cal_backend_get_kind (E_CAL_BACKEND (backend));
	cache_dir = e_cal_backend_get_cache_dir (E_CAL_BACKEND (backend));

	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);
	e_return_data_cal_error_if_fail (calobj != NULL, InvalidArg);

	if (!e_cal_backend_is_online (backend)) {
		g_propagate_error (error, EDC_ERROR (RepositoryOffline));
		return;
	}

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp) {
		g_propagate_error (error, EDC_ERROR (InvalidObject));
		return;
	}

	*modified_calobj = NULL;
	*users = NULL;

	if (icalcomponent_isa (icalcomp) == ICAL_VCALENDAR_COMPONENT) {
		icalproperty_method method = icalcomponent_get_method (icalcomp);
		icalcomponent *subcomp = icalcomponent_get_first_component (icalcomp, kind);
		while (subcomp) {
			ECalComponent *comp = e_cal_component_new ();
			struct cal_cbdata cbdata = { 0 };
			mapi_id_t mid = 0;
			GSList *recipients = NULL;
			GSList *attachments = NULL;
			GSList *streams = NULL;
			const gchar *compuid;
			gchar *propval;
			struct Binary_r globalid = { 0 }, cleanglobalid = { 0 };
			struct timeval *exception_repleace_time = NULL, ex_rep_time = { 0 };
			struct FILETIME creation_time = { 0 };
			struct icaltimetype ical_creation_time = { 0 };

			e_cal_component_set_icalcomponent (comp, icalcomponent_new_clone (subcomp));

			/* FIXME: Add support for recurrences */
			if (e_cal_component_has_recurrences (comp)) {
				GByteArray *ba = exchange_mapi_cal_util_rrule_to_bin (comp, NULL);
				if (ba) {
					ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1);
					stream->value = ba;
					stream->proptag = exchange_mapi_connection_resolve_named_prop (priv->conn, priv->fid, PidLidAppointmentRecur, NULL);
					if (stream->proptag != MAPI_E_RESERVED)
						streams = g_slist_append (streams, stream);
				}
			}

			if (e_cal_component_has_attachments (comp))
				exchange_mapi_cal_util_fetch_attachments (comp, &attachments, cache_dir);

			cbdata.kind = kind;
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
			case ICAL_METHOD_REPLY:
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
					exchange_mapi_cal_util_fetch_organizer (comp, &recipients);
				break;
			}

			get_server_data (cbmapi, comp, &cbdata);
			free_and_dupe_str (cbdata.username, ecbm_get_user_name (cbmapi));
			free_and_dupe_str (cbdata.useridtype, "SMTP");
			free_and_dupe_str (cbdata.userid, ecbm_get_user_email (cbmapi));
			free_and_dupe_str (cbdata.ownername, ecbm_get_owner_name (cbmapi));
			free_and_dupe_str (cbdata.owneridtype, "SMTP");
			free_and_dupe_str (cbdata.ownerid, ecbm_get_owner_email (cbmapi));
			cbdata.get_timezone = (icaltimezone * (*)(gpointer data, const gchar *tzid)) ecbm_internal_get_timezone;
			cbdata.get_tz_data = cbmapi;

			e_cal_component_get_uid (comp, &compuid);

			e_cal_component_get_dtstamp (comp, &ical_creation_time);
			exchange_mapi_util_time_t_to_filetime (icaltime_as_timet (ical_creation_time), &creation_time);

			propval = exchange_mapi_cal_utils_get_icomp_x_prop (e_cal_component_get_icalcomponent (comp), "X-EVOLUTION-MAPI-EXREPTIME");
			if (propval && *propval) {
				mapi_id_t val64 = 0;

				if (exchange_mapi_util_mapi_id_from_string (propval, &val64)) {
					memcpy (&ex_rep_time, &val64, 8);
					exception_repleace_time = &ex_rep_time;
				}
			}
			g_free (propval);

			/* inherit GlobalID from the source object, if available */
			if (e_cal_component_get_icalcomponent (comp)) {
				propval = exchange_mapi_cal_utils_get_icomp_x_prop (e_cal_component_get_icalcomponent (comp), "X-EVOLUTION-MAPI-GLOBALID");
				if (propval && *propval) {
					gsize len = 0;

					globalid.lpb = g_base64_decode (propval, &len);
					globalid.cb = len;

					cleanglobalid.lpb = g_memdup (globalid.lpb, globalid.cb);
					cleanglobalid.cb = globalid.cb;

					/* PidLidCleanGlobalObjectId is same as PidLidGlobalObjectId,
					   only exception-information are zeros */
					if (cleanglobalid.lpb && cleanglobalid.cb > 20) {
						for (len = 16; len < 20; len++) {
							cleanglobalid.lpb[len] = 0;
						}
					}

					compuid = NULL;
				}

				g_free (propval);
			}

			if (compuid) {
				exchange_mapi_cal_util_generate_globalobjectid (FALSE, compuid, exception_repleace_time, ical_creation_time.year ? &creation_time : NULL, &globalid);
				exchange_mapi_cal_util_generate_globalobjectid (TRUE,  compuid, exception_repleace_time, ical_creation_time.year ? &creation_time : NULL, &cleanglobalid);
			}

			if (cbdata.globalid)
				exchange_mapi_util_free_binary_r (cbdata.globalid);
			if (cbdata.cleanglobalid)
				exchange_mapi_util_free_binary_r (cbdata.cleanglobalid);
			cbdata.globalid = &globalid;
			cbdata.cleanglobalid = &cleanglobalid;

			mid = exchange_mapi_connection_create_item (priv->conn, olFolderSentMail, 0,
							exchange_mapi_cal_utils_write_props_cb, &cbdata,
							recipients, attachments, streams, MAPI_OPTIONS_DELETE_ON_SUBMIT_FAILURE, &mapi_error);
			cbdata.globalid = NULL;
			cbdata.cleanglobalid = NULL;
			free_server_data (&cbdata);
			g_free (cbdata.props);
			g_free (globalid.lpb);
			g_free (cleanglobalid.lpb);

			if (!mid) {
				g_object_unref (comp);
				exchange_mapi_util_free_recipient_list (&recipients);
				exchange_mapi_util_free_attachment_list (&attachments);
				mapi_error_to_edc_error (error, mapi_error, OtherError, _("Failed to create item on a server"));
				if (mapi_error)
					g_error_free (mapi_error);
				return;
			}

			g_object_unref (comp);
			exchange_mapi_util_free_recipient_list (&recipients);
			exchange_mapi_util_free_attachment_list (&attachments);

			subcomp = icalcomponent_get_next_component (icalcomp,
								    e_cal_backend_get_kind (E_CAL_BACKEND (backend)));
		}
	}

	*modified_calobj = g_strdup (calobj);

	icalcomponent_free (icalcomp);
}

static void
ecbm_receive_objects (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *calobj, GError **error)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent_kind kind;
	icalcomponent *icalcomp;
	GError *err = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (backend));

	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);
	e_return_data_cal_error_if_fail (calobj != NULL, InvalidArg);

	if (!e_cal_backend_is_online (backend)) {
		g_propagate_error (error, EDC_ERROR (RepositoryOffline));
		return;
	}

	/* check the component for validity */
	icalcomp = icalparser_parse_string (calobj);
	if (!icalcomp) {
		g_propagate_error (error, EDC_ERROR (InvalidObject));
		return;
	}

	if (icalcomponent_isa (icalcomp) == ICAL_VCALENDAR_COMPONENT) {
		gboolean stop = FALSE;
		icalproperty_method method = icalcomponent_get_method (icalcomp);
		icalcomponent *subcomp = icalcomponent_get_first_component (icalcomp, kind);
		while (subcomp && !stop) {
			ECalComponent *comp = e_cal_component_new ();
			gchar *rid = NULL;
			const gchar *uid;
			gchar *old_object = NULL, *new_object = NULL, *comp_str;

			e_cal_component_set_icalcomponent (comp, icalcomponent_new_clone (subcomp));

			/* FIXME: Add support for recurrences */
			if (e_cal_component_has_recurrences (comp)) {
				g_object_unref (comp);
				g_propagate_error (error, EDC_ERROR_EX (OtherError, "No support for recurrences"));
				return;
			}

			e_cal_component_get_uid (comp, &uid);
			rid = e_cal_component_get_recurid_as_string (comp);

			switch (method) {
			case ICAL_METHOD_REQUEST :
				comp_str = NULL;
				ecbm_get_object (backend, cal, NULL, uid, NULL, &comp_str, &err);
				if (err) {
					g_clear_error (&err);
					comp_str = e_cal_component_get_as_string (comp);
					new_object = comp_str;
					ecbm_create_object (backend, cal, cancellable, comp_str, NULL, &new_object, &err);
					if (new_object == comp_str)
						new_object = NULL;
				} else {
					g_free (comp_str);
					comp_str = e_cal_component_get_as_string (comp);
					ecbm_modify_object (backend, cal, cancellable, comp_str, CALOBJ_MOD_ALL, &old_object, &new_object, &err);
				}
				g_free (comp_str);
				g_free (old_object);
				g_free (new_object);

				if (err)
					stop = TRUE;
				break;
			case ICAL_METHOD_CANCEL :
				ecbm_remove_object (backend, cal, cancellable, uid, rid, CALOBJ_MOD_THIS, &old_object, &new_object, &err);
				if (err)
					stop = TRUE;
				g_free (old_object);
				g_free (new_object);
				break;
			case ICAL_METHOD_REPLY : {
				ECalComponent *cache_comp;

				g_mutex_lock (priv->mutex);
				cache_comp = e_cal_backend_store_get_component (priv->store, uid, NULL);
				g_mutex_unlock (priv->mutex);
				if (cache_comp) {
					gboolean any_changed = FALSE;
					GSList *reply_attendees = NULL, *ri, *cache_attendees = NULL, *ci;

					e_cal_component_get_attendee_list (comp, &reply_attendees);
					e_cal_component_get_attendee_list (cache_comp, &cache_attendees);

					for (ri = reply_attendees; ri; ri = ri->next) {
						ECalComponentAttendee *ra = ri->data;

						if (!ra || !ra->value || !*ra->value)
							continue;

						for (ci = cache_attendees; ci; ci = ci->next) {
							ECalComponentAttendee *ca = ci->data;

							if (!ca || !ca->value || !*ca->value || g_ascii_strcasecmp (ra->value, ca->value) != 0)
								continue;

							if (ca->status == ra->status)
								continue;

							ca->status = ra->status;
							any_changed = TRUE;
						}
					}

					if (any_changed) {
						old_object = NULL;
						new_object = NULL;

						e_cal_component_set_attendee_list (cache_comp, cache_attendees);

						comp_str = e_cal_component_get_as_string (cache_comp);
						ecbm_modify_object (backend, cal, cancellable, comp_str, CALOBJ_MOD_ALL, &old_object, &new_object, &err);

						g_free (old_object);
						g_free (new_object);
						g_free (comp_str);
					}

					e_cal_component_free_attendee_list (reply_attendees);
					e_cal_component_free_attendee_list (cache_attendees);

					if (err)
						stop = TRUE;

					g_object_unref (cache_comp);
				}
				} break;
			default :
				break;
			}

			g_free (rid);
			g_object_unref (comp);

			subcomp = icalcomponent_get_next_component (icalcomp,
								    e_cal_backend_get_kind (E_CAL_BACKEND (backend)));
		}
	}

	if (err)
		g_propagate_error (error, err);
}

static void
ecbm_get_timezone (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *tzid, gchar **object, GError **error)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icaltimezone *zone = NULL;

	cbmapi = (ECalBackendMAPI *) backend;

	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);
	e_return_data_cal_error_if_fail (tzid != NULL, InvalidArg);

	priv = cbmapi->priv;
	e_return_data_cal_error_if_fail (priv != NULL, InvalidArg);

	zone = ecbm_internal_get_timezone (E_CAL_BACKEND (backend), tzid);

	if (!zone) {
		g_propagate_error (error, e_data_cal_create_error (ObjectNotFound, NULL));
	} else {
		icalcomponent *icalcomp;

		icalcomp = icaltimezone_get_component (zone);

		if (!icalcomp) {
			g_propagate_error (error, e_data_cal_create_error (InvalidObject, NULL));
		} else {
			*object = icalcomponent_as_ical_string_r (icalcomp);
		}
	}
}

static void
ecbm_add_timezone (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const gchar *tzobj, GError **error)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	icalcomponent *tz_comp;

	cbmapi = (ECalBackendMAPI *) backend;

	e_return_data_cal_error_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), InvalidArg);
	e_return_data_cal_error_if_fail (tzobj != NULL, InvalidArg);

	priv = cbmapi->priv;

	tz_comp = icalparser_parse_string (tzobj);
	if (!tz_comp) {
		g_propagate_error (error, EDC_ERROR (InvalidObject));
		return;
	}

	if (icalcomponent_isa (tz_comp) == ICAL_VTIMEZONE_COMPONENT) {
		icaltimezone *zone;
		zone = icaltimezone_new ();
		icaltimezone_set_component (zone, tz_comp);

		if (e_cal_backend_store_put_timezone (priv->store, zone) == FALSE) {
			icaltimezone_free (zone, 1);
			g_propagate_error (error, EDC_ERROR_EX (OtherError, "Cannot push timezone to cache"));
			return;
		}
		icaltimezone_free (zone, 1);
	}
}

static void
ecbm_get_free_busy (ECalBackend *backend, EDataCal *cal, GCancellable *cancellable, const GSList *users, time_t start, time_t end, GSList **freebusy, GError **perror)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	GError *mapi_error = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	if (!priv->conn) {
		g_propagate_error (perror, EDC_ERROR (RepositoryOffline));
		return;
	}

	if (!exchange_mapi_cal_utils_get_free_busy_data (priv->conn, users, start, end, freebusy, &mapi_error)) {
		mapi_error_to_edc_error (perror, mapi_error, OtherError, _("Failed to get Free/Busy data"));

		if (mapi_error)
			g_error_free (mapi_error);
	}
}

/***** BACKEND CLASS FUNCTIONS *****/

static void
ecbm_start_view (ECalBackend *backend, EDataCalView *view)
{
        GSList *objects = NULL;
	GError *err = NULL;

        ecbm_get_object_list (backend, NULL, NULL, e_data_cal_view_get_text (view), &objects, &err);
        if (err) {
		e_data_cal_view_notify_complete (view, err);
		g_error_free (err);
                return;
	}

	/* notify listeners of all objects */
	if (objects) {
		e_data_cal_view_notify_objects_added (view, objects);
		/* free memory */
		g_slist_foreach (objects, (GFunc) g_free, NULL);
		g_slist_free (objects);
	}

	e_data_cal_view_notify_complete (view, NULL /* Success */);
}

static void
ecbm_set_online (ECalBackend *backend, gboolean is_online)
{
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;
	gboolean re_open = FALSE;

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;

	if ((e_cal_backend_is_online (backend) ? 1 : 0) == (is_online ? 1 : 0)) {
		return;
	}

	g_mutex_lock (priv->mutex);

	re_open = (e_cal_backend_is_online (backend) ? 1 : 0) < (is_online ? 1 : 0);
	e_cal_backend_notify_online (backend, is_online);

	priv->mode_changed = TRUE;
	if (is_online) {
		priv->read_only = FALSE;
		if (e_cal_backend_is_opened (backend) && re_open)
			e_cal_backend_notify_auth_required (backend, TRUE, NULL);
	} else {
		priv->read_only = TRUE;
	}

	e_cal_backend_notify_readonly (backend, priv->read_only);
	g_mutex_unlock (priv->mutex);
}

static icaltimezone *
ecbm_internal_get_timezone (ECalBackend *backend, const gchar *tzid)
{
	ECalBackendMAPI *cbmapi;
	icaltimezone *zone;

	cbmapi = E_CAL_BACKEND_MAPI (backend);

	g_return_val_if_fail (cbmapi != NULL, NULL);
	g_return_val_if_fail (cbmapi->priv != NULL, NULL);
	g_return_val_if_fail (tzid != NULL, NULL);

	if (tzid && g_str_equal (tzid, "*default-zone*"))
		zone = icaltimezone_get_utc_timezone ();
	else
		zone = (icaltimezone *) e_cal_backend_store_get_timezone (cbmapi->priv->store, tzid);

	if (!zone && E_CAL_BACKEND_CLASS (e_cal_backend_mapi_parent_class)->internal_get_timezone)
		zone = E_CAL_BACKEND_CLASS (e_cal_backend_mapi_parent_class)->internal_get_timezone (backend, tzid);

	if (!zone) {
		if (!tzid || !*tzid)
			return NULL;

		zone = icaltimezone_get_builtin_timezone_from_tzid (tzid);

		if (!zone) {
			const gchar *s, *slash1 = NULL, *slash2 = NULL;

			/* get builtin by a location, if any */
			for (s = tzid; *s; s++) {
				if (*s == '/') {
					slash1 = slash2;
					slash2 = s;
				}
			}

			if (slash1)
				zone = icaltimezone_get_builtin_timezone (slash1 + 1);
			else if (slash2)
				zone = icaltimezone_get_builtin_timezone (tzid);
		}

		if (!zone)
			zone = icaltimezone_get_utc_timezone ();
	}

	return zone;
}

/* Async OP functions, data structures and so on */

typedef enum {
	OP_GET_BACKEND_PROPERTY,
	OP_OPEN,
	OP_AUTHENTICATE_USER,
	OP_REFRESH,
	OP_REMOVE,
	OP_CREATE_OBJECT,
	OP_MODIFY_OBJECT,
	OP_REMOVE_OBJECT,
	OP_DISCARD_ALARM,
	OP_RECEIVE_OBJECTS,
	OP_SEND_OBJECTS,
	OP_GET_OBJECT,
	OP_GET_ATTACHMENT_URIS,
	OP_GET_OBJECT_LIST,
	OP_GET_TIMEZONE,
	OP_ADD_TIMEZONE,
	OP_GET_FREE_BUSY,
	OP_START_VIEW
} OperationType;

typedef struct {
	OperationType ot;

	EDataCal *cal;
	guint32 opid;
	GCancellable *cancellable;
} OperationBase;

typedef struct {
	OperationBase base;

	gboolean only_if_exists;
} OperationOpen;

typedef struct {
	OperationBase base;

	ECredentials *credentials;
	GCancellable *cancellable;
} OperationAuthenticateUser;

typedef struct {
	OperationBase base;

	gchar *calobj;
	CalObjModType mod;
} OperationModify;

typedef struct {
	OperationBase base;

	gchar *uid;
	gchar *rid;
	CalObjModType mod;
} OperationRemove;

typedef struct {
	OperationBase base;

	gchar *str;
} OperationStr;

typedef struct {
	OperationBase base;

	gchar *str1;
	gchar *str2;
} OperationStr2;

typedef struct {
	OperationBase base;

	gchar *uid;
	gchar *rid;
	gchar *auid;
} OperationDiscardAlarm;

typedef struct {
	OperationBase base;

	GSList *users;
	time_t start;
	time_t end;
} OperationGetFreeBusy;

typedef struct {
	OperationBase base;

	EDataCalView *view;
} OperationStartView;

static void
ecbm_operation_cb (OperationBase *op, gboolean cancelled, ECalBackend *backend)
{
	GError *error = NULL;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND (backend));
	g_return_if_fail (op != NULL);

	cancelled = cancelled || (op->cancellable && g_cancellable_is_cancelled (op->cancellable));

	switch (op->ot) {
	case OP_GET_BACKEND_PROPERTY: {
		OperationStr *ops1 = (OperationStr *) op;
		if (!cancelled) {
			gchar *value = NULL;

			if (ecbm_get_backend_property (backend, op->cal, ops1->str, &value, &error) || error)
				e_data_cal_respond_get_backend_property (op->cal, op->opid, error, value);
			else
				(* E_CAL_BACKEND_CLASS (e_cal_backend_mapi_parent_class)->get_backend_property) (backend, op->cal, op->opid, op->cancellable, ops1->str);

			g_free (value);
		}
		g_free (ops1->str);
	} break;
	case OP_OPEN: {
		OperationOpen *opo = (OperationOpen *) op;

		if (!cancelled) {
			ecbm_open (backend, op->cal, op->cancellable, opo->only_if_exists, &error);

			e_data_cal_respond_open (op->cal, op->opid, error);
		}
	} break;
	case OP_AUTHENTICATE_USER: {
		OperationAuthenticateUser *opau = (OperationAuthenticateUser *) op;

		if (!cancelled) {
			ecbm_authenticate_user (backend, op->cancellable, opau->credentials, &error);

			e_cal_backend_notify_opened (backend, error);
		}
		e_credentials_free (opau->credentials);
	} break;
	case OP_REFRESH: {
		if (!cancelled) {
			ecbm_refresh (backend, op->cal, op->cancellable, &error);

			e_data_cal_respond_refresh (op->cal, op->opid, error);
		}
	} break;
	case OP_REMOVE: {
		if (!cancelled) {
			ecbm_remove (backend, op->cal, op->cancellable, &error);

			e_data_cal_respond_remove (op->cal, op->opid, error);
		}
	} break;
	case OP_CREATE_OBJECT: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *calobj = ops->str;

		if (!cancelled) {
			gchar *uid = NULL, *modified_calobj = NULL;

			ecbm_create_object (backend, op->cal, op->cancellable, calobj, &uid, &modified_calobj, &error);

			e_data_cal_respond_create_object (op->cal, op->opid, error, uid, modified_calobj);

			/* free memory */
			g_free (uid);

			if (modified_calobj != calobj)
				g_free (modified_calobj);
		}

		g_free (ops->str);
	} break;
	case OP_MODIFY_OBJECT: {
		OperationModify *opm = (OperationModify *) op;

		if (!cancelled) {
			gchar *old_object = NULL;
			gchar *new_object = NULL;

			ecbm_modify_object (backend, op->cal, op->cancellable, opm->calobj, opm->mod, &old_object, &new_object, &error);

			if (new_object)
				e_data_cal_respond_modify_object (op->cal, op->opid, error, old_object, new_object);
			else
				e_data_cal_respond_modify_object (op->cal, op->opid, error, old_object, opm->calobj);

			g_free (old_object);
			g_free (new_object);
		}

		g_free (opm->calobj);
	} break;
	case OP_REMOVE_OBJECT: {
		OperationRemove *opr = (OperationRemove *) op;

		if (!cancelled) {
			gchar *object = NULL, *old_object = NULL;

			ecbm_remove_object (backend, op->cal, op->cancellable, opr->uid, opr->rid, opr->mod, &old_object, &object, &error);

			if (!error) {
				ECalComponentId *id = g_new0 (ECalComponentId, 1);
				id->uid = g_strdup (opr->uid);

				if (opr->mod == CALOBJ_MOD_THIS)
					id->rid = g_strdup (opr->rid);

				e_data_cal_respond_remove_object (op->cal, op->opid, error, id, old_object, object);

				e_cal_component_free_id (id);
			} else
				e_data_cal_respond_remove_object (op->cal, op->opid, error, NULL, old_object, object);

			g_free (old_object);
			g_free (object);
		}

		g_free (opr->uid);
		g_free (opr->rid);
	} break;
	case OP_DISCARD_ALARM: {
		OperationDiscardAlarm *opda = (OperationDiscardAlarm *) op;

		if (!cancelled) {
			ecbm_discard_alarm (backend, op->cal, op->cancellable, opda->uid, opda->rid, opda->auid, &error);

			e_data_cal_respond_discard_alarm (op->cal, op->opid, error);
		}

		g_free (opda->uid);
		g_free (opda->rid);
		g_free (opda->auid);
	} break;
	case OP_RECEIVE_OBJECTS: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *calobj = ops->str;

		if (!cancelled) {
			ecbm_receive_objects (backend, op->cal, op->cancellable, calobj, &error);

			e_data_cal_respond_receive_objects (op->cal, op->opid, error);
		}

		g_free (ops->str);
	} break;
	case OP_SEND_OBJECTS: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *calobj = ops->str;

		if (!cancelled) {
			GSList *users = NULL;
			gchar *modified_calobj = NULL;

			ecbm_send_objects (backend, op->cal, op->cancellable, calobj, &users, &modified_calobj, &error);

			e_data_cal_respond_send_objects (op->cal, op->opid, error, users, modified_calobj);

			g_slist_foreach (users, (GFunc) g_free, NULL);
			g_slist_free (users);
			g_free (modified_calobj);
		}

		g_free (ops->str);
	} break;
	case OP_GET_OBJECT: {
		OperationStr2 *ops2 = (OperationStr2 *) op;
		const gchar *uid = ops2->str1, *rid = ops2->str2;

		if (!cancelled) {
			gchar *object = NULL;

			ecbm_get_object (backend, op->cal, op->cancellable, uid, rid, &object, &error);

			e_data_cal_respond_get_object (op->cal, op->opid, error, object);

			g_free (object);
		}

		g_free (ops2->str1);
		g_free (ops2->str2);
	} break;
	case OP_GET_ATTACHMENT_URIS: {
		OperationStr2 *ops2 = (OperationStr2 *) op;
		const gchar *uid = ops2->str1, *rid = ops2->str2;

		if (!cancelled) {
			GSList *list = NULL;

			ecbm_get_attachment_uris (backend, op->cal, op->cancellable, uid, rid, &list, &error);

			e_data_cal_respond_get_attachment_uris (op->cal, op->opid, error, list);

			g_slist_foreach (list, (GFunc) g_free, NULL);
			g_free (list);
		}

		g_free (ops2->str1);
		g_free (ops2->str2);
	} break;
	case OP_GET_OBJECT_LIST: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *sexp = ops->str;

		if (!cancelled) {
			GSList *objects = NULL;

			ecbm_get_object_list (backend, op->cal, op->cancellable, sexp, &objects, &error);

			e_data_cal_respond_get_object_list (op->cal, op->opid, error, objects);

			g_slist_foreach (objects, (GFunc) g_free, NULL);
			g_slist_free (objects);
		}

		g_free (ops->str);
	} break;
	case OP_GET_TIMEZONE: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *tzid = ops->str;

		if (!cancelled) {
			gchar *object = NULL;

			ecbm_get_timezone (backend, op->cal, op->cancellable, tzid, &object, &error);

			if (!object && tzid) {
				/* fallback if tzid contains only the location of timezone */
				gint i, slashes = 0;

				for (i = 0; tzid [i]; i++) {
					if (tzid [i] == '/')
						slashes++;
				}

				if (slashes == 1) {
					icalcomponent *icalcomp = NULL, *free_comp = NULL;

					icaltimezone *zone = icaltimezone_get_builtin_timezone (tzid);
					if (!zone) {
						/* Try fetching the timezone from zone directory. There are some timezones like MST, US/Pacific etc. which do not appear in
						zone.tab, so they will not be available in the libical builtin timezone */
						icalcomp = free_comp = icaltzutil_fetch_timezone (tzid);
					}

					if (zone)
						icalcomp = icaltimezone_get_component (zone);

					if (icalcomp) {
						icalcomponent *clone = icalcomponent_new_clone (icalcomp);
						icalproperty *prop;

						prop = icalcomponent_get_first_property (clone, ICAL_TZID_PROPERTY);
						if (prop) {
							/* change tzid to our, because the component has the buildin tzid */
							icalproperty_set_tzid (prop, tzid);

							object = icalcomponent_as_ical_string_r (clone);
							g_clear_error (&error);
						}
						icalcomponent_free (clone);
					}

					if (free_comp)
						icalcomponent_free (free_comp);
				}

				/* also cache this timezone to backend */
				if (object)
					ecbm_add_timezone (backend, op->cal, op->cancellable, object, NULL);
			}

			e_data_cal_respond_get_timezone (op->cal, op->opid, error, object);

			g_free (object);
		}

		g_free (ops->str);
	} break;
	case OP_ADD_TIMEZONE: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *tzobj = ops->str;

		if (!cancelled) {
			ecbm_add_timezone (backend, op->cal, op->cancellable, tzobj, &error);

			e_data_cal_respond_add_timezone (op->cal, op->opid, error);
		}

		g_free (ops->str);
	} break;
	case OP_GET_FREE_BUSY: {
		OperationGetFreeBusy *opgfb = (OperationGetFreeBusy *) op;

		if (!cancelled) {
			GSList *freebusy = NULL;

			ecbm_get_free_busy (backend, op->cal, op->cancellable, opgfb->users, opgfb->start, opgfb->end, &freebusy, &error);

			if (freebusy)
				e_data_cal_report_free_busy_data (op->cal, freebusy);
			e_data_cal_respond_get_free_busy (op->cal, op->opid, error);

			g_slist_foreach (freebusy, (GFunc) g_free, NULL);
			g_slist_free (freebusy);
		}

		g_slist_foreach (opgfb->users, (GFunc) g_free, NULL);
		g_slist_free (opgfb->users);
	} break;
	case OP_START_VIEW: {
		OperationStartView *opsv = (OperationStartView *) op;

		if (!cancelled) {
			ecbm_start_view (backend, opsv->view);
			/* do not notify here, is should start its own thread */
		}

		g_object_unref (opsv->view);
	} break;
	}

	if (op->cancellable)
		g_object_unref (op->cancellable);
	if (op->cal)
		g_object_unref (op->cal);

	g_free (op);
}

static GSList *
copy_string_slist (const GSList *lst)
{
	GSList *res, *l;

	res = g_slist_copy ((GSList *) lst);
	for (l = res; l; l = l->next) {
		l->data = g_strdup (l->data);
	}

	return res;
}

static void
base_op_abstract (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, OperationType ot)
{
	OperationBase *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationBase, 1);
	op->ot = ot;
	op->cal = cal;
	op->opid = opid;
	op->cancellable = cancellable;

	em_operation_queue_push (priv->op_queue, op);
}

static void
str_op_abstract (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, const gchar *str, OperationType ot)
{
	OperationStr *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationStr, 1);
	op->base.ot = ot;
	op->base.cal = cal;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->str = g_strdup (str);

	em_operation_queue_push (priv->op_queue, op);
}

static void
str2_op_abstract (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, const gchar *str1, const gchar *str2, OperationType ot)
{
	OperationStr2 *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationStr2, 1);
	op->base.ot = ot;
	op->base.cal = cal;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->str1 = g_strdup (str1);
	op->str2 = g_strdup (str2);

	em_operation_queue_push (priv->op_queue, op);
}

#define BASE_OP_DEF(_func, _ot)										\
static void												\
_func (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable)			\
{													\
	base_op_abstract (backend, cal, opid, cancellable, _ot);					\
}

#define STR_OP_DEF(_func, _ot)										\
static void												\
_func (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable * cancellable, const gchar *str)	\
{													\
	str_op_abstract (backend, cal, opid, cancellable, str, _ot);					\
}

#define STR2_OP_DEF(_func, _ot)									\
static void											\
_func (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, const gchar *str1, const gchar *str2)	\
{												\
	str2_op_abstract (backend, cal, opid, cancellable, str1, str2, _ot);			\
}

static void
ecbm_op_open (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, gboolean only_if_exists)
{
	OperationOpen *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationOpen, 1);
	op->base.ot = OP_OPEN;
	op->base.cal = cal;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->only_if_exists = only_if_exists;

	em_operation_queue_push (priv->op_queue, op);
}

static void
ecbm_op_authenticate_user (ECalBackend *backend, GCancellable *cancellable, ECredentials *credentials)
{
	OperationAuthenticateUser *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationAuthenticateUser, 1);
	op->base.ot = OP_AUTHENTICATE_USER;
	op->base.cal = NULL;
	op->base.opid = 0;
	op->base.cancellable = cancellable;
	op->credentials = e_credentials_new_clone (credentials);

	em_operation_queue_push (priv->op_queue, op);
}

STR_OP_DEF (ecbm_op_get_backend_property, OP_GET_BACKEND_PROPERTY)
BASE_OP_DEF (ecbm_op_refresh, OP_REFRESH)
BASE_OP_DEF (ecbm_op_remove, OP_REMOVE)

STR_OP_DEF (ecbm_op_create_object, OP_CREATE_OBJECT)

static void
ecbm_op_modify_object (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, const gchar *calobj, CalObjModType mod)
{
	OperationModify *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationModify, 1);
	op->base.ot = OP_MODIFY_OBJECT;
	op->base.cal = cal;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->calobj = g_strdup (calobj);
	op->mod = mod;

	em_operation_queue_push (priv->op_queue, op);
}

static void
ecbm_op_remove_object (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, const gchar *uid, const gchar *rid, CalObjModType mod)
{
	OperationRemove *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationRemove, 1);
	op->base.ot = OP_REMOVE_OBJECT;
	op->base.cal = cal;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->uid = g_strdup (uid);
	op->rid = g_strdup (rid);
	op->mod = mod;

	em_operation_queue_push (priv->op_queue, op);
}

static void
ecbm_op_discard_alarm (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, const gchar *uid, const gchar *rid, const gchar *auid)
{
	OperationDiscardAlarm *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationDiscardAlarm, 1);
	op->base.ot = OP_DISCARD_ALARM;
	op->base.cal = cal;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->uid = g_strdup (uid);
	op->rid = g_strdup (rid);
	op->auid = g_strdup (auid);

	em_operation_queue_push (priv->op_queue, op);
}

STR_OP_DEF  (ecbm_op_receive_objects, OP_RECEIVE_OBJECTS)
STR_OP_DEF  (ecbm_op_send_objects, OP_SEND_OBJECTS)
STR2_OP_DEF (ecbm_op_get_object, OP_GET_OBJECT)
STR_OP_DEF  (ecbm_op_get_object_list, OP_GET_OBJECT_LIST)
STR2_OP_DEF (ecbm_op_get_attachment_uris, OP_GET_ATTACHMENT_URIS)
STR_OP_DEF  (ecbm_op_get_timezone, OP_GET_TIMEZONE)
STR_OP_DEF  (ecbm_op_add_timezone, OP_ADD_TIMEZONE)

static void
ecbm_op_start_view (ECalBackend *backend, EDataCalView *view)
{
	OperationStartView *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	op = g_new0 (OperationStartView, 1);
	op->base.ot = OP_START_VIEW;
	op->view = g_object_ref (view);

	em_operation_queue_push (priv->op_queue, op);
}

static void
ecbm_op_get_free_busy (ECalBackend *backend, EDataCal *cal, guint32 opid, GCancellable *cancellable, const GSList *users, time_t start, time_t end)
{
	OperationGetFreeBusy *op;
	ECalBackendMAPI *cbmapi;
	ECalBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (backend));

	cbmapi = E_CAL_BACKEND_MAPI (backend);
	priv = cbmapi->priv;
	g_return_if_fail (priv != NULL);

	if (cal)
		g_object_ref (cal);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationGetFreeBusy, 1);
	op->base.ot = OP_GET_FREE_BUSY;
	op->base.cal = cal;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->users = copy_string_slist (users);
	op->start = start;
	op->end = end;

	em_operation_queue_push (priv->op_queue, op);
}

static void
ecbm_finalize (GObject *object)
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

	if (priv->updating_mutex) {
		g_mutex_free (priv->updating_mutex);
		priv->updating_mutex = NULL;
	}

	if (priv->store) {
		g_object_unref (priv->store);
		priv->store = NULL;
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

	if (priv->sendoptions_sync_timeout) {
		g_source_remove (priv->sendoptions_sync_timeout);
		priv->sendoptions_sync_timeout = 0;
	}

	if (priv->conn) {
		g_object_unref (priv->conn);
		priv->conn = NULL;
	}

	if (priv->op_queue) {
		g_object_unref (priv->op_queue);
		priv->op_queue = NULL;
	}

	g_free (priv);
	cbmapi->priv = NULL;

	if (G_OBJECT_CLASS (e_cal_backend_mapi_parent_class)->finalize)
		(* G_OBJECT_CLASS (e_cal_backend_mapi_parent_class)->finalize) (object);
}

/* MAPI CLASS INIT */
static void
e_cal_backend_mapi_class_init (ECalBackendMAPIClass *class)
{
	GObjectClass *object_class;
	ECalBackendClass *backend_class;

	object_class = (GObjectClass *) class;
	backend_class = (ECalBackendClass *) class;

	object_class->finalize = ecbm_finalize;

	/* functions done asynchronously */
	backend_class->get_backend_property = ecbm_op_get_backend_property;
	backend_class->open = ecbm_op_open;
	backend_class->authenticate_user = ecbm_op_authenticate_user;
	backend_class->refresh = ecbm_op_refresh;
	backend_class->remove = ecbm_op_remove;
	backend_class->get_object = ecbm_op_get_object;
	backend_class->get_object_list = ecbm_op_get_object_list;
	backend_class->get_attachment_uris = ecbm_op_get_attachment_uris;
	backend_class->create_object = ecbm_op_create_object;
	backend_class->modify_object = ecbm_op_modify_object;
	backend_class->remove_object = ecbm_op_remove_object;
	backend_class->discard_alarm = ecbm_op_discard_alarm;
	backend_class->receive_objects = ecbm_op_receive_objects;
	backend_class->send_objects = ecbm_op_send_objects;
	backend_class->get_timezone = ecbm_op_get_timezone;
	backend_class->add_timezone = ecbm_op_add_timezone;
	backend_class->get_free_busy = ecbm_op_get_free_busy;
	backend_class->start_view = ecbm_op_start_view;

	/* functions done synchronously */
	backend_class->set_online = ecbm_set_online;
	backend_class->internal_get_timezone = ecbm_internal_get_timezone;
}

static void
e_cal_backend_mapi_init (ECalBackendMAPI *cbmapi)
{
	ECalBackendMAPIPrivate *priv;

	priv = g_new0 (ECalBackendMAPIPrivate, 1);

	priv->timeout_id = 0;
	priv->sendoptions_sync_timeout = 0;

	/* create the mutex for thread safety */
	priv->mutex = g_mutex_new ();
	priv->updating_mutex = g_mutex_new ();
	priv->populating_cache = FALSE;
	priv->op_queue = em_operation_queue_new ((EMOperationQueueFunc) ecbm_operation_cb, cbmapi);

	cbmapi->priv = priv;
}
