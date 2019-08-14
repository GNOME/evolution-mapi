/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 * Copyright (C) 2017 Red Hat, Inc. (www.redhat.com)
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
 *
 * Authors:
 *    Suman Manjunath <msuman@novell.com>
 */

#include "evolution-mapi-config.h"

#include <glib/gi18n-lib.h>
#include <gio/gio.h>

#include <libedata-cal/libedata-cal.h>
#include <libedataserver/libedataserver.h>

#include "e-mapi-connection.h"
#include "e-mapi-cal-utils.h"
#include "e-mapi-utils.h"
#include "e-source-mapi-folder.h"

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

#define EC_ERROR(_code) e_client_error_create (_code, NULL)
#define EC_ERROR_EX(_code, _msg) e_client_error_create (_code, _msg)
#define ECC_ERROR(_code) e_cal_client_error_create (_code, NULL)

/* Current data version */
#define EMA_DATA_VERSION	1
#define EMA_DATA_VERSION_KEY	"ema-data-version"

struct _ECalBackendMAPIPrivate {
	GRecMutex conn_lock;
	EMapiConnection *conn;
};

G_DEFINE_TYPE_WITH_PRIVATE (ECalBackendMAPI, e_cal_backend_mapi, E_TYPE_CAL_META_BACKEND)

static gchar *	ecb_mapi_dup_component_revision_cb	(ECalCache *cal_cache,
							 ICalComponent *icomp);

static void
ecb_mapi_error_to_client_error (GError **perror,
				const GError *mapi_error,
				GQuark domain,
				gint code,
				const gchar *context)
{
	gchar *err_msg = NULL;

	if (!perror)
		return;

	if (g_error_matches (mapi_error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_propagate_error (perror, g_error_copy (mapi_error));
		return;
	}

	if (domain == E_CLIENT_ERROR && code == E_CLIENT_ERROR_OTHER_ERROR &&
	    mapi_error && mapi_error->domain == E_MAPI_ERROR) {
		/* Change error to more accurate only with OtherError */
		switch (mapi_error->code) {
		case MAPI_E_PASSWORD_CHANGE_REQUIRED:
		case MAPI_E_PASSWORD_EXPIRED:
			code = E_CLIENT_ERROR_AUTHENTICATION_REQUIRED;
			break;
		case ecRpcFailed:
			code = E_CLIENT_ERROR_REPOSITORY_OFFLINE;
			break;
		default:
			break;
		}
	}

	if (context)
		err_msg = g_strconcat (context, mapi_error ? ": " : NULL, mapi_error ? mapi_error->message : NULL, NULL);

	g_set_error_literal (perror, domain, code, err_msg ? err_msg : mapi_error ? mapi_error->message : _("Unknown error"));

	g_free (err_msg);
}

static void
ecb_mapi_lock_connection (ECalBackendMAPI *cbmapi)
{
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi));

	g_rec_mutex_lock (&cbmapi->priv->conn_lock);
}

static void
ecb_mapi_unlock_connection (ECalBackendMAPI *cbmapi)
{
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi));

	g_rec_mutex_unlock (&cbmapi->priv->conn_lock);
}

static CamelMapiSettings *
ecb_mapi_get_collection_settings (ECalBackendMAPI *cbmapi)
{
	ESource *source;
	ESource *collection;
	ESourceCamel *extension;
	ESourceRegistry *registry;
	CamelSettings *settings;
	const gchar *extension_name;

	source = e_backend_get_source (E_BACKEND (cbmapi));
	registry = e_cal_backend_get_registry (E_CAL_BACKEND (cbmapi));

	extension_name = e_source_camel_get_extension_name ("mapi");
	e_source_camel_generate_subtype ("mapi", CAMEL_TYPE_MAPI_SETTINGS);

	/* The collection settings live in our parent data source. */
	collection = e_source_registry_find_extension (registry, source, extension_name);
	g_return_val_if_fail (collection != NULL, NULL);

	extension = e_source_get_extension (collection, extension_name);
	settings = e_source_camel_get_settings (extension);

	g_object_unref (collection);

	return CAMEL_MAPI_SETTINGS (settings);
}

static gboolean
ecb_mapi_open_folder (ECalBackendMAPI *cbmapi,
		      mapi_object_t *out_obj_folder,
		      GCancellable *cancellable,
		      GError **error)
{
	ESource *source;
	ESourceMapiFolder *ext_mapi_folder;
	mapi_id_t fid;
	gchar *foreign_username;
	gboolean success;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), FALSE);
	g_return_val_if_fail (cbmapi->priv->conn != NULL, FALSE);
	g_return_val_if_fail (out_obj_folder != NULL, FALSE);

	source = e_backend_get_source (E_BACKEND (cbmapi));
	ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

	fid = e_source_mapi_folder_get_id (ext_mapi_folder);
	foreign_username = e_source_mapi_folder_dup_foreign_username (ext_mapi_folder);

	if (foreign_username && *foreign_username)
		success = e_mapi_connection_open_foreign_folder (cbmapi->priv->conn, foreign_username, fid, out_obj_folder, cancellable, error);
	else if (e_source_mapi_folder_is_public (ext_mapi_folder))
		success = e_mapi_connection_open_public_folder (cbmapi->priv->conn, fid, out_obj_folder, cancellable, error);
	else
		success = e_mapi_connection_open_personal_folder (cbmapi->priv->conn, fid, out_obj_folder, cancellable, error);

	g_free (foreign_username);

	return success;
}

static void
ecb_mapi_maybe_disconnect (ECalBackendMAPI *cbmapi,
			   const GError *mapi_error)
{
	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi));

	/* no error or already disconnected */
	if (!mapi_error || !cbmapi->priv->conn)
		return;

	if (g_error_matches (mapi_error, E_MAPI_ERROR, ecRpcFailed) ||
	    g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_CALL_FAILED)) {
		e_mapi_connection_disconnect (cbmapi->priv->conn,
			!g_error_matches (mapi_error, E_MAPI_ERROR, ecRpcFailed),
			NULL, NULL);
		g_clear_object (&cbmapi->priv->conn);
	}
}

static void
ecb_mapi_get_comp_mid (ICalComponent *icomp,
		       mapi_id_t *mid)
{
	gchar *x_mid;

	g_return_if_fail (icomp != NULL);
	g_return_if_fail (mid != NULL);

	x_mid = e_cal_util_component_dup_x_property (icomp, "X-EVOLUTION-MAPI-MID");
	if (x_mid) {
		e_mapi_util_mapi_id_from_string (x_mid, mid);
		g_free (x_mid);
	} else {
		e_mapi_util_mapi_id_from_string (i_cal_component_get_uid (icomp), mid);
	}
}

static gboolean
ecb_mapi_capture_req_props (EMapiConnection *conn,
			    TALLOC_CTX *mem_ctx,
			    /* const */ EMapiObject *object,
			    guint32 obj_index,
			    guint32 obj_total,
			    gpointer user_data,
			    GCancellable *cancellable,
			    GError **perror)
{
	struct cal_cbdata *cbdata = user_data;
	const uint32_t *ui32;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (cbdata != NULL, FALSE);

	ui32 = e_mapi_util_find_array_propval (&object->properties, PidTagOwnerAppointmentId);
	if (ui32)
		cbdata->appt_id = *ui32;
	ui32 = e_mapi_util_find_array_propval (&object->properties, PidLidAppointmentSequence);
	if (ui32)
		cbdata->appt_seq = *ui32;

	cbdata->cleanglobalid = e_mapi_util_copy_sbinary_short (e_mapi_util_find_array_propval (&object->properties, PidLidCleanGlobalObjectId));
	cbdata->globalid = e_mapi_util_copy_sbinary_short (e_mapi_util_find_array_propval (&object->properties, PidLidGlobalObjectId));

	cbdata->username = g_strdup (e_mapi_util_find_array_propval (&object->properties, PidTagSentRepresentingName));
	cbdata->useridtype = g_strdup (e_mapi_util_find_array_propval (&object->properties, PidTagSentRepresentingAddressType));
	cbdata->userid = g_strdup (e_mapi_util_find_array_propval (&object->properties, PidTagSentRepresentingEmailAddress));

	cbdata->ownername = g_strdup (e_mapi_util_find_array_propval (&object->properties, PidTagSenderName));
	cbdata->owneridtype = g_strdup (e_mapi_util_find_array_propval (&object->properties, PidTagSenderAddressType));
	cbdata->ownerid = g_strdup (e_mapi_util_find_array_propval (&object->properties, PidTagSenderEmailAddress));

	return TRUE;
}

static gboolean
ecb_mapi_list_for_one_mid_cb (EMapiConnection *conn,
			      TALLOC_CTX *mem_ctx,
			      const ListObjectsData *object_data,
			      guint32 obj_index,
			      guint32 obj_total,
			      gpointer user_data,
			      GCancellable *cancellable,
			      GError **perror)
{
	mapi_id_t *pmid = user_data;

	g_return_val_if_fail (pmid != NULL, FALSE);
	g_return_val_if_fail (object_data != NULL, FALSE);

	*pmid = object_data->mid;

	return TRUE;
}

static gboolean
ecb_mapi_build_global_id_restriction (EMapiConnection *conn,
				      TALLOC_CTX *mem_ctx,
				      struct mapi_SRestriction **restrictions,
				      gpointer user_data,
				      GCancellable *cancellable,
				      GError **perror)
{
	ECalComponent *comp = user_data;
	struct SBinary_short sb;
	struct SPropValue sprop;
	struct mapi_SRestriction *restriction;
	gchar *propval;

	g_return_val_if_fail (restrictions != NULL, FALSE);
	g_return_val_if_fail (comp != NULL, FALSE);

	restriction = talloc_zero (mem_ctx, struct mapi_SRestriction);
	g_return_val_if_fail (restriction != NULL, FALSE);

	restriction->rt = RES_PROPERTY;
	restriction->res.resProperty.relop = RELOP_EQ;
	restriction->res.resProperty.ulPropTag = PidLidGlobalObjectId;

	propval = e_cal_util_component_dup_x_property (e_cal_component_get_icalcomponent (comp), "X-EVOLUTION-MAPI-GLOBALID");
	if (propval && *propval) {
		gsize len = 0;

		sb.lpb = g_base64_decode (propval, &len);
		sb.cb = len;
	} else {
		ICalTime *dtstamp;
		struct FILETIME creation_time = { 0 };
		const gchar *uid;

		uid = e_cal_component_get_uid (comp);

		dtstamp = e_cal_component_get_dtstamp (comp);
		if (!dtstamp)
			dtstamp = i_cal_time_new_null_time ();

		e_mapi_util_time_t_to_filetime (i_cal_time_as_timet (dtstamp), &creation_time);
		e_mapi_cal_util_generate_globalobjectid (FALSE, uid, NULL, (dtstamp && i_cal_time_get_year (dtstamp)) ? &creation_time : NULL, &sb);

		g_clear_object (&dtstamp);
	}
	g_free (propval);

	set_SPropValue_proptag (&sprop, PidLidGlobalObjectId, &sb);
	cast_mapi_SPropValue (mem_ctx, &(restriction->res.resProperty.lpProp), &sprop);

	*restrictions = restriction;

	return TRUE;
}

static gboolean
ecb_mapi_build_global_id_or_mid_restriction_from_uid (EMapiConnection *conn,
						      TALLOC_CTX *mem_ctx,
						      struct mapi_SRestriction **restrictions,
						      gpointer user_data,
						      GCancellable *cancellable,
						      GError **perror)
{
	const gchar *uid = user_data;
	struct SPropValue sprop;
	struct mapi_SRestriction *restriction;
	mapi_id_t mid = 0;

	g_return_val_if_fail (restrictions != NULL, FALSE);
	g_return_val_if_fail (uid != NULL, FALSE);

	restriction = talloc_zero (mem_ctx, struct mapi_SRestriction);
	g_return_val_if_fail (restriction != NULL, FALSE);

	restriction->rt = RES_PROPERTY;
	restriction->res.resProperty.relop = RELOP_EQ;

	if (e_mapi_util_mapi_id_from_string (uid, &mid) && mid) {
		restriction->res.resProperty.ulPropTag = PidTagMid;

		set_SPropValue_proptag (&sprop, PidTagMid, &mid);
		cast_mapi_SPropValue (mem_ctx, &(restriction->res.resProperty.lpProp), &sprop);
	} else {
		struct SBinary_short sb;
		gsize len = 0;

		sb.lpb = g_base64_decode (uid, &len);
		sb.cb = len;

		restriction->res.resProperty.ulPropTag = PidLidGlobalObjectId;

		set_SPropValue_proptag (&sprop, PidLidGlobalObjectId, &sb);
		cast_mapi_SPropValue (mem_ctx, &(restriction->res.resProperty.lpProp), &sprop);
	}

	*restrictions = restriction;

	return TRUE;
}

/* should call free_server_data() before done with cbdata */
static void
ecb_mapi_get_server_data (ECalBackendMAPI *cbmapi,
			  ECalComponent *comp,
			  struct cal_cbdata *cbdata,
			  GCancellable *cancellable)
{
	EMapiConnection *conn;
	ICalComponent *icomp;
	mapi_id_t mid;
	mapi_object_t obj_folder;
	GError *mapi_error = NULL;

	icomp = e_cal_component_get_icalcomponent (comp);
	ecb_mapi_get_comp_mid (icomp, &mid);

	conn = cbmapi->priv->conn;
	if (!conn)
		goto cleanup;

	if (!ecb_mapi_open_folder (cbmapi, &obj_folder, cancellable, &mapi_error))
		goto cleanup;

	if (!e_mapi_connection_transfer_object (conn, &obj_folder, mid, ecb_mapi_capture_req_props, cbdata, cancellable, &mapi_error)) {
		if (!g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_NOT_FOUND)) {
			g_clear_error (&mapi_error);
			e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
			goto cleanup;
		}

		/* try to find by global-id, if not found by MID */
		g_clear_error (&mapi_error);
	}

	if (e_mapi_connection_list_objects (conn, &obj_folder,
					    ecb_mapi_build_global_id_restriction, comp,
					    ecb_mapi_list_for_one_mid_cb, &mid,
					    cancellable, &mapi_error)) {
		e_mapi_connection_transfer_object (conn, &obj_folder, mid, ecb_mapi_capture_req_props, cbdata, cancellable, &mapi_error);
	}

	e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

 cleanup:
	ecb_mapi_maybe_disconnect (cbmapi, mapi_error);
	g_clear_error (&mapi_error);
}

/* frees data members allocated in get_server_data(), not the cbdata itself */
static void
ecb_mapi_free_server_data (struct cal_cbdata *cbdata)
{
	if (!cbdata)
		return;

	#define do_free(_func, _val) _func (_val); _val = NULL

	do_free (e_mapi_util_free_sbinary_short, cbdata->cleanglobalid);
	do_free (e_mapi_util_free_sbinary_short, cbdata->globalid);
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

static ESource *
ecb_mapi_find_identity_source (ECalBackendMAPI *cbmapi)
{
	ESourceRegistry *registry;
	GList *all_sources, *my_sources, *iter;
	CamelMapiSettings *settings;
	ESource *res = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), NULL);

	settings = ecb_mapi_get_collection_settings (cbmapi);
	g_return_val_if_fail (settings != NULL, NULL);

	registry = e_cal_backend_get_registry (E_CAL_BACKEND (cbmapi));
	all_sources = e_source_registry_list_sources (registry, NULL);
	my_sources = e_mapi_utils_filter_sources_for_profile (all_sources,
		camel_mapi_settings_get_profile (settings));
	g_list_free_full (all_sources, g_object_unref);

	for (iter = my_sources; iter; iter = iter->next) {
		ESource *source = iter->data;

		if (!source)
			continue;

		if (e_source_has_extension (source, E_SOURCE_EXTENSION_MAIL_IDENTITY)) {
			res = g_object_ref (source);
			break;
		}
	}

	g_list_free_full (my_sources, g_object_unref);

	return res;
}

static const gchar *
ecb_mapi_get_owner_name (ECalBackendMAPI *cbmapi)
{
	ESource *identity_source;
	ESourceMailIdentity *identity_ext;
	const gchar *res = NULL;

	identity_source = ecb_mapi_find_identity_source (cbmapi);
	if (!identity_source)
		return NULL;

	identity_ext = e_source_get_extension (identity_source, E_SOURCE_EXTENSION_MAIL_IDENTITY);
	if (identity_ext)
		res = e_source_mail_identity_get_name (identity_ext);

	g_object_unref (identity_source);

	return res;
}

static const gchar *
ecb_mapi_get_owner_email (ECalBackendMAPI *cbmapi)
{
	ESource *identity_source;
	ESourceMailIdentity *identity_ext;
	const gchar *res = NULL;

	identity_source = ecb_mapi_find_identity_source (cbmapi);
	if (!identity_source)
		return NULL;

	identity_ext = e_source_get_extension (identity_source, E_SOURCE_EXTENSION_MAIL_IDENTITY);
	if (identity_ext)
		res = e_source_mail_identity_get_address (identity_ext);

	g_object_unref (identity_source);

	return res;
}

static gboolean
ecb_mapi_modifier_is_organizer (ECalBackendMAPI *cbmapi,
				ECalComponent *comp)
{
	ECalComponentOrganizer *org;
	const gchar *ownerid, *orgid;
	gboolean res;

	if (!e_cal_component_has_organizer (comp))
		return TRUE;

	org = e_cal_component_get_organizer (comp);
	if (!org)
		return TRUE;

	orgid = e_cal_component_organizer_get_value (org);

	if (orgid && !g_ascii_strncasecmp (orgid, "mailto:", 7))
		orgid = orgid + 7;

	ownerid = ecb_mapi_get_owner_email (cbmapi);

	res = g_ascii_strcasecmp (orgid, ownerid) == 0;

	e_cal_component_organizer_free (org);

	return res;
}

static OlResponseStatus
ecb_mapi_find_my_response (ECalBackendMAPI *cbmapi,
			   ECalComponent *comp)
{
	ICalComponent *icomp = e_cal_component_get_icalcomponent (comp);
	ICalProperty *attendee;
	gchar *att = NULL;
	OlResponseStatus val = olResponseTentative;

	att = g_strdup_printf ("mailto:%s", ecb_mapi_get_owner_email (cbmapi));

	for (attendee = i_cal_component_get_first_property (icomp, I_CAL_ATTENDEE_PROPERTY);
	     attendee;
	     g_object_unref (attendee), attendee = i_cal_component_get_next_property (icomp, I_CAL_ATTENDEE_PROPERTY)) {
		const gchar *value = i_cal_property_get_attendee (attendee);
		if (!g_ascii_strcasecmp (value, att)) {
			ICalParameterPartstat partstat = I_CAL_PARTSTAT_NONE;
			ICalParameter *param;

			param = i_cal_property_get_first_parameter (attendee, I_CAL_PARTSTAT_PARAMETER);
			if (param) {
				partstat = i_cal_parameter_get_partstat (param);
				g_object_unref (param);
			}

			switch (partstat) {
			case I_CAL_PARTSTAT_ACCEPTED:
				val = olResponseAccepted;
				break;
			case I_CAL_PARTSTAT_TENTATIVE:
				val = olResponseTentative;
				break;
			case I_CAL_PARTSTAT_DECLINED:
				val = olResponseDeclined;
				break;
			default:
				val = olResponseTentative;
				break;
			}

			g_object_unref (attendee);
			break;
		}
	}

	g_free (att);

	return val;
}

static void
ecb_mapi_server_notification_cb (EMapiConnection *conn,
				 guint event_mask,
				 gpointer event_data,
				 gpointer user_data)
{
	ECalBackendMAPI *cbmapi = user_data;
	mapi_id_t update_folder1 = 0, update_folder2 = 0;

	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi));

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

	if (update_folder1 || update_folder2) {
		ESource *source;
		ESourceMapiFolder *ext_mapi_folder;

		source = e_backend_get_source (E_BACKEND (cbmapi));
		ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

		if (update_folder1 == e_source_mapi_folder_get_id (ext_mapi_folder) ||
		    update_folder2 == e_source_mapi_folder_get_id (ext_mapi_folder)) {
			e_cal_meta_backend_schedule_refresh (E_CAL_META_BACKEND (cbmapi));
		}
	}
}

static gboolean
ecb_mapi_connect_sync (ECalMetaBackend *meta_backend,
		       const ENamedParameters *credentials,
		       ESourceAuthenticationResult *out_auth_result,
		       gchar **out_certificate_pem,
		       GTlsCertificateFlags *out_certificate_errors,
		       GCancellable *cancellable,
		       GError **error)
{
	ECalBackendMAPI *cbmapi;
	EMapiConnection *old_conn;
	CamelMapiSettings *settings;
	ESource *source;
	ESourceMapiFolder *ext_mapi_folder;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (out_auth_result != NULL, FALSE);

	cbmapi = E_CAL_BACKEND_MAPI (meta_backend);

	ecb_mapi_lock_connection (cbmapi);

	if (cbmapi->priv->conn &&
	    e_mapi_connection_connected (cbmapi->priv->conn)) {
		ecb_mapi_unlock_connection (cbmapi);
		return TRUE;
	}

	settings = ecb_mapi_get_collection_settings (cbmapi);
	source = e_backend_get_source (E_BACKEND (cbmapi));
	ext_mapi_folder = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

	old_conn = cbmapi->priv->conn;

	cbmapi->priv->conn = e_mapi_connection_new (
		e_cal_backend_get_registry (E_CAL_BACKEND (cbmapi)),
		camel_mapi_settings_get_profile (settings),
		credentials, cancellable, &mapi_error);

	if (!cbmapi->priv->conn) {
		cbmapi->priv->conn = e_mapi_connection_find (camel_mapi_settings_get_profile (settings));
		if (cbmapi->priv->conn && !e_mapi_connection_connected (cbmapi->priv->conn))
			e_mapi_connection_reconnect (cbmapi->priv->conn, credentials, cancellable, &mapi_error);
	}

	if (old_conn)
		g_signal_handlers_disconnect_by_func (old_conn, G_CALLBACK (ecb_mapi_server_notification_cb), cbmapi);

	g_clear_object (&old_conn);

	if (!cbmapi->priv->conn || mapi_error) {
		gboolean is_network_error = mapi_error && mapi_error->domain != E_MAPI_ERROR;

		g_clear_object (&cbmapi->priv->conn);
		ecb_mapi_unlock_connection (cbmapi);

		if (is_network_error)
			ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_OTHER_ERROR, NULL);

		g_clear_error (&mapi_error);

		if (is_network_error) {
			*out_auth_result = E_SOURCE_AUTHENTICATION_ERROR;
		} else if ((!credentials || !e_named_parameters_count (credentials)) && !camel_mapi_settings_get_kerberos (settings)) {
			*out_auth_result = E_SOURCE_AUTHENTICATION_REQUIRED;
		} else {
			*out_auth_result = E_SOURCE_AUTHENTICATION_REJECTED;
		}

		return FALSE;
	}

	if (e_source_mapi_folder_get_server_notification (ext_mapi_folder)) {
		mapi_object_t obj_folder;
		GError *mapi_error = NULL;

		g_signal_connect (cbmapi->priv->conn, "server-notification", G_CALLBACK (ecb_mapi_server_notification_cb), cbmapi);

		if (ecb_mapi_open_folder (cbmapi, &obj_folder, cancellable, &mapi_error)) {
			e_mapi_connection_enable_notifications (cbmapi->priv->conn, &obj_folder,
				fnevObjectCreated | fnevObjectModified | fnevObjectDeleted | fnevObjectMoved | fnevObjectCopied,
				cancellable, &mapi_error);

			e_mapi_connection_close_folder (cbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
		}

		if (mapi_error) {
			ecb_mapi_maybe_disconnect (cbmapi, mapi_error);
			g_clear_error (&mapi_error);
		}
	}

	ecb_mapi_unlock_connection (cbmapi);

	*out_auth_result = E_SOURCE_AUTHENTICATION_ACCEPTED;

	return TRUE;
}

static gboolean
ecb_mapi_disconnect_sync (ECalMetaBackend *meta_backend,
			  GCancellable *cancellable,
			  GError **error)
{
	ECalBackendMAPI *cbmapi;
	gboolean success = TRUE;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (meta_backend), FALSE);

	cbmapi = E_CAL_BACKEND_MAPI (meta_backend);

	ecb_mapi_lock_connection (cbmapi);

	if (cbmapi->priv->conn) {
		g_signal_handlers_disconnect_by_func (cbmapi->priv->conn, G_CALLBACK (ecb_mapi_server_notification_cb), cbmapi);

		success = e_mapi_connection_disconnect (cbmapi->priv->conn, FALSE, cancellable, error);
		g_clear_object (&cbmapi->priv->conn);
	}

	ecb_mapi_unlock_connection (cbmapi);

	return success;
}

typedef struct _LoadMultipleData {
	ECalMetaBackend *meta_backend;
	ICalComponentKind kind;
	GSList **out_components; /* ICalComponent * */
} LoadMultipleData;

static gboolean
transfer_calendar_objects_cb (EMapiConnection *conn,
			      TALLOC_CTX *mem_ctx,
			      /* const */ EMapiObject *object,
			      guint32 obj_index,
			      guint32 obj_total,
			      gpointer user_data,
			      GCancellable *cancellable,
			      GError **perror)
{
	LoadMultipleData *lmd = user_data;
	ECalComponent *comp;
	const mapi_id_t *pmid;
	gchar *use_uid;
	GSList *instances = NULL;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (lmd != NULL, FALSE);

	pmid = e_mapi_util_find_array_propval (&object->properties, PidTagMid);
	if (pmid)
		use_uid = e_mapi_util_mapi_id_to_string (*pmid);
	else
		use_uid = e_util_generate_uid ();

	comp = e_mapi_cal_util_object_to_comp (conn, object,
		lmd->kind, FALSE, use_uid, &instances);

	g_free (use_uid);

	if (comp)
		instances = g_slist_prepend (instances, comp);

	if (instances) {
		ICalComponent *icomp;

		icomp = e_cal_meta_backend_merge_instances (lmd->meta_backend, instances, FALSE);
		if (icomp)
			*lmd->out_components = g_slist_prepend (*lmd->out_components, icomp);
	}

	g_slist_free_full (instances, g_object_unref);

	return TRUE;
}

static gboolean
ecb_mapi_load_multiple_sync (ECalBackendMAPI *cbmapi,
			     const GSList *uids, /* gchar * */
			     GSList **out_components, /* ICalComponent * */
			     GCancellable *cancellable,
			     GError **error)
{
	LoadMultipleData lmd;
	GSList *mids = NULL, *link;
	mapi_object_t obj_folder;
	gboolean success;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), FALSE);
	g_return_val_if_fail (uids != NULL, FALSE);
	g_return_val_if_fail (out_components != NULL, FALSE);

	for (link = (GSList *) uids; link; link = g_slist_next (link)) {
		mapi_id_t *pmid, mid;

		if (e_mapi_util_mapi_id_from_string  (link->data, &mid)) {
			pmid = g_new0 (mapi_id_t, 1);
			*pmid = mid;

			mids = g_slist_prepend (mids, pmid);
		}
	}

	ecb_mapi_lock_connection (cbmapi);

	lmd.meta_backend = E_CAL_META_BACKEND (cbmapi);
	lmd.kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
	lmd.out_components = out_components;

	success = ecb_mapi_open_folder (cbmapi, &obj_folder, cancellable, &mapi_error);

	if (success) {
		success = e_mapi_connection_transfer_objects (cbmapi->priv->conn, &obj_folder, mids,
			transfer_calendar_objects_cb, &lmd, cancellable, &mapi_error);

		e_mapi_connection_close_folder (cbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error) {
		ecb_mapi_maybe_disconnect (cbmapi, mapi_error);
		ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_OTHER_ERROR, _("Failed to transfer objects from a server"));
		g_error_free (mapi_error);

		success = FALSE;
	}

	ecb_mapi_unlock_connection (cbmapi);

	g_slist_free_full (mids, g_free);

	return success;
}

static gboolean
ecb_mapi_preload_infos_sync (ECalBackendMAPI *cbmapi,
			     GSList *created_objects,
			     GSList *modified_objects,
			     GCancellable *cancellable,
			     GError **error)
{
	GHashTable *infos;
	GSList *uids = NULL, *link;
	gboolean success = TRUE;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (cbmapi), FALSE);

	infos = g_hash_table_new (g_str_hash, g_str_equal);

	for (link = created_objects; link; link = g_slist_next (link)) {
		ECalMetaBackendInfo *nfo = link->data;

		if (nfo && nfo->extra) {
			uids = g_slist_prepend (uids, nfo->extra);
			g_hash_table_insert (infos, nfo->extra, nfo);
		} else if (nfo && nfo->uid) {
			uids = g_slist_prepend (uids, nfo->uid);
			g_hash_table_insert (infos, nfo->uid, nfo);
		}
	}

	for (link = modified_objects; link; link = g_slist_next (link)) {
		ECalMetaBackendInfo *nfo = link->data;

		if (nfo && nfo->extra) {
			uids = g_slist_prepend (uids, nfo->extra);
			g_hash_table_insert (infos, nfo->extra, nfo);
		} else if (nfo && nfo->uid) {
			uids = g_slist_prepend (uids, nfo->uid);
			g_hash_table_insert (infos, nfo->uid, nfo);
		}
	}

	uids = g_slist_reverse (uids);
	if (uids) {
		GSList *components = NULL;

		success = ecb_mapi_load_multiple_sync (cbmapi, uids, &components, cancellable, error);
		if (success) {
			for (link = components; link; link = g_slist_next (link)) {
				ICalComponent *icomp = link->data;

				if (icomp) {
					ECalMetaBackendInfo *nfo;
					const gchar *uid = NULL;
					gchar *xmid = NULL;

					if (i_cal_component_isa (icomp) == I_CAL_VCALENDAR_COMPONENT) {
						ICalComponent *subcomp;
						ICalComponentKind kind;

						kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));

						for (subcomp = i_cal_component_get_first_component (icomp, kind);
						     subcomp && !uid;
						     g_object_unref (subcomp), subcomp = i_cal_component_get_next_component (icomp, kind)) {
							uid = i_cal_component_get_uid (subcomp);
							xmid = e_cal_util_component_dup_x_property (subcomp, "X-EVOLUTION-MAPI-MID");
						}

						g_clear_object (&subcomp);
					} else {
						uid = i_cal_component_get_uid (icomp);
						xmid = e_cal_util_component_dup_x_property (icomp, "X-EVOLUTION-MAPI-MID");
					}

					nfo = uid ? g_hash_table_lookup (infos, uid) : NULL;
					if (!nfo && xmid)
						nfo = g_hash_table_lookup (infos, xmid);

					if (nfo && !nfo->object)
						nfo->object = i_cal_component_as_ical_string (icomp);

					g_free (xmid);
				}
			}
		}

		g_slist_free_full (components, g_object_unref);
	}

	g_hash_table_destroy (infos);
	g_slist_free (uids);

	return success;
}

static gboolean
ecb_mapi_get_changes_sync (ECalMetaBackend *meta_backend,
			   const gchar *last_sync_tag,
			   gboolean is_repeat,
			   gchar **out_new_sync_tag,
			   gboolean *out_repeat,
			   GSList **out_created_objects,
			   GSList **out_modified_objects,
			   GSList **out_removed_objects,
			   GCancellable *cancellable,
			   GError **error)
{
	ECalBackendMAPI *cbmapi;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (out_created_objects != NULL, FALSE);
	g_return_val_if_fail (out_modified_objects != NULL, FALSE);

	/* Chain up to parent's method */
	if (!E_CAL_META_BACKEND_CLASS (e_cal_backend_mapi_parent_class)->get_changes_sync (meta_backend,
		last_sync_tag, is_repeat, out_new_sync_tag, out_repeat, out_created_objects,
		out_modified_objects, out_removed_objects, cancellable, error)) {
		return FALSE;
	}

	cbmapi = E_CAL_BACKEND_MAPI (meta_backend);

	/* Preload some of the components in chunk, to speed-up things;
	   ignore errors, to not break whole update process. */
	ecb_mapi_preload_infos_sync (cbmapi, *out_created_objects, *out_modified_objects, cancellable, NULL);

	return TRUE;
}

static gboolean
ecb_mapi_list_existing_uids_cb (EMapiConnection *conn,
				TALLOC_CTX *mem_ctx,
				const ListObjectsData *object_data,
				guint32 obj_index,
				guint32 obj_total,
				gpointer user_data,
				GCancellable *cancellable,
				GError **perror)
{
	GSList **out_existing_objects = user_data;
	gchar *uid;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (object_data != NULL, FALSE);
	g_return_val_if_fail (out_existing_objects != NULL, FALSE);

	uid = e_mapi_util_mapi_id_to_string (object_data->mid);
	if (uid) {
		ICalTime *itt;
		gchar *rev;

		itt = i_cal_time_new_from_timet_with_zone (object_data->last_modified, 0, i_cal_timezone_get_utc_timezone ());
		rev = i_cal_time_as_ical_string (itt);
		g_clear_object (&itt);

		*out_existing_objects = g_slist_prepend (*out_existing_objects,
			e_cal_meta_backend_info_new (uid, rev, NULL, uid));

		g_free (uid);
		g_free (rev);
	}

	return TRUE;
}

static gboolean
ecb_mapi_populate_mid_to_gid_cb (ECalCache *cal_cache,
				 const gchar *uid,
				 const gchar *rid,
				 const gchar *revision,
				 const gchar *object,
				 const gchar *extra,
				 guint32 custom_flags,
				 EOfflineState offline_state,
				 gpointer user_data)
{
	GHashTable *mid_to_gid = user_data;

	g_return_val_if_fail (mid_to_gid != NULL, FALSE);

	if (uid && *uid && extra && *extra && g_strcmp0 (uid, extra) != 0)
		g_hash_table_insert (mid_to_gid, g_strdup (extra), g_strdup (uid));

	return TRUE;
}

static gboolean
ecb_mapi_list_existing_sync (ECalMetaBackend *meta_backend,
			     gchar **out_new_sync_tag,
			     GSList **out_existing_objects,
			     GCancellable *cancellable,
			     GError **error)
{
	ECalBackendMAPI *cbmapi;
	mapi_object_t obj_folder;
	gboolean success;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (out_existing_objects, FALSE);

	*out_existing_objects = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (meta_backend);

	ecb_mapi_lock_connection (cbmapi);

	success = ecb_mapi_open_folder (cbmapi, &obj_folder, cancellable, &mapi_error);
	if (success) {
		success = e_mapi_connection_list_objects (cbmapi->priv->conn, &obj_folder, NULL, NULL,
			ecb_mapi_list_existing_uids_cb, out_existing_objects, cancellable, &mapi_error);

		e_mapi_connection_close_folder (cbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error) {
		ecb_mapi_maybe_disconnect (cbmapi, mapi_error);
		ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_OTHER_ERROR, _("Failed to list items from a server"));
		g_error_free (mapi_error);

		success = FALSE;
	}

	ecb_mapi_unlock_connection (cbmapi);

	/* Components with GlobalId has UID the GlobalId, all other have MessageID,
	   but here the 'nfo->uid' is MessageID */
	if (success) {
		ECalCache *cal_cache;

		cal_cache = e_cal_meta_backend_ref_cache (meta_backend);
		if (cal_cache) {
			GHashTable *mid_to_gid;

			mid_to_gid = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

			if (e_cal_cache_search_with_callback (cal_cache, NULL, ecb_mapi_populate_mid_to_gid_cb, mid_to_gid, cancellable, NULL) &&
			    g_hash_table_size (mid_to_gid) > 0) {
				GSList *link;

				for (link = *out_existing_objects; link; link = g_slist_next (link)) {
					ECalMetaBackendInfo *nfo = link->data;

					if (nfo && nfo->uid) {
						const gchar *gid = g_hash_table_lookup (mid_to_gid, nfo->uid);

						if (gid && *gid) {
							g_free (nfo->uid);
							nfo->uid = g_strdup (gid);
						}
					}
				}
			}

			g_hash_table_destroy (mid_to_gid);
			g_object_unref (cal_cache);
		}
	}

	return success;
}

static gboolean
ecb_mapi_load_component_sync (ECalMetaBackend *meta_backend,
			      const gchar *uid,
			      const gchar *extra,
			      ICalComponent **out_component,
			      gchar **out_extra,
			      GCancellable *cancellable,
			      GError **error)
{
	ECalBackendMAPI *cbmapi;
	GSList *uids, *components = NULL;
	gboolean success;
	GError *local_error = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (uid != NULL, FALSE);
	g_return_val_if_fail (out_component != NULL, FALSE);

	*out_component = NULL;

	cbmapi = E_CAL_BACKEND_MAPI (meta_backend);

	uids = g_slist_prepend (NULL, (gpointer) uid);

	ecb_mapi_lock_connection (cbmapi);

	success = ecb_mapi_load_multiple_sync (cbmapi, uids, &components, cancellable, &local_error);
	if (!success) {
		mapi_object_t obj_folder;
		mapi_id_t mid = 0;

		/* Not downloaded in the local cache yet, try to find it. */
		if (ecb_mapi_open_folder (cbmapi, &obj_folder, cancellable, NULL)) {
			if (e_mapi_connection_list_objects (cbmapi->priv->conn, &obj_folder,
				ecb_mapi_build_global_id_or_mid_restriction_from_uid, (gpointer) uid,
				ecb_mapi_list_for_one_mid_cb, &mid, cancellable, NULL) && mid) {
				LoadMultipleData lmd;

				lmd.meta_backend = E_CAL_META_BACKEND (cbmapi);
				lmd.kind = e_cal_backend_get_kind (E_CAL_BACKEND (cbmapi));
				lmd.out_components = &components;

				success = e_mapi_connection_transfer_object (cbmapi->priv->conn, &obj_folder, mid,
					transfer_calendar_objects_cb, &lmd, cancellable, NULL);

				if (success)
					g_clear_error (&local_error);
			}

			e_mapi_connection_close_folder (cbmapi->priv->conn, &obj_folder, cancellable, NULL);
		}
	}

	ecb_mapi_unlock_connection (cbmapi);

	if (success && components) {
		*out_component = components->data;
		g_slist_free (components);
	} else {
		g_slist_free_full (components, g_object_unref);
	}

	if (local_error)
		g_propagate_error (error, local_error);

	g_slist_free (uids);

	return success;
}

static gboolean
ecb_mapi_save_component_sync (ECalMetaBackend *meta_backend,
			      gboolean overwrite_existing,
			      EConflictResolution conflict_resolution,
			      const GSList *instances,
			      const gchar *extra,
			      guint32 opflags, /* bit-or of ECalOperationFlags */
			      gchar **out_new_uid,
			      gchar **out_new_extra,
			      GCancellable *cancellable,
			      GError **error)
{
	ECalBackendMAPI *cbmapi;
	ECalComponent *comp;
	ICalComponent *icomp;
	gboolean no_increment;
	mapi_object_t obj_folder;
	mapi_id_t mid = 0;
	gboolean success;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (instances != NULL, FALSE);
	g_return_val_if_fail (out_new_uid != NULL, FALSE);

	*out_new_uid = NULL;

	if (instances->next ||
	    e_cal_component_is_instance (instances->data)) {
		g_propagate_error (error, EC_ERROR_EX (E_CLIENT_ERROR_OTHER_ERROR,
			_("Support for modifying single instances of a recurring appointment is not yet implemented. No change was made to the appointment on the server.")));
		return FALSE;
	}

	cbmapi = E_CAL_BACKEND_MAPI (meta_backend);

	icomp = i_cal_component_clone (e_cal_component_get_icalcomponent (instances->data));
	no_increment = e_cal_util_component_remove_x_property (icomp, "X-EVOLUTION-IS-REPLY");

	comp = e_cal_component_new_from_icalcomponent (icomp);
	if (!comp) {
		g_propagate_error (error, ECC_ERROR (E_CAL_CLIENT_ERROR_INVALID_OBJECT));
		return FALSE;
	}

	ecb_mapi_lock_connection (cbmapi);

	success = ecb_mapi_open_folder (cbmapi, &obj_folder, cancellable, &mapi_error);
	if (success) {
		struct cal_cbdata cbdata = { 0 };
		gboolean has_attendees = e_cal_component_has_attendees (comp);

		cbdata.kind = e_cal_backend_get_kind (E_CAL_BACKEND (meta_backend));
		cbdata.comp = comp;
		cbdata.is_modify = overwrite_existing;
		cbdata.msgflags = MSGFLAG_READ;
		cbdata.get_timezone = e_timezone_cache_get_timezone;
		cbdata.get_tz_data = cbmapi;

		if (overwrite_existing) {
			ecb_mapi_get_comp_mid (icomp, &mid);

			ecb_mapi_get_server_data (cbmapi, comp, &cbdata, cancellable);
			if (ecb_mapi_modifier_is_organizer (cbmapi, comp)) {
				cbdata.meeting_type = has_attendees ? MEETING_OBJECT : NOT_A_MEETING;
				cbdata.resp = has_attendees ? olResponseOrganized : olResponseNone;
				if (!no_increment)
					cbdata.appt_seq += 1;
				free_and_dupe_str (cbdata.username, ecb_mapi_get_owner_name (cbmapi));
				free_and_dupe_str (cbdata.useridtype, "SMTP");
				free_and_dupe_str (cbdata.userid, ecb_mapi_get_owner_email (cbmapi));
				free_and_dupe_str (cbdata.ownername, ecb_mapi_get_owner_name (cbmapi));
				free_and_dupe_str (cbdata.owneridtype, "SMTP");
				free_and_dupe_str (cbdata.ownerid, ecb_mapi_get_owner_email (cbmapi));
			} else {
				cbdata.resp = has_attendees ? ecb_mapi_find_my_response (cbmapi, comp) : olResponseNone;
				cbdata.meeting_type = has_attendees ? MEETING_OBJECT_RCVD : NOT_A_MEETING;
			}

			success = e_mapi_connection_modify_object (cbmapi->priv->conn, &obj_folder, mid,
					e_mapi_cal_utils_comp_to_object, &cbdata, cancellable, &mapi_error);

			ecb_mapi_free_server_data (&cbdata);
		} else {
			cbdata.username = g_strdup (ecb_mapi_get_owner_name (cbmapi));
			cbdata.useridtype = (gchar *) "SMTP";
			cbdata.userid = g_strdup (ecb_mapi_get_owner_email (cbmapi));
			cbdata.ownername = g_strdup (ecb_mapi_get_owner_name (cbmapi));
			cbdata.owneridtype = (gchar *) "SMTP";
			cbdata.ownerid = g_strdup (ecb_mapi_get_owner_email (cbmapi));

			cbdata.meeting_type = has_attendees ? MEETING_OBJECT : NOT_A_MEETING;
			cbdata.resp = has_attendees ? olResponseOrganized : olResponseNone;
			cbdata.appt_id = e_mapi_cal_util_get_new_appt_id (cbmapi->priv->conn, mapi_object_get_id (&obj_folder));
			cbdata.appt_seq = 0;
			cbdata.globalid = NULL;
			cbdata.cleanglobalid = NULL;

			success = e_mapi_connection_create_object (cbmapi->priv->conn, &obj_folder, E_MAPI_CREATE_FLAG_NONE,
				e_mapi_cal_utils_comp_to_object, &cbdata, &mid, cancellable, &mapi_error);
		}

		g_free (cbdata.username);
		g_free (cbdata.userid);
		g_free (cbdata.ownername);
		g_free (cbdata.ownerid);

		e_mapi_connection_close_folder (cbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error || !mid) {
		ecb_mapi_maybe_disconnect (cbmapi, mapi_error);
		ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_OTHER_ERROR,
			overwrite_existing ? _("Failed to modify item on a server") : _("Failed to create item on a server"));
		g_clear_error (&mapi_error);

		success = FALSE;
	}

	ecb_mapi_unlock_connection (cbmapi);

	if (success)
		*out_new_uid = e_mapi_util_mapi_id_to_string (mid);

	g_object_unref (comp);

	return success;
}

static gboolean
ecb_mapi_remove_component_sync (ECalMetaBackend *meta_backend,
				EConflictResolution conflict_resolution,
				const gchar *uid,
				const gchar *extra,
				const gchar *object,
				guint32 opflags, /* bit-or of ECalOperationFlags */
				GCancellable *cancellable,
				GError **error)
{
	ECalBackendMAPI *cbmapi;
	mapi_id_t mid = 0;
	gboolean success = TRUE;
	GError *mapi_error = NULL;

	g_return_val_if_fail (E_IS_CAL_BACKEND_MAPI (meta_backend), FALSE);
	g_return_val_if_fail (uid != NULL, FALSE);

	cbmapi = E_CAL_BACKEND_MAPI (meta_backend);

	if (object) {
		ICalComponent *icomp;

		icomp = i_cal_component_new_from_string (object);
		if (icomp) {
			ecb_mapi_get_comp_mid (icomp, &mid);
			g_object_unref (icomp);
		}
	}

	if (mid || e_mapi_util_mapi_id_from_string (uid, &mid)) {
		mapi_object_t obj_folder;

		ecb_mapi_lock_connection (cbmapi);

		success = ecb_mapi_open_folder (cbmapi, &obj_folder, cancellable, &mapi_error);
		if (success) {
			GSList *mids;

			mids = g_slist_prepend (NULL, &mid);

			success = e_mapi_connection_remove_items (cbmapi->priv->conn, &obj_folder, mids, cancellable, &mapi_error);

			e_mapi_connection_close_folder (cbmapi->priv->conn, &obj_folder, cancellable, &mapi_error);

			g_slist_free (mids);
		}

		ecb_mapi_unlock_connection (cbmapi);
	}

	if (mapi_error || !mid) {
		ecb_mapi_maybe_disconnect (cbmapi, mapi_error);
		ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_OTHER_ERROR, _("Failed to remove item from a server"));
		g_clear_error (&mapi_error);

		success = FALSE;
	}

	return success;
}

static gchar *
ecb_mapi_get_backend_property (ECalBackend *backend,
			       const gchar *prop_name)
{
	ECalBackendMAPI *cbmapi;

	g_return_val_if_fail (prop_name != NULL, NULL);

	cbmapi = E_CAL_BACKEND_MAPI (backend);

	if (g_str_equal (prop_name, CLIENT_BACKEND_PROPERTY_CAPABILITIES)) {
		return g_strjoin (
			",",
			E_CAL_STATIC_CAPABILITY_NO_ALARM_REPEAT,
			E_CAL_STATIC_CAPABILITY_NO_AUDIO_ALARMS,
			E_CAL_STATIC_CAPABILITY_NO_EMAIL_ALARMS,
			E_CAL_STATIC_CAPABILITY_NO_PROCEDURE_ALARMS,
			E_CAL_STATIC_CAPABILITY_ONE_ALARM_ONLY,
			E_CAL_STATIC_CAPABILITY_REMOVE_ALARMS,
			E_CAL_STATIC_CAPABILITY_NO_THISANDFUTURE,
			E_CAL_STATIC_CAPABILITY_NO_THISANDPRIOR,
			E_CAL_STATIC_CAPABILITY_CREATE_MESSAGES,
			E_CAL_STATIC_CAPABILITY_NO_CONV_TO_ASSIGN_TASK,
			E_CAL_STATIC_CAPABILITY_NO_CONV_TO_RECUR,
			E_CAL_STATIC_CAPABILITY_HAS_UNACCEPTED_MEETING,
			E_CAL_STATIC_CAPABILITY_REFRESH_SUPPORTED,
			E_CAL_STATIC_CAPABILITY_NO_MEMO_START_DATE,
			E_CAL_STATIC_CAPABILITY_TASK_DATE_ONLY,
			E_CAL_STATIC_CAPABILITY_TASK_NO_ALARM,
			e_cal_meta_backend_get_capabilities (E_CAL_META_BACKEND (backend)),
			NULL);
	} else if (g_str_equal (prop_name, E_CAL_BACKEND_PROPERTY_CAL_EMAIL_ADDRESS)) {
		return g_strdup (ecb_mapi_get_owner_email (cbmapi));
	} else if (g_str_equal (prop_name, E_CAL_BACKEND_PROPERTY_ALARM_EMAIL_ADDRESS)) {
		/* We don't support email alarms. This should not have been called. */
		return NULL;
	}

	/* Chain up to parent's method */
	return E_CAL_BACKEND_CLASS (e_cal_backend_mapi_parent_class)->impl_get_backend_property (backend, prop_name);
}

static void
ecb_mapi_send_objects_sync (ECalBackendSync *sync_backend,
			    EDataCal *cal,
			    GCancellable *cancellable,
			    const gchar *calobj,
			    guint32 opflags, /* bit-or of ECalOperationFlags */
			    GSList **users,
			    gchar **modified_calobj,
			    GError **error)
{
	ECalBackendMAPI *cbmapi;
	EMapiConnection *conn;
	ICalComponentKind kind;
	ICalComponent *icomp;
	GError *mapi_error = NULL;

	e_mapi_return_client_error_if_fail (E_IS_CAL_BACKEND_MAPI (sync_backend), E_CLIENT_ERROR_INVALID_ARG);
	e_mapi_return_client_error_if_fail (calobj != NULL, E_CLIENT_ERROR_INVALID_ARG);

	cbmapi = E_CAL_BACKEND_MAPI (sync_backend);
	kind = e_cal_backend_get_kind (E_CAL_BACKEND (sync_backend));

	ecb_mapi_lock_connection (cbmapi);

	if (!e_cal_meta_backend_ensure_connected_sync (E_CAL_META_BACKEND (cbmapi), cancellable, &mapi_error) ||
	    !cbmapi->priv->conn) {
		ecb_mapi_unlock_connection (cbmapi);

		if (!mapi_error)
			g_propagate_error (error, EC_ERROR (E_CLIENT_ERROR_REPOSITORY_OFFLINE));
		else
			ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_REPOSITORY_OFFLINE, NULL);
		g_clear_error (&mapi_error);
		return;
	}

	conn = cbmapi->priv->conn;

	/* check the component for validity */
	icomp = i_cal_parser_parse_string (calobj);
	if (!icomp) {
		ecb_mapi_unlock_connection (cbmapi);
		g_propagate_error (error, ECC_ERROR (E_CAL_CLIENT_ERROR_INVALID_OBJECT));
		return;
	}

	*modified_calobj = NULL;
	*users = NULL;

	if (i_cal_component_isa (icomp) == I_CAL_VCALENDAR_COMPONENT) {
		ICalPropertyMethod method = i_cal_component_get_method (icomp);
		ICalComponent *subcomp;

		for (subcomp = i_cal_component_get_first_component (icomp, kind);
		     subcomp;
		     g_object_unref (subcomp), subcomp = i_cal_component_get_next_component (icomp, kind)) {
			ECalComponent *comp;
			struct cal_cbdata cbdata = { 0 };
			mapi_id_t mid = 0;
			const gchar *compuid;
			gchar *propval;
			struct SBinary_short globalid = { 0 }, cleanglobalid = { 0 };
			struct timeval *exception_repleace_time = NULL, ex_rep_time = { 0 };
			struct FILETIME creation_time = { 0 };
			ICalTime *dtstamp;
			mapi_object_t obj_folder;

			comp = e_cal_component_new_from_icalcomponent (i_cal_component_clone (subcomp));
			if (!comp)
				continue;

			cbdata.kind = kind;
			cbdata.comp = comp;
			cbdata.is_modify = TRUE;
			cbdata.msgflags = MSGFLAG_READ | MSGFLAG_SUBMIT | MSGFLAG_UNSENT;

			switch (method) {
			case I_CAL_METHOD_REQUEST:
				cbdata.meeting_type = MEETING_REQUEST;
				cbdata.resp = olResponseNotResponded;
				break;
			case I_CAL_METHOD_CANCEL:
				cbdata.meeting_type = MEETING_CANCEL;
				cbdata.resp = olResponseNotResponded;
				break;
			case I_CAL_METHOD_REPLY:
			case I_CAL_METHOD_RESPONSE:
				cbdata.meeting_type = MEETING_RESPONSE;
				cbdata.resp = ecb_mapi_find_my_response (cbmapi, comp);
				break;
			default:
				cbdata.meeting_type = NOT_A_MEETING;
				cbdata.resp = olResponseNone;
				break;
			}

			ecb_mapi_get_server_data (cbmapi, comp, &cbdata, cancellable);
			free_and_dupe_str (cbdata.username, ecb_mapi_get_owner_name (cbmapi));
			free_and_dupe_str (cbdata.useridtype, "SMTP");
			free_and_dupe_str (cbdata.userid, ecb_mapi_get_owner_email (cbmapi));
			free_and_dupe_str (cbdata.ownername, ecb_mapi_get_owner_name (cbmapi));
			free_and_dupe_str (cbdata.owneridtype, "SMTP");
			free_and_dupe_str (cbdata.ownerid, ecb_mapi_get_owner_email (cbmapi));
			cbdata.get_timezone = e_timezone_cache_get_timezone;
			cbdata.get_tz_data = cbmapi;

			compuid = e_cal_component_get_uid (comp);

			dtstamp = e_cal_component_get_dtstamp (comp);
			if (!dtstamp)
				dtstamp = i_cal_time_new_null_time ();
			e_mapi_util_time_t_to_filetime (i_cal_time_as_timet (dtstamp), &creation_time);

			propval = e_cal_util_component_dup_x_property (e_cal_component_get_icalcomponent (comp), "X-EVOLUTION-MAPI-EXREPTIME");
			if (propval && *propval) {
				mapi_id_t val64 = 0;

				if (e_mapi_util_mapi_id_from_string (propval, &val64)) {
					memcpy (&ex_rep_time, &val64, 8);
					exception_repleace_time = &ex_rep_time;
				}
			}
			g_free (propval);

			/* inherit GlobalID from the source object, if available */
			if (e_cal_component_get_icalcomponent (comp)) {
				propval = e_cal_util_component_dup_x_property (e_cal_component_get_icalcomponent (comp), "X-EVOLUTION-MAPI-GLOBALID");
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
				e_mapi_cal_util_generate_globalobjectid (FALSE, compuid, exception_repleace_time,
					(dtstamp && i_cal_time_get_year (dtstamp)) ? &creation_time : NULL, &globalid);
				e_mapi_cal_util_generate_globalobjectid (TRUE,  compuid, exception_repleace_time,
					(dtstamp && i_cal_time_get_year (dtstamp)) ? &creation_time : NULL, &cleanglobalid);
			}

			g_clear_object (&dtstamp);

			if (cbdata.globalid)
				e_mapi_util_free_sbinary_short (cbdata.globalid);
			if (cbdata.cleanglobalid)
				e_mapi_util_free_sbinary_short (cbdata.cleanglobalid);
			cbdata.globalid = &globalid;
			cbdata.cleanglobalid = &cleanglobalid;

			mid = 0;
			if (e_mapi_connection_open_default_folder (conn, olFolderSentMail, &obj_folder, cancellable, &mapi_error)) {
				e_mapi_connection_create_object (conn, &obj_folder, E_MAPI_CREATE_FLAG_SUBMIT,
								 e_mapi_cal_utils_comp_to_object, &cbdata,
								 &mid, cancellable, &mapi_error);

				e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
			}

			cbdata.globalid = NULL;
			cbdata.cleanglobalid = NULL;
			ecb_mapi_free_server_data (&cbdata);
			g_free (globalid.lpb);
			g_free (cleanglobalid.lpb);

			if (!mid) {
				ecb_mapi_unlock_connection (cbmapi);
				g_object_unref (comp);
				ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_OTHER_ERROR, _("Failed to create item on a server"));
				ecb_mapi_maybe_disconnect (cbmapi, mapi_error);
				if (mapi_error)
					g_error_free (mapi_error);
				return;
			}

			g_object_unref (comp);
		}
	}

	ecb_mapi_unlock_connection (cbmapi);

	*modified_calobj = g_strdup (calobj);

	g_object_unref (icomp);
}

static void
ecb_mapi_get_free_busy_sync (ECalBackendSync *sync_backend,
			     EDataCal *cal,
			     GCancellable *cancellable,
			     const GSList *users,
			     time_t start,
			     time_t end,
			     GSList **freebusyobjs,
			     GError **error)
{
	ECalBackendMAPI *cbmapi;
	GError *mapi_error = NULL;

	g_return_if_fail (E_IS_CAL_BACKEND_MAPI (sync_backend));

	cbmapi = E_CAL_BACKEND_MAPI (sync_backend);

	ecb_mapi_lock_connection (cbmapi);

	if (!e_cal_meta_backend_ensure_connected_sync (E_CAL_META_BACKEND (cbmapi), cancellable, &mapi_error) ||
	    !cbmapi->priv->conn) {
		ecb_mapi_unlock_connection (cbmapi);

		if (!mapi_error)
			g_propagate_error (error, EC_ERROR (E_CLIENT_ERROR_REPOSITORY_OFFLINE));
		else
			ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_REPOSITORY_OFFLINE, NULL);
		g_clear_error (&mapi_error);
		return;
	}

	if (!e_mapi_cal_utils_get_free_busy_data (cbmapi->priv->conn, users, start, end, freebusyobjs, cancellable, &mapi_error)) {
		ecb_mapi_error_to_client_error (error, mapi_error, E_CLIENT_ERROR, E_CLIENT_ERROR_OTHER_ERROR, _("Failed to get Free/Busy data"));
		ecb_mapi_maybe_disconnect (cbmapi, mapi_error);

		if (mapi_error)
			g_error_free (mapi_error);
	}

	ecb_mapi_unlock_connection (cbmapi);
}

static gboolean
ecb_mapi_get_destination_address (EBackend *backend,
				  gchar **host,
				  guint16 *port)
{
	ESourceRegistry *registry;
	ESource *source;
	gboolean result = FALSE;

	g_return_val_if_fail (host != NULL, FALSE);
	g_return_val_if_fail (port != NULL, FALSE);

	registry = e_cal_backend_get_registry (E_CAL_BACKEND (backend));
	source = e_backend_get_source (backend);

	/* Sanity checking */
	if (!registry || !source || !e_source_get_parent (source))
		return FALSE;

	source = e_source_registry_ref_source (registry, e_source_get_parent (source));
	if (!source)
		return FALSE;

	if (e_source_has_extension (source, E_SOURCE_EXTENSION_AUTHENTICATION)) {
		ESourceAuthentication *auth = e_source_get_extension (source, E_SOURCE_EXTENSION_AUTHENTICATION);

		*host = g_strdup (e_source_authentication_get_host (auth));
		*port = e_source_authentication_get_port (auth);

		if (!*port)
			*port = 135;

		result = *host && **host;
		if (!result) {
			g_free (*host);
			*host = NULL;
		}
	}

	g_object_unref (source);

	return result;
}

static gboolean
ecb_mapi_update_tzid_cb (ECache *cache,
			 const gchar *uid,
			 const gchar *revision,
			 const gchar *object,
			 EOfflineState offline_state,
			 gint ncols,
			 const gchar *column_names[],
			 const gchar *column_values[],
			 gchar **out_revision,
			 gchar **out_object,
			 EOfflineState *out_offline_state,
			 ECacheColumnValues **out_other_columns,
			 gpointer user_data)
{
	ICalComponent *icomp;
	ICalProperty *prop;
	gboolean changed = FALSE;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (out_object != NULL, FALSE);

	icomp = i_cal_component_new_from_string (object);
	if (!icomp)
		return TRUE;

	prop = i_cal_component_get_first_property (icomp, I_CAL_DTSTART_PROPERTY);
	if (prop && e_cal_util_property_has_parameter (prop, I_CAL_TZID_PARAMETER)) {
		ICalTime *itt;

		itt = i_cal_property_get_dtstart (prop);
		if (itt && i_cal_time_is_valid_time (itt) && i_cal_time_is_utc (itt)) {
			i_cal_time_set_timezone (itt, NULL);
			i_cal_property_set_dtstart (prop, itt);
			changed = TRUE;
		}

		g_clear_object (&itt);
	}
	g_clear_object (&prop);

	prop = i_cal_component_get_first_property (icomp, I_CAL_DTEND_PROPERTY);
	if (prop && e_cal_util_property_has_parameter (prop, I_CAL_TZID_PARAMETER)) {
		ICalTime *itt;

		itt = i_cal_property_get_dtend (prop);
		if (itt && i_cal_time_is_valid_time (itt) && i_cal_time_is_utc (itt)) {
			i_cal_time_set_timezone (itt, NULL);
			i_cal_property_set_dtend (prop, itt);
			changed = TRUE;
		}

		g_clear_object (&itt);
	}
	g_clear_object (&prop);

	if (changed)
		*out_object = i_cal_component_as_ical_string (icomp);

	g_object_unref (icomp);

	return TRUE;
}

static void
ecb_mapi_migrate (ECalBackendMAPI *cbmapi,
		  ECalCache *cal_cache,
		  gint data_version)
{
	if (data_version < 1) {
		/* DTSTART/DTEND stores with both TZID and 'Z' suffix */
		e_cache_foreach_update (E_CACHE (cal_cache), E_CACHE_EXCLUDE_DELETED, NULL,
			ecb_mapi_update_tzid_cb, NULL, NULL, NULL);
	}
}

static gchar *
ecb_mapi_dup_component_revision_cb (ECalCache *cal_cache,
				    ICalComponent *icomp)
{
	ICalProperty *prop;
	ICalTime *itt;
	gchar *res;

	g_return_val_if_fail (I_CAL_IS_COMPONENT (icomp), NULL);

	prop = i_cal_component_get_first_property (icomp, I_CAL_LASTMODIFIED_PROPERTY);
	if (!prop)
		return NULL;

	itt = i_cal_property_get_lastmodified (prop);
	res = i_cal_time_as_ical_string (itt);

	g_clear_object (&prop);
	g_clear_object (&itt);

	return res;
}

static void
ecb_mapi_constructed (GObject *object)
{
	ECalBackendMAPI *cbmapi = E_CAL_BACKEND_MAPI (object);
	ECalCache *cal_cache;
	gint data_version;

	/* Chaing up to parent's method */
	G_OBJECT_CLASS (e_cal_backend_mapi_parent_class)->constructed (object);

	/* Reset the connectable, it steals data from Authentication extension,
	   where is written no address */
	e_backend_set_connectable (E_BACKEND (object), NULL);

	e_cal_backend_set_writable (E_CAL_BACKEND (cbmapi), TRUE);

	cal_cache = e_cal_meta_backend_ref_cache (E_CAL_META_BACKEND (cbmapi));

	g_signal_connect (cal_cache, "dup-component-revision",
		G_CALLBACK (ecb_mapi_dup_component_revision_cb), NULL);

	data_version = e_cache_get_key_int (E_CACHE (cal_cache), EMA_DATA_VERSION_KEY, NULL);

	if (EMA_DATA_VERSION != data_version) {
		GError *local_error = NULL;

		ecb_mapi_migrate (cbmapi, cal_cache, data_version);

		if (!e_cache_set_key_int (E_CACHE (cal_cache), EMA_DATA_VERSION_KEY, EMA_DATA_VERSION, &local_error)) {
			g_warning ("%s: Failed to store data version: %s\n", G_STRFUNC, local_error ? local_error->message : "Unknown error");
		}

		g_clear_error (&local_error);
	}

	g_clear_object (&cal_cache);
}

static void
ecb_mapi_dispose (GObject *object)
{
	ECalBackendMAPI *cbmapi = E_CAL_BACKEND_MAPI (object);

	g_clear_object (&cbmapi->priv->conn);

	/* Chain up to parent's method */
	G_OBJECT_CLASS (e_cal_backend_mapi_parent_class)->dispose (object);
}

static void
ecb_mapi_finalize (GObject *object)
{
	ECalBackendMAPI *cbmapi = E_CAL_BACKEND_MAPI (object);

	g_rec_mutex_clear (&cbmapi->priv->conn_lock);

	/* Chain up to parent's method */
	G_OBJECT_CLASS (e_cal_backend_mapi_parent_class)->finalize (object);
}

static void
e_cal_backend_mapi_class_init (ECalBackendMAPIClass *klass)
{
	GObjectClass *object_class;
	EBackendClass *backend_class;
	ECalBackendClass *cal_backend_class;
	ECalBackendSyncClass *sync_backend_class;
	ECalMetaBackendClass *meta_backend_class;

	meta_backend_class = E_CAL_META_BACKEND_CLASS (klass);
	meta_backend_class->connect_sync = ecb_mapi_connect_sync;
	meta_backend_class->disconnect_sync = ecb_mapi_disconnect_sync;
	meta_backend_class->get_changes_sync = ecb_mapi_get_changes_sync;
	meta_backend_class->list_existing_sync = ecb_mapi_list_existing_sync;
	meta_backend_class->load_component_sync = ecb_mapi_load_component_sync;
	meta_backend_class->save_component_sync = ecb_mapi_save_component_sync;
	meta_backend_class->remove_component_sync = ecb_mapi_remove_component_sync;

	cal_backend_class = E_CAL_BACKEND_CLASS (klass);
	cal_backend_class->impl_get_backend_property = ecb_mapi_get_backend_property;

	sync_backend_class = E_CAL_BACKEND_SYNC_CLASS (klass);
	sync_backend_class->send_objects_sync = ecb_mapi_send_objects_sync;
	sync_backend_class->get_free_busy_sync = ecb_mapi_get_free_busy_sync;

	backend_class = E_BACKEND_CLASS (klass);
	backend_class->get_destination_address = ecb_mapi_get_destination_address;

	object_class = G_OBJECT_CLASS (klass);
	object_class->constructed = ecb_mapi_constructed;
	object_class->dispose = ecb_mapi_dispose;
	object_class->finalize = ecb_mapi_finalize;
}

static void
e_cal_backend_mapi_init (ECalBackendMAPI *cbmapi)
{
	cbmapi->priv = e_cal_backend_mapi_get_instance_private (cbmapi);

	g_rec_mutex_init (&cbmapi->priv->conn_lock);
}
