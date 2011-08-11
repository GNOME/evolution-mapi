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

#include <libebook/e-contact.h>
#include <camel/camel.h>

#include <em-operation-queue.h>

#include "exchange-mapi-utils.h"
#include "exchange-mapi-defs.h"

#include "e-book-backend-mapi.h"

G_DEFINE_TYPE (EBookBackendMAPI, e_book_backend_mapi, E_TYPE_BOOK_BACKEND)

struct _EBookBackendMAPIPrivate
{
	EMOperationQueue *op_queue;

	GMutex *conn_lock;
	ExchangeMapiConnection *conn;
	gchar *profile;
	gchar *book_uri;
	gboolean marked_for_offline;

	GThread *update_cache_thread;
	GCancellable *update_cache;

	EBookBackendSqliteDB *db;
	GHashTable *running_book_views;
};

#define ELEMENT_TYPE_MASK   0xF /* mask where the real type of the element is stored */

#define ELEMENT_TYPE_SIMPLE 0x01
#define ELEMENT_TYPE_COMPLEX 0x02

#define ELEMENT_TYPE_NAMEDID 0x10

static const struct field_element_mapping {
		EContactField field_id;
		gint element_type;
		gint mapi_id;
		gint contact_type;
	} mappings [] = {

	{ E_CONTACT_UID, PT_UNICODE, PR_EMAIL_ADDRESS_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_REV, PT_SYSTIME, PR_LAST_MODIFICATION_TIME, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_FILE_AS, PT_UNICODE, PidLidFileUnder, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_FULL_NAME, PT_UNICODE, PR_DISPLAY_NAME_UNICODE, ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_GIVEN_NAME, PT_UNICODE, PR_GIVEN_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FAMILY_NAME, PT_UNICODE, PR_SURNAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_NICKNAME, PT_UNICODE, PR_NICKNAME_UNICODE, ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_EMAIL_1, PT_UNICODE, PidLidEmail1OriginalDisplayName, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_EMAIL_2, PT_UNICODE, PidLidEmail2EmailAddress, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_EMAIL_3, PT_UNICODE, PidLidEmail3EmailAddress, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_IM_AIM,  PT_UNICODE, PidLidInstantMessagingAddress, ELEMENT_TYPE_COMPLEX | ELEMENT_TYPE_NAMEDID},

	{ E_CONTACT_PHONE_BUSINESS, PT_UNICODE, PR_OFFICE_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME, PT_UNICODE, PR_HOME_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_MOBILE, PT_UNICODE, PR_MOBILE_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME_FAX, PT_UNICODE, PR_HOME_FAX_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_BUSINESS_FAX, PT_UNICODE, PR_BUSINESS_FAX_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_PAGER, PT_UNICODE, PR_PAGER_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_ASSISTANT, PT_UNICODE, PR_ASSISTANT_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_COMPANY, PT_UNICODE, PR_COMPANY_MAIN_PHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_HOMEPAGE_URL, PT_UNICODE, PidLidHtml, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_FREEBUSY_URL, PT_UNICODE, PidLidFreeBusyLocation, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},

	{ E_CONTACT_ROLE, PT_UNICODE, PR_PROFESSION_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_TITLE, PT_UNICODE, PR_TITLE_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG, PT_UNICODE, PR_COMPANY_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG_UNIT, PT_UNICODE, PR_DEPARTMENT_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_MANAGER, PT_UNICODE, PR_MANAGER_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ASSISTANT, PT_UNICODE, PR_ASSISTANT_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_OFFICE, PT_UNICODE, PR_OFFICE_LOCATION_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_SPOUSE, PT_UNICODE, PR_SPOUSE_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_BIRTH_DATE,  PT_SYSTIME, PR_BIRTHDAY, ELEMENT_TYPE_COMPLEX},
	{ E_CONTACT_ANNIVERSARY, PT_SYSTIME, PR_WEDDING_ANNIVERSARY, ELEMENT_TYPE_COMPLEX},

	{ E_CONTACT_NOTE, PT_UNICODE, PR_BODY_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_ADDRESS_HOME, PT_UNICODE, PidLidHomeAddress, ELEMENT_TYPE_COMPLEX | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_ADDRESS_WORK, PT_UNICODE, PidLidOtherAddress, ELEMENT_TYPE_COMPLEX | ELEMENT_TYPE_NAMEDID}
	/* { E_CONTACT_BOOK_URI, ELEMENT_TYPE_SIMPLE, "book_uri"}, */
	/* { E_CONTACT_CATEGORIES, } */
	};

static gboolean
ebbm_get_cache_time (EBookBackendMAPI *ebma, glong *cache_seconds)
{
	GError *error = NULL;
	GTimeVal tv = { 0 };
	gchar *last_update;
	gboolean ret = TRUE;

	g_return_val_if_fail (ebma != NULL, FALSE);
	g_return_val_if_fail (ebma->priv != NULL, FALSE);
	g_return_val_if_fail (ebma->priv->db != NULL, FALSE);
	g_return_val_if_fail (cache_seconds != NULL, FALSE);

	last_update = e_book_backend_sqlitedb_get_sync_data (ebma->priv->db, EMA_EBB_CACHE_FOLDERID, &error);
	ret = !error && last_update && g_time_val_from_iso8601 (last_update, &tv);
	if (error)
		g_error_free (error);
	g_free (last_update);

	if (ret)
		*cache_seconds = tv.tv_sec;

	return ret;
}

static void
ebbm_set_cache_time (EBookBackendMAPI *ebma, glong cache_seconds)
{
	GError *error = NULL;
	gchar *iso_time = NULL;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (ebma->priv != NULL);
	g_return_if_fail (ebma->priv->db != NULL);

	if (cache_seconds > 0) {
		GTimeVal tv = { 0 };

		tv.tv_sec = cache_seconds;
		iso_time = g_time_val_to_iso8601 (&tv);
	}

	e_book_backend_sqlitedb_set_sync_data (ebma->priv->db,
					       EMA_EBB_CACHE_FOLDERID,
					       iso_time ? iso_time : "0",
					       &error);
	g_free (iso_time);

	if (error) {
		exchange_mapi_debug_print ("%s: Failed to set value: %s", G_STRFUNC, error->message);
		g_error_free (error);
	}
}

static gboolean
pick_view_cb (EDataBookView *view, gpointer user_data)
{
	EDataBookView **pick = user_data;

	g_return_val_if_fail (user_data != NULL, FALSE);

	/* just always use the first book view */
	*pick = view;
	return view == NULL;
}

static EDataBookView *
ebbm_pick_book_view (EBookBackendMAPI *ebma)
{
	EDataBookView *pick = NULL;

	e_book_backend_foreach_view (E_BOOK_BACKEND (ebma), pick_view_cb, &pick);

	return pick;
}

static gboolean
complete_view_cb (EDataBookView *view, gpointer user_data)
{
	e_data_book_view_notify_complete (view, NULL);

	return TRUE;
}

static void
complete_views (EBookBackendMAPI *ebma)
{
	e_book_backend_foreach_view (E_BOOK_BACKEND (ebma), complete_view_cb, NULL);
}

struct FetchContactsData
{
	glong last_notification;
	glong last_modification;
};

static void
ebbm_notify_connection_status (EBookBackendMAPI *ebma, gboolean is_online)
{
	EBookBackendMAPIClass *ebmac;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_if_fail (ebmac != NULL);

	if (ebmac->op_connection_status_changed)
		ebmac->op_connection_status_changed (ebma, is_online);
}

static void
ebbm_fetch_contacts (EBookBackendMAPI *ebma, struct mapi_SRestriction *restriction, EDataBookView *book_view, glong *last_modification_secs, GError **error)
{
	EBookBackendMAPIClass *ebmac;
	struct FetchContactsData notify_data = { 0 };

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (ebma->priv != NULL);
	g_return_if_fail (ebma->priv->conn != NULL);

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_if_fail (ebmac != NULL);
	g_return_if_fail (ebmac->op_fetch_contacts != NULL);

	ebmac->op_fetch_contacts (ebma, restriction, book_view, &notify_data, error);

	if (last_modification_secs && *last_modification_secs < notify_data.last_modification)
		*last_modification_secs = notify_data.last_modification;
}

static struct mapi_SRestriction *
ebbm_build_cache_update_restriction (EBookBackendMAPI *ebma, TALLOC_CTX *mem_ctx)
{
	struct mapi_SRestriction *restriction;
	EBookBackendMAPIPrivate *priv;
	struct SPropValue sprop;
	struct timeval t = { 0 };
	glong last_update_secs = 0;

	g_return_val_if_fail (ebma != NULL, NULL);
	g_return_val_if_fail (mem_ctx != NULL, NULL);
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);

	priv = ebma->priv;
	g_return_val_if_fail (priv != NULL, NULL);
	g_return_val_if_fail (priv->db != NULL, NULL);

	if (!ebbm_get_cache_time (ebma, &last_update_secs) || last_update_secs <= 0)
		return NULL;

	restriction = talloc_zero (mem_ctx, struct mapi_SRestriction);
	g_assert (restriction != NULL);

	restriction->rt = RES_PROPERTY;
	restriction->res.resProperty.relop = RELOP_GE;
	restriction->res.resProperty.ulPropTag = PR_LAST_MODIFICATION_TIME;

	t.tv_sec = last_update_secs;
	t.tv_usec = 0;

	set_SPropValue_proptag_date_timeval (&sprop, PR_LAST_MODIFICATION_TIME, &t);

	cast_mapi_SPropValue (mem_ctx, &(restriction->res.resProperty.lpProp),
			      &sprop);

	return restriction;
}

static gboolean
unref_backend_idle_cb (gpointer data)
{
	EBookBackendMAPI *ebma = data;

	g_return_val_if_fail (ebma != NULL, FALSE);

	g_object_unref (ebma);

	return FALSE;
}

static gpointer
ebbm_update_cache_cb (gpointer data)
{
	EBookBackendMAPI *ebma = (EBookBackendMAPI *) data;
	EBookBackendMAPIPrivate *priv;
	EBookBackendMAPIClass *ebmac;
	glong last_modification_secs = 0;
	GError *error = NULL;

	g_return_val_if_fail (ebma != NULL, NULL);
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);

	priv = ebma->priv;
	g_return_val_if_fail (priv != NULL, NULL);
	g_return_val_if_fail (priv->db != NULL, NULL);
	g_return_val_if_fail (priv->conn != NULL, NULL);

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_val_if_fail (ebmac != NULL, NULL);

	g_cancellable_reset (priv->update_cache);

	if (!g_cancellable_is_cancelled (priv->update_cache) && ebmac->op_fetch_contacts) {
		TALLOC_CTX *mem_ctx;
		struct mapi_SRestriction *restriction;

		mem_ctx = talloc_init (G_STRFUNC);
		restriction = ebbm_build_cache_update_restriction (ebma, mem_ctx);

		/* get time stored in a cache, to always use the latest last modification time */
		if (!ebbm_get_cache_time (ebma, &last_modification_secs))
			last_modification_secs = 0;

		ebbm_fetch_contacts (ebma, restriction, NULL, &last_modification_secs, &error);
		e_book_backend_sqlitedb_set_is_populated (priv->db, EMA_EBB_CACHE_FOLDERID, error != NULL, NULL);

		talloc_free (mem_ctx);
	}

	if (!error && !g_cancellable_is_cancelled (priv->update_cache) && ebmac->op_fetch_known_uids) {
		GHashTable *uids = g_hash_table_new_full (g_str_hash, g_str_equal, (GDestroyNotify) g_free, NULL);

		ebmac->op_fetch_known_uids (ebma, priv->update_cache, uids, &error);

		if (!error && !g_cancellable_is_cancelled (priv->update_cache)) {
			GSList *cache_keys, *c;

			cache_keys = e_book_backend_sqlitedb_search_uids (priv->db, EMA_EBB_CACHE_FOLDERID, NULL, NULL, NULL);

			for (c = cache_keys; c; c = c->next) {
				const gchar *uid = c->data;

				if (!uid || g_hash_table_lookup (uids, uid))
					continue;

				e_book_backend_mapi_notify_contact_removed (ebma, uid);
			}

			ebbm_set_cache_time (ebma, last_modification_secs);

			g_slist_foreach (cache_keys, (GFunc) g_free, NULL);
			g_slist_free (cache_keys);
		}

		g_hash_table_destroy (uids);
	}

	if (error)
		g_error_free (error);

	complete_views (ebma);

	/* indicate the thread is not running */
	g_cancellable_cancel (priv->update_cache);

	/* May unref it out of the thread, in case it's the last reference to it */
	g_idle_add (unref_backend_idle_cb, ebma);

	return NULL;
}

static void
ebbm_connect_user (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *password, GError **error)
{
	EBookBackendMAPIPrivate *priv = ebma->priv;
	GError *mapi_error = NULL;
	ExchangeMapiConnection *old_conn;

	if (!e_book_backend_is_online (E_BOOK_BACKEND (ebma))) {
		ebbm_notify_connection_status (ebma, FALSE);
	} else {
		if (priv->update_cache_thread) {
			g_cancellable_cancel (priv->update_cache);
			g_thread_join (priv->update_cache_thread);
			priv->update_cache_thread = NULL;
		}

		e_book_backend_mapi_lock_connection (ebma);

		old_conn = priv->conn;
		priv->conn = NULL;

		priv->conn = exchange_mapi_connection_new (priv->profile,
							   password,
							   &mapi_error);
		if (!priv->conn) {
			priv->conn = exchange_mapi_connection_find (priv->profile);
			if (priv->conn && !exchange_mapi_connection_connected (priv->conn))
				exchange_mapi_connection_reconnect (priv->conn, password, &mapi_error);
		}

		if (old_conn)
			g_object_unref (old_conn);

		if (!priv->conn || mapi_error) {
			if (priv->conn) {
				g_object_unref (priv->conn);
				priv->conn = NULL;
			}

			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Cannot connect"));
			e_book_backend_mapi_unlock_connection (ebma);

			if (mapi_error)
				g_error_free (mapi_error);

			ebbm_notify_connection_status (ebma, FALSE);
			return;
		}

		e_book_backend_mapi_unlock_connection (ebma);

		ebbm_notify_connection_status (ebma, TRUE);

		/* if (priv->marked_for_offline) */
		priv->update_cache_thread = g_thread_create (ebbm_update_cache_cb, ebma, TRUE, NULL);
	}
}

static void
ebbm_open (EBookBackendMAPI *ebma, GCancellable *cancellable, gboolean only_if_exists, GError **perror)
{
	EBookBackendMAPIPrivate *priv = ebma->priv;
	ESource *source = e_book_backend_get_source (E_BOOK_BACKEND (ebma));
	const gchar *offline;
	const gchar *cache_dir, *krb_sso;
	GError *error = NULL;

	if (e_book_backend_is_opened (E_BOOK_BACKEND (ebma))) {
		e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), NULL /* Success */);
		return;
	}

	offline = e_source_get_property (source, "offline_sync");
	priv->marked_for_offline = offline  && g_str_equal (offline, "1");

	if (priv->book_uri)
		g_free (priv->book_uri);
	priv->book_uri = e_source_get_uri (source);

	g_free (priv->profile);
	priv->profile = g_strdup (e_source_get_property (source, "profile"));

	cache_dir = e_book_backend_get_cache_dir (E_BOOK_BACKEND (ebma));

	if (priv->db)
		g_object_unref (priv->db);
	priv->db = e_book_backend_sqlitedb_new (cache_dir,
						EMA_EBB_CACHE_PROFILEID,
						EMA_EBB_CACHE_FOLDERID,
						EMA_EBB_CACHE_FOLDERID,
	                                        TRUE, &error);

	if (error) {
		g_propagate_error (perror, error);
		return;
	}

	e_book_backend_notify_readonly (E_BOOK_BACKEND (ebma), TRUE);

	ebbm_notify_connection_status (ebma, e_book_backend_is_online (E_BOOK_BACKEND (ebma)));

	/* Either we are in Online mode or this is marked for offline */
	if (!e_book_backend_is_online (E_BOOK_BACKEND (ebma)) &&
	    !priv->marked_for_offline) {
		g_propagate_error (perror, EDB_ERROR (OFFLINE_UNAVAILABLE));
		e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), EDB_ERROR (OFFLINE_UNAVAILABLE));
		return;
	}

	/* Once aunthentication in address book works this can be removed */
	if (!e_book_backend_is_online (E_BOOK_BACKEND (ebma))) {
		e_book_backend_notify_online (E_BOOK_BACKEND (ebma), FALSE);
		e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), NULL /* Success */);
		return;
	}

	e_book_backend_notify_online (E_BOOK_BACKEND (ebma), TRUE);
	krb_sso = e_source_get_property (source, "kerberos");
	if (!krb_sso || !g_str_equal (krb_sso, "required")) {
		e_book_backend_notify_auth_required (E_BOOK_BACKEND (ebma),
						     TRUE, NULL);
	} else {
		ebbm_connect_user (ebma, cancellable, NULL, perror);
		e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), NULL);
	}
}

static void
ebbm_remove (EBookBackendMAPI *ebma, GCancellable *cancellable, GError **error)
{
	EBookBackendMAPIPrivate *priv;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (ebma->priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebma->priv;

	if (!priv->book_uri)
		return;

	e_book_backend_mapi_lock_connection (ebma);

	if (!priv->db) {
		const gchar *cache_dir = e_book_backend_get_cache_dir (E_BOOK_BACKEND (ebma));

		/* pity, but it's required to be removed completely */
		priv->db = e_book_backend_sqlitedb_new (cache_dir,
							EMA_EBB_CACHE_PROFILEID,
							EMA_EBB_CACHE_FOLDERID,
							EMA_EBB_CACHE_FOLDERID,
							TRUE, NULL);
	}

	if (priv->db) {
		e_book_backend_sqlitedb_remove (priv->db, NULL);
		g_object_unref (priv->db);
		priv->db = NULL;
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static gboolean
ebbm_get_backend_property (EBookBackendMAPI *ebma, const gchar *prop_name, gchar **prop_value, GError **error)
{
	gboolean processed = TRUE;

	g_return_val_if_fail (ebma != NULL, FALSE);
	g_return_val_if_fail (prop_name != NULL, FALSE);
	g_return_val_if_fail (prop_value != NULL, FALSE);

	if (g_str_equal (prop_name, CLIENT_BACKEND_PROPERTY_CAPABILITIES)) {
		*prop_value = g_strdup ("net,bulk-removes,do-initial-query,contact-lists");
	} else if (g_str_equal (prop_name, BOOK_BACKEND_PROPERTY_REQUIRED_FIELDS)) {
		*prop_value = g_strdup (e_contact_field_name (E_CONTACT_FILE_AS));
	} else if (g_str_equal (prop_name, BOOK_BACKEND_PROPERTY_SUPPORTED_FIELDS)) {
		gint ii;
		GSList *fields = NULL;

		for (ii = 0; ii < G_N_ELEMENTS (mappings); ii++) {
			fields = g_slist_append (fields, (gpointer) e_contact_field_name (mappings[ii].field_id));
		}

		fields = g_slist_append (fields, (gpointer) e_contact_field_name (E_CONTACT_BOOK_URI));

		*prop_value = e_data_book_string_slist_to_comma_string (fields);

		g_slist_free (fields);
	} else if (g_str_equal (prop_name, BOOK_BACKEND_PROPERTY_SUPPORTED_AUTH_METHODS)) {
		*prop_value = g_strdup ("plain/password");
	} else {
		processed = FALSE;
	}

	return processed;
}

static void
ebbm_authenticate_user (EBookBackendMAPI *ebma, GCancellable *cancellable, ECredentials *credentials, GError **error)
{
	const gchar *password;

	if (!e_book_backend_is_online (E_BOOK_BACKEND (ebma))) {
		ebbm_notify_connection_status (ebma, FALSE);
	} else {
		password = e_credentials_peek (credentials, E_CREDENTIALS_KEY_PASSWORD);
		ebbm_connect_user (ebma, cancellable, password, error);
	}
}

static void
ebbm_set_online (EBookBackend *backend, gboolean is_online)
{
	EBookBackendMAPI *ebma = E_BOOK_BACKEND_MAPI (backend);
	EBookBackendMAPIPrivate *priv = ebma->priv;
	ESource *esource;
	const gchar *krb_sso = NULL;

	e_book_backend_notify_online (backend, is_online);
	if (e_book_backend_is_opened (backend)) {
		e_book_backend_mapi_lock_connection (ebma);

		esource = e_book_backend_get_source (E_BOOK_BACKEND (ebma));
		if (!is_online) {
			e_book_backend_notify_readonly (backend, TRUE);
			ebbm_notify_connection_status (ebma, FALSE);

			if (priv->conn) {
				g_object_unref (priv->conn);
				priv->conn = NULL;
			}
		} else {
			ebbm_notify_connection_status (ebma, TRUE);
			if (!priv->conn) {
				krb_sso = e_source_get_property (esource,
								 "kerberos");
				if (!krb_sso
				    || !g_str_equal (krb_sso, "required")) {
					e_book_backend_notify_auth_required (backend, TRUE, NULL);
				} else {
					ebbm_connect_user (ebma, NULL, NULL,
							   NULL);
					e_book_backend_notify_opened (backend,
								      NULL);
				}
			}
		}

		e_book_backend_mapi_unlock_connection (ebma);
	}
}

static void
ebbm_get_contact (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *id, gchar **vcard, GError **error)
{
	EBookBackendMAPIPrivate *priv;
	gchar *contact;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (vcard != NULL);

	priv = ebma->priv;
	g_return_if_fail (priv != NULL);

	if (!priv->db) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	contact = e_book_backend_sqlitedb_get_vcard_string (priv->db,
							    EMA_EBB_CACHE_FOLDERID,
							    id, NULL, NULL, error);
	if (contact)
		*vcard = contact;
	else
		g_propagate_error (error, EDB_ERROR (CONTACT_NOT_FOUND));
}

static void
ebbm_get_contact_list (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *query, GSList **vCards, GError **error)
{
	EBookBackendMAPIPrivate *priv;
	GSList *hits, *l;
	GError *err = NULL;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (query != NULL);
	g_return_if_fail (vCards != NULL);

	priv = ebma->priv;
	g_return_if_fail (priv != NULL);

	if (!priv->db) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	hits = e_book_backend_sqlitedb_search (priv->db, EMA_EBB_CACHE_FOLDERID,
					       query, NULL, NULL, NULL, &err);

	for (l = hits; !err && l; l = l->next) {
		EbSdbSearchData *sdata = (EbSdbSearchData *) l->data;
		gchar *vcard = sdata->vcard;

		if (!err && vcard)
			*vCards = g_slist_prepend (*vCards, g_strdup (vcard));

		e_book_backend_sqlitedb_search_data_free (sdata);
	}

	if (err)
		g_propagate_error (error, err);

	g_slist_free (hits);
}

struct BookViewThreadData
{
	EBookBackendMAPI *ebma;
	EDataBookView *book_view;
};

static gpointer
ebbm_book_view_thread (gpointer data)
{
	struct BookViewThreadData *bvtd = data;
	EBookBackendMAPIPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (bvtd != NULL, NULL);
	g_return_val_if_fail (bvtd->ebma != NULL, NULL);
	g_return_val_if_fail (bvtd->book_view != NULL, NULL);

	priv = bvtd->ebma->priv;

	e_data_book_view_notify_progress (bvtd->book_view, -1, _("Searching"));

	e_book_backend_mapi_update_view_by_cache (bvtd->ebma, bvtd->book_view, &error);

	if (!error && priv && priv->conn && (!priv->update_cache_thread || g_cancellable_is_cancelled (priv->update_cache))
	    && e_book_backend_mapi_book_view_is_running (bvtd->ebma, bvtd->book_view)) {
		EBookBackendMAPIClass *ebmac;

		ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (bvtd->ebma);
		if (ebmac && ebmac->op_book_view_thread)
			ebmac->op_book_view_thread (bvtd->ebma, bvtd->book_view, &error);

		if (!error && !e_book_backend_sqlitedb_get_is_populated (priv->db, EMA_EBB_CACHE_FOLDERID, &error)) {
			/* todo: create restriction based on the book_view */
			if (!error) {
				g_cancellable_reset (priv->update_cache);
				ebbm_fetch_contacts (bvtd->ebma, NULL, bvtd->book_view, NULL, &error);
				g_cancellable_cancel (priv->update_cache);
			}

			if (!error)
				e_book_backend_sqlitedb_set_is_populated (priv->db, EMA_EBB_CACHE_FOLDERID, TRUE, &error);
		}
	}

	if (error && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		g_clear_error (&error);

	/* do not stop book view when filling cache */
	if (e_book_backend_mapi_book_view_is_running (bvtd->ebma, bvtd->book_view)
	    && (!priv->update_cache_thread || g_cancellable_is_cancelled (priv->update_cache)))
		e_data_book_view_notify_complete (bvtd->book_view, error);

	if (error)
		g_error_free (error);

	g_object_unref (bvtd->book_view);
	/* May unref it out of the thread, in case it's the last reference to it */
	g_idle_add (unref_backend_idle_cb, bvtd->ebma);
	g_free (bvtd);

	return NULL;
}

/* Async OP functions, data structures and so on */

typedef enum {
	OP_OPEN,
	OP_REMOVE,

	OP_CREATE_CONTACT,
	OP_REMOVE_CONTACTS,
	OP_MODIFY_CONTACT,
	OP_GET_CONTACT,
	OP_GET_CONTACT_LIST,
	OP_START_BOOK_VIEW,
	OP_STOP_BOOK_VIEW,
	OP_AUTHENTICATE_USER,
	OP_GET_BACKEND_PROPERTY
} OperationType;

typedef struct {
	OperationType ot;

	EDataBook *book;
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
} OperationAuthenticateUser;

typedef struct {
	OperationBase base;

	gchar *str;
} OperationStr;

typedef struct {
	OperationBase base;

	GSList *id_list;
} OperationIDList;

typedef struct {
	OperationBase base;

	EDataBookView *book_view;
} OperationBookView;

static void
ebbm_operation_cb (OperationBase *op, gboolean cancelled, EBookBackend *backend)
{
	EBookBackendMAPI *ebma;
	EBookBackendMAPIClass *ebmac;
	GError *error = NULL;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND (backend));
	g_return_if_fail (op != NULL);

	ebma = E_BOOK_BACKEND_MAPI (backend);
	g_return_if_fail (ebma != NULL);

	ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);
	g_return_if_fail (ebmac != NULL);

	cancelled = cancelled || (op->cancellable && g_cancellable_is_cancelled (op->cancellable));

	switch (op->ot) {
	case OP_OPEN: {
		OperationOpen *opo = (OperationOpen *) op;

		if (!cancelled) {
			if (ebmac->op_open)
				ebmac->op_open (ebma, op->cancellable, opo->only_if_exists, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_data_book_respond_open (op->book, op->opid, error);
		}
	} break;
	case OP_REMOVE: {
		if (!cancelled) {
			if (ebmac->op_remove)
				ebmac->op_remove (ebma, op->cancellable, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_data_book_respond_remove (op->book, op->opid, error);
		}
	} break;
	case OP_CREATE_CONTACT: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *vcard = ops->str;

		if (!cancelled) {
			EContact *contact = NULL;

			if (ebmac->op_create_contact)
				ebmac->op_create_contact (ebma, op->cancellable, vcard, &contact, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			if (contact && !error)
				e_book_backend_mapi_notify_contact_update (ebma, NULL, contact, NULL, -1, -1, NULL);

			e_data_book_respond_create (op->book, op->opid, error, contact);

			if (contact)
				g_object_unref (contact);
		}

		g_free (ops->str);
	} break;
	case OP_REMOVE_CONTACTS: {
		OperationIDList *opil = (OperationIDList *) op;

		if (!cancelled) {
			GSList *removed_ids = NULL;

			if (ebmac->op_remove_contacts)
				ebmac->op_remove_contacts (ebma, op->cancellable, opil->id_list, &removed_ids, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			if (!error) {
				GSList *r;

				for (r = removed_ids; r; r = r->next) {
					const gchar *uid = r->data;

					if (uid)
						e_book_backend_mapi_notify_contact_removed (ebma, uid);
				}
			}

			e_data_book_respond_remove_contacts (op->book, op->opid, error, removed_ids);

			g_slist_foreach (removed_ids, (GFunc) g_free, NULL);
			g_slist_free (removed_ids);
		}

		g_slist_foreach (opil->id_list, (GFunc) g_free, NULL);
		g_slist_free (opil->id_list);
	} break;
	case OP_MODIFY_CONTACT: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *vcard = ops->str;

		if (!cancelled) {
			EContact *contact = NULL;

			if (ebmac->op_modify_contact)
				ebmac->op_modify_contact (ebma, op->cancellable, vcard, &contact, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			if (contact && !error)
				e_book_backend_mapi_notify_contact_update (ebma, NULL, contact, NULL, -1, -1, NULL);

			e_data_book_respond_modify (op->book, op->opid, error, contact);

			if (contact)
				g_object_unref (contact);
		}

		g_free (ops->str);
	} break;
	case OP_GET_CONTACT: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *id = ops->str;

		if (!cancelled) {
			gchar *vcard = NULL;

			if (ebmac->op_get_contact)
				ebmac->op_get_contact (ebma, op->cancellable, id, &vcard, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_data_book_respond_get_contact (op->book, op->opid, error, vcard);

			g_free (vcard);
		}

		g_free (ops->str);
	} break;
	case OP_GET_CONTACT_LIST: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *query = ops->str;

		if (!cancelled) {
			GSList *vCards = NULL;

			if (ebmac->op_get_contact_list)
				ebmac->op_get_contact_list (ebma, op->cancellable, query, &vCards, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_data_book_respond_get_contact_list (op->book, op->opid, error, vCards);

			g_slist_foreach (vCards, (GFunc) g_free, NULL);
			g_slist_free (vCards);
		}

		g_free (ops->str);
	} break;
	case OP_START_BOOK_VIEW: {
		OperationBookView *opbv = (OperationBookView *) op;

		if (!cancelled && e_book_backend_mapi_book_view_is_running (ebma, opbv->book_view)) {
			GError *err = NULL;
			struct BookViewThreadData *bvtd = g_new0 (struct BookViewThreadData, 1);

			bvtd->ebma = g_object_ref (ebma);
			bvtd->book_view = g_object_ref (opbv->book_view);

			g_thread_create (ebbm_book_view_thread, bvtd, FALSE, &err);

			if (err) {
				error = EDB_ERROR_EX (OTHER_ERROR, err->message);
				e_data_book_view_notify_complete (opbv->book_view, error);
				g_error_free (error);
				g_error_free (err);
			}
		}

		g_object_unref (opbv->book_view);
	} break;
	case OP_STOP_BOOK_VIEW: {
		OperationBookView *opbv = (OperationBookView *) op;

		if (!cancelled) {
			e_data_book_view_notify_complete (opbv->book_view, NULL);
		}

		g_object_unref (opbv->book_view);
	} break;
	case OP_AUTHENTICATE_USER: {
		OperationAuthenticateUser *opau = (OperationAuthenticateUser *) op;

		if (!cancelled) {
			if (ebmac->op_authenticate_user)
				ebmac->op_authenticate_user (ebma, op->cancellable, opau->credentials, &error);
			else
				error = EDB_ERROR (NOT_SUPPORTED);

			e_book_backend_notify_opened (E_BOOK_BACKEND (ebma), error);
		}

		e_credentials_free (opau->credentials);
	} break;
	case OP_GET_BACKEND_PROPERTY: {
		OperationStr *ops = (OperationStr *) op;
		const gchar *prop_name = ops->str;

		if (!cancelled) {
			gchar *prop_value = NULL;

			if (ebbm_get_backend_property (ebma, prop_name, &prop_value, &error))
				e_data_book_respond_get_backend_property (op->book, op->opid, error, prop_value);
			else
				(* E_BOOK_BACKEND_CLASS (e_book_backend_mapi_parent_class)->get_backend_property) (backend, op->book, op->opid, op->cancellable, prop_name);
		}

		g_free (ops->str);
	} break;
	}

	if (op->cancellable)
		g_object_unref (op->cancellable);
	if (op->book)
		g_object_unref (op->book);
	g_object_unref (ebma);
	g_free (op);
}

static void
base_op_abstract (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, OperationType ot)
{
	OperationBase *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);
	if (book)
		g_object_ref (book);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationBase, 1);
	op->ot = ot;
	op->book = book;
	op->opid = opid;
	op->cancellable = cancellable;

	em_operation_queue_push (priv->op_queue, op);
}

static void
str_op_abstract (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, const gchar *str, OperationType ot)
{
	OperationStr *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);
	if (book)
		g_object_ref (book);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationStr, 1);
	op->base.ot = ot;
	op->base.book = book;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->str = g_strdup (str);

	em_operation_queue_push (priv->op_queue, op);
}

#define BASE_OP_DEF(_func, _ot)								\
static void										\
_func (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable)	\
{											\
	base_op_abstract (backend, book, opid, cancellable, _ot);			\
}

#define STR_OP_DEF(_func, _ot)							\
static void									\
_func (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, const gchar *str)	\
{										\
	str_op_abstract (backend, book, opid, cancellable, str, _ot);		\
}

BASE_OP_DEF (ebbm_op_remove, OP_REMOVE)
STR_OP_DEF  (ebbm_op_create_contact, OP_CREATE_CONTACT)
STR_OP_DEF  (ebbm_op_modify_contact, OP_MODIFY_CONTACT)
STR_OP_DEF  (ebbm_op_get_contact, OP_GET_CONTACT)
STR_OP_DEF  (ebbm_op_get_contact_list, OP_GET_CONTACT_LIST)
STR_OP_DEF  (ebbm_op_get_backend_property, OP_GET_BACKEND_PROPERTY)

static void
ebbm_op_open (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, gboolean only_if_exists)
{
	OperationOpen *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);
	if (book)
		g_object_ref (book);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationOpen, 1);
	op->base.ot = OP_OPEN;
	op->base.book = book;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->only_if_exists = only_if_exists;

	em_operation_queue_push (priv->op_queue, op);
}

static void
ebbm_op_remove_contacts (EBookBackend *backend, EDataBook *book, guint32 opid, GCancellable *cancellable, const GSList *id_list)
{
	OperationIDList *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;
	GSList *l;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));
	g_return_if_fail (id_list != NULL);

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);
	if (book)
		g_object_ref (book);
	if (cancellable)
		g_object_ref (cancellable);

	op = g_new0 (OperationIDList, 1);
	op->base.ot = OP_REMOVE_CONTACTS;
	op->base.book = book;
	op->base.opid = opid;
	op->base.cancellable = cancellable;
	op->id_list = g_slist_copy ((GSList *) id_list);

	for (l = op->id_list; l; l = l->next) {
		l->data = g_strdup (l->data);
	}

	em_operation_queue_push (priv->op_queue, op);
}

static void
ebbm_op_start_book_view (EBookBackend *backend, EDataBookView *book_view)
{
	OperationBookView *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));
	g_return_if_fail (book_view != NULL);

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);

	op = g_new0 (OperationBookView, 1);
	op->base.ot = OP_START_BOOK_VIEW;
	op->base.book = NULL;
	op->base.opid = 0;
	op->book_view = g_object_ref (book_view);

	g_hash_table_insert (priv->running_book_views, book_view, GINT_TO_POINTER(1));

	em_operation_queue_push (priv->op_queue, op);
}

static void
ebbm_op_stop_book_view (EBookBackend *backend, EDataBookView *book_view)
{
	OperationBookView *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));
	g_return_if_fail (book_view != NULL);

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	g_object_ref (ebbm);

	op = g_new0 (OperationBookView, 1);
	op->base.ot = OP_STOP_BOOK_VIEW;
	op->base.book = NULL;
	op->base.opid = 0;
	op->book_view = g_object_ref (book_view);

	g_hash_table_remove (priv->running_book_views, book_view);

	em_operation_queue_push (priv->op_queue, op);
}

static void
ebbm_op_authenticate_user (EBookBackend *backend, GCancellable *cancellable, ECredentials *credentials)
{
	OperationAuthenticateUser *op;
	EBookBackendMAPI *ebbm;
	EBookBackendMAPIPrivate *priv;

	g_return_if_fail (backend != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (backend));

	ebbm = E_BOOK_BACKEND_MAPI (backend);
	priv = ebbm->priv;
	g_return_if_fail (priv != NULL);

	if (cancellable)
		g_object_ref (cancellable);

	g_object_ref (ebbm);

	op = g_new0 (OperationAuthenticateUser, 1);
	op->base.ot = OP_AUTHENTICATE_USER;
	op->base.book = NULL;
	op->base.opid = 0;
	op->base.cancellable = cancellable;
	op->credentials = e_credentials_new_clone (credentials);

	em_operation_queue_push (priv->op_queue, op);
}

static void
e_book_backend_mapi_init (EBookBackendMAPI *ebma)
{
	ebma->priv = G_TYPE_INSTANCE_GET_PRIVATE (ebma, E_TYPE_BOOK_BACKEND_MAPI, EBookBackendMAPIPrivate);

	ebma->priv->op_queue = em_operation_queue_new ((EMOperationQueueFunc) ebbm_operation_cb, ebma);
	ebma->priv->running_book_views = g_hash_table_new (g_direct_hash, g_direct_equal);
	ebma->priv->conn_lock = g_mutex_new ();

	ebma->priv->update_cache = g_cancellable_new ();
	ebma->priv->update_cache_thread = NULL;
}

static void
ebbm_dispose (GObject *object)
{
	EBookBackendMAPI *ebma = E_BOOK_BACKEND_MAPI (object);
	EBookBackendMAPIPrivate *priv = ebma->priv;

	if (priv) {
		if (priv->update_cache_thread) {
			g_cancellable_cancel (priv->update_cache);
			g_thread_join (priv->update_cache_thread);
			priv->update_cache_thread = NULL;
		}

		#define FREE(x) if (x) { g_free (x); x = NULL; }
		#define UNREF(x) if (x) { g_object_unref (x); x = NULL; }

		e_book_backend_mapi_lock_connection (ebma);
		UNREF (priv->conn);
		e_book_backend_mapi_unlock_connection (ebma);
		UNREF (priv->op_queue);
		UNREF (priv->db);
		UNREF (priv->update_cache);

		FREE (priv->profile);
		FREE (priv->book_uri);

		g_hash_table_destroy (priv->running_book_views);
		g_mutex_free (priv->conn_lock);

		#undef UNREF
		#undef FREE

		ebma->priv = NULL;
	}

	/* Chain up to parent's dispose() method. */
	if (G_OBJECT_CLASS (e_book_backend_mapi_parent_class)->dispose)
		G_OBJECT_CLASS (e_book_backend_mapi_parent_class)->dispose (object);
}

static void
e_book_backend_mapi_class_init (EBookBackendMAPIClass *klass)
{
	GObjectClass  *object_class = G_OBJECT_CLASS (klass);
	EBookBackendClass *backend_class = E_BOOK_BACKEND_CLASS (klass);

	g_type_class_add_private (klass, sizeof (EBookBackendMAPIPrivate));

	object_class->dispose                     = ebbm_dispose;

	backend_class->open			  = ebbm_op_open;
	backend_class->remove			  = ebbm_op_remove;
	backend_class->create_contact		  = ebbm_op_create_contact;
	backend_class->remove_contacts		  = ebbm_op_remove_contacts;
	backend_class->modify_contact		  = ebbm_op_modify_contact;
	backend_class->get_contact                = ebbm_op_get_contact;
	backend_class->get_contact_list           = ebbm_op_get_contact_list;
	backend_class->start_book_view            = ebbm_op_start_book_view;
	backend_class->stop_book_view             = ebbm_op_stop_book_view;
	backend_class->authenticate_user          = ebbm_op_authenticate_user;
	backend_class->get_backend_property	  = ebbm_op_get_backend_property;
	backend_class->set_online                 = ebbm_set_online;

	klass->op_open				  = ebbm_open;
	klass->op_remove                          = ebbm_remove;
	klass->op_authenticate_user               = ebbm_authenticate_user;
	klass->op_get_contact                     = ebbm_get_contact;
	klass->op_get_contact_list                = ebbm_get_contact_list;

	klass->op_connection_status_changed       = NULL;
	klass->op_get_status_message              = NULL;
	klass->op_book_view_thread                = NULL;
	klass->op_fetch_contacts                  = NULL;
	klass->op_fetch_known_uids                = NULL;
}

gboolean
e_book_backend_mapi_debug_enabled (void)
{
	gint8 debug_enabled = -1;

	if (debug_enabled == -1) {
		if (g_getenv ("MAPI_DEBUG"))
			debug_enabled = 1;
		else
			debug_enabled = 0;
	}

	return debug_enabled != 0;
}

const gchar *
e_book_backend_mapi_get_book_uri (EBookBackendMAPI *ebma)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);
	g_return_val_if_fail (ebma->priv != NULL, NULL);

	return ebma->priv->book_uri;
}

void
e_book_backend_mapi_lock_connection (EBookBackendMAPI *ebma)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);
	g_return_if_fail (ebma->priv->conn_lock != NULL);

	g_mutex_lock (ebma->priv->conn_lock);
}

void
e_book_backend_mapi_unlock_connection (EBookBackendMAPI *ebma)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);
	g_return_if_fail (ebma->priv->conn_lock != NULL);

	g_mutex_unlock (ebma->priv->conn_lock);
}

ExchangeMapiConnection *
e_book_backend_mapi_get_connection (EBookBackendMAPI *ebma)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);
	g_return_val_if_fail (ebma->priv != NULL, NULL);

	return ebma->priv->conn;
}

void
e_book_backend_mapi_get_db (EBookBackendMAPI *ebma, EBookBackendSqliteDB **db)
{
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);

	if (db)
		*db = ebma->priv->db;
}

gboolean
e_book_backend_mapi_book_view_is_running (EBookBackendMAPI *ebma, EDataBookView *book_view)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), FALSE);
	g_return_val_if_fail (ebma->priv != NULL, FALSE);

	return g_hash_table_lookup (ebma->priv->running_book_views, book_view) != NULL;
}

gboolean
e_book_backend_mapi_is_marked_for_offline (EBookBackendMAPI *ebma)
{
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), FALSE);
	g_return_val_if_fail (ebma->priv != NULL, FALSE);

	return ebma->priv->marked_for_offline;
}

void
e_book_backend_mapi_update_view_by_cache (EBookBackendMAPI *ebma, EDataBookView *book_view, GError **error)
{
	gint i = 0;
	const gchar *query = NULL;
	EBookBackendSqliteDB *db = NULL;
	GSList *hits, *l;

	g_return_if_fail (ebma != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (book_view != NULL);
	g_return_if_fail (E_IS_DATA_BOOK_VIEW (book_view));

	query = e_data_book_view_get_card_query (book_view);
	e_book_backend_mapi_get_db (ebma, &db);

	g_return_if_fail (db != NULL);

	hits = e_book_backend_sqlitedb_search (db, EMA_EBB_CACHE_FOLDERID,
					       query, NULL, NULL, NULL, error);

	for (l = hits; (!error || !*error) && l; l = l->next) {
		EbSdbSearchData *sdata = (EbSdbSearchData *) l->data;
		gchar *vcard = sdata->vcard;

		if (i > 0 && ((i++) % 10) == 0 && !e_book_backend_mapi_book_view_is_running (ebma, book_view))
			break;

		if (vcard) {
			EContact *contact = e_contact_new_from_vcard (vcard);
			e_data_book_view_notify_update (book_view, contact);
			g_object_unref (contact);
		}
	}

	if (hits) {
		g_slist_foreach (hits, (GFunc) e_book_backend_sqlitedb_search_data_free, NULL);
		g_slist_free (hits);
	}
}

static glong
get_current_time_ms (void)
{
	GTimeVal tv;

	g_get_current_time (&tv);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* called from op_fetch_contacts - book_view and notify_contact_data are taken from there;
   notify_contact_data is a pointer to FetchContactsData, if not NULL;
   returns whether can continue with fetching */
gboolean
e_book_backend_mapi_notify_contact_update (EBookBackendMAPI *ebma, EDataBookView *pbook_view, EContact *contact, const struct timeval *pr_last_modification_time, gint index, gint total, gpointer notify_contact_data)
{
	EBookBackendMAPIPrivate *priv;
	struct FetchContactsData *fcd = notify_contact_data;
	EDataBookView *book_view = pbook_view;
	GError *error = NULL;

	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), FALSE);
	g_return_val_if_fail (ebma->priv, FALSE);
	g_return_val_if_fail (contact != NULL, FALSE);

	priv = ebma->priv;
	g_return_val_if_fail (priv != NULL, FALSE);

	/* report progres to any book_view, if not passed in;
	   it can happen when cache is filling and the book view started later */
	if (!book_view)
		book_view = ebbm_pick_book_view (ebma);

	if (book_view) {
		guint32 current_time;

		if (!e_book_backend_mapi_book_view_is_running (ebma, book_view))
			return FALSE;

		current_time = get_current_time_ms ();
		if (index > 0 && fcd && current_time - fcd->last_notification > 333) {
			gchar *status_msg = NULL;
			EBookBackendMAPIClass *ebmac = E_BOOK_BACKEND_MAPI_GET_CLASS (ebma);

			if (ebmac->op_get_status_message)
				status_msg = ebmac->op_get_status_message (ebma, index, total);

			if (status_msg)
				e_data_book_view_notify_progress (book_view, -1, status_msg);

			g_free (status_msg);

			fcd->last_notification = current_time;
		}
	}

	if (!pbook_view && g_cancellable_is_cancelled (priv->update_cache))
		return FALSE;

	e_book_backend_sqlitedb_add_contact (ebma->priv->db,
					     EMA_EBB_CACHE_FOLDERID, contact,
					     FALSE, &error);
	if (!error) {
		e_book_backend_notify_update (E_BOOK_BACKEND (ebma), contact);

		if (fcd && pr_last_modification_time) {
			if (fcd->last_modification < pr_last_modification_time->tv_sec)
				fcd->last_modification = pr_last_modification_time->tv_sec;
		}
		return TRUE;
	}
	g_error_free (error);
	return FALSE;
}

void
e_book_backend_mapi_notify_contact_removed (EBookBackendMAPI *ebma, const gchar *uid)
{
	EBookBackendMAPIPrivate *priv;
	GError *error = NULL;
	gboolean ret;

	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv);
	g_return_if_fail (uid != NULL);

	priv = ebma->priv;
	g_return_if_fail (priv != NULL);

	ret = e_book_backend_sqlitedb_remove_contact (priv->db,
						      EMA_EBB_CACHE_FOLDERID,
						      uid, &error);
	if (ret && !error)
		e_book_backend_notify_remove (E_BOOK_BACKEND (ebma), uid);

	if (error)
		g_error_free (error);
}

void
e_book_backend_mapi_cache_set (EBookBackendMAPI *ebma, const gchar *key, const gchar *value)
{
	g_return_if_fail (ebma != NULL);
	g_return_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma));
	g_return_if_fail (ebma->priv != NULL);
	g_return_if_fail (ebma->priv->db != NULL);
	g_return_if_fail (key != NULL);

	e_book_backend_sqlitedb_set_key_value (ebma->priv->db, EMA_EBB_CACHE_FOLDERID, key, value, NULL);
}

gchar *
e_book_backend_mapi_cache_get (EBookBackendMAPI *ebma, const gchar *key)
{
	g_return_val_if_fail (ebma != NULL, NULL);
	g_return_val_if_fail (E_IS_BOOK_BACKEND_MAPI (ebma), NULL);
	g_return_val_if_fail (ebma->priv != NULL, NULL);
	g_return_val_if_fail (ebma->priv->db != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	return e_book_backend_sqlitedb_get_key_value (ebma->priv->db, EMA_EBB_CACHE_FOLDERID, key, NULL);
}

/* utility functions/macros */

/* 'data' is one of GET_ALL_KNOWN_IDS or GET_UIDS_ONLY */
gboolean
mapi_book_utils_get_prop_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
{
	/* this is a list of all known book MAPI tag IDs;
	   if you add new add it here too, otherwise it may not be fetched */
	static uint32_t known_book_mapi_ids[] = {
		PR_ASSISTANT_TELEPHONE_NUMBER_UNICODE,
		PR_ASSISTANT_UNICODE,
		PR_BIRTHDAY,
		PR_BODY,
		PR_BODY_UNICODE,
		PR_BUSINESS_FAX_NUMBER_UNICODE,
		PR_COMPANY_MAIN_PHONE_NUMBER_UNICODE,
		PR_COMPANY_NAME_UNICODE,
		PR_COUNTRY_UNICODE,
		PR_DEPARTMENT_NAME_UNICODE,
		PR_DISPLAY_NAME_UNICODE,
		PR_EMAIL_ADDRESS_UNICODE,
		PR_SMTP_ADDRESS_UNICODE, /* used in GAL */
		PR_FID,
		PR_GIVEN_NAME_UNICODE,
		PR_HASATTACH,
		PR_HOME_ADDRESS_CITY_UNICODE,
		PR_HOME_ADDRESS_COUNTRY_UNICODE,
		PR_HOME_ADDRESS_POSTAL_CODE_UNICODE,
		PR_HOME_ADDRESS_POST_OFFICE_BOX_UNICODE,
		PR_HOME_ADDRESS_STATE_OR_PROVINCE_UNICODE,
		PR_HOME_FAX_NUMBER_UNICODE,
		PR_HOME_TELEPHONE_NUMBER_UNICODE,
		PR_INSTANCE_NUM,
		PR_INST_ID,
		PR_LAST_MODIFICATION_TIME,
		PR_LOCALITY_UNICODE,
		PR_MANAGER_NAME_UNICODE,
		PR_MESSAGE_CLASS,
		PR_MID,
		PR_MOBILE_TELEPHONE_NUMBER_UNICODE,
		PR_NICKNAME_UNICODE,
		PR_NORMALIZED_SUBJECT_UNICODE,
		PR_OFFICE_LOCATION_UNICODE,
		PR_OFFICE_TELEPHONE_NUMBER_UNICODE,
		PR_PAGER_TELEPHONE_NUMBER_UNICODE,
		PR_POSTAL_CODE_UNICODE,
		PR_POST_OFFICE_BOX_UNICODE,
		PR_PROFESSION_UNICODE,
		PR_RULE_MSG_NAME,
		PR_RULE_MSG_PROVIDER,
		PR_SPOUSE_NAME_UNICODE,
		PR_STATE_OR_PROVINCE_UNICODE,
		PR_SUBJECT_UNICODE,
		PR_SURNAME_UNICODE,
		PR_TITLE_UNICODE,
		PR_WEDDING_ANNIVERSARY,
		PROP_TAG(PT_UNICODE, 0x801f)
	};

	static uint32_t uids_only_ids[] = {
		PR_FID,
		PR_MID,
		PR_EMAIL_ADDRESS_UNICODE
	};

	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData nids[] = {
		{ PidLidDistributionListName, 0 },
		{ PidLidDistributionListOneOffMembers, 0 },
		{ PidLidDistributionListMembers, 0 },
		{ PidLidDistributionListChecksum, 0 },

		{ PidLidFileUnder, 0 },

		{ PidLidEmail1OriginalDisplayName, 0 },
		{ PidLidEmail2OriginalDisplayName, 0 },
		{ PidLidEmail3OriginalDisplayName, 0 },
		{ PidLidInstantMessagingAddress, 0 },
		{ PidLidHtml, 0 },
		{ PidLidFreeBusyLocation, 0 }
	};

	g_return_val_if_fail (props != NULL, FALSE);

	if (data == GET_UIDS_ONLY)
		return exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, uids_only_ids, G_N_ELEMENTS (uids_only_ids));

	if (data == GET_ALL_KNOWN_IDS && !exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, known_book_mapi_ids, G_N_ELEMENTS (known_book_mapi_ids)))
		return FALSE;

	/* called with fid = 0 from GAL */
	if (!fid)
		fid = exchange_mapi_connection_get_default_folder_id (conn, olFolderContacts, NULL);

	return exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids));
}

static gchar *
bin_to_string (const uint8_t *lpb, uint32_t cb)
{
	gchar *res, *p;
	uint32_t i;

	g_return_val_if_fail (lpb != NULL, NULL);
	g_return_val_if_fail (cb > 0, NULL);

	res = g_new0 (gchar, cb * 2 + 1);
	for (i = 0, p = res; i < cb; i++, p += 2) {
		sprintf (p, "%02x", lpb[i] & 0xFF);
	}

	return res;
}

static const gchar *
not_null (gconstpointer ptr)
{
	return ptr ? (const gchar *) ptr : "";
}

/* This is not setting E_CONTACT_UID */
EContact *
mapi_book_utils_contact_from_props (ExchangeMapiConnection *conn, mapi_id_t fid, const gchar *book_uri, struct mapi_SPropValue_array *mapi_properties, struct SRow *aRow)
{
	EContact *contact = e_contact_new ();
	gint i;

	if (book_uri)
		e_contact_set (contact, E_CONTACT_BOOK_URI, book_uri);

	#define get_proptag(proptag) (aRow ? exchange_mapi_util_find_row_propval (aRow, proptag) : exchange_mapi_util_find_array_propval (mapi_properties, proptag))
	#define get_str_proptag(proptag) not_null (get_proptag (proptag))
	#define get_namedid(nid) (aRow ? exchange_mapi_util_find_row_namedid (aRow, conn, fid, nid) : exchange_mapi_util_find_array_namedid (mapi_properties, conn, fid, nid))
	#define get_str_namedid(nid) not_null (get_namedid (nid))

	if (g_str_equal (get_str_proptag (PR_MESSAGE_CLASS), IPM_DISTLIST)) {
		const struct mapi_SBinaryArray *members, *members_dlist;
		GSList *attrs = NULL, *a;
		gint i;

		/* it's a contact list/distribution list, fetch members and return it */
		e_contact_set (contact, E_CONTACT_IS_LIST, GINT_TO_POINTER (TRUE));
		/* we do not support this option, same as GroupWise */
		e_contact_set (contact, E_CONTACT_LIST_SHOW_ADDRESSES, GINT_TO_POINTER (TRUE));

		e_contact_set (contact, E_CONTACT_FILE_AS, get_str_namedid (PidLidDistributionListName));

		members = get_namedid (PidLidDistributionListOneOffMembers);
		members_dlist = get_namedid (PidLidDistributionListMembers);

		g_return_val_if_fail (members != NULL, NULL);
		g_return_val_if_fail (members_dlist != NULL, NULL);

		/* these two lists should be in sync */
		g_return_val_if_fail (members_dlist->cValues == members->cValues, NULL);

		for (i = 0; i < members->cValues; i++) {
			struct Binary_r br;
			gchar *display_name = NULL, *email = NULL;
			gchar *str;

			br.lpb = members->bin[i].lpb;
			br.cb = members->bin[i].cb;
			if (exchange_mapi_util_recip_entryid_decode (conn, &br, &display_name, &email)) {
				EVCardAttribute *attr;
				gchar *value;
				CamelInternetAddress *addr;

				addr = camel_internet_address_new ();
				attr = e_vcard_attribute_new (NULL, EVC_EMAIL);

				camel_internet_address_add (addr, display_name, email);

				value = camel_address_encode (CAMEL_ADDRESS (addr));

				if (value)
					e_vcard_attribute_add_value (attr, value);

				g_free (value);
				g_object_unref (addr);

				str = g_strdup_printf ("%d", i + 1);
				e_vcard_attribute_add_param_with_value (attr,
						e_vcard_attribute_param_new (EMA_X_MEMBERID),
						str);
				g_free (str);

				/* keep the value from ListMembers with the email, to not need to generate it on list changes;
				   new values added in evolution-mapi will be always SMTP addresses anyway */
				str = bin_to_string (members_dlist->bin[i].lpb, members_dlist->bin[i].cb);
				if (str) {
					e_vcard_attribute_add_param_with_value (attr,
						e_vcard_attribute_param_new (EMA_X_MEMBERVALUE),
						str);
					g_free (str);
				}

				attrs = g_slist_prepend (attrs, attr);
			}

			g_free (display_name);
			g_free (email);
		}

		for (a = attrs; a; a = a->next) {
			e_vcard_add_attribute (E_VCARD (contact), a->data);
		}

		g_slist_free (attrs);

		return contact;
	}

	for (i = 0; i < G_N_ELEMENTS (mappings); i++) {
		gpointer value;
		gint contact_type;

		/* can cast value, no writing to the value; and it'll be freed not before the end of this function */
		if (mappings[i].contact_type & ELEMENT_TYPE_NAMEDID)
			value = (gpointer) get_namedid (mappings[i].mapi_id);
		else
			value = (gpointer) get_proptag (mappings[i].mapi_id);
		contact_type = mappings[i].contact_type & ELEMENT_TYPE_MASK;
		if (mappings[i].element_type == PT_UNICODE && contact_type == ELEMENT_TYPE_SIMPLE) {
			const gchar *str = value;
			if (str && *str)
				e_contact_set (contact, mappings[i].field_id, str);
		} else if (contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value && mappings[i].element_type == PT_SYSTIME) {
				const struct FILETIME *t = value;
				gchar *buff = NULL;
				GTimeVal tv;

				tv.tv_sec = exchange_mapi_util_filetime_to_time_t (t);
				tv.tv_usec = 0;
				
				buff = g_time_val_to_iso8601 (&tv);

				if (buff)
					e_contact_set (contact, mappings[i].field_id, buff);

				g_free (buff);
			}
		} else if (contact_type == ELEMENT_TYPE_COMPLEX) {
			if (mappings[i].field_id == E_CONTACT_IM_AIM) {
				const gchar *str = value;
				if (str && *str) {
					GList *list = g_list_append (NULL, (gpointer) str);

					e_contact_set (contact, mappings[i].field_id, list);

					g_list_free (list);
				}
			} else if (mappings[i].field_id == E_CONTACT_BIRTH_DATE
				   || mappings[i].field_id == E_CONTACT_ANNIVERSARY) {
				const struct FILETIME *t = value;
				time_t time;
				struct tm * tmtime;
				if (value) {
					EContactDate date = {0};

					time = exchange_mapi_util_filetime_to_time_t (t);
					tmtime = gmtime (&time);

					date.day = tmtime->tm_mday;
					date.month = tmtime->tm_mon + 1;
					date.year = tmtime->tm_year + 1900;
					e_contact_set (contact, mappings[i].field_id, &date);
				}

			} else if (mappings[i].field_id == E_CONTACT_ADDRESS_WORK
				   || mappings[i].field_id == E_CONTACT_ADDRESS_HOME) {
				EContactAddress contact_addr = { 0 };

				/* type-casting below to not allocate memory twice; e_contact_set will copy values itself. */
				if (mappings[i].field_id == E_CONTACT_ADDRESS_HOME) {
					contact_addr.address_format = NULL;
					contact_addr.po = NULL;
					contact_addr.street = (gchar *) value;
					contact_addr.ext = (gchar *) get_str_proptag (PR_HOME_ADDRESS_POST_OFFICE_BOX_UNICODE);
					contact_addr.locality = (gchar *) get_str_proptag (PR_HOME_ADDRESS_CITY_UNICODE);
					contact_addr.region = (gchar *) get_str_proptag (PR_HOME_ADDRESS_STATE_OR_PROVINCE_UNICODE);
					contact_addr.code = (gchar *) get_str_proptag (PR_HOME_ADDRESS_POSTAL_CODE_UNICODE);
					contact_addr.country = (gchar *) get_str_proptag (PR_HOME_ADDRESS_COUNTRY_UNICODE);
				} else {
					contact_addr.address_format = NULL;
					contact_addr.po = NULL;
					contact_addr.street = (gchar *) value;
					contact_addr.ext = (gchar *) get_str_proptag (PR_POST_OFFICE_BOX_UNICODE);
					contact_addr.locality = (gchar *) get_str_proptag (PR_LOCALITY_UNICODE);
					contact_addr.region = (gchar *) get_str_proptag (PR_STATE_OR_PROVINCE_UNICODE);
					contact_addr.code = (gchar *) get_str_proptag (PR_POSTAL_CODE_UNICODE);
					contact_addr.country = (gchar *) get_str_proptag (PR_COUNTRY_UNICODE);
				}

				#define is_set(x) ((x) && *(x))
				if (is_set (contact_addr.address_format) ||
				    is_set (contact_addr.po) ||
				    is_set (contact_addr.street) ||
				    is_set (contact_addr.ext) ||
				    is_set (contact_addr.locality) ||
				    is_set (contact_addr.region) ||
				    is_set (contact_addr.code) ||
				    is_set (contact_addr.country)) {
					e_contact_set (contact, mappings[i].field_id, &contact_addr);
				}
				#undef is_set
			}
		}
	}

	if (!e_contact_get (contact, E_CONTACT_EMAIL_1)) {
		gconstpointer value = get_proptag (PR_SMTP_ADDRESS_UNICODE);

		if (value)
			e_contact_set (contact, E_CONTACT_EMAIL_1, value);
	}

	#undef get_proptag
	#undef get_str_proptag
	#undef get_namedid
	#undef get_str_namedid

	return contact;
}

void
mapi_error_to_edb_error (GError **perror, const GError *mapi_error, EDataBookStatus code, const gchar *context)
{
	gchar *err_msg = NULL;

	if (!perror)
		return;

	if (code == E_DATA_BOOK_STATUS_OTHER_ERROR && mapi_error) {
		/* Change error to more accurate only with OTHER_ERROR */
		switch (mapi_error->code) {
		case MAPI_E_PASSWORD_CHANGE_REQUIRED:
		case MAPI_E_PASSWORD_EXPIRED:
			code = E_DATA_BOOK_STATUS_AUTHENTICATION_REQUIRED;
			break;
		default:
			break;
		}
	}

	if (context)
		err_msg = g_strconcat (context, mapi_error ? ": " : NULL, mapi_error ? mapi_error->message : NULL, NULL);
	else if (!mapi_error)
		err_msg = g_strdup (_("Unknown error"));

	g_propagate_error (perror, e_data_book_create_error (code, err_msg ? err_msg : mapi_error->message));

	g_free (err_msg);
}
