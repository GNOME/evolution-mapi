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
 *    Suman Manjunath <msuman@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <camel/camel.h>
#include <libedataserver/libedataserver.h>

#include <tevent.h>

#include "e-mapi-connection.h"
#include "e-mapi-folder.h"
#include "e-mapi-utils.h"
#include "e-mapi-book-utils.h"
#include "e-mapi-mail-utils.h"
#include "e-mapi-fast-transfer.h"

/* how many bytes can be written within one property with SetProps() call;
   if its size exceeds this limit, it's converted into an EMapiStreamedProp */
#define MAX_PROPERTY_WRITE_SIZE	2048

/* how may contacts in one chunk can GAL ask to fetch */
#define MAX_GAL_CHUNK 50

static void register_connection (EMapiConnection *conn);
static void unregister_connection (EMapiConnection *conn);
static gboolean mapi_profile_create (struct mapi_context *mapi_ctx, const EMapiProfileData *empd, mapi_profile_callback_t callback, gconstpointer data, GCancellable *cancellable, GError **perror, gboolean use_locking);
static struct mapi_session *mapi_profile_load (ESourceRegistry *registry, struct mapi_context *mapi_ctx, const gchar *profname, const gchar *password, GCancellable *cancellable, GError **perror);

/* GObject foo - begin */

G_DEFINE_TYPE (EMapiConnection, e_mapi_connection, G_TYPE_OBJECT)

/* These three macros require 'priv' variable of type EMapiConnectionPrivate */
#define LOCK(_cclb,_err,_ret) G_STMT_START { 						\
	e_mapi_debug_print ("%s: %s: lock(session & global)", G_STRLOC, G_STRFUNC);	\
	if (!e_mapi_cancellable_rec_mutex_lock (&priv->session_lock, _cclb, _err)) {	\
		e_mapi_debug_print ("   %s: %s: cancelled before got session lock)", G_STRLOC, G_STRFUNC); \
		return _ret;								\
	}										\
	if (!e_mapi_utils_global_lock (_cclb, _err)) {					\
		e_mapi_cancellable_rec_mutex_unlock (&priv->session_lock);		\
		e_mapi_debug_print ("   %s: %s: cancelled before got global lock)", G_STRLOC, G_STRFUNC); \
		return _ret;								\
	}										\
	} G_STMT_END

#define LOCK_VOID(_cclb,_err) G_STMT_START { 						\
	e_mapi_debug_print ("%s: %s: lock(session & global)", G_STRLOC, G_STRFUNC);	\
	if (!e_mapi_cancellable_rec_mutex_lock (&priv->session_lock, _cclb, _err)) {	\
		e_mapi_debug_print ("   %s: %s: cancelled before got session lock)", G_STRLOC, G_STRFUNC); \
		return;									\
	}										\
	if (!e_mapi_utils_global_lock (_cclb, _err)) {					\
		e_mapi_cancellable_rec_mutex_unlock (&priv->session_lock);		\
		e_mapi_debug_print ("   %s: %s: cancelled before got global lock)", G_STRLOC, G_STRFUNC); \
		return;									\
	}										\
	} G_STMT_END

#define UNLOCK() G_STMT_START {								\
	e_mapi_debug_print ("%s: %s: unlock(session & global)", G_STRLOC, G_STRFUNC);	\
	e_mapi_utils_global_unlock ();							\
	e_mapi_cancellable_rec_mutex_unlock (&priv->session_lock);			\
	} G_STMT_END

#define e_return_val_mapi_error_if_fail(expr, _code, _val)				\
	G_STMT_START {									\
		if (G_LIKELY(expr)) {							\
		} else {								\
			g_log (G_LOG_DOMAIN,						\
				G_LOG_LEVEL_CRITICAL,					\
				"file %s: line %d (%s): assertion `%s' failed",		\
				__FILE__, __LINE__, G_STRFUNC, #expr);			\
			if (perror)							\
				g_set_error (perror, E_MAPI_ERROR, (_code),		\
					"file %s: line %d (%s): assertion `%s' failed",	\
					__FILE__, __LINE__, G_STRFUNC, #expr);		\
			return (_val);							\
		}									\
	} G_STMT_END

/* Create the EDataCal error quark */
GQuark
e_mapi_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("e_mapi_error");
	return quark;
}

void
make_mapi_error (GError **perror, const gchar *context, enum MAPISTATUS mapi_status)
{
	const gchar *error_msg = NULL, *status_name;
	gchar *to_free = NULL;
	GQuark error_domain;
	GError *error;

	if (!perror)
		return;

	/* do not overwrite already set error */
	if (*perror != NULL)
		return;

	switch (mapi_status) {
	case MAPI_E_SUCCESS:
		return;
	#define err(_code, _str)		\
		case _code:			\
			error_msg = _str;	\
			break

	err (MAPI_E_LOGON_FAILED,			_("Failed to login into the server"));
	err (MAPI_E_SESSION_LIMIT,			_("Cannot create more sessions, session limit was reached"));
	err (MAPI_E_USER_CANCEL,			_("User cancelled operation"));
	err (MAPI_E_UNABLE_TO_ABORT,			_("Unable to abort"));
	err (MAPI_E_NETWORK_ERROR,			_("Network error"));
	err (MAPI_E_DISK_ERROR,				_("Disk error"));
	err (MAPI_E_PASSWORD_CHANGE_REQUIRED,		_("Password change required"));
	err (MAPI_E_PASSWORD_EXPIRED,			_("Password expired"));
	err (MAPI_E_INVALID_WORKSTATION_ACCOUNT,	_("Invalid workstation account"));
	err (MAPI_E_INVALID_ACCESS_TIME,		_("Invalid access time"));
	err (MAPI_E_ACCOUNT_DISABLED,			_("Account is disabled"));
	err (MAPI_E_END_OF_SESSION,			_("End of session"));
	err (MAPI_E_NOT_INITIALIZED,			_("MAPI is not initialized or connected"));
	err (MAPI_E_NO_ACCESS,				_("Permission denied"));
	err (ecShutoffQuotaExceeded,			_("Mailbox quota exceeded"));

	#undef err

	default:
		status_name = mapi_get_errstr (mapi_status);
		if (!status_name)
			status_name = "";
		to_free = g_strdup_printf (_("MAPI error %s (0x%x) occurred"), status_name, mapi_status);
		error_msg = to_free;
	}

	g_return_if_fail (error_msg != NULL);

	error_domain = E_MAPI_ERROR;

	if (mapi_status == MAPI_E_USER_CANCEL) {
		error_domain = G_IO_ERROR;
		mapi_status = G_IO_ERROR_CANCELLED;
	}

	if (context && *context) {
		/* Translators: The first '%s' is replaced with an error context,
		   aka where the error occurred, the second '%s' is replaced with
		   the error message. */
		error = g_error_new (error_domain, mapi_status, C_("EXCHANGEMAPI_ERROR", "%s: %s"), context, error_msg);
	} else {
		error = g_error_new_literal (error_domain, mapi_status, error_msg);
	}

	g_free (to_free);

	g_propagate_error (perror, error);
}

struct _EMapiConnectionPrivate {
	ESourceRegistry *registry;

	struct mapi_context *mapi_ctx;
	struct mapi_session *session;
	EMapiCancellableRecMutex session_lock;

	gchar *profile;			/* profile name, where the session is connected to */
	mapi_object_t msg_store;	/* valid only when session != NULL */

	gboolean has_public_store;	/* whether is 'public_store' filled */
	mapi_object_t public_store;

	GHashTable *foreign_stores;	/* username (gchar *) => msg_store (mapi_object_t *); opened foreign stores */

	GSList *folders;		/* list of ExchangeMapiFolder pointers */
	GRecMutex folders_lock;		/* lock for 'folders' variable */

	GHashTable *named_ids;		/* cache of named ids; key is a folder ID, value is a hash table
					   of named_id to prop_id in that respective folder */

	GHashTable *known_notifications;/* mapi_id_t * -> uint32_t for Unsubscribe call */
	GThread *notification_thread;
	EFlag *notification_flag;
	enum MAPISTATUS	register_notification_result; /* MAPI_E_RESERVED if not called yet */
	gint notification_poll_seconds; /* delay between polls, in seconds */
};

enum {
	SERVER_NOTIFICATION,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

static gboolean
stop_notification (EMapiConnectionPrivate *priv,
		   uint32_t conn_id,
		   GCancellable *cancellable,
		   GError **perror)
{
	enum MAPISTATUS ms;

	e_return_val_mapi_error_if_fail (priv != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	ms = Unsubscribe (priv->session, conn_id);
	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "Unsubscribe", ms);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static void
call_stop_notification (gpointer key,
			gpointer value,
			gpointer user_data)
{
	stop_notification (user_data, GPOINTER_TO_UINT (value), NULL, NULL);
}

static void
stop_all_notifications (EMapiConnectionPrivate *priv)
{
	g_return_if_fail (priv != NULL);

	if (!priv->notification_thread)
		return;

	LOCK_VOID (NULL, NULL);
	if (priv->session)
		g_hash_table_foreach (priv->known_notifications, call_stop_notification, priv);
	g_hash_table_remove_all (priv->known_notifications);
	e_flag_set (priv->notification_flag);
	UNLOCK ();

	g_thread_join (priv->notification_thread);
	priv->notification_thread = NULL;
}

static void
release_foreign_stores_cb (gpointer pusername, gpointer pmsg_store, gpointer user_data)
{
	mapi_object_t *msg_store = pmsg_store;

	g_return_if_fail (msg_store != NULL);

	mapi_object_release (msg_store);
	talloc_free (msg_store);
}

/* should have session_lock locked already, when calling this function */
static void
disconnect (EMapiConnectionPrivate *priv,
	    gboolean clean)
{
	g_return_if_fail (priv != NULL);

	if (!priv->session)
		return;

	g_rec_mutex_lock (&priv->folders_lock);
	if (priv->folders)
		e_mapi_folder_free_list (priv->folders);
	priv->folders = NULL;
	g_rec_mutex_unlock (&priv->folders_lock);

	if (priv->has_public_store)
		mapi_object_release (&priv->public_store);

	g_hash_table_foreach (priv->foreign_stores, release_foreign_stores_cb, NULL);
	g_hash_table_remove_all (priv->foreign_stores); 

	if (clean) {
		Logoff (&priv->msg_store);
		/* it's released by the Logoff() call
		mapi_object_release (&priv->msg_store); */
	}

	if (priv->named_ids)
		g_hash_table_remove_all (priv->named_ids);

	priv->session = NULL;
	priv->has_public_store = FALSE;
}

/* should have session_lock locked already, when calling this function */
static gboolean
ensure_public_store (EMapiConnectionPrivate *priv,
		     GError **perror)
{
	e_return_val_mapi_error_if_fail (priv != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	if (!priv->session)
		return FALSE;

	if (!priv->has_public_store) {
		enum MAPISTATUS ms;

		mapi_object_init (&priv->public_store);

		ms = OpenPublicFolder (priv->session, &priv->public_store);
		if (ms == MAPI_E_SUCCESS) {
			priv->has_public_store = TRUE;
		} else {
			make_mapi_error (perror, "OpenPublicFolder", ms);
		}
	}

	return priv->has_public_store;
}

/* should have session_lock locked already, when calling this function */
static gboolean
ensure_foreign_store (EMapiConnectionPrivate *priv,
		      const gchar *username,
		      mapi_object_t **pmsg_store,
		      GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t *msg_store;

	e_return_val_mapi_error_if_fail (priv != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (username != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (pmsg_store != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	*pmsg_store = NULL;

	if (!priv->session)
		return FALSE;

	msg_store = g_hash_table_lookup (priv->foreign_stores, username);
	if (msg_store) {
		*pmsg_store = msg_store;
		return TRUE;
	}

	msg_store = talloc_zero (priv->session, mapi_object_t);
	mapi_object_init (msg_store);

	ms = OpenUserMailbox (priv->session, username, msg_store);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenUserMailbox", ms);

		mapi_object_release (msg_store);
		talloc_free (msg_store);

		return FALSE;
	}

	g_hash_table_insert (priv->foreign_stores, g_strdup (username), msg_store);

	*pmsg_store = msg_store;

	return TRUE;
}

static void
e_mapi_connection_dispose (GObject *object)
{
	EMapiConnectionPrivate *priv;

	unregister_connection (E_MAPI_CONNECTION (object));

	priv = E_MAPI_CONNECTION (object)->priv;

	if (priv) {
		stop_all_notifications (priv);
	}

	if (G_OBJECT_CLASS (e_mapi_connection_parent_class)->dispose)
		G_OBJECT_CLASS (e_mapi_connection_parent_class)->dispose (object);
}

static void
e_mapi_connection_finalize (GObject *object)
{
	EMapiConnection *conn;
	EMapiConnectionPrivate *priv;

	conn = E_MAPI_CONNECTION (object);
	priv = conn->priv;

	if (priv) {
		LOCK_VOID (NULL, NULL);
		disconnect (priv, TRUE && e_mapi_connection_connected (conn));
		g_free (priv->profile);
		priv->profile = NULL;

		if (priv->named_ids)
			g_hash_table_destroy (priv->named_ids);
		priv->named_ids = NULL;

		if (priv->foreign_stores)
			g_hash_table_destroy (priv->foreign_stores);
		priv->foreign_stores = NULL;

		e_mapi_utils_destroy_mapi_context (priv->mapi_ctx);
		priv->mapi_ctx = NULL;

		g_hash_table_destroy (priv->known_notifications);
		priv->known_notifications = NULL;

		e_flag_free (priv->notification_flag);
		priv->notification_flag = NULL;

		if (priv->registry)
			g_object_unref (priv->registry);
		priv->registry = NULL;

		UNLOCK ();

		e_mapi_cancellable_rec_mutex_clear (&priv->session_lock);
		g_rec_mutex_clear (&priv->folders_lock);
	}

	if (G_OBJECT_CLASS (e_mapi_connection_parent_class)->finalize)
		G_OBJECT_CLASS (e_mapi_connection_parent_class)->finalize (object);
}

static void
e_mapi_connection_class_init (EMapiConnectionClass *klass)
{
	GObjectClass *object_class;

	g_type_class_add_private (klass, sizeof (EMapiConnectionPrivate));

	object_class = G_OBJECT_CLASS (klass);
	object_class->dispose = e_mapi_connection_dispose;
	object_class->finalize = e_mapi_connection_finalize;

	signals[SERVER_NOTIFICATION] = g_signal_new (
		"server-notification",
		G_OBJECT_CLASS_TYPE (object_class),
		G_SIGNAL_RUN_FIRST | G_SIGNAL_DETAILED | G_SIGNAL_ACTION,
		0, NULL, NULL,
		g_cclosure_marshal_VOID__UINT_POINTER,
		G_TYPE_NONE, 2,
		G_TYPE_UINT, G_TYPE_POINTER);
}

static void
e_mapi_connection_init (EMapiConnection *conn)
{
	conn->priv = G_TYPE_INSTANCE_GET_PRIVATE (conn, E_MAPI_TYPE_CONNECTION, EMapiConnectionPrivate);
	g_return_if_fail (conn->priv != NULL);

	e_mapi_cancellable_rec_mutex_init (&conn->priv->session_lock);
	g_rec_mutex_init (&conn->priv->folders_lock);

	conn->priv->session = NULL;
	conn->priv->profile = NULL;
	conn->priv->has_public_store = FALSE;
	conn->priv->folders = NULL;

	conn->priv->foreign_stores = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	conn->priv->named_ids = g_hash_table_new_full (g_int64_hash, g_int64_equal, g_free, (GDestroyNotify) g_hash_table_destroy);

	conn->priv->known_notifications = g_hash_table_new_full (g_int64_hash, g_int64_equal, g_free, NULL);
	conn->priv->notification_thread = NULL;
	conn->priv->notification_flag = e_flag_new ();
	conn->priv->register_notification_result = MAPI_E_RESERVED;
	conn->priv->notification_poll_seconds = 60;

	if (g_getenv ("MAPI_SERVER_POLL")) {
		conn->priv->notification_poll_seconds = atoi (g_getenv ("MAPI_SERVER_POLL"));
		if (conn->priv->notification_poll_seconds < 1)
			conn->priv->notification_poll_seconds = 60;
	}

	register_connection (conn);
}

/* GObject foo - end */

/* tracking alive connections - begin  */

static GSList *known_connections = NULL;
G_LOCK_DEFINE_STATIC (known_connections);

static void
register_connection (EMapiConnection *conn)
{
	g_return_if_fail (conn != NULL);
	g_return_if_fail (E_MAPI_IS_CONNECTION (conn));

	G_LOCK (known_connections);
	/* append to prefer older connections when searching with e_mapi_connection_find() */
	known_connections = g_slist_append (known_connections, conn);
	G_UNLOCK (known_connections);
}

static void
unregister_connection (EMapiConnection *conn)
{
	g_return_if_fail (conn != NULL);
	g_return_if_fail (E_MAPI_IS_CONNECTION (conn));

	G_LOCK (known_connections);
	if (!g_slist_find (known_connections, conn)) {
		G_UNLOCK (known_connections);
		return;
	}

	known_connections = g_slist_remove (known_connections, conn);
	G_UNLOCK (known_connections);
}

/* Tries to find a connection associated with the 'profile'.
   If there are more, then the first created is returned.
   Note if it doesn't return NULL, then the returned pointer
   should be g_object_unref-ed, when done with it.
*/
EMapiConnection *
e_mapi_connection_find (const gchar *profile)
{
	GSList *l;
	EMapiConnection *res = NULL;

	g_return_val_if_fail (profile != NULL, NULL);

	G_LOCK (known_connections);
	for (l = known_connections; l != NULL && res == NULL; l = l->next) {
		EMapiConnection *conn = E_MAPI_CONNECTION (l->data);
		EMapiConnectionPrivate *priv = conn->priv;

		if (priv && priv->profile && g_str_equal (profile, priv->profile) &&
		    e_mapi_connection_connected (conn))
			res = conn;
	}

	if (res)
		g_object_ref (res);

	G_UNLOCK (known_connections);

	return res;
}

/* tracking alive connections - end  */

/* Specifies READ/WRITE sizes to be used while handling normal streams */
#define STREAM_MAX_READ_SIZE    0x8000
#define STREAM_MAX_READ_SIZE_DF 0x1000
#define STREAM_MAX_WRITE_SIZE   0x1000

#define CHECK_CORRECT_CONN_AND_GET_PRIV(_conn, _val)							\
	EMapiConnectionPrivate *priv;									\
													\
	e_return_val_mapi_error_if_fail (_conn != NULL, MAPI_E_INVALID_PARAMETER, _val);		\
	e_return_val_mapi_error_if_fail (E_MAPI_IS_CONNECTION (_conn), MAPI_E_INVALID_PARAMETER, _val);	\
													\
	priv = (_conn)->priv;										\
	e_return_val_mapi_error_if_fail (priv != NULL, MAPI_E_INVALID_PARAMETER, _val);

/* Creates a new connection object and connects to a server as defined in 'profile' */
EMapiConnection *
e_mapi_connection_new (ESourceRegistry *registry,
		       const gchar *profile,
		       const GString *password,
		       GCancellable *cancellable,
		       GError **perror)
{
	EMapiConnection *conn;
	EMapiConnectionPrivate *priv;
	struct mapi_context *mapi_ctx = NULL;
	struct mapi_session *session;
	enum MAPISTATUS ms;

	e_return_val_mapi_error_if_fail (profile != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	if (!e_mapi_utils_create_mapi_context (&mapi_ctx, perror))
		return NULL;

	session = mapi_profile_load (registry, mapi_ctx, profile, password ? password->str : NULL, cancellable, perror);
	if (!session) {
		e_mapi_utils_destroy_mapi_context (mapi_ctx);
		return NULL;
	}

	conn = g_object_new (E_MAPI_TYPE_CONNECTION, NULL);
	priv = conn->priv;
	e_return_val_mapi_error_if_fail (priv != NULL, MAPI_E_INVALID_PARAMETER, conn);

	LOCK (cancellable, perror, NULL);
	mapi_object_init (&priv->msg_store);
	priv->registry = registry ? g_object_ref (registry) : NULL;
	priv->mapi_ctx = mapi_ctx;
	priv->session = session;

	/* Open the message store and keep it opened for all the life-time for this connection */
	ms = OpenMsgStore (priv->session, &priv->msg_store);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenMsgStore", ms);

		/* how to close and free session without store? */
		priv->session = NULL;

		UNLOCK ();
		g_object_unref (conn);
		return NULL;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		UNLOCK ();
		g_object_unref (conn);
		return NULL;
	}

	priv->profile = g_strdup (profile);
	priv->has_public_store = FALSE;

	UNLOCK ();

	e_mapi_debug_print ("%s: %s: Connected ", G_STRLOC, G_STRFUNC);

	return conn;
}

gboolean
e_mapi_connection_disconnect (EMapiConnection *conn,
			      gboolean clean,
			      GCancellable *cancellable,
			      GError **perror)
{
	gboolean res = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	LOCK (cancellable, perror, FALSE);

	res = priv->session != NULL;
	disconnect (priv, clean && e_mapi_connection_connected (conn));

	UNLOCK ();

	return res;
}

gboolean
e_mapi_connection_reconnect (EMapiConnection *conn,
			     const GString *password,
			     GCancellable *cancellable,
			     GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	e_return_val_mapi_error_if_fail (priv->profile != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	if (priv->session)
		e_mapi_connection_disconnect (conn, FALSE, cancellable, perror);

	priv->session = mapi_profile_load (priv->registry, priv->mapi_ctx, priv->profile, password ? password->str : NULL, cancellable, perror);
	if (!priv->session) {
		e_mapi_debug_print ("%s: %s: Login failed ", G_STRLOC, G_STRFUNC);
		UNLOCK ();
		return FALSE;
	}

	mapi_object_init (&priv->msg_store);

	/* Open the message store and keep it opened for all the life-time for this connection */
	ms = OpenMsgStore (priv->session, &priv->msg_store);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenMsgStore", ms);

		/* how to close and free session without store? */
		priv->session = NULL;

		UNLOCK ();
		return FALSE;
	}

	priv->has_public_store = FALSE;

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		UNLOCK ();
		return FALSE;
	}

	UNLOCK ();

	e_mapi_debug_print ("%s: %s: Connected ", G_STRLOC, G_STRFUNC);

	return priv->session != NULL;
}

static gboolean
can_reach_mapi_server (const gchar *server_address,
		       GCancellable *cancellable,
		       GError **perror)
{
	GNetworkMonitor *network_monitor;
	GSocketConnectable *connectable;
	GError *local_error = NULL;
	gboolean reachable;

	g_return_val_if_fail (server_address != NULL, FALSE);

	network_monitor = g_network_monitor_get_default ();
	connectable = g_network_address_new (server_address, 135);
	reachable = g_network_monitor_can_reach (network_monitor, connectable, cancellable, &local_error);
	g_object_unref (connectable);

	if (!reachable) {
		if (local_error)
			g_propagate_error (perror, local_error);
		else
			g_set_error (perror, G_IO_ERROR, G_IO_ERROR_HOST_UNREACHABLE, _("Server '%s' cannot be reached"), server_address);
	}

	return reachable;
}

gboolean
e_mapi_connection_connected (EMapiConnection *conn)
{
	/* to have this used in the below macros */
	GError **perror = NULL;
	gboolean res;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	LOCK (NULL, NULL, FALSE);

	res = priv->session != NULL;
	if (res) {
		struct mapi_profile *profile;

		profile = talloc_zero (priv->mapi_ctx, struct mapi_profile);
		if (MAPI_E_SUCCESS == OpenProfile (priv->mapi_ctx, profile, priv->profile, NULL)) {
			res = can_reach_mapi_server (profile->server, NULL, perror);
			ShutDown (profile);
		}

		talloc_free (profile);
	}

	UNLOCK ();

	return res;
}

static gboolean
may_skip_property (uint32_t proptag)
{
	/* skip all "strange" properties */
	gboolean skip = TRUE;

	switch (proptag & 0xFFFF) {
	case PT_BOOLEAN:
	case PT_I2:
	case PT_LONG:
	case PT_DOUBLE:
	case PT_I8:
	case PT_STRING8:
	case PT_UNICODE:
	case PT_SYSTIME:
	case PT_BINARY:
	case PT_ERROR:
	case PT_CLSID:
	case PT_SVREID:
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
	case PT_MV_BINARY:
	case PT_MV_LONG:
		skip = FALSE;
		break;
	default:
		break;
	}

	return skip;
}

gboolean
e_mapi_connection_test_foreign_folder (EMapiConnection *conn,
				       const gchar *username,
				       const gchar *folder_name,
				       mapi_id_t *fid, /* out */
				       GCancellable *cancellable,
				       GError **perror)
{
	enum MAPISTATUS ms;
	mapi_id_t foreign_fid = 0;
	mapi_object_t obj_store, obj_folder;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (username != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (folder_name != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (fid != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	mapi_object_init (&obj_store);
	mapi_object_init (&obj_folder);

	ms = OpenUserMailbox (priv->session, username, &obj_store);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenUserMailbox", ms);
		goto cleanup;
	}

	if (folder_name[0] == '0' && folder_name[1] == 'x' && e_mapi_util_mapi_id_from_string (folder_name + 2, &foreign_fid)) {
		ms = OpenFolder (&obj_store, foreign_fid, &obj_folder);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "OpenFolder", ms);
			goto cleanup;
		}
	} else {
		uint32_t def_folder_id = 0;

		/* intentionally not localized strings */
		if (g_ascii_strcasecmp (folder_name, "Inbox") == 0) {
			def_folder_id = olFolderInbox;
		} else if (g_ascii_strcasecmp (folder_name, "DeletedItems") == 0) {
			def_folder_id = olFolderDeletedItems;
		} else if (g_ascii_strcasecmp (folder_name, "Outbox") == 0) {
			def_folder_id = olFolderOutbox;
		} else if (g_ascii_strcasecmp (folder_name, "SentMail") == 0) {
			def_folder_id = olFolderSentMail;
		} else if (g_ascii_strcasecmp (folder_name, "Calendar") == 0) {
			def_folder_id = olFolderCalendar;
		} else if (g_ascii_strcasecmp (folder_name, "Contacts") == 0) {
			def_folder_id = olFolderContacts;
		} else if (g_ascii_strcasecmp (folder_name, "Notes") == 0) {
			def_folder_id = olFolderNotes;
		} else if (g_ascii_strcasecmp (folder_name, "Tasks") == 0) {
			def_folder_id = olFolderTasks;
		} else if (g_ascii_strcasecmp (folder_name, "Drafts") == 0) {
			def_folder_id = olFolderDrafts;
		} else if (g_ascii_strcasecmp (folder_name, "Junk") == 0) {
			def_folder_id = olFolderJunk;
		} else if (!e_mapi_util_mapi_id_from_string (folder_name, &foreign_fid)) {
			ms = MAPI_E_CALL_FAILED;
			g_propagate_error (perror, g_error_new (E_MAPI_ERROR, ms, _("Folder name '%s' is not a known default folder name, nor folder ID."), folder_name));
			goto cleanup;
		}

		if (def_folder_id != 0) {
			ms = GetDefaultFolder (&obj_store, &foreign_fid, def_folder_id);
			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "GetDefaultFolder", ms);
				goto cleanup;
			}
		}

		ms = OpenFolder (&obj_store, foreign_fid, &obj_folder);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "OpenFolder", ms);
			goto cleanup;
		}
	}

	*fid = mapi_object_get_id (&obj_folder);

 cleanup:
	mapi_object_release (&obj_folder);
	mapi_object_release (&obj_store);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_get_public_folder (EMapiConnection *conn,
				     mapi_object_t *obj_folder,
				     GCancellable *cancellable,
				     GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	mapi_object_init (obj_folder);

	ms = OpenPublicFolder (priv->session, obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenPublicFolder", ms);
	}

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_peek_store (EMapiConnection *conn,
			      gboolean public_store,
			      const gchar *foreign_username,
			      mapi_object_t **obj_store, /* out */
			      GCancellable *cancellable,
			      GError **perror)
{
	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	if (public_store)
		e_return_val_mapi_error_if_fail (foreign_username == NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	if (foreign_username)
		e_return_val_mapi_error_if_fail (!public_store, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_store != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	if (public_store) {
		if (!ensure_public_store (priv, perror)) {
			UNLOCK ();
			return FALSE;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			UNLOCK ();
			return FALSE;
		}

		*obj_store = &priv->public_store;

		UNLOCK ();

		return TRUE;
	}

	if (foreign_username) {
		if (!ensure_foreign_store (priv, foreign_username, obj_store, perror)) {
			UNLOCK ();
			return FALSE;
		}

		UNLOCK ();
		return TRUE;
	}

	*obj_store = &priv->msg_store;

	UNLOCK ();

	return TRUE;
}

/* sets quotas and current_size to -1 when not available, but still can return TRUE */
gboolean
e_mapi_connection_get_store_quotas (EMapiConnection *conn,
				    mapi_object_t *obj_store, /* can be NULL, for mailbox store */
				    uint64_t *current_size, /* out */
				    uint64_t *receive_quota, /* out */
				    uint64_t *send_quota, /* out */
				    GCancellable *cancellable,
				    GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_RESERVED;
	TALLOC_CTX *mem_ctx;
	struct SPropTagArray *spropTagArray = NULL;
	struct SPropValue *lpProps = NULL;
	mapi_object_t *use_store;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (current_size != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (receive_quota != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (send_quota != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	use_store = obj_store;
	if (!use_store)
		use_store = &priv->msg_store;

	*current_size = -1;
	*receive_quota = -1;
	*send_quota = -1;

	mem_ctx = talloc_new (priv->session);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	spropTagArray = set_SPropTagArray (mem_ctx, 4,
		PidTagMessageSize,
		PidTagMessageSizeExtended,
		PidTagProhibitReceiveQuota,
		PidTagProhibitSendQuota);

	if (spropTagArray && spropTagArray->cValues) {
		uint32_t prop_count = 0;
		const uint32_t *pmessage_size, *preceive_quota, *psend_quota;
		const uint64_t *pmessage_size_ex;

		ms = GetProps (use_store, MAPI_PROPS_SKIP_NAMEDID_CHECK | MAPI_UNICODE, spropTagArray, &lpProps, &prop_count);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "GetProps", ms);
			goto cleanup;
		} else if (!lpProps) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "GetProps", ms);
			goto cleanup;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			goto cleanup;
		}

		pmessage_size = e_mapi_util_find_SPropVal_array_propval (lpProps, PidTagMessageSize);
		pmessage_size_ex = e_mapi_util_find_SPropVal_array_propval (lpProps, PidTagMessageSizeExtended);
		preceive_quota = e_mapi_util_find_SPropVal_array_propval (lpProps, PidTagProhibitReceiveQuota);
		psend_quota = e_mapi_util_find_SPropVal_array_propval (lpProps, PidTagProhibitSendQuota);

		if (pmessage_size && *pmessage_size != -1)
			*current_size = *pmessage_size;
		else if (pmessage_size_ex && *pmessage_size_ex)
			*current_size = *pmessage_size_ex;

		if (*current_size != -1) {
			if (preceive_quota && *preceive_quota != -1) {
				*receive_quota = *preceive_quota;
				*receive_quota *= 1024;
			}

			if (psend_quota && *psend_quota != -1) {
				*send_quota = *psend_quota;
				*send_quota *= 1024;
			}
		}
	} else {
		ms = MAPI_E_NOT_ENOUGH_RESOURCES;
		make_mapi_error (perror, "set_SPropTagArray", ms);
	}

 cleanup:
	talloc_free (spropTagArray);
	talloc_free (lpProps);
	talloc_free (mem_ctx);
	UNLOCK();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_open_default_folder (EMapiConnection *conn,
				       uint32_t olFolderIdentifier,
				       mapi_object_t *obj_folder,
				       GCancellable *cancellable,
				       GError **perror)
{
	enum MAPISTATUS ms;
	mapi_id_t fid = 0;
	gboolean res;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mapi_object_init (obj_folder);

	LOCK (cancellable, perror, FALSE);

	ms = GetDefaultFolder (&priv->msg_store, &fid, olFolderIdentifier);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultFolder", ms);
		UNLOCK ();
		return FALSE;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		UNLOCK ();
		return FALSE;
	}

	res = e_mapi_connection_open_personal_folder (conn, fid, obj_folder, cancellable, perror);

	UNLOCK ();

	return res;
}

gboolean
e_mapi_connection_open_personal_folder (EMapiConnection *conn,
					mapi_id_t fid,
					mapi_object_t *obj_folder,
					GCancellable *cancellable,
					GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mapi_object_init (obj_folder);

	LOCK (cancellable, perror, FALSE);

	ms = OpenFolder (&priv->msg_store, fid, obj_folder);
	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "OpenFolder", ms);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_open_public_folder (EMapiConnection *conn,
				      mapi_id_t fid,
				      mapi_object_t *obj_folder,
				      GCancellable *cancellable,
				      GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mapi_object_init (obj_folder);

	LOCK (cancellable, perror, FALSE);

	if (!ensure_public_store (priv, perror)) {
		UNLOCK ();
		return FALSE;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		UNLOCK ();
		return FALSE;
	}

	ms = OpenFolder (&priv->public_store, fid, obj_folder);
	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "OpenFolder", ms);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_open_foreign_folder (EMapiConnection *conn,
				       const gchar *username,
				       mapi_id_t fid,
				       mapi_object_t *obj_folder, /* out */
				       GCancellable *cancellable,
				       GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t *msg_store = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (username != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mapi_object_init (obj_folder);

	LOCK (cancellable, perror, FALSE);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		UNLOCK ();
		return FALSE;
	}

	if (!ensure_foreign_store (conn->priv, username, &msg_store, perror)) {
		ms = MAPI_E_CALL_FAILED;
		if (perror && !*perror)
			g_propagate_error (perror, g_error_new (E_MAPI_ERROR, ms, _("Failed to open store for user '%s'"), username));
	} else {
		ms = MAPI_E_SUCCESS;
	}

	if (ms == MAPI_E_SUCCESS) {
		ms = OpenFolder (msg_store, fid, obj_folder);
		if (ms == MAPI_E_NOT_FOUND)
			g_propagate_error (perror, g_error_new (E_MAPI_ERROR, ms, _("Folder of user '%s' not found"), username));
		else if (ms != MAPI_E_SUCCESS)
			make_mapi_error (perror, "OpenFolder", ms);
	}

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_close_folder (EMapiConnection *conn,
				mapi_object_t *obj_folder,
				GCancellable *cancellable,
				GError **perror)
{
	gboolean was_cancelled = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	/* kinda bad thing to do, but nothing better;
	   if the open_folder succeeded, then it's always good to free resources,
	   even when the operation on the folder was cancelled; and as it's good
	   to be cancellable, then this is better than passing NULL to LOCK().
	*/
	if (cancellable) {
		was_cancelled = g_cancellable_is_cancelled (cancellable);
		if (was_cancelled)
			g_cancellable_reset (cancellable);
	}

	LOCK (cancellable, perror, FALSE);

	mapi_object_release (obj_folder);

	/* this can invoke 'cancelled' again, but no big deal for evo-mapi */
	if (was_cancelled)
		g_cancellable_cancel (cancellable);

	UNLOCK ();

	return TRUE;
}

static void
maybe_add_named_id_tag (uint32_t proptag,
			EResolveNamedIDsData **named_ids_list,
			guint *named_ids_len)
{
	g_return_if_fail (named_ids_list != NULL);
	g_return_if_fail (named_ids_len != NULL);

	if (get_namedid_name (proptag)) {
		if (!*named_ids_list) {
			*named_ids_list = g_new0 (EResolveNamedIDsData, 1);
			*named_ids_len = 0;
		} else {
			*named_ids_list = g_renew (EResolveNamedIDsData, *named_ids_list, *named_ids_len + 1);
		}

		(*named_ids_list)[*named_ids_len].pidlid_propid = proptag;
		(*named_ids_list)[*named_ids_len].propid = MAPI_E_RESERVED;
		(*named_ids_len) += 1;
	}
}

/* free returned pointer with g_hash_table_destroy */
static GHashTable *
prepare_maybe_replace_hash (const EResolveNamedIDsData *named_ids_list,
			    guint named_ids_len,
			    gboolean to_server_ids)
{
	GHashTable *res;
	gint ii;

	if (!named_ids_list || !named_ids_len)
		return NULL;

	res = g_hash_table_new (g_direct_hash, g_direct_equal);

	for (ii = 0; ii < named_ids_len; ii++) {
		uint32_t search_tag = named_ids_list[ii].pidlid_propid;
		uint32_t replace_with = named_ids_list[ii].propid;

		if (!to_server_ids) {
			uint32_t ui32;

			ui32 = search_tag;
			search_tag = replace_with;
			replace_with = ui32;
		}

		g_hash_table_insert (res, GUINT_TO_POINTER (search_tag), GUINT_TO_POINTER (replace_with));

		search_tag = (search_tag & ~0xFFFF) | PT_ERROR;
		replace_with = (replace_with & ~0xFFFF) | PT_ERROR;

		g_hash_table_insert (res, GUINT_TO_POINTER (search_tag), GUINT_TO_POINTER (replace_with));
	}

	return res;
}

static void
maybe_replace_named_id_tag (uint32_t *pproptag,
			    GHashTable *replace_hash)
{
	gpointer key, value;

	g_return_if_fail (pproptag != NULL);

	if (!replace_hash)
		return;

	if (g_hash_table_lookup_extended (replace_hash, GUINT_TO_POINTER (*pproptag), &key, &value))
		*pproptag = GPOINTER_TO_UINT (value);
}

/* deals with named IDs transparently, if not using NULL bpr_cb, thus it's OK to check with PidLid and PidName constants only */
gboolean
e_mapi_connection_get_folder_properties (EMapiConnection *conn,
					 mapi_object_t *obj_folder,
					 BuildReadPropsCB brp_cb,
					 gpointer brp_cb_user_data,
					 GetPropertiesCB cb,
					 gpointer cb_user_data,
					 GCancellable *cancellable,
					 GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	struct SPropTagArray *spropTagArray = NULL;
	struct mapi_SPropValue_array *properties = NULL;
	struct SPropValue *lpProps = NULL;
	gboolean res = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		goto cleanup;

	spropTagArray = set_SPropTagArray (mem_ctx, 3, PidTagFolderId, PidTagLastModificationTime, PidTagContentCount);
	if (brp_cb) {
		if (!brp_cb (conn, mem_ctx, spropTagArray, brp_cb_user_data, cancellable, perror)) {
			goto cleanup;
		}
	} else {
		talloc_free (spropTagArray);
		spropTagArray = NULL;
	}

	properties = talloc_zero (mem_ctx, struct mapi_SPropValue_array);
	if (spropTagArray && spropTagArray->cValues) {
		uint32_t prop_count = 0, k, ll;
		EResolveNamedIDsData *named_ids_list = NULL;
		guint named_ids_len = 0;
		GHashTable *replace_hash = NULL;

		for (k = 0; k < spropTagArray->cValues; k++) {
			uint32_t proptag = spropTagArray->aulPropTag[k];

			if (may_skip_property (proptag)) {
				const gchar *name = get_proptag_name (proptag);
				if (!name)
					name = "";

				g_debug ("%s: Cannot fetch property 0x%08x %s", G_STRFUNC, proptag, name);
			} else {
				maybe_add_named_id_tag (proptag, &named_ids_list, &named_ids_len);
			}
		}

		if (named_ids_list) {
			if (!e_mapi_connection_resolve_named_props (conn, obj_folder, named_ids_list, named_ids_len, cancellable, perror)) {
				g_free (named_ids_list);
				goto cleanup;
			}

			if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
				g_free (named_ids_list);
				goto cleanup;
			}

			replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, TRUE);
			if (replace_hash) {
				for (k = 0; k < spropTagArray->cValues; k++) {
					uint32_t proptag = spropTagArray->aulPropTag[k];

					maybe_replace_named_id_tag (&proptag, replace_hash);

					spropTagArray->aulPropTag[k] = proptag;
				}
				g_hash_table_destroy (replace_hash);
				replace_hash = NULL;
			}
		}

		ms = GetProps (obj_folder, MAPI_PROPS_SKIP_NAMEDID_CHECK | MAPI_UNICODE, spropTagArray, &lpProps, &prop_count);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "GetProps", ms);
			g_free (named_ids_list);
			goto cleanup;
		} else if (!lpProps) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "GetProps", ms);
			g_free (named_ids_list);
			goto cleanup;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			g_free (named_ids_list);
			goto cleanup;
		}

		if (named_ids_list)
			replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, FALSE);

		/* Conversion from SPropValue to mapi_SPropValue. (no padding here) */
		properties->cValues = prop_count;
		properties->lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, prop_count + 1);
		for (k = 0, ll = 0; k < prop_count; k++, ll++) {
			if (may_skip_property (lpProps[k].ulPropTag)) {
				ll--;
				properties->cValues--;
			} else {
				uint32_t proptag = lpProps[k].ulPropTag;

				maybe_replace_named_id_tag (&proptag, replace_hash);
				lpProps[k].ulPropTag = proptag;

				cast_mapi_SPropValue (mem_ctx, &properties->lpProps[ll], &lpProps[k]);
			}
		}

		g_free (named_ids_list);
		if (replace_hash)
			g_hash_table_destroy (replace_hash);
	} else {
		ms = GetPropsAll (obj_folder, MAPI_UNICODE, properties);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "GetPropsAll", ms);
			goto cleanup;
		}

		if (properties)
			properties->lpProps = talloc_steal (properties, properties->lpProps);
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		goto cleanup;

	res = cb (conn, mem_ctx, properties, cb_user_data, cancellable, perror);

 cleanup:
	talloc_free (spropTagArray);
	talloc_free (properties);
	talloc_free (lpProps);
	talloc_free (mem_ctx);
	UNLOCK();

	return res;
}

typedef gboolean (*ForeachTableRowCB)	(EMapiConnection *conn,
					 TALLOC_CTX *mem_ctx,
					 struct SRow *srow,
					 guint32 row_index,
					 guint32 rows_total,
					 gpointer user_data,
					 GCancellable *cancellable,
					 GError **perror);

static enum MAPISTATUS
foreach_tablerow (EMapiConnection *conn,
		  TALLOC_CTX *mem_ctx,
		  mapi_object_t *obj_table,
		  ForeachTableRowCB cb,
		  gpointer user_data,
		  GCancellable *cancellable,
		  GError **perror)
{
	enum MAPISTATUS ms;
	struct SRowSet SRowSet;
	uint32_t count, i, cursor_pos = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_table != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	do {
		/* Number of items in the container */
		ms = QueryPosition (obj_table, &cursor_pos, &count);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "QueryPosition", ms);
			break;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}

		if (!count)
			break;

		/* Fill the table columns with data from the rows */
		ms = QueryRows (obj_table, count, TBL_ADVANCE, &SRowSet);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "QueryRows", ms);
			break;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}

		for (i = 0; i < SRowSet.cRows && ms == MAPI_E_SUCCESS; i++) {
			if (!cb (conn, mem_ctx, &SRowSet.aRow[i], cursor_pos + i + 1, count, user_data, cancellable, perror))
				ms = MAPI_E_RESERVED;
			else if (g_cancellable_set_error_if_cancelled (cancellable, perror))
				ms = MAPI_E_USER_CANCEL;
		}
	} while (cursor_pos < count && ms == MAPI_E_SUCCESS);

	return ms;
}

static gboolean
gather_folder_permissions_cb (EMapiConnection *conn,
			      TALLOC_CTX *mem_ctx,
			      struct SRow *srow,
			      guint32 row_index,
			      guint32 rows_total,
			      gpointer user_data,
			      GCancellable *cancellable,
			      GError **perror)
{
	GSList **entries = user_data;
	const gchar *username;
	const struct Binary_r *pentry_id;
	const uint64_t *pid;
	const uint32_t *prights;

	g_return_val_if_fail (srow != NULL, FALSE);
	g_return_val_if_fail (entries != NULL, FALSE);

	username = e_mapi_util_find_row_propval (srow, PidTagMemberName);
	pid = e_mapi_util_find_row_propval (srow, PidTagMemberId);
	pentry_id = e_mapi_util_find_row_propval (srow, PidTagEntryId);
	prights = e_mapi_util_find_row_propval (srow, PidTagMemberRights);

	if (prights && pid) {
		EMapiPermissionEntry *pem;
		struct SBinary_short entry_id;

		entry_id.cb = pentry_id ? pentry_id->cb : 0;
		entry_id.lpb = pentry_id ? pentry_id->lpb : NULL;

		pem = e_mapi_permission_entry_new (username, pentry_id ? &entry_id : NULL, *pid, *prights);
		g_return_val_if_fail (pem != NULL, FALSE);

		*entries = g_slist_prepend (*entries, pem);
	} else {
		g_debug ("%s: Skipping [%d/%d] (%s) No rights or member ID set", G_STRFUNC, row_index, rows_total, username ? username : "no member name");
	}

	return TRUE;
}

gboolean
e_mapi_connection_get_permissions (EMapiConnection *conn,
				   mapi_object_t *obj_folder,
				   gboolean with_freebusy,
				   GSList **entries, /* EMapiPermissionEntry */
				   GCancellable *cancellable,
				   GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_RESERVED;
	struct SPropTagArray *propTagArray;
	mapi_object_t obj_table;
	TALLOC_CTX *mem_ctx;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (entries != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);
	mapi_object_init (&obj_table);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = GetPermissionsTable (obj_folder, with_freebusy ? IncludeFreeBusy : 0, &obj_table);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetPermissionsTable", ms);
		goto cleanup;
	}

	propTagArray = set_SPropTagArray (mem_ctx, 4,
					  PidTagMemberId,
					  PidTagEntryId,
					  PidTagMemberName,
					  PidTagMemberRights);

	/* Set primary columns to be fetched */
	ms = SetColumns (&obj_table, propTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	*entries = NULL;

	ms = foreach_tablerow (conn, mem_ctx, &obj_table, gather_folder_permissions_cb, entries, cancellable, perror);
	if (ms == MAPI_E_SUCCESS) {
		*entries = g_slist_reverse (*entries);
	} else {
		g_slist_free_full (*entries, (GDestroyNotify) e_mapi_permission_entry_free);
		*entries = NULL;
	}

 cleanup:
	mapi_object_release (&obj_table);
	talloc_free (mem_ctx);
	UNLOCK();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_set_permissions (EMapiConnection *conn,
				   mapi_object_t *obj_folder,
				   gboolean with_freebusy,
				   const GSList *entries, /* EMapiPermissionEntry */
				   GCancellable *cancellable,
				   GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_RESERVED;
	struct mapi_PermissionsData *rows = NULL;
	GSList *current_entries = NULL;
	TALLOC_CTX *mem_ctx;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	rows = talloc_zero (mem_ctx, struct mapi_PermissionsData);
	if (!rows) {
		ms = MAPI_E_NOT_ENOUGH_RESOURCES;
		make_mapi_error (perror, "talloc_zero", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (!e_mapi_connection_get_permissions (conn, obj_folder, with_freebusy, &current_entries, cancellable, perror)) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "e_mapi_connection_get_permissions", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	rows->ModifyCount = g_slist_length ((GSList *) entries) + g_slist_length (current_entries);
	if (rows->ModifyCount > 0) {
		const GSList *iter, *citer;
		GSList *removed_entries = g_slist_copy (current_entries);
		gint row_index = 0;

		rows->PermissionsData = talloc_array (rows, struct PermissionData, rows->ModifyCount);
		if (!rows->PermissionsData) {
			ms = MAPI_E_NOT_ENOUGH_RESOURCES;
			make_mapi_error (perror, "talloc_zero", ms);
			g_slist_free (removed_entries);
			goto cleanup;
		}

		for (iter = entries; iter; iter = iter->next) {
			const EMapiPermissionEntry *pem = iter->data, *cpem = NULL;

			if (!pem) {
				ms = MAPI_E_INVALID_PARAMETER;
				make_mapi_error (perror, "entries::data", ms);
				g_slist_free (removed_entries);
				goto cleanup;
			}

			for (citer = current_entries; citer; citer = citer->next) {
				cpem = citer->data;

				if (cpem && ((cpem->entry_id.cb == pem->entry_id.cb && cpem->member_id == pem->member_id) ||
				   (cpem->entry_id.cb > 0 && e_mapi_util_recip_entryid_equal (&cpem->entry_id, &pem->entry_id)))) {
					removed_entries = g_slist_remove (removed_entries, cpem);
					break;
				}

				cpem = NULL;
			}

			if (cpem == NULL) {
				rows->PermissionsData[row_index].PermissionDataFlags = ROW_ADD;
				rows->PermissionsData[row_index].lpProps.cValues = 2;
				rows->PermissionsData[row_index].lpProps.lpProps = talloc_zero_array (rows, struct mapi_SPropValue, 3);
				if (!rows->PermissionsData[row_index].lpProps.lpProps) {
					ms = MAPI_E_NOT_ENOUGH_RESOURCES;
					make_mapi_error (perror, "talloc_zero", ms);
					g_slist_free (removed_entries);
					goto cleanup;
				}

				rows->PermissionsData[row_index].lpProps.lpProps[0].ulPropTag = PidTagEntryId;
				rows->PermissionsData[row_index].lpProps.lpProps[0].value.bin.cb = pem->entry_id.cb;
				rows->PermissionsData[row_index].lpProps.lpProps[0].value.bin.lpb = pem->entry_id.lpb;

				rows->PermissionsData[row_index].lpProps.lpProps[1].ulPropTag = PidTagMemberRights;
				rows->PermissionsData[row_index].lpProps.lpProps[1].value.l = pem->member_rights &
					~(with_freebusy ? 0 : (E_MAPI_PERMISSION_BIT_FREE_BUSY_DETAILED | E_MAPI_PERMISSION_BIT_FREE_BUSY_SIMPLE));

				row_index++;
			} else if (cpem->member_rights != pem->member_rights) {
				rows->PermissionsData[row_index].PermissionDataFlags = ROW_MODIFY;
				rows->PermissionsData[row_index].lpProps.cValues = 2;
				rows->PermissionsData[row_index].lpProps.lpProps = talloc_zero_array (rows, struct mapi_SPropValue, 3);
				if (!rows->PermissionsData[row_index].lpProps.lpProps) {
					ms = MAPI_E_NOT_ENOUGH_RESOURCES;
					make_mapi_error (perror, "talloc_zero", ms);
					g_slist_free (removed_entries);
					goto cleanup;
				}

				rows->PermissionsData[row_index].lpProps.lpProps[0].ulPropTag = PidTagMemberId;
				rows->PermissionsData[row_index].lpProps.lpProps[0].value.d = pem->member_id;

				rows->PermissionsData[row_index].lpProps.lpProps[1].ulPropTag = PidTagMemberRights;
				rows->PermissionsData[row_index].lpProps.lpProps[1].value.l = pem->member_rights &
					~(with_freebusy ? 0 : (E_MAPI_PERMISSION_BIT_FREE_BUSY_DETAILED | E_MAPI_PERMISSION_BIT_FREE_BUSY_SIMPLE));

				row_index++;
			}
		}

		for (citer = removed_entries; citer; citer = citer->next) {
			const EMapiPermissionEntry *cpem = citer->data;

			if (cpem) {
				rows->PermissionsData[row_index].PermissionDataFlags = ROW_REMOVE;
				rows->PermissionsData[row_index].lpProps.cValues = 1;
				rows->PermissionsData[row_index].lpProps.lpProps = talloc_zero_array (rows, struct mapi_SPropValue, 2);
				if (!rows->PermissionsData[row_index].lpProps.lpProps) {
					ms = MAPI_E_NOT_ENOUGH_RESOURCES;
					make_mapi_error (perror, "talloc_zero", ms);
					g_slist_free (removed_entries);
					goto cleanup;
				}

				rows->PermissionsData[row_index].lpProps.lpProps[0].ulPropTag = PidTagMemberId;
				rows->PermissionsData[row_index].lpProps.lpProps[0].value.d = cpem->member_id;

				row_index++;
			}
		}

		rows->ModifyCount = row_index;

		g_slist_free (removed_entries);
	}

	if (rows->ModifyCount > 0) {
		ms = ModifyPermissions (obj_folder, with_freebusy ? ModifyPerms_IncludeFreeBusy : 0, rows);
		if (ms == MAPI_E_INVALID_PARAMETER && with_freebusy) {
			gint ii;

			for (ii = 0; ii < rows->ModifyCount; ii++) {
				if (rows->PermissionsData[ii].PermissionDataFlags == ROW_ADD) {
					rows->PermissionsData[ii].lpProps.lpProps[1].value.l &=
						~(E_MAPI_PERMISSION_BIT_FREE_BUSY_DETAILED | E_MAPI_PERMISSION_BIT_FREE_BUSY_SIMPLE);
				} else if (rows->PermissionsData[ii].PermissionDataFlags == ROW_MODIFY) {
					rows->PermissionsData[ii].lpProps.lpProps[1].value.l &=
						~(E_MAPI_PERMISSION_BIT_FREE_BUSY_DETAILED | E_MAPI_PERMISSION_BIT_FREE_BUSY_SIMPLE);
				}
			}

			/* older servers (up to 8.0.360.0) can have issue setting Free/Busy flags,
			   thus try to set permissions without modifying these;
			   similar error can be also thrown when setting Free/Busy flags in rights,
			   but does not use ModifyPerms_IncludeFreeBusy flag
			*/
			ms = ModifyPermissions (obj_folder, 0, rows);
		}

		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "ModifyPermissions", ms);
			goto cleanup;
		}
	}

 cleanup:
	g_slist_free_full (current_entries, (GDestroyNotify) e_mapi_permission_entry_free);
	talloc_free (rows);
	talloc_free (mem_ctx);
	UNLOCK();

	return ms == MAPI_E_SUCCESS;
}

struct ListObjectsInternalData
{
	ListObjectsCB cb;
	gpointer user_data;
};

static gboolean
list_objects_internal_cb (EMapiConnection *conn,
			  TALLOC_CTX *mem_ctx,
			  struct SRow *srow,
			  guint32 row_index,
			  guint32 rows_total,
			  gpointer user_data,
			  GCancellable *cancellable,
			  GError **perror)
{
	struct ListObjectsInternalData *loi_data = user_data;
	ListObjectsData lod = { 0 };
	const mapi_id_t	*pmid;
	const gchar *msg_class;
	const uint32_t *pmsg_flags;
	const struct FILETIME *last_modified;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (srow != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	pmid = e_mapi_util_find_row_propval (srow, PidTagMid);
	msg_class = e_mapi_util_find_row_propval (srow, PidTagMessageClass);
	pmsg_flags = e_mapi_util_find_row_propval (srow, PidTagMessageFlags);
	last_modified = e_mapi_util_find_row_propval (srow, PidTagLastModificationTime);

	lod.mid = pmid ? *pmid : 0;
	lod.msg_class = msg_class;
	lod.msg_flags = pmsg_flags ? *pmsg_flags : 0;
	lod.last_modified = last_modified ? e_mapi_util_filetime_to_time_t (last_modified) : 0;

	return loi_data->cb (conn, mem_ctx, &lod, row_index, rows_total, loi_data->user_data, cancellable, perror);
}

static void
gather_mapi_SRestriction_named_ids (struct mapi_SRestriction *restriction,
				    EResolveNamedIDsData **named_ids_list,
				    guint *named_ids_len)
{
	guint i;

	g_return_if_fail (restriction != NULL);
	g_return_if_fail (named_ids_list != NULL);
	g_return_if_fail (named_ids_len != NULL);

	switch (restriction->rt) {
	case RES_AND:
		for (i = 0; i < restriction->res.resAnd.cRes; i++) {
			gather_mapi_SRestriction_named_ids ((struct mapi_SRestriction *) &(restriction->res.resAnd.res[i]), named_ids_list, named_ids_len);
		}
		break;
	case RES_OR:
		for (i = 0; i < restriction->res.resOr.cRes; i++) {
			gather_mapi_SRestriction_named_ids ((struct mapi_SRestriction *) &(restriction->res.resOr.res[i]), named_ids_list, named_ids_len);
		}
		break;
	#ifdef HAVE_RES_NOT_SUPPORTED
	case RES_NOT:
		gather_mapi_SRestriction_named_ids ((struct mapi_SRestriction *) restriction->res.resNot.res, named_ids_list, named_ids_len);
		break;
	#endif
	case RES_CONTENT:
		maybe_add_named_id_tag (restriction->res.resContent.ulPropTag, named_ids_list, named_ids_len);
		maybe_add_named_id_tag (restriction->res.resContent.lpProp.ulPropTag, named_ids_list, named_ids_len);
		break;
	case RES_PROPERTY:
		maybe_add_named_id_tag (restriction->res.resProperty.ulPropTag, named_ids_list, named_ids_len);
		maybe_add_named_id_tag (restriction->res.resProperty.lpProp.ulPropTag, named_ids_list, named_ids_len);
		break;
	case RES_COMPAREPROPS:
		maybe_add_named_id_tag (restriction->res.resCompareProps.ulPropTag1, named_ids_list, named_ids_len);
		maybe_add_named_id_tag (restriction->res.resCompareProps.ulPropTag2, named_ids_list, named_ids_len);
		break;
	case RES_BITMASK:
		maybe_add_named_id_tag (restriction->res.resBitmask.ulPropTag, named_ids_list, named_ids_len);
		break;
	case RES_SIZE:
		maybe_add_named_id_tag (restriction->res.resSize.ulPropTag, named_ids_list, named_ids_len);
		break;
	case RES_EXIST:
		maybe_add_named_id_tag (restriction->res.resExist.ulPropTag, named_ids_list, named_ids_len);
		break;
	}
}

static void
replace_mapi_SRestriction_named_ids (struct mapi_SRestriction *restriction,
				     GHashTable *replace_hash)
{
	guint i;
	uint32_t proptag;

	g_return_if_fail (restriction != NULL);

	#define check_proptag(x) {						\
			proptag = x;						\
			maybe_replace_named_id_tag (&proptag, replace_hash);	\
			x = proptag;						\
		}

	switch (restriction->rt) {
	case RES_AND:
		for (i = 0; i < restriction->res.resAnd.cRes; i++) {
			replace_mapi_SRestriction_named_ids ((struct mapi_SRestriction *) &(restriction->res.resAnd.res[i]), replace_hash);
		}
		break;
	case RES_OR:
		for (i = 0; i < restriction->res.resOr.cRes; i++) {
			replace_mapi_SRestriction_named_ids ((struct mapi_SRestriction *) &(restriction->res.resOr.res[i]), replace_hash);
		}
		break;
	#ifdef HAVE_RES_NOT_SUPPORTED
	case RES_NOT:
		replace_mapi_SRestriction_named_ids (restriction->res.resNot.res, replace_hash);
		break;
	#endif
	case RES_CONTENT:
		check_proptag (restriction->res.resContent.ulPropTag);
		check_proptag (restriction->res.resContent.lpProp.ulPropTag);
		break;
	case RES_PROPERTY:
		check_proptag (restriction->res.resProperty.ulPropTag);
		check_proptag (restriction->res.resProperty.lpProp.ulPropTag);
		break;
	case RES_COMPAREPROPS:
		check_proptag (restriction->res.resCompareProps.ulPropTag1);
		check_proptag (restriction->res.resCompareProps.ulPropTag2);
		break;
	case RES_BITMASK:
		check_proptag (restriction->res.resBitmask.ulPropTag);
		break;
	case RES_SIZE:
		check_proptag (restriction->res.resSize.ulPropTag);
		break;
	case RES_EXIST:
		check_proptag (restriction->res.resExist.ulPropTag);
		break;
	}

	#undef check_proptag
}

static void
remove_unknown_proptags_mapi_SRestriction_rec (struct mapi_SRestriction *restriction,
					       TALLOC_CTX *mem_ctx,
					       GSList **new_rests)
{
	gint ii;
	GSList *sub_rests = NULL, *iter;

	if (!restriction)
		return;

	g_return_if_fail (mem_ctx != NULL);

	#define proptag_is_ok(x) (((uint32_t) (x)) != 0 && ((uint32_t) (x)) != MAPI_E_RESERVED)

	switch (restriction->rt) {
	case RES_AND:
		for (ii = 0; ii < restriction->res.resAnd.cRes; ii++) {
			remove_unknown_proptags_mapi_SRestriction_rec ((struct mapi_SRestriction *) &(restriction->res.resAnd.res[ii]), mem_ctx, &sub_rests);
		}

		if (sub_rests) {
			struct mapi_SRestriction *rest = talloc_zero (mem_ctx, struct mapi_SRestriction);
			g_return_if_fail (rest != NULL);

			rest->rt = RES_AND;
			rest->res.resAnd.cRes = g_slist_length (sub_rests);
			rest->res.resAnd.res = talloc_zero_array (mem_ctx, struct mapi_SRestriction_and, rest->res.resAnd.cRes + 1);
			g_return_if_fail (rest->res.resAnd.res != NULL);

			for (iter = sub_rests, ii = 0; iter; iter = iter->next, ii++) {
				struct mapi_SRestriction *subrest = iter->data;

				g_return_if_fail (subrest != NULL);

				rest->res.resAnd.res[ii].rt = subrest->rt;
				rest->res.resAnd.res[ii].res = subrest->res;
			}

			*new_rests = g_slist_append (*new_rests, rest);
		}
		break;
	case RES_OR:
		for (ii = 0; ii < restriction->res.resOr.cRes; ii++) {
			remove_unknown_proptags_mapi_SRestriction_rec ((struct mapi_SRestriction *) &(restriction->res.resOr.res[ii]), mem_ctx, &sub_rests);
		}

		if (sub_rests) {
			struct mapi_SRestriction *rest = talloc_zero (mem_ctx, struct mapi_SRestriction);
			g_return_if_fail (rest != NULL);

			rest->rt = RES_OR;
			rest->res.resOr.cRes = g_slist_length (sub_rests);
			rest->res.resOr.res = talloc_zero_array (mem_ctx, struct mapi_SRestriction_or, rest->res.resOr.cRes + 1);
			g_return_if_fail (rest->res.resOr.res != NULL);

			for (iter = sub_rests, ii = 0; iter; iter = iter->next, ii++) {
				struct mapi_SRestriction *subrest = iter->data;

				g_return_if_fail (subrest != NULL);

				rest->res.resOr.res[ii].rt = subrest->rt;
				rest->res.resOr.res[ii].res = subrest->res;
			}

			*new_rests = g_slist_append (*new_rests, rest);
		}
		break;
	#ifdef HAVE_RES_NOT_SUPPORTED
	case RES_NOT:
		remove_unknown_proptags_mapi_SRestriction_rec (restriction->res.resNot.res, mem_ctx, &sub_rests);
		if (sub_rests) {
			struct mapi_SRestriction *rest = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
			g_return_if_fail (rest != NULL);

			rest->rt = RES_NOT;
			res->res.resNot.res = sub_rests->data;
		}
		break;
	#endif
	case RES_CONTENT:
		if (proptag_is_ok (restriction->res.resContent.ulPropTag) &&
		    proptag_is_ok (restriction->res.resContent.lpProp.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_PROPERTY:
		if (proptag_is_ok (restriction->res.resProperty.ulPropTag) &&
		    proptag_is_ok (restriction->res.resProperty.lpProp.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_COMPAREPROPS:
		if (proptag_is_ok (restriction->res.resCompareProps.ulPropTag1) &&
		    proptag_is_ok (restriction->res.resCompareProps.ulPropTag2)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_BITMASK:
		if (proptag_is_ok (restriction->res.resBitmask.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_SIZE:
		if (proptag_is_ok (restriction->res.resSize.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_EXIST:
		if (proptag_is_ok (restriction->res.resExist.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	default:
		g_warn_if_reached ();
		break;
	}

	#undef proptag_is_ok

	g_slist_free (sub_rests);
}

static void
remove_unknown_proptags_mapi_SRestriction (struct mapi_SRestriction **prestrictions,
					   TALLOC_CTX *mem_ctx)
{
	GSList *new_rests = NULL;

	g_return_if_fail (mem_ctx != NULL);

	remove_unknown_proptags_mapi_SRestriction_rec (*prestrictions, mem_ctx, &new_rests);

	if (new_rests) {
		g_return_if_fail (g_slist_length (new_rests) == 1);

		*prestrictions = new_rests->data;

		g_slist_free (new_rests);
	} else {
		*prestrictions = NULL;
	}
}

static gboolean
change_mapi_SRestriction_named_ids (EMapiConnection *conn,
				    mapi_object_t *obj_folder,
				    TALLOC_CTX *mem_ctx,
				    struct mapi_SRestriction **prestrictions,
				    GCancellable *cancellable,
				    GError **perror)
{
	EResolveNamedIDsData *named_ids_list = NULL;
	guint named_ids_len = 0;
	gboolean res = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (prestrictions != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (*prestrictions != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	gather_mapi_SRestriction_named_ids (*prestrictions, &named_ids_list, &named_ids_len);

	if (!named_ids_list)
		return TRUE;

	res = e_mapi_connection_resolve_named_props (conn, obj_folder, named_ids_list, named_ids_len, cancellable, perror);

	if (res) {
		GHashTable *replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, TRUE);

		if (replace_hash) {
			replace_mapi_SRestriction_named_ids (*prestrictions, replace_hash);
			g_hash_table_destroy (replace_hash);
		}
	}

	g_free (named_ids_list);

	remove_unknown_proptags_mapi_SRestriction (prestrictions, mem_ctx); 

	return res;
}

/* deals with named IDs transparently, thus it's OK to pass Restrictions with PidLid and PidName constants */
gboolean
e_mapi_connection_list_objects (EMapiConnection *conn,
				mapi_object_t *obj_folder,
				BuildRestrictionsCB build_rs_cb,
				gpointer build_rs_cb_data,
				ListObjectsCB cb,
				gpointer user_data,
				GCancellable *cancellable,
				GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_table;
	struct SPropTagArray *propTagArray;
	struct ListObjectsInternalData loi_data;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);
	mapi_object_init (&obj_table);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Get a handle on the container */
	ms = GetContentsTable (obj_folder, &obj_table, TableFlags_UseUnicode, NULL);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetContentsTable", ms);
		goto cleanup;
	}

	propTagArray = set_SPropTagArray (mem_ctx, 4,
		PidTagMid,
		PidTagMessageClass,
		PidTagMessageFlags,
		PidTagLastModificationTime);
		/* PidTagObjectType doesn't work with Exchange 2010 servers */

	/* Set primary columns to be fetched */
	ms = SetColumns (&obj_table, propTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (build_rs_cb) {
		struct mapi_SRestriction *restrictions = NULL;

		if (!build_rs_cb (conn, mem_ctx, &restrictions, build_rs_cb_data, cancellable, perror)) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "build_restrictions", ms);
			goto cleanup;
		}

		if (restrictions) {
			change_mapi_SRestriction_named_ids (conn, obj_folder, mem_ctx, &restrictions, cancellable, perror);

			if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
				ms = MAPI_E_USER_CANCEL;
				goto cleanup;
			}

			if (restrictions) {
				/* Applying any restriction that are set. */
				ms = Restrict (&obj_table, restrictions, NULL);
				if (ms != MAPI_E_SUCCESS) {
					make_mapi_error (perror, "Restrict", ms);
					goto cleanup;
				}

				if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
					ms = MAPI_E_USER_CANCEL;
					goto cleanup;
				}
			}
		}
	}

	loi_data.cb = cb;
	loi_data.user_data = user_data;

	ms = foreach_tablerow (conn, mem_ctx, &obj_table, list_objects_internal_cb, &loi_data, cancellable, perror);

 cleanup:
	mapi_object_release (&obj_table);
	talloc_free (mem_ctx);
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean
has_embedded_message_without_body (EMapiObject *object)
{
	EMapiAttachment *attach;

	if (!object)
		return FALSE;

	for (attach = object->attachments; attach; attach = attach->next) {
		if (!attach->embedded_object)
			continue;

		if (!e_mapi_object_contains_prop (attach->embedded_object, PidTagBody))
			return TRUE;

		if (has_embedded_message_without_body (attach->embedded_object))
			return TRUE;
	}

	return FALSE;
}

static gboolean
get_additional_properties_cb (EMapiConnection *conn,
			      TALLOC_CTX *mem_ctx,
			      /* const */ EMapiObject *object,
			      guint32 obj_index,
			      guint32 obj_total,
			      gpointer user_data,
			      GCancellable *cancellable,
			      GError **perror)
{
	uint32_t ii;
	EMapiObject *dest_object = user_data;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (dest_object != NULL, FALSE);

	for (ii = 0; ii < object->properties.cValues; ii++) {
		uint32_t proptag = object->properties.lpProps[ii].ulPropTag;

		if ((proptag & 0xFFFF) == PT_ERROR
		    || e_mapi_util_find_array_propval (&dest_object->properties, proptag))
			continue;

		dest_object->properties.cValues++;
		dest_object->properties.lpProps = talloc_realloc (mem_ctx,
				    dest_object->properties.lpProps,
				    struct mapi_SPropValue,
				    dest_object->properties.cValues + 1);
		dest_object->properties.lpProps[dest_object->properties.cValues - 1] = object->properties.lpProps[ii];

		#define steal_ptr(x) (x) = talloc_steal (dest_object, (x))
		switch (proptag & 0xFFFF) {
		case PT_BOOLEAN:
		case PT_I2:
		case PT_LONG:
		case PT_DOUBLE:
		case PT_I8:
		case PT_SYSTIME:
			break;
		case PT_STRING8:
			steal_ptr (dest_object->properties.lpProps[dest_object->properties.cValues - 1].value.lpszA);
			break;
		case PT_UNICODE:
			steal_ptr (dest_object->properties.lpProps[dest_object->properties.cValues - 1].value.lpszW);
			break;
		default:
			g_debug ("%s: Do not know how to steal property type 0x%x, skipping it", G_STRFUNC, proptag & 0xFFFF);
			dest_object->properties.cValues--;
			break;
		}
		#undef steal_ptr

		dest_object->properties.lpProps[dest_object->properties.cValues].ulPropTag = 0;
	}

	return TRUE;
}

static void
traverse_attachments_for_body (EMapiConnection *conn,
			       TALLOC_CTX *mem_ctx,
			       EMapiObject *object,
			       mapi_object_t *obj_message,
			       GCancellable *cancellable,
			       GError **perror)
{
	EMapiAttachment *attach;

	g_return_if_fail (conn != NULL);
	g_return_if_fail (mem_ctx != NULL);
	g_return_if_fail (obj_message != NULL);

	for (attach = object->attachments; attach && !g_cancellable_is_cancelled (cancellable); attach = attach->next) {
		if (attach->embedded_object) {
			const uint32_t *pattach_num;
			mapi_object_t obj_attach;
			mapi_object_t obj_embedded;
			gboolean have_embedded = FALSE;

			pattach_num = e_mapi_util_find_array_propval (&attach->properties, PidTagAttachNumber);
			if (!pattach_num)
				continue;

			mapi_object_init (&obj_attach);
			mapi_object_init (&obj_embedded);

			if (!e_mapi_object_contains_prop (attach->embedded_object, PidTagBody)) {
				struct SPropTagArray *tags;

				if (OpenAttach (obj_message, *pattach_num, &obj_attach) != MAPI_E_SUCCESS)
					continue;

				if (OpenEmbeddedMessage (&obj_attach, &obj_embedded, MAPI_READONLY) != MAPI_E_SUCCESS) {
					mapi_object_release (&obj_attach);
					continue;
				}

				have_embedded = TRUE;

				tags = set_SPropTagArray (mem_ctx, 1, PidTagBody);

				e_mapi_fast_transfer_properties (conn, mem_ctx, &obj_embedded, tags, get_additional_properties_cb, attach->embedded_object, cancellable, perror);

				talloc_free (tags);
			}

			if (has_embedded_message_without_body (attach->embedded_object)) {
				if (!have_embedded) {
					if (OpenAttach (obj_message, *pattach_num, &obj_attach) != MAPI_E_SUCCESS)
						continue;

					if (OpenEmbeddedMessage (&obj_attach, &obj_embedded, MAPI_READONLY) != MAPI_E_SUCCESS) {
						mapi_object_release (&obj_attach);
						continue;
					}

					have_embedded = TRUE;
				}

				traverse_attachments_for_body (conn, mem_ctx, attach->embedded_object, &obj_embedded, cancellable, perror);
			}

			mapi_object_release (&obj_embedded);
			mapi_object_release (&obj_attach);
		}
	}
}

struct EnsureAdditionalPropertiesData
{
	TransferObjectCB cb;
	gpointer cb_user_data;
	mapi_object_t *obj_folder;
	guint32 downloaded;
	guint32 download_offset;
	guint32 download_total;
};

static gboolean
ensure_additional_properties_cb (EMapiConnection *conn,
				 TALLOC_CTX *mem_ctx,
				 /* const */ EMapiObject *object,
				 guint32 obj_index,
				 guint32 obj_total,
				 gpointer user_data,
				 GCancellable *cancellable,
				 GError **perror)
{
	struct ap_data {
		uint32_t orig_proptag, use_proptag;
	} additional_properties[] = {
		{ PidTagBody, MAPI_E_RESERVED },
		{ PidTagMessageSize, MAPI_E_RESERVED },
		{ PidNameContentClass, MAPI_E_RESERVED }
	};
	struct EnsureAdditionalPropertiesData *eap = user_data;
	gboolean need_any = FALSE;
	uint32_t ii;

	g_return_val_if_fail (eap != NULL, FALSE);
	g_return_val_if_fail (eap->cb != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);

	if (g_cancellable_is_cancelled (cancellable))
		return FALSE;

	for (ii = 0; ii < G_N_ELEMENTS (additional_properties); ii++) {
		uint32_t prop = additional_properties[ii].orig_proptag;

		if (!e_mapi_object_contains_prop (object, prop)) {
			if (get_namedid_name (prop)) {
				prop = e_mapi_connection_resolve_named_prop (conn, eap->obj_folder, prop, cancellable, NULL);
			}
		} else {
			prop = MAPI_E_RESERVED;
		}

		additional_properties[ii].use_proptag = prop;
		need_any = need_any || prop != MAPI_E_RESERVED;
	}

	/* Fast-transfer transfers only Html or Body, never both */
	if (!g_cancellable_is_cancelled (cancellable) && (need_any || has_embedded_message_without_body (object))) {
		const mapi_id_t *mid;

		mid = e_mapi_util_find_array_propval (&object->properties, PidTagMid);
		if (mid && *mid) {
			mapi_object_t obj_message;
			
			mapi_object_init (&obj_message);

			if (OpenMessage (eap->obj_folder, mapi_object_get_id (eap->obj_folder), *mid, &obj_message, 0) == MAPI_E_SUCCESS) {
				struct SPropTagArray *tags = NULL;

				for (ii = 0; ii < G_N_ELEMENTS (additional_properties); ii++) {
					uint32_t prop = additional_properties[ii].use_proptag;

					if (prop == MAPI_E_RESERVED)
						continue;

					if (!tags)
						tags = set_SPropTagArray (mem_ctx, 1, prop);
					else
						SPropTagArray_add (mem_ctx, tags, prop);
				}

				if (tags) {
					uint32_t jj = object->properties.cValues;

					e_mapi_fast_transfer_properties	(conn, mem_ctx, &obj_message, tags, get_additional_properties_cb, object, cancellable, perror);

					while (jj < object->properties.cValues) {
						for (ii = 0; ii < G_N_ELEMENTS (additional_properties); ii++) {
							uint32_t proptag = object->properties.lpProps[jj].ulPropTag;

							if (additional_properties[ii].use_proptag == proptag ||
							    (((proptag & 0xFFFF) == PT_STRING8 || (proptag & 0xFFFF) == PT_UNICODE) &&
							        (proptag & ~0xFFFF) == (additional_properties[ii].use_proptag & ~0xFFFF))) {
								/* string8 and unicode properties are interchangeable in the union, luckily */
								object->properties.lpProps[jj].ulPropTag = additional_properties[ii].orig_proptag;
								break;
							}
						}

						jj++;
					}

					talloc_free (tags);
				}

				traverse_attachments_for_body (conn, mem_ctx, object, &obj_message, cancellable, perror);
			}

			mapi_object_release (&obj_message);
		}
	}

	eap->downloaded++;

	return eap->cb (conn, mem_ctx, object, eap->downloaded + eap->download_offset, eap->download_total, eap->cb_user_data, cancellable, perror);
}

static enum MAPISTATUS
fetch_object_property_as_stream (EMapiConnection *conn,
				 TALLOC_CTX *mem_ctx,
				 mapi_object_t *obj_message,
				 uint32_t proptag,
				 uint64_t *pcb,
				 uint8_t **plpb,
				 GCancellable *cancellable,
				 GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_stream;
	uint32_t buf_size, max_read;
	uint16_t off_data, cn_read;
	uint64_t cb = 0;
	uint8_t *lpb = NULL;
	gboolean done = FALSE;

	g_return_val_if_fail (conn != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (obj_message != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (pcb != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (plpb != NULL, MAPI_E_INVALID_PARAMETER);

	mapi_object_init (&obj_stream);

	ms = OpenStream (obj_message, proptag, OpenStream_ReadOnly, &obj_stream);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenStream", ms);
		goto cleanup;
	}

	cb = 0;

	ms = GetStreamSize (&obj_stream, &buf_size);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetStreamSize", ms);
		goto cleanup;
	}

	cb = buf_size;
	lpb = talloc_size (mem_ctx, cb + 1);
	if (!lpb || !cb)
		goto cleanup;

	/* determine max_read first, to read by chunks as long as possible */
	off_data = 0;
	max_read = buf_size > STREAM_MAX_READ_SIZE ? STREAM_MAX_READ_SIZE : buf_size;
	do {
		ms = ReadStream (&obj_stream, lpb + off_data, max_read, &cn_read);
		if (ms == MAPI_E_SUCCESS) {
			if (cn_read == 0) {
				done = TRUE;
			} else {
				off_data += cn_read;
				if (off_data >= buf_size)
					done = TRUE;
			}
			break;
		}

		if (ms == 0x2c80)
			max_read = max_read >> 1;
		else
			max_read = STREAM_MAX_READ_SIZE_DF;

		if (max_read < STREAM_MAX_READ_SIZE_DF)
			max_read = STREAM_MAX_READ_SIZE_DF;
	} while (ms == 0x2c80); /* an error when max_read is too large? */

	while (!done) {
		ms = ReadStream (&obj_stream, lpb + off_data, max_read, &cn_read);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "ReadStream", ms);
			done = TRUE;
		} else if (cn_read == 0) {
			done = TRUE;
		} else {
			off_data += cn_read;
			if (off_data >= buf_size)
				done = TRUE;
		}
	}

 cleanup:
	mapi_object_release (&obj_stream);

	*pcb = cb;
	*plpb = lpb;

	return ms;
}

static enum MAPISTATUS
e_mapi_connection_fetch_object_internal (EMapiConnection *conn,
					 TALLOC_CTX *mem_ctx,
					 mapi_object_t *obj_message,
					 struct EnsureAdditionalPropertiesData *eap,
					 EMapiObject **out_object,
					 GCancellable *cancellable,
					 GError **perror);

struct FetchObjectAttachmentData
{
	mapi_object_t *obj_message;
	struct EnsureAdditionalPropertiesData *eap;
	EMapiObject *object; /* to add attachments to */
};

static gboolean
fetch_object_attachment_cb (EMapiConnection *conn,
			    TALLOC_CTX *mem_ctx,
			    struct SRow *srow,
			    guint32 row_index,
			    guint32 rows_total,
			    gpointer user_data,
			    GCancellable *cancellable,
			    GError **perror)
{
	enum MAPISTATUS ms;
	struct FetchObjectAttachmentData *foa = user_data;
	EMapiAttachment *attachment = NULL;
	mapi_object_t obj_attach;
	const uint32_t *attach_num, *attach_method;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (srow != NULL, FALSE);
	g_return_val_if_fail (user_data != NULL, FALSE);
	g_return_val_if_fail (foa->obj_message != NULL, FALSE);
	g_return_val_if_fail (foa->object != NULL, FALSE);

	mapi_object_init (&obj_attach);

	attach_num = e_mapi_util_find_row_propval (srow, PidTagAttachNumber);
	if (!attach_num)
		return FALSE;

	ms = OpenAttach (foa->obj_message, *attach_num, &obj_attach);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenAttach", ms);
		goto cleanup;
	}

	attachment = e_mapi_attachment_new (foa->object);

	ms = GetPropsAll (&obj_attach, MAPI_UNICODE, &attachment->properties);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "Attachment::GetPropsAll", ms);
		goto cleanup;
	}

	if (attachment->properties.lpProps)
		attachment->properties.lpProps = talloc_steal (attachment, attachment->properties.lpProps);

	attach_method = e_mapi_util_find_row_propval (srow, PidTagAttachMethod);
	if (attach_method && *attach_method == ATTACH_BY_VALUE) {
		if (!e_mapi_attachment_contains_prop (attachment, PidTagAttachDataBinary)) {
			uint64_t cb = 0;
			uint8_t *lpb = NULL;

			ms = fetch_object_property_as_stream (conn, mem_ctx, &obj_attach, PidTagAttachDataBinary, &cb, &lpb, cancellable, perror);
			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "Attachment::fetch PidTagAttachDataBinary", ms);
				goto cleanup;
			}

			e_mapi_attachment_add_streamed (attachment, PidTagAttachDataBinary, cb, lpb);
		}
	} else if (attach_method && *attach_method == ATTACH_EMBEDDED_MSG) {
		mapi_object_t obj_emb_msg;

		mapi_object_init (&obj_emb_msg);

		if (OpenEmbeddedMessage (&obj_attach, &obj_emb_msg, MAPI_READONLY) == MAPI_E_SUCCESS) {
			e_mapi_connection_fetch_object_internal (conn, mem_ctx, &obj_emb_msg, foa->eap, &attachment->embedded_object, cancellable, perror);
		}

		mapi_object_release (&obj_emb_msg);
	}

 cleanup:
	mapi_object_release (&obj_attach);

	if (ms == MAPI_E_SUCCESS) {
		if (!foa->object->attachments) {
			foa->object->attachments = attachment;
		} else {
			EMapiAttachment *attach = foa->object->attachments;
			while (attach->next)
				attach = attach->next;
			attach->next = attachment;
		}
	} else {
		e_mapi_attachment_free (attachment);
	}

	return ms == MAPI_E_SUCCESS;
}

static enum MAPISTATUS
e_mapi_connection_fetch_object_internal (EMapiConnection *conn,
					 TALLOC_CTX *mem_ctx,
					 mapi_object_t *obj_message,
					 struct EnsureAdditionalPropertiesData *eap,
					 EMapiObject **out_object,
					 GCancellable *cancellable,
					 GError **perror)
{
	enum MAPISTATUS ms;
	EMapiObject *object;
	uint16_t ui16, uj16, np_count = 0, *np_propID = NULL;
	uint32_t ui32;
	struct MAPINAMEID *np_nameid = NULL;
	const uint8_t *has_attachments;
	struct SPropTagArray recipient_proptags;
	struct SRowSet recipient_rows;
	mapi_object_t attach_table;

	g_return_val_if_fail (conn != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (obj_message != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (eap != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (out_object != NULL, MAPI_E_INVALID_PARAMETER);

	mapi_object_init (&attach_table);

	object = e_mapi_object_new (mem_ctx);

	ms = GetPropsAll (obj_message, MAPI_UNICODE, &object->properties);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetPropsAll", ms);
		goto cleanup;
	}

	if (object->properties.lpProps)
		object->properties.lpProps = talloc_steal (object, object->properties.lpProps);

	/* to transform named ids to their PidLid or PidName tags, like the fast-transfer does */
	ms = QueryNamedProperties (obj_message, 0, NULL, &np_count, &np_propID, &np_nameid);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "QueryNamedProperties", ms);
		goto cleanup;
	}

	if (np_count && np_propID && np_nameid) {
		for (ui16 = 0; ui16 < np_count; ui16++) {
			uint32_t proptag = np_propID[ui16];

			for (uj16 = 0; uj16 < object->properties.cValues; uj16++) {
				if (object->properties.lpProps[uj16].ulPropTag == proptag) {
					uint32_t lid = MAPI_E_RESERVED;
					char *guid;

					guid = GUID_string (mem_ctx, &(np_nameid[ui16].lpguid));

					if (np_nameid[ui16].ulKind == MNID_ID) {
						if (mapi_nameid_lid_lookup_canonical (np_nameid[ui16].kind.lid, guid, &lid) != MAPI_E_SUCCESS)
							lid = MAPI_E_RESERVED;
					} else if (np_nameid[ui16].ulKind == MNID_STRING) {
						if (mapi_nameid_string_lookup_canonical (np_nameid[ui16].kind.lpwstr.Name, guid, &lid) != MAPI_E_SUCCESS)
							lid = MAPI_E_RESERVED;
					}

					talloc_free (guid);

					if (lid != MAPI_E_RESERVED && (lid & 0xFFFF) == (proptag & 0xFFFF)) {
						object->properties.lpProps[uj16].ulPropTag = lid;
					}

					break;
				}
			}
		}
	}

	talloc_free (np_propID);
	talloc_free (np_nameid);

	/* ensure certain properties */
	if (!e_mapi_object_contains_prop (object, PidTagHtml)) {
		uint8_t best_body = 0;

		if (GetBestBody (obj_message, &best_body) == MAPI_E_SUCCESS && best_body == olEditorHTML) {
			uint64_t cb = 0;
			uint8_t *lpb = NULL;

			ms = fetch_object_property_as_stream (conn, mem_ctx, obj_message, PidTagHtml, &cb, &lpb, cancellable, perror);
			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "Object::fetch PidTagHtml", ms);
				goto cleanup;
			}

			e_mapi_object_add_streamed (object, PidTagHtml, cb, lpb);
		}
	}

	if (!e_mapi_object_contains_prop (object, PidTagBody)) {
		uint64_t cb = 0;
		uint8_t *lpb = NULL;

		if (fetch_object_property_as_stream (conn, mem_ctx, obj_message, PidTagBody, &cb, &lpb, cancellable, NULL) == MAPI_E_SUCCESS) {
			object->properties.cValues++;
			object->properties.lpProps = talloc_realloc (mem_ctx,
								     object->properties.lpProps,
								     struct mapi_SPropValue,
								     object->properties.cValues + 1);
			object->properties.lpProps[object->properties.cValues - 1].ulPropTag = PidTagBody;
			if (cb > 0 && lpb[cb - 1] == 0)
				object->properties.lpProps[object->properties.cValues - 1].value.lpszW = (const char *) talloc_steal (object, lpb);
			else
				object->properties.lpProps[object->properties.cValues - 1].value.lpszW = talloc_strndup (object, (char *) lpb, cb);
			object->properties.lpProps[object->properties.cValues].ulPropTag = 0;
		}
	}

	if (!e_mapi_util_find_array_propval (&object->properties, PidNameContentClass)) {
		uint32_t prop = PidNameContentClass;

		prop = e_mapi_connection_resolve_named_prop (conn, eap->obj_folder, prop, cancellable, NULL);
		if (prop != MAPI_E_RESERVED) {
			struct SPropTagArray *tags;
			struct SPropValue *lpProps = NULL;
			uint32_t prop_count = 0;

			tags = set_SPropTagArray (mem_ctx, 1, prop);

			if (GetProps (obj_message, MAPI_PROPS_SKIP_NAMEDID_CHECK | MAPI_UNICODE, tags, &lpProps, &prop_count) == MAPI_E_SUCCESS && lpProps) {
				if (lpProps[0].ulPropTag == prop) {
					object->properties.cValues++;
					object->properties.lpProps = talloc_realloc (mem_ctx,
										     object->properties.lpProps,
										     struct mapi_SPropValue,
										     object->properties.cValues + 1);
					object->properties.lpProps[object->properties.cValues - 1].ulPropTag = PidNameContentClass;
					object->properties.lpProps[object->properties.cValues - 1].value.lpszW = talloc_strdup (object, lpProps[0].value.lpszW);
					object->properties.lpProps[object->properties.cValues].ulPropTag = 0;
				}
			}

			talloc_free (tags);
			talloc_free (lpProps);
		}
	}

	/* fetch attachments */
	has_attachments = e_mapi_util_find_array_propval (&object->properties, PidTagHasAttachments);
	if (has_attachments && *has_attachments) {
		struct SPropTagArray *attach_columns;
		struct FetchObjectAttachmentData foa;

		ms = GetAttachmentTable (obj_message, &attach_table);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "GetAttachmentTable", ms);
			goto cleanup;
		}

		attach_columns = set_SPropTagArray (mem_ctx, 1, PidTagAttachNumber);
		ms = SetColumns (&attach_table, attach_columns);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "AttachTable::SetColumns", ms);
			talloc_free (attach_columns);
			goto cleanup;
		}
		talloc_free (attach_columns);

		foa.obj_message = obj_message;
		foa.eap = eap;
		foa.object = object;

		ms = foreach_tablerow (conn, mem_ctx, &attach_table, fetch_object_attachment_cb, &foa, cancellable, perror);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "AttachTable::foreach_tablerow", ms);
			goto cleanup;
		}
	}

	/* get recipients */
	ms = GetRecipientTable (obj_message, &recipient_rows, &recipient_proptags);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetRecipientTable", ms);
		goto cleanup;
	}

	if (recipient_rows.cRows > 0) {
		uint32_t uj32, uk32;
		EMapiRecipient *first_recipient = NULL;

		for (ui32 = 0; ui32 < recipient_rows.cRows; ui32++) {
			struct SRow *row = &recipient_rows.aRow[ui32];
			EMapiRecipient *recipient;

			recipient = e_mapi_recipient_new (object);
			recipient->properties.cValues = row->cValues;
			recipient->properties.lpProps = talloc_zero_array (recipient, struct mapi_SPropValue, recipient->properties.cValues + 1);

			for (uj32 = 0, uk32 = 0; uj32 < row->cValues; uj32++, uk32++) {
				if (may_skip_property (row->lpProps[uj32].ulPropTag) ||
				    !e_mapi_utils_copy_to_mapi_SPropValue (recipient, &recipient->properties.lpProps[uk32], &row->lpProps[uj32])) {
					uk32--;
					recipient->properties.cValues--;
					recipient->properties.lpProps[recipient->properties.cValues].ulPropTag = 0;
				}
			}

			recipient->properties.lpProps[recipient->properties.cValues].ulPropTag = 0;
		}

		object->recipients = first_recipient;
	}

 cleanup:
	mapi_object_release (&attach_table);

	if (ms == MAPI_E_SUCCESS) {
		*out_object = object;
	} else {
		*out_object = NULL;
		e_mapi_object_free (object);
	}

	return ms;
}

static enum MAPISTATUS
e_mapi_connection_fetch_objects_internal (EMapiConnection *conn,
					  TALLOC_CTX *mem_ctx,
					  mapi_id_array_t *ids,
					  struct EnsureAdditionalPropertiesData *eap,
					  GCancellable *cancellable,
					  GError **perror)
{
	enum MAPISTATUS ms;
	guint32 idx;
	mapi_container_list_t *element;

	g_return_val_if_fail (conn != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (ids != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (eap != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (eap->obj_folder != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (eap->downloaded < ids->count, MAPI_E_INVALID_PARAMETER);

	for (idx = 0, element = ids->lpContainerList; idx < ids->count && idx < eap->downloaded && element; idx++) {
		element = element->next;
	}

	g_return_val_if_fail (idx < ids->count, MAPI_E_INVALID_PARAMETER);

	ms = MAPI_E_SUCCESS;
	while (element && ms == MAPI_E_SUCCESS) {
		mapi_object_t obj_message;
		EMapiObject *object = NULL;
		GError *local_error = NULL;

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}

		mapi_object_init (&obj_message);

		ms = OpenMessage (eap->obj_folder, mapi_object_get_id (eap->obj_folder), element->id, &obj_message, 0 /* read-only */);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "OpenMessage", ms);
			mapi_object_release (&obj_message);
			break;
		}

		/* silently skip broken objects */
		ms = e_mapi_connection_fetch_object_internal (conn, mem_ctx, &obj_message, eap, &object, cancellable, &local_error);
		if (ms == MAPI_E_SUCCESS) {
			if (!eap->cb (conn, mem_ctx, object, eap->downloaded + eap->download_offset, eap->download_total, eap->cb_user_data, cancellable, perror)) {
				ms = MAPI_E_USER_CANCEL;
				make_mapi_error (perror, "Object processing", ms);
			}
		} else {
			e_mapi_debug_print ("%s: Failed to fetch object %016" G_GINT64_MODIFIER "X: %s",
				G_STRFUNC, element->id, local_error ? local_error->message : mapi_get_errstr (ms));
		}

		e_mapi_object_free (object);
		mapi_object_release (&obj_message);

		eap->downloaded++;

		element = element->next;
	}

	return ms;
}

/* deals with named IDs transparently, thus it's OK to check with PidLid and PidName constants only */
gboolean
e_mapi_connection_transfer_objects (EMapiConnection *conn,
				    mapi_object_t *obj_folder,
				    const GSList *mids,
				    TransferObjectCB cb,
				    gpointer cb_user_data,
				    GCancellable *cancellable,
				    GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_CALL_FAILED;
	TALLOC_CTX *mem_ctx;
	const GSList *iter;
	struct EnsureAdditionalPropertiesData eap;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	eap.download_offset = 0;
	eap.download_total = g_slist_length ((GSList *) mids);

	iter = mids;
	while (iter) {
		mapi_id_array_t ids;

		ms = mapi_id_array_init (mem_ctx, &ids);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "mapi_id_array_init", ms);
			goto cleanup;
		}

		/* run this in chunks of 100 IDs */
		for (; iter && ids.count < 100; iter = iter->next) {
			mapi_id_t *pmid = iter->data;

			if (pmid)
				mapi_id_array_add_id (&ids, *pmid);
		}

		if (g_cancellable_is_cancelled (cancellable)) {
			if (perror && !*perror)
				g_cancellable_set_error_if_cancelled (cancellable, perror);

			ms = MAPI_E_USER_CANCEL;
			mapi_id_array_release (&ids);
			goto cleanup;
		}

		eap.cb = cb;
		eap.cb_user_data = cb_user_data;
		eap.obj_folder = obj_folder;
		eap.downloaded = 0;

		ms = e_mapi_fast_transfer_objects (conn, mem_ctx, obj_folder, &ids, ensure_additional_properties_cb, &eap, cancellable, perror);
		if (ms == MAPI_E_CALL_FAILED) {
			/* err, fallback to slow transfer, probably FXGetBuffer failed;
			   see http://tracker.openchange.org/issues/378
			*/

			g_clear_error (perror);

			e_mapi_debug_print ("%s: Failed to fast-transfer, fallback to slow fetch from %d of %d objects\n", G_STRFUNC, eap.downloaded, ids.count);

			ms = e_mapi_connection_fetch_objects_internal (conn, mem_ctx, &ids, &eap, cancellable, perror);
		}

		eap.download_offset += ids.count;

		mapi_id_array_release (&ids);
	}

 cleanup:
	talloc_free (mem_ctx);
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_transfer_object (EMapiConnection *conn,
				   mapi_object_t *obj_folder,
				   mapi_id_t message_id,
				   TransferObjectCB cb,
				   gpointer cb_user_data,
				   GCancellable *cancellable,
				   GError **perror)
{
	GSList *mids;
	gboolean res;

	mids = g_slist_append (NULL, &message_id);
	res = e_mapi_connection_transfer_objects (conn, obj_folder, mids, cb, cb_user_data, cancellable, perror);
	g_slist_free (mids);

	return res;
}

struct GetSummaryData {
	guint32 obj_index;
	guint32 obj_total;
	struct SPropValue *lpProps;
	uint32_t prop_count;
	TransferObjectCB cb;
	gpointer cb_user_data;
};

static gboolean
internal_get_summary_cb (EMapiConnection *conn,
			 TALLOC_CTX *mem_ctx,
			 /* const */ EMapiObject *object,
			 guint32 obj_index,
			 guint32 obj_total,
			 gpointer user_data,
			 GCancellable *cancellable,
			 GError **perror)
{
	struct GetSummaryData *gsd = user_data;

	g_return_val_if_fail (gsd != NULL, FALSE);
	g_return_val_if_fail (gsd->cb != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);

	if (g_cancellable_is_cancelled (cancellable))
		return FALSE;

	/* also include properties received from GetProps,
	   as those like PR_MID are not included by default */
	if (gsd->lpProps && gsd->prop_count > 0) {
		uint32_t ii;

		for (ii = 0; ii < gsd->prop_count; ii++) {
			/* skip errors and already included properties */
			if ((gsd->lpProps[ii].ulPropTag & 0xFFFF) == PT_ERROR
			    || e_mapi_object_contains_prop (object, gsd->lpProps[ii].ulPropTag))
				continue;

			object->properties.cValues++;
			object->properties.lpProps = talloc_realloc (mem_ctx,
					    object->properties.lpProps,
					    struct mapi_SPropValue,
					    object->properties.cValues + 1);
			cast_mapi_SPropValue (mem_ctx, &object->properties.lpProps[object->properties.cValues - 1], &gsd->lpProps[ii]);
			object->properties.lpProps[object->properties.cValues].ulPropTag = 0;
		}
	}

	return gsd->cb (conn, mem_ctx, object, gsd->obj_index, gsd->obj_total, gsd->cb_user_data, cancellable, perror);
}

/* transfers items summary, which is either PidTagTransportMessageHeaders or
   the object without attachment */
gboolean
e_mapi_connection_transfer_summary (EMapiConnection *conn,
				    mapi_object_t *obj_folder,
				    const GSList *mids,
				    TransferObjectCB cb,
				    gpointer cb_user_data,
				    GCancellable *cancellable,
				    GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	const GSList *iter;
	guint32 index, total;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	ms = MAPI_E_SUCCESS;
	total = g_slist_length ((GSList *) mids);
	for (iter = mids, index = 0; iter && ms == MAPI_E_SUCCESS; iter = iter->next, index++) {
		mapi_id_t *pmid = iter->data;

		if (pmid) {
			mapi_object_t obj_message;
			struct SPropTagArray *tags;
			struct SPropValue *lpProps = NULL;
			uint32_t prop_count = 0, ii;

			mapi_object_init (&obj_message);

			ms = OpenMessage (obj_folder, mapi_object_get_id (obj_folder), *pmid, &obj_message, 0);
			if (ms != MAPI_E_SUCCESS && ms != MAPI_E_NOT_FOUND) {
				make_mapi_error (perror, "OpenMessage", ms);
				goto cleanup;
			}

			tags = set_SPropTagArray (mem_ctx, 9,
				PidTagFolderId,
				PidTagMid,
				PidTagMessageFlags,
				PidTagMessageSize,
				PidTagMessageClass,
				PidTagLastModificationTime,
				PidTagTransportMessageHeaders,
				PidTagIconIndex,
				PidTagReadReceiptRequested);

			ms = GetProps (&obj_message, MAPI_PROPS_SKIP_NAMEDID_CHECK | MAPI_UNICODE, tags, &lpProps, &prop_count);
			if (ms == MAPI_E_SUCCESS) {
				ms = MAPI_E_NOT_FOUND;
				if (lpProps && prop_count > 0) {
					const gchar *headers = e_mapi_util_find_SPropVal_array_propval (lpProps, PidTagTransportMessageHeaders);

					if (headers && *headers) {
						EMapiObject *object;

						ms = MAPI_E_SUCCESS;

						object = e_mapi_object_new (mem_ctx);
						for (ii = 0; ii < prop_count; ii++) {
							object->properties.cValues++;
							object->properties.lpProps = talloc_realloc (mem_ctx,
									    object->properties.lpProps,
									    struct mapi_SPropValue,
									    object->properties.cValues + 1);
							cast_mapi_SPropValue (mem_ctx, &object->properties.lpProps[object->properties.cValues - 1], &lpProps[ii]);
							object->properties.lpProps[object->properties.cValues].ulPropTag = 0;
						}

						if (!cb (conn, mem_ctx, object, index, total, cb_user_data, cancellable, perror)) {
							ms = MAPI_E_USER_CANCEL;
							e_mapi_object_free (object);
							mapi_object_release (&obj_message);
							talloc_free (lpProps);
							talloc_free (tags);
							goto cleanup;
						}

						e_mapi_object_free (object);
					}
				}
			}

			if (ms == MAPI_E_NOT_FOUND) {
				struct GetSummaryData gsd;

				gsd.obj_index = index;
				gsd.obj_total = total;
				gsd.lpProps = lpProps;
				gsd.prop_count = prop_count;
				gsd.cb = cb;
				gsd.cb_user_data = cb_user_data;

				ms = e_mapi_fast_transfer_object (conn, mem_ctx, &obj_message, E_MAPI_FAST_TRANSFER_FLAG_RECIPIENTS, internal_get_summary_cb, &gsd, cancellable, perror);
				if (ms != MAPI_E_SUCCESS) {
					make_mapi_error (perror, "transfer_object", ms);
					mapi_object_release (&obj_message);
					talloc_free (lpProps);
					talloc_free (tags);
					goto cleanup;
				}
			}

			mapi_object_release (&obj_message);
			talloc_free (lpProps);
			talloc_free (tags);
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			goto cleanup;
		}
	}

 cleanup:
	talloc_free (mem_ctx);
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean
convert_mapi_props_to_props (EMapiConnection *conn,
			     mapi_object_t *obj_folder,
			     const struct mapi_SPropValue_array *mapi_props,
			     const EMapiStreamedProp *known_streams,
			     guint known_streams_count,
			     struct SPropValue **props,
			     uint32_t *propslen,
			     EMapiStreamedProp **streams, /* can be NULL for no streaming */
			     guint *streamslen, /* can be NULL only if streams is NULL; is ignored if streams is NULL */
			     TALLOC_CTX *mem_ctx,
			     GCancellable *cancellable,
			     GError **perror)
{
	uint16_t ii;
	EResolveNamedIDsData *named_ids_list = NULL;
	guint named_ids_len = 0;
	gboolean res = TRUE;

	e_return_val_mapi_error_if_fail (conn != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (mapi_props != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (props != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (propslen != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	if (streams) {
		e_return_val_mapi_error_if_fail (streamslen != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	} else {
		e_return_val_mapi_error_if_fail (known_streams == NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	}

	#define addstream() {										\
			if (!*streams) {								\
				*streams = g_new0 (EMapiStreamedProp, 1);				\
				*streamslen = 0;							\
			} else {									\
				*streams = g_renew (EMapiStreamedProp, *streams, *streamslen + 1);	\
			}										\
													\
			(*streams)[*streamslen].proptag = proptag;					\
			(*streams)[*streamslen].cb = 0;							\
			(*streams)[*streamslen].lpb = NULL;						\
			(*streams)[*streamslen].orig_value = NULL;					\
			(*streamslen) += 1;								\
		}

	for (ii = 0; ii < mapi_props->cValues; ii++) {
		gboolean processed = FALSE;
		uint32_t proptag = mapi_props->lpProps[ii].ulPropTag;
		gconstpointer propdata = get_mapi_SPropValue_data (&mapi_props->lpProps[ii]);

		maybe_add_named_id_tag (proptag, &named_ids_list, &named_ids_len);

		if (streams && propdata) {
			/* copy anything longer than 1KB as streams; this doesn't count total packet size needed,
			   but because this is usually useful only for PidTagBody, PidTagHtml, which are there
			   only once, then no big deal
			*/

			uint32_t sz;
			const gchar *str;
			const struct SBinary_short *bin;

			switch (proptag & 0xFFFF) {
			case PT_BINARY:
				bin = propdata;
				if (bin->cb > MAX_PROPERTY_WRITE_SIZE) {
					addstream ();
					(*streams)[(*streamslen) - 1].cb = bin->cb;
					(*streams)[(*streamslen) - 1].lpb = bin->lpb;
					(*streams)[(*streamslen) - 1].orig_value = propdata;
					processed = TRUE;
				}
				break;
			case PT_STRING8:
				str = propdata;
				sz = get_mapi_property_size (&mapi_props->lpProps[ii]);
				if (sz > MAX_PROPERTY_WRITE_SIZE) {
					addstream ();
					(*streams)[(*streamslen) - 1].cb = sz;
					(*streams)[(*streamslen) - 1].lpb = (uint8_t *) str;
					(*streams)[(*streamslen) - 1].orig_value = propdata;
					processed = TRUE;
				}
				break;
			case PT_UNICODE:
				str = propdata;
				sz = get_mapi_property_size (&mapi_props->lpProps[ii]);
				if (sz > MAX_PROPERTY_WRITE_SIZE) {
					gchar *in_unicode;
					gsize written = 0;

					addstream ();
					(*streams)[(*streamslen) - 1].orig_value = propdata;

					in_unicode = g_convert (str, strlen (str), "UTF-16", "UTF-8", NULL, &written, NULL);
					if (in_unicode && written > 0) {
						uint8_t *bytes = talloc_zero_size (mem_ctx, written + 2);

						/* skip Unicode marker, if there */
						if (written >= 2 && (const guchar) in_unicode[0] == 0xFF && (const guchar) in_unicode[1] == 0xFE) {
							memcpy (bytes, in_unicode + 2, written - 2);
							written -= 2;
						} else
							memcpy (bytes, in_unicode, written);

						/* null-terminated unicode string */
						(*streams)[(*streamslen) - 1].lpb = bytes;
						(*streams)[(*streamslen) - 1].cb = written + 2;
					}
					g_free (in_unicode);
					processed = TRUE;
				}
				break;
			}
		}

		if (!processed)
			e_mapi_utils_add_spropvalue (mem_ctx, props, propslen, proptag, propdata);
	}

	if (known_streams && known_streams_count > 0 && streams) {
		for (ii = 0; ii < known_streams_count; ii++) {
			uint32_t proptag = known_streams[ii].proptag;

			maybe_add_named_id_tag (proptag, &named_ids_list, &named_ids_len);

			addstream ();
			(*streams)[(*streamslen) - 1].cb = known_streams[ii].cb;
			(*streams)[(*streamslen) - 1].lpb = known_streams[ii].lpb;
			(*streams)[(*streamslen) - 1].orig_value = NULL;
		}
	}
	#undef addstream

	if (named_ids_list) {
		GHashTable *replace_hash = NULL;

		res = e_mapi_connection_resolve_named_props (conn, obj_folder, named_ids_list, named_ids_len, cancellable, perror);

		if (res)
			replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, TRUE);

		if (replace_hash && *props) {
			for (ii = 0; ii < *propslen; ii++) {
				uint32_t proptag = (*props)[ii].ulPropTag;

				maybe_replace_named_id_tag (&proptag, replace_hash);

				(*props)[ii].ulPropTag = proptag;
			}
		}

		if (replace_hash && streams) {
			for (ii = 0; ii < *streamslen; ii++) {
				maybe_replace_named_id_tag (&((*streams)[ii].proptag), replace_hash);
			}
		}

		if (replace_hash)
			g_hash_table_destroy (replace_hash);
	}

	g_free (named_ids_list);

	return res;
}

static gboolean
write_streamed_prop (EMapiConnection *conn,
		     mapi_object_t *obj_object,
		     const EMapiStreamedProp *stream,
		     TALLOC_CTX *mem_ctx,
		     GCancellable *cancellable,
		     GError **perror)
{
	enum MAPISTATUS	ms;
	uint64_t total_written;
	gboolean done = FALSE;
	mapi_object_t obj_stream;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_object != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (stream != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	mapi_object_init (&obj_stream);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* OpenStream on required proptag */
	ms = OpenStream (obj_object, stream->proptag, OpenStream_Create, &obj_stream);
	if (ms != MAPI_E_SUCCESS) {
		if (ms == MAPI_E_NO_ACCESS && stream->orig_value) {
			/* write property with SetProps, because this one cannot be written as stream */
			struct SPropValue *props = NULL;
			uint32_t propslen = 0;

			e_mapi_utils_add_spropvalue (mem_ctx, &props, &propslen, stream->proptag, stream->orig_value);

			ms = SetProps (obj_object, MAPI_PROPS_SKIP_NAMEDID_CHECK, props, propslen);

			talloc_free (props);

			if (ms != MAPI_E_SUCCESS)
				make_mapi_error (perror, "SetProps", ms);
		} else {
			make_mapi_error (perror, "OpenStream", ms);
		}
		goto cleanup;
	}

	/* Set the stream size */
	ms = SetStreamSize (&obj_stream, stream->cb);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetStreamSize", ms);
		goto cleanup;
	}

	total_written = 0;
	/* Write stream */
	while (!done) {
		uint16_t cn_written = 0;
		DATA_BLOB blob;

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			goto cleanup;
		}

		blob.length = (stream->cb - total_written) < STREAM_MAX_WRITE_SIZE ?
			      (stream->cb - total_written) : STREAM_MAX_WRITE_SIZE;
		blob.data = (uint8_t *) (stream->lpb + total_written);

		ms = WriteStream (&obj_stream, &blob, &cn_written);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "WriteStream", ms);
			done = TRUE;
		} else if (cn_written == 0) {
			done = TRUE;
		} else {
			total_written += cn_written;
			if (total_written >= stream->cb)
				done = TRUE;
		}
	}

	if (ms == MAPI_E_SUCCESS) {
		/* Commit the stream */
		ms = CommitStream (&obj_stream);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "CommitStream", ms);
			goto cleanup;
		}
	}

 cleanup:
	mapi_object_release (&obj_stream);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean
update_props_on_object (EMapiConnection *conn,
			mapi_object_t *obj_folder,
			mapi_object_t *obj_object,
			const struct mapi_SPropValue_array *properties,
			const EMapiStreamedProp *known_streams,
			guint known_streams_count,
			TALLOC_CTX *mem_ctx,
			GCancellable *cancellable,
			GError **perror)
{
	enum MAPISTATUS	ms = MAPI_E_RESERVED;
	struct SPropValue *props = NULL;
	uint32_t propslen = 0;
	EMapiStreamedProp *streams = NULL;
	guint streamslen = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	if (!convert_mapi_props_to_props (conn, obj_folder, properties, known_streams, known_streams_count, &props, &propslen, &streams, &streamslen, mem_ctx, cancellable, perror)) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "convert_mapi_props_to_props", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (props) {
		/* set properties for the item */
		ms = SetProps (obj_object, MAPI_PROPS_SKIP_NAMEDID_CHECK, props, propslen);

		talloc_free (props);

		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SetProps", ms);
			goto cleanup;
		}
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (streams) {
		guint ii;

		for (ii = 0; ii < streamslen; ii++) {
			if (!write_streamed_prop (conn, obj_object, &streams[ii], mem_ctx, cancellable, perror)) {
				ms = MAPI_E_CALL_FAILED;
				make_mapi_error (perror, "write_streamed_prop", ms);
				break;
			}

			if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
				ms = MAPI_E_USER_CANCEL;
				break;
			}
		}

		g_free (streams);
	}
 cleanup:
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean
update_recipient_properties (EMapiConnection *conn,
			     mapi_object_t *obj_folder,
			     struct SRow *aRow,
			     EMapiRecipient *recipient,
			     gboolean is_resolved,
			     TALLOC_CTX *mem_ctx,
			     GCancellable *cancellable,
			     GError **perror)
{
	struct SPropValue *props = NULL;
	uint32_t propslen = 0, ii;

	g_return_val_if_fail (recipient != NULL, FALSE);

	if (!convert_mapi_props_to_props (conn, obj_folder, &recipient->properties, NULL, 0, &props, &propslen, NULL, NULL, mem_ctx, cancellable, perror))
		return FALSE;

	for (ii = 0; ii < propslen; ii++) {
		/* do not overwrite all properties, if recipient was resolved properly */
		if (!is_resolved
		    || props[ii].ulPropTag == PidTagRecipientType
		    || props[ii].ulPropTag == PidTagSendInternetEncoding
		    || props[ii].ulPropTag == PidTagRecipientFlags
		    || props[ii].ulPropTag == PidTagRecipientTrackStatus)
			SRow_addprop (aRow, props[ii]);
	}

	return TRUE;
}

static gboolean
delete_object_recipients (EMapiConnection *conn,
			  mapi_object_t *obj_folder,
			  mapi_object_t *obj_object,
			  TALLOC_CTX *mem_ctx,
			  GCancellable *cancellable,
			  GError **perror)
{
	enum MAPISTATUS	ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	ms = RemoveAllRecipients (obj_object);
	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "RemoveAllRecipients", ms);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean
add_object_recipients (EMapiConnection *conn,
		       mapi_object_t *obj_folder,
		       mapi_object_t *obj_message,
		       EMapiRecipient *recipients,
		       TALLOC_CTX *mem_ctx,
		       GCancellable *cancellable,
		       GError **perror)
{
	const uint32_t required_tags[] = {PidTagEntryId,
					  PidTagDisplayName,
					  PidTagObjectType,
					  PidTagDisplayType,
					  PidTagTransmittableDisplayName,
					  PidTagEmailAddress,
					  PidTagAddressType,
					  PidTagSendRichInfo};
	enum MAPISTATUS	ms;
	struct SPropTagArray *tags;
	struct SRowSet *rows = NULL;
	struct PropertyRowSet_r *prop_rows = NULL;
	struct PropertyTagArray_r *flagList = NULL;
	EResolveNamedIDsData *named_ids_list = NULL;
	guint named_ids_len = 0;
	const gchar **users = NULL;
	EMapiRecipient *recipient;
	EMapiRecipient **recips;
	uint32_t ii, jj, count = 0;
	GHashTable *all_proptags;
	GHashTableIter iter;
	gpointer key, value;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	count = 0;
	for (recipient = recipients, ii = 0; recipient; recipient = recipient->next, ii++) {
		if (!e_mapi_util_find_array_propval (&recipient->properties, PidTagPrimarySmtpAddress)
		    && !e_mapi_util_find_array_propval (&recipient->properties, PidTagDisplayName))
			g_debug ("%s: Cannot get email or display name for a recipient %d, skipping it", G_STRFUNC, ii);
		else
			count++;
	}

	if (!count)
		return TRUE;

	LOCK (cancellable, perror, FALSE);

	all_proptags = g_hash_table_new (g_direct_hash, g_direct_equal);
	users = g_new0 (const gchar *, count + 1);
	recips = g_new0 (EMapiRecipient *, count + 1);

	for (ii = 0; ii < G_N_ELEMENTS (required_tags); ii++) {
		g_hash_table_insert (all_proptags, GUINT_TO_POINTER (required_tags[ii]), GUINT_TO_POINTER (1));
	}

	for (ii = 0, jj = 0, recipient = recipients; ii < count && recipient != NULL; ii++, recipient = recipient->next) {
		users[ii] = e_mapi_util_find_array_propval (&recipient->properties, PidTagPrimarySmtpAddress);
		if (!users[ii])
			users[ii] = e_mapi_util_find_array_propval (&recipient->properties, PidTagDisplayName);
		if (!users[ii]) {
			ii--;
		} else {
			uint32_t kk;

			recips[jj] = recipient;
			jj++;

			for (kk = 0; kk < recipient->properties.cValues; kk++) {
				g_hash_table_insert (all_proptags, GUINT_TO_POINTER (recipient->properties.lpProps[kk].ulPropTag), GUINT_TO_POINTER (1));
			}
		}
	}

	/* Attempt to resolve names from the server */
	tags = NULL;
	g_hash_table_iter_init (&iter, all_proptags);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		uint32_t proptag = GPOINTER_TO_UINT (key);

		maybe_add_named_id_tag (proptag, &named_ids_list, &named_ids_len);

		if (!tags)
			tags = set_SPropTagArray (mem_ctx, 1, proptag);
		else
			SPropTagArray_add (mem_ctx, tags, proptag);
	}

	if (named_ids_list) {
		GHashTable *replace_hash;

		if (!e_mapi_connection_resolve_named_props (conn, obj_folder, named_ids_list, named_ids_len, cancellable, perror)) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "e_mapi_connection_resolve_named_props", ms);
			goto cleanup;
		}

		replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, TRUE);

		for (ii = 0; ii < tags->cValues && replace_hash; ii++) {
			uint32_t proptag = tags->aulPropTag[ii];

			maybe_replace_named_id_tag (&proptag, replace_hash);

			tags->aulPropTag[ii] = proptag;
		}

		if (replace_hash)
			g_hash_table_destroy (replace_hash);
	}

	ms = ResolveNames (priv->session, users, tags, &prop_rows, &flagList, MAPI_UNICODE);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "ResolveNames", ms);
		goto cleanup;
	}

	g_assert (count == flagList->cValues);

	rows = talloc_zero (mem_ctx, struct SRowSet);

	/* 'prop_rows == NULL' happens when there are none resolved recipients */
	if (prop_rows)
		cast_PropertyRowSet_to_SRowSet (mem_ctx, prop_rows, rows);

	for (ii = 0, jj = 0; ii < count; ii++) {
		recipient = recips[ii];

		if (flagList->aulPropTag[ii] == MAPI_AMBIGUOUS) {
			/* We should never get an ambiguous resolution as we use the email-id for resolving.
			 * However, if we do still get an ambiguous entry, we can't handle it :-( */
			ms = MAPI_E_AMBIGUOUS_RECIP;
			/* Translators: %s is replaced with an email address which was found ambiguous on a remote server */
			g_set_error (perror, E_MAPI_ERROR, ms, _("Recipient '%s' is ambiguous"), users[ii]);
			goto cleanup;
		} else if (flagList->aulPropTag[ii] == MAPI_UNRESOLVED) {
			uint32_t last;

			/* If the recipient is unresolved, consider it is a SMTP one */
			rows->aRow = talloc_realloc (mem_ctx, rows->aRow, struct SRow, rows->cRows + 1);
			last = rows->cRows;
			rows->aRow[last].cValues = 0;
			rows->aRow[last].lpProps = talloc_zero (mem_ctx, struct SPropValue);
			if (!update_recipient_properties (conn, obj_folder, &rows->aRow[last], recipient, FALSE, mem_ctx, cancellable, perror)) {
				ms = MAPI_E_CALL_FAILED;
				goto cleanup;
			}
			rows->cRows += 1;
		} else if (flagList->aulPropTag[ii] == MAPI_RESOLVED) {
			if (!update_recipient_properties (conn, obj_folder, &rows->aRow[jj], recipient, TRUE, mem_ctx, cancellable, perror)) {
				ms = MAPI_E_CALL_FAILED;
				goto cleanup;
			}
			jj += 1;
		}
	}

	/* Modify the recipient table */
	ms = ModifyRecipients (obj_message, rows);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "ModifyRecipients", ms);
		goto cleanup;
	}

 cleanup:
	talloc_free (rows);
	talloc_free (prop_rows);
	talloc_free (flagList);

	UNLOCK ();

	g_free (users);
	g_free (recips);
	g_free (named_ids_list);
	g_hash_table_destroy (all_proptags);

	return ms == MAPI_E_SUCCESS;
}

static gboolean
delete_attachment_cb (EMapiConnection *conn,
		      TALLOC_CTX *mem_ctx,
		      struct SRow *srow,
		      guint32 row_index,
		      guint32 rows_total,
		      gpointer user_data,
		      GCancellable *cancellable,
		      GError **perror)
{
	const uint32_t *attach_num;
	mapi_object_t *obj_object = user_data;
	enum MAPISTATUS ms;

	g_return_val_if_fail (obj_object != NULL, FALSE);

	attach_num = e_mapi_util_find_row_propval (srow, PidTagAttachNumber);
	g_return_val_if_fail (attach_num != NULL, FALSE);

	ms = DeleteAttach (obj_object, *attach_num);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "DeleteAttach", ms);
	}

	return ms == MAPI_E_SUCCESS;
}

static gboolean
delete_object_attachments (EMapiConnection *conn,
			   mapi_object_t *obj_folder,
			   mapi_object_t *obj_object,
			   TALLOC_CTX *mem_ctx,
			   GCancellable *cancellable,
			   GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_table;
	struct SPropTagArray *proptags;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	LOCK (cancellable, perror, FALSE);

	mapi_object_init (&obj_table);

	/* open attachment table */
	ms = GetAttachmentTable (obj_object, &obj_table);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetAttachmentTable", ms);
		goto cleanup;
	}

	proptags = set_SPropTagArray (mem_ctx, 1, PidTagAttachNumber);

	ms = SetColumns (&obj_table, proptags);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	ms = foreach_tablerow (conn, mem_ctx, &obj_table, delete_attachment_cb, obj_object, cancellable, perror);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "foreach_tablerow", ms);
	}

 cleanup:
	mapi_object_release (&obj_table);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean update_message_with_object (EMapiConnection *conn,
					    mapi_object_t *obj_folder,
					    mapi_object_t *obj_message,
					    EMapiObject *object,
					    TALLOC_CTX *mem_ctx,
					    GCancellable *cancellable,
					    GError **perror);

static gboolean
add_object_attachments (EMapiConnection *conn,
			mapi_object_t *obj_folder,
			mapi_object_t *obj_message,
			EMapiAttachment *attachments,
			TALLOC_CTX *mem_ctx,
			GCancellable *cancellable,
			GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_SUCCESS;
	EMapiAttachment *attachment;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_message != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	for (attachment = attachments; attachment && ms == MAPI_E_SUCCESS; attachment = attachment->next) {
		mapi_object_t obj_attach;

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}

		mapi_object_init (&obj_attach);

		ms = CreateAttach (obj_message, &obj_attach);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "CreateAttach", ms);
			goto cleanup;
		}

		if (!update_props_on_object (conn, obj_folder, &obj_attach,
			&attachment->properties,
			attachment->streamed_properties, attachment->streamed_properties_count,
			mem_ctx, cancellable, perror)) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "update_props_on_object", ms);
			goto cleanup;
		}

		if (attachment->embedded_object) {
			mapi_object_t obj_emb_msg;

			mapi_object_init (&obj_emb_msg);

			ms = OpenEmbeddedMessage (&obj_attach, &obj_emb_msg, MAPI_CREATE);
			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "OpenEmbeddedMessage", ms);
				goto cleanup;
			}

			if (!update_message_with_object (conn, obj_folder, &obj_emb_msg, attachment->embedded_object, mem_ctx, cancellable, perror)) {
				ms = MAPI_E_CALL_FAILED;
				make_mapi_error (perror, "SaveChangesMessage", ms);
				mapi_object_release (&obj_emb_msg);
				goto cleanup;
			}

			ms = SaveChangesMessage (&obj_attach, &obj_emb_msg, KeepOpenReadOnly);
			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "SaveChangesMessage", ms);
				mapi_object_release (&obj_emb_msg);
				goto cleanup;
			}

			mapi_object_release (&obj_emb_msg);
		}

		ms = SaveChangesAttachment (obj_message, &obj_attach, KeepOpenReadWrite);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SaveChangesAttachment", ms);
			goto cleanup;
		}

	 cleanup:
		mapi_object_release (&obj_attach);
	}

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean
update_message_with_object (EMapiConnection *conn,
			    mapi_object_t *obj_folder,
			    mapi_object_t *obj_message,
			    EMapiObject *object,
			    TALLOC_CTX *mem_ctx,
			    GCancellable *cancellable,
			    GError **perror)
{
	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_message != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (object != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	if (!update_props_on_object (conn, obj_folder, obj_message,
		&object->properties,
		object->streamed_properties, object->streamed_properties_count,
		mem_ctx, cancellable, perror))
		return FALSE;

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		return FALSE;

	/* do not touch recipients if not set */
	if (object->recipients) {
		/* remove current recipients... */
		if (!delete_object_recipients (conn, obj_folder, obj_message, mem_ctx, cancellable, perror))
			return FALSE;

		if (g_cancellable_set_error_if_cancelled (cancellable, perror))
			return FALSE;

		/* ... and add new */
		if (!add_object_recipients (conn, obj_folder, obj_message, object->recipients, mem_ctx, cancellable, perror))
			return FALSE;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		return FALSE;

	/* remove current attachments... */
	if (!delete_object_attachments (conn, obj_folder, obj_message, mem_ctx, cancellable, perror))
		return FALSE;

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		return FALSE;

	/* ... and add new */
	if (object->attachments && !add_object_attachments (conn, obj_folder, obj_message, object->attachments, mem_ctx, cancellable, perror))
		return FALSE;

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		return FALSE;

	return TRUE;
}

gboolean
e_mapi_connection_create_object (EMapiConnection *conn,
				 mapi_object_t *obj_folder,
				 uint32_t flags, /* bit-or of EMapiCreateFlags */
				 WriteObjectCB write_object_cb,
				 gpointer woc_data,
				 mapi_id_t *out_mid,
				 GCancellable *cancellable,
				 GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	EMapiObject *object = NULL;
	mapi_object_t obj_message;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (write_object_cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (out_mid != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	*out_mid = 0;

	mem_ctx = talloc_new (priv->session);
	mapi_object_init (&obj_message);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (!write_object_cb (conn, mem_ctx, &object, woc_data, cancellable, perror) || !object) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "write_object_cb", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = CreateMessage (obj_folder, &obj_message);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "CreateMessage", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (!update_message_with_object (conn, obj_folder, &obj_message, object, mem_ctx, cancellable, perror)) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "update_message_with_object", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = SaveChangesMessage (obj_folder, &obj_message, KeepOpenReadWrite);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SaveChangesMessage", ms);
		goto cleanup;
	}

	if ((flags & E_MAPI_CREATE_FLAG_SUBMIT) != 0) {
		/* Mark message as ready to be sent */
		ms = SubmitMessage (&obj_message);
		if (ms != MAPI_E_SUCCESS) {
			mapi_id_t mid;
			make_mapi_error (perror, "SubmitMessage", ms);

			/*
			The code is storing message right to Sent items instead of Outbox,
			because fetching PR_ENTRYID or PR_IPM_SENTMAIL_ENTRYID didn't seem
			to work in time of doing this change.

			For more information and other possible (correct) approaches see:
			https://bugzilla.gnome.org/show_bug.cgi?id=561794
			*/
			mid = mapi_object_get_id (&obj_message);

			mapi_object_release (&obj_message);
			/* to not release a message object twice */
			mapi_object_init (&obj_message);

			ms = DeleteMessage (obj_folder, &mid, 1);
			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "DeleteMessage", ms);
			}

			goto cleanup;
		}
	}

	*out_mid = mapi_object_get_id (&obj_message);

 cleanup:
	e_mapi_object_free (object);
	mapi_object_release (&obj_message);
	talloc_free (mem_ctx);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_modify_object (EMapiConnection *conn,
				 mapi_object_t *obj_folder,
				 mapi_id_t mid,
				 WriteObjectCB write_object_cb,
				 gpointer woc_data,
				 GCancellable *cancellable,
				 GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	EMapiObject *object = NULL;
	mapi_object_t obj_message;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (write_object_cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (mid != 0, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	mem_ctx = talloc_new (priv->session);
	mapi_object_init (&obj_message);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (!write_object_cb (conn, mem_ctx, &object, woc_data, cancellable, perror)) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "write_object_cb", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = OpenMessage (obj_folder, mapi_object_get_id (obj_folder), mid, &obj_message, MAPI_MODIFY);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenMessage", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (!update_message_with_object (conn, obj_folder, &obj_message, object, mem_ctx, cancellable, perror)) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "update_message_with_object", ms);
		goto cleanup;
	}

	ms = SaveChangesMessage (obj_folder, &obj_message, KeepOpenReadOnly);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SaveChangesMessage", ms);
		goto cleanup;
	}

 cleanup:
	e_mapi_object_free (object);
	mapi_object_release (&obj_message);
	talloc_free (mem_ctx);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static void
e_mapi_cast_SPropValue_to_PropertyValue (struct SPropValue *spropvalue,
					 struct PropertyValue_r *propvalue)
{
	propvalue->ulPropTag = spropvalue->ulPropTag;

	switch (spropvalue->ulPropTag & 0xFFFF) {
	case PT_BOOLEAN:
		propvalue->value.b = spropvalue->value.b;
		break;
	case PT_I2:
		propvalue->value.i = spropvalue->value.i;
		break;
	case PT_LONG:
		propvalue->value.l = spropvalue->value.l;
		break;
	case PT_STRING8:
		propvalue->value.lpszA = spropvalue->value.lpszA;
		break;
	case PT_UNICODE:
		propvalue->value.lpszW = spropvalue->value.lpszW;
		break;
	case PT_SYSTIME:
		propvalue->value.ft = spropvalue->value.ft;
		break;
	case PT_CLSID:
		propvalue->value.lpguid = spropvalue->value.lpguid;
		break;
	case PT_SVREID:
	case PT_BINARY:
		propvalue->value.bin = spropvalue->value.bin;
		break;
        case PT_ERROR:
                propvalue->value.err = spropvalue->value.err;
		break;
	case PT_MV_LONG:
		propvalue->value.MVl = spropvalue->value.MVl;
		break;
	case PT_MV_STRING8:
		propvalue->value.MVszA = spropvalue->value.MVszA;
		break;
        case PT_MV_UNICODE:
		propvalue->value.MVszW = spropvalue->value.MVszW;
		break;
	case PT_MV_CLSID:
		propvalue->value.MVguid = spropvalue->value.MVguid;
		break;
	case PT_MV_BINARY:
		propvalue->value.MVbin = spropvalue->value.MVbin;
		break;
        default:
                g_warning ("%s: unhandled conversion case: 0x%x", G_STRFUNC, (spropvalue->ulPropTag & 0xFFFF));
		break;
	}
}

static void
convert_mapi_SRestriction_to_Restriction_r (struct mapi_SRestriction *restriction,
					    struct Restriction_r *rr,
					    TALLOC_CTX *mem_ctx,
					    GHashTable *replace_hash)
{
	guint i;
	uint32_t proptag;

	g_return_if_fail (restriction != NULL);
	g_return_if_fail (rr != NULL);
	g_return_if_fail (mem_ctx != NULL);

	#define copy(x, y) rr->res.x = restriction->res.y
	#define copy_prop(pprop, mprop)	{							\
			struct SPropValue *helper = talloc_zero (mem_ctx, struct SPropValue);	\
			rr->res.pprop = talloc_zero (mem_ctx, struct PropertyValue_r);		\
			g_return_if_fail (rr->res.pprop != NULL);				\
			rr->res.pprop->ulPropTag = restriction->res.mprop.ulPropTag;		\
			rr->res.pprop->dwAlignPad = 0;						\
			cast_SPropValue (mem_ctx, &(restriction->res.mprop), helper);		\
			e_mapi_cast_SPropValue_to_PropertyValue (helper, rr->res.pprop);	\
		}
	#define check_proptag(x) {								\
			proptag = x;								\
			maybe_replace_named_id_tag (&proptag, replace_hash);			\
			/* workaround for unresolved properties */				\
			if (proptag == MAPI_E_RESERVED)						\
				proptag = PidTagDisplayName;					\
			x = proptag;								\
		}

	rr->rt = restriction->rt;

	switch (restriction->rt) {
	case RES_AND:
		rr->res.resAnd.lpRes = talloc_zero_array (mem_ctx, struct Restriction_r, restriction->res.resAnd.cRes);
		g_return_if_fail (rr->res.resAnd.lpRes != NULL);

		copy (resAnd.cRes, resAnd.cRes);
		for (i = 0; i < restriction->res.resAnd.cRes; i++) {
			convert_mapi_SRestriction_to_Restriction_r (
				(struct mapi_SRestriction *) &(restriction->res.resAnd.res[i]),
				&(rr->res.resAnd.lpRes[i]),
				mem_ctx, replace_hash);
		}
		break;
	case RES_OR:
		rr->res.resOr.lpRes = talloc_zero_array (mem_ctx, struct Restriction_r, restriction->res.resOr.cRes);
		g_return_if_fail (rr->res.resOr.lpRes != NULL);

		copy (resOr.cRes, resOr.cRes);
		for (i = 0; i < restriction->res.resOr.cRes; i++) {
			convert_mapi_SRestriction_to_Restriction_r (
				(struct mapi_SRestriction *) &(restriction->res.resOr.res[i]),
				&(rr->res.resOr.lpRes[i]),
				mem_ctx, replace_hash);
		}
		break;
	#ifdef HAVE_RES_NOT_SUPPORTED
	case RES_NOT:
		rr->res.resNot.lpRes = talloc_zero (mem_ctx, struct Restriction_r);
		g_return_if_fail (rr->res.resNot.lpRes != NULL);

		convert_mapi_SRestriction_to_Restriction_r (
			restriction->res.resNot.res,
			rr->res.resNot.lpRes,
			mem_ctx, replace_hash);
		break;
	#endif
	case RES_CONTENT:
		copy (resContent.ulFuzzyLevel, resContent.fuzzy);
		copy (resContent.ulPropTag, resContent.ulPropTag);
		copy_prop (resContent.lpProp, resContent.lpProp);

		check_proptag (rr->res.resContent.ulPropTag);
		check_proptag (rr->res.resContent.lpProp->ulPropTag);
		break;
	case RES_PROPERTY:
		copy (resProperty.relop, resProperty.relop);
		copy (resProperty.ulPropTag, resProperty.ulPropTag);
		copy_prop (resProperty.lpProp, resProperty.lpProp);


		check_proptag (rr->res.resProperty.ulPropTag);
		check_proptag (rr->res.resProperty.lpProp->ulPropTag);
		break;
	case RES_COMPAREPROPS:
		copy (resCompareProps.relop, resCompareProps.relop);
		copy (resCompareProps.ulPropTag1, resCompareProps.ulPropTag1);
		copy (resCompareProps.ulPropTag2, resCompareProps.ulPropTag2);

		check_proptag (rr->res.resCompareProps.ulPropTag1);
		check_proptag (rr->res.resCompareProps.ulPropTag2);
		break;
	case RES_BITMASK:
		copy (resBitMask.relMBR, resBitmask.relMBR);
		copy (resBitMask.ulPropTag, resBitmask.ulPropTag);
		copy (resBitMask.ulMask, resBitmask.ulMask);

		check_proptag (rr->res.resBitMask.ulPropTag);
		break;
	case RES_SIZE:
		copy (resSize.relop, resSize.relop);
		copy (resSize.ulPropTag, resSize.ulPropTag);
		copy (resSize.cb, resSize.size);

		check_proptag (rr->res.resSize.ulPropTag);
		break;
	case RES_EXIST:
		rr->res.resExist.ulReserved1 = 0;
		rr->res.resExist.ulReserved2 = 0;
		copy (resExist.ulPropTag, resExist.ulPropTag);

		check_proptag (rr->res.resExist.ulPropTag);
		break;
	}

	#undef check_proptag
	#undef copy_prop
	#undef copy
}

static void
remove_unknown_proptags_Restriction_r_rec (struct Restriction_r *restriction,
					   TALLOC_CTX *mem_ctx,
					   GSList **new_rests)
{
	gint ii;
	GSList *sub_rests = NULL, *iter;

	if (!restriction)
		return;

	g_return_if_fail (mem_ctx != NULL);

	#define proptag_is_ok(x) (((uint32_t) (x)) != 0 && ((uint32_t) (x)) != MAPI_E_RESERVED)

	switch (restriction->rt) {
	case RES_AND:
		for (ii = 0; ii < restriction->res.resAnd.cRes; ii++) {
			remove_unknown_proptags_Restriction_r_rec (&(restriction->res.resAnd.lpRes[ii]), mem_ctx, &sub_rests);
		}

		if (sub_rests) {
			struct Restriction_r *rest = talloc_zero (mem_ctx, struct Restriction_r);
			g_return_if_fail (rest != NULL);

			rest->rt = RES_AND;
			rest->res.resAnd.cRes = g_slist_length (sub_rests);
			rest->res.resAnd.lpRes = talloc_zero_array (mem_ctx, struct Restriction_r, rest->res.resAnd.cRes + 1);
			g_return_if_fail (rest->res.resAnd.lpRes != NULL);

			for (iter = sub_rests, ii = 0; iter; iter = iter->next, ii++) {
				struct Restriction_r *subrest = iter->data;

				g_return_if_fail (subrest != NULL);

				rest->res.resAnd.lpRes[ii].rt = subrest->rt;
				rest->res.resAnd.lpRes[ii].res = subrest->res;
			}

			*new_rests = g_slist_append (*new_rests, rest);
		}
		break;
	case RES_OR:
		for (ii = 0; ii < restriction->res.resOr.cRes; ii++) {
			remove_unknown_proptags_Restriction_r_rec (&(restriction->res.resOr.lpRes[ii]), mem_ctx, &sub_rests);
		}

		if (sub_rests) {
			struct Restriction_r *rest = talloc_zero (mem_ctx, struct Restriction_r);
			g_return_if_fail (rest != NULL);

			rest->rt = RES_OR;
			rest->res.resOr.cRes = g_slist_length (sub_rests);
			rest->res.resOr.lpRes = talloc_zero_array (mem_ctx, struct Restriction_r, rest->res.resOr.cRes + 1);
			g_return_if_fail (rest->res.resOr.lpRes != NULL);

			for (iter = sub_rests, ii = 0; iter; iter = iter->next, ii++) {
				struct Restriction_r *subrest = iter->data;

				g_return_if_fail (subrest != NULL);

				rest->res.resOr.lpRes[ii].rt = subrest->rt;
				rest->res.resOr.lpRes[ii].res = subrest->res;
			}

			*new_rests = g_slist_append (*new_rests, rest);
		}
		break;
	#ifdef HAVE_RES_NOT_SUPPORTED
	case RES_NOT:
		remove_unknown_proptags_Restriction_r_rec (restriction->res.resNot.lpRes, mem_ctx, &sub_rests);
		if (sub_rests) {
			struct Restriction_r *rest = talloc_zero (esp->mem_ctx, struct Restriction_r);
			g_return_if_fail (rest != NULL);

			rest->rt = RES_NOT;
			res->res.resNot.lpRes = sub_rests->data;
		}
		break;
	#endif
	case RES_CONTENT:
		if (proptag_is_ok (restriction->res.resContent.ulPropTag) &&
		    proptag_is_ok (restriction->res.resContent.lpProp->ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_PROPERTY:
		if (proptag_is_ok (restriction->res.resProperty.ulPropTag) &&
		    proptag_is_ok (restriction->res.resProperty.lpProp->ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_COMPAREPROPS:
		if (proptag_is_ok (restriction->res.resCompareProps.ulPropTag1) &&
		    proptag_is_ok (restriction->res.resCompareProps.ulPropTag2)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_BITMASK:
		if (proptag_is_ok (restriction->res.resBitMask.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_SIZE:
		if (proptag_is_ok (restriction->res.resSize.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	case RES_EXIST:
		if (proptag_is_ok (restriction->res.resExist.ulPropTag)) {
			*new_rests = g_slist_append (*new_rests, restriction);
		}
		break;
	default:
		g_warn_if_reached ();
		break;
	}

	#undef proptag_is_ok

	g_slist_free (sub_rests);
}

static void
remove_unknown_proptags_Restriction_r (struct Restriction_r **prestrictions,
				       TALLOC_CTX *mem_ctx)
{
	GSList *new_rests = NULL;

	g_return_if_fail (mem_ctx != NULL);

	remove_unknown_proptags_Restriction_r_rec (*prestrictions, mem_ctx, &new_rests);

	if (new_rests) {
		g_return_if_fail (g_slist_length (new_rests) == 1);

		*prestrictions = new_rests->data;

		g_slist_free (new_rests);
	} else {
		*prestrictions = NULL;
	}
}

static enum MAPISTATUS
process_gal_rows_chunk (EMapiConnection *conn,
			TALLOC_CTX *mem_ctx,
			uint32_t rows_offset,
			uint32_t rows_total,
			struct PropertyRowSet_r *rows,
			struct PropertyTagArray_r *mids,
			ForeachTableRowCB cb,
			gpointer user_data,
			GCancellable *cancellable,
			GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_SUCCESS;
	uint32_t ii;

	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (rows != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (mids != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (rows->cRows <= mids->cValues, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);

	for (ii = 0; ii < rows->cRows; ii++) {
		struct SRow *row;
		int64_t mid = mids->aulPropTag[ii];

		row = talloc_zero (mem_ctx, struct SRow);
		cast_PropertyRow_to_SRow (mem_ctx, &rows->aRow[ii], row);

		/* add the temporary mid as a PidTagMid */
		if (!e_mapi_utils_add_spropvalue (mem_ctx, &row->lpProps, &row->cValues, PidTagMid, &mid)) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "e_mapi_utils_add_spropvalue", ms);
			talloc_free (row);
			break;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			talloc_free (row);
			break;
		}

		if (!cb (conn, mem_ctx, row, rows_offset + ii + 1, rows_total, user_data, cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			talloc_free (row);
			break;
		}

		talloc_free (row);
	}

	return ms;
}

static enum MAPISTATUS
foreach_gal_tablerow (EMapiConnection *conn,
		      TALLOC_CTX *mem_ctx,
		      struct PropertyRowSet_r *first_rows,
		      struct PropertyTagArray_r *all_mids,
		      struct SPropTagArray *propTagArray,
		      ForeachTableRowCB cb,
		      gpointer user_data,
		      GCancellable *cancellable,
		      GError **perror)
{
	enum MAPISTATUS ms;
	struct PropertyRowSet_r *rows = NULL;
	struct PropertyTagArray_r *to_query = NULL;
	uint32_t  midspos;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (first_rows != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (all_mids != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (first_rows->cRows <= all_mids->cValues, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);

	midspos = 0;
	ms = process_gal_rows_chunk (conn, mem_ctx, midspos, all_mids->cValues, first_rows, all_mids, cb, user_data, cancellable, perror);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "process_gal_rows_chunk", ms);
		goto cleanup;
	}

	midspos = first_rows->cRows;
	to_query = talloc_zero (mem_ctx, struct PropertyTagArray_r);
	to_query->aulPropTag = talloc_zero_array (mem_ctx, uint32_t, MAX_GAL_CHUNK);

	while (midspos < all_mids->cValues) {
		uint32_t ii;

		to_query->cValues = 0;
		for (ii = midspos; to_query->cValues < MAX_GAL_CHUNK && ii < all_mids->cValues; to_query->cValues++, ii++) {
			to_query->aulPropTag[to_query->cValues] = all_mids->aulPropTag[ii];
		}

		if (!to_query->cValues)
			break;

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}

		ms = nspi_QueryRows (priv->session->nspi->ctx, mem_ctx, propTagArray, to_query, to_query->cValues, &rows);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "nspi_QueryRows", ms);
			goto cleanup;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}

		if (!rows || rows->cRows <= 0) {
			/* success or finished, probably */
			break;
		}

		ms = process_gal_rows_chunk (conn, mem_ctx, midspos, all_mids->cValues, rows, to_query, cb, user_data, cancellable, perror);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "process_gal_rows_chunk", ms);
			goto cleanup;
		}

		midspos += rows->cRows;
		talloc_free (rows);
		rows = NULL;
	}

 cleanup:
	talloc_free (to_query);
	talloc_free (rows);

	return ms;
}

gboolean
e_mapi_connection_count_gal_objects (EMapiConnection *conn,
				     guint32 *obj_total,
				     GCancellable *cancellable,
				     GError **perror)
{
	enum MAPISTATUS ms;
	uint32_t count = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (priv->session->nspi != NULL, MAPI_E_UNCONFIGURED, FALSE);
	e_return_val_mapi_error_if_fail (priv->session->nspi->ctx != NULL, MAPI_E_UNCONFIGURED, FALSE);
	e_return_val_mapi_error_if_fail (obj_total != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	*obj_total = 0;

	LOCK (cancellable, perror, FALSE);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
	} else {
		ms = GetGALTableCount (priv->session, &count);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "GetGALTableCount", ms);
		} else {
			*obj_total = count;
		}
	}

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_list_gal_objects (EMapiConnection *conn,
				    BuildRestrictionsCB build_rs_cb,
				    gpointer build_rs_cb_data,
				    ListObjectsCB cb,
				    gpointer user_data,
				    GCancellable *cancellable,
				    GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	struct SPropTagArray *propTagArray = NULL;
	struct Restriction_r *use_restriction = NULL;
	struct PropertyRowSet_r *rows = NULL;
	struct PropertyTagArray_r *pMIds = NULL;
	struct ListObjectsInternalData loi_data;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (priv->session->nspi != NULL, MAPI_E_UNCONFIGURED, FALSE);
	e_return_val_mapi_error_if_fail (priv->session->nspi->ctx != NULL, MAPI_E_UNCONFIGURED, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* other listing tags not found/used by GAL */
	propTagArray = set_SPropTagArray (mem_ctx, 1, PidTagLastModificationTime);

	if (build_rs_cb) {
		struct mapi_SRestriction *restrictions = NULL;

		if (!build_rs_cb (conn, mem_ctx, &restrictions, build_rs_cb_data, cancellable, perror)) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "build_restrictions", ms);
			goto cleanup;
		}

		if (restrictions) {
			EResolveNamedIDsData *named_ids_list = NULL;
			guint named_ids_len = 0;
			gboolean res = FALSE;

			gather_mapi_SRestriction_named_ids (restrictions, &named_ids_list, &named_ids_len);

			if (named_ids_list) {
				/* use NULL for GAL as a folder ID parameter */
				res = e_mapi_connection_resolve_named_props (conn, NULL, named_ids_list, named_ids_len, cancellable, perror);

				if (res) {
					GHashTable *replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, TRUE);

					use_restriction = talloc_zero (mem_ctx, struct Restriction_r);
					convert_mapi_SRestriction_to_Restriction_r (restrictions, use_restriction, mem_ctx, replace_hash);

					if (replace_hash)
						g_hash_table_destroy (replace_hash);
				} else {
					ms = MAPI_E_CALL_FAILED;
					goto cleanup;
				}

				g_free (named_ids_list);
			} else {
				use_restriction = talloc_zero (mem_ctx, struct Restriction_r);
				convert_mapi_SRestriction_to_Restriction_r (restrictions, use_restriction, mem_ctx, NULL);
			}

			remove_unknown_proptags_Restriction_r (&use_restriction, mem_ctx);

			if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
				ms = MAPI_E_USER_CANCEL;
				goto cleanup;
			}
		}
	}

	loi_data.cb = cb;
	loi_data.user_data = user_data;

	ms = nspi_GetMatches (priv->session->nspi->ctx, mem_ctx, propTagArray, use_restriction, (uint32_t) -1, &rows, &pMIds);
	if (ms == MAPI_E_TOO_COMPLEX && use_restriction && use_restriction->rt == RES_OR) {
		/* case lazy MS servers which do not want to search sertain properties in OR-s */
		gint ii;
		gboolean any_good = FALSE;

		for (ii = 0; ii < use_restriction->res.resOr.cRes; ii++) {
			talloc_free (pMIds);
			talloc_free (rows);
			pMIds = NULL;
			rows = NULL;

			ms = nspi_GetMatches (priv->session->nspi->ctx, mem_ctx, propTagArray,
				&use_restriction->res.resOr.lpRes[ii],
				(uint32_t) -1, &rows, &pMIds);

			if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
				ms = MAPI_E_USER_CANCEL;
				goto cleanup;
			}

			if (ms == MAPI_E_SUCCESS) {
				if (!rows)
					continue;

				ms = foreach_gal_tablerow (conn, mem_ctx, rows, pMIds, propTagArray, list_objects_internal_cb, &loi_data, cancellable, perror);
				if (ms != MAPI_E_SUCCESS) {
					make_mapi_error (perror, "foreach_gal_tablerow", ms);
					goto cleanup;
				}

				any_good = TRUE;
			} else if (ms != MAPI_E_NOT_FOUND && ms != MAPI_E_TOO_COMPLEX && ms != MAPI_E_TABLE_TOO_BIG) {
				break;
			}
		}

		/* in case the last check fails, update based on the overall result */
		if (any_good) {
			ms = MAPI_E_SUCCESS;
			goto cleanup;
		} else {
			ms = MAPI_E_TOO_COMPLEX;
		}
	}

	if (ms != MAPI_E_SUCCESS || !rows) {
		if (ms == MAPI_E_NOT_FOUND || (!rows && ms == MAPI_E_SUCCESS))
			ms = MAPI_E_SUCCESS;
		else if (ms == MAPI_E_TABLE_TOO_BIG)
			g_set_error (perror, E_MAPI_ERROR, MAPI_E_TABLE_TOO_BIG, _("Search result exceeded allowed size limit. Use more specific search term, please"));
		else if (ms != MAPI_E_SUCCESS)
			make_mapi_error (perror, "nspi_GetMatches", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = foreach_gal_tablerow (conn, mem_ctx, rows, pMIds, propTagArray, list_objects_internal_cb, &loi_data, cancellable, perror);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "foreach_gal_tablerow", ms);
		goto cleanup;
	}

 cleanup:
	talloc_free (pMIds);
	talloc_free (rows);
	talloc_free (propTagArray);
	talloc_free (mem_ctx);
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

struct TransferGALObjectData
{
	GHashTable *reverse_replace_hash;
	TransferObjectCB cb;
	gpointer cb_user_data;
};

static gboolean
e_mapi_transfer_gal_objects_cb (EMapiConnection *conn,
				TALLOC_CTX *mem_ctx,
				struct SRow *srow,
				guint32 row_index,
				guint32 rows_total,
				gpointer user_data,
				GCancellable *cancellable,
				GError **perror)
{
	struct TransferGALObjectData *tgo = user_data;
	EMapiObject *object;
	uint32_t ii;
	gboolean res;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (srow != NULL, FALSE);
	g_return_val_if_fail (tgo != NULL, FALSE);
	g_return_val_if_fail (tgo->cb != NULL, FALSE);

	object = e_mapi_object_new (mem_ctx);

	res = TRUE;

	for (ii = 0; ii < srow->cValues; ii++) {
		uint32_t proptag = srow->lpProps[ii].ulPropTag;
		gconstpointer propdata = get_SPropValue_data (&srow->lpProps[ii]);

		if (!propdata || may_skip_property (srow->lpProps[ii].ulPropTag))
			continue;

		/* reverse_replace_hash has them stored in opposite,
		   the key is the name-id-proptag as stored on the server,
		   the value is a pidlid/pidname proptag */
		maybe_replace_named_id_tag (&proptag, tgo->reverse_replace_hash);

		if (!e_mapi_utils_add_property (&object->properties, proptag, propdata, object)) {
			res = FALSE;
			make_mapi_error (perror, "e_mapi_utils_add_property", MAPI_E_CALL_FAILED);
			break;
		}
	}

	if (res)
		res = tgo->cb (conn, mem_ctx, object, row_index, rows_total, tgo->cb_user_data, cancellable, perror);

	e_mapi_object_free (object);

	return res;
}

static void
fill_reverse_replace_hash (gpointer key,
			   gpointer value,
			   gpointer user_data)
{
	GHashTable *reverse_replace_hash = user_data;

	g_return_if_fail (reverse_replace_hash != NULL);

	g_hash_table_insert (reverse_replace_hash, value, key);
}

gboolean
e_mapi_connection_transfer_gal_objects (EMapiConnection *conn,
					const GSList *mids,
					BuildReadPropsCB brp_cb,
					gpointer brp_cb_user_data,
					TransferObjectCB cb,
					gpointer cb_user_data,
					GCancellable *cancellable,
					GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	struct PropertyTagArray_r *ids = NULL;
	struct SPropTagArray *propTagArray = NULL;
	struct PropertyRowSet_r rows;
	struct TransferGALObjectData tgo;
	GHashTable *reverse_replace_hash = NULL;
	EResolveNamedIDsData *named_ids_list = NULL;
	guint named_ids_len = 0, ii;
	const GSList *iter;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (priv->session->nspi != NULL, MAPI_E_UNCONFIGURED, FALSE);
	e_return_val_mapi_error_if_fail (priv->session->nspi->ctx != NULL, MAPI_E_UNCONFIGURED, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	for (iter = mids; iter; iter = iter->next) {
		mapi_id_t *pmid = iter->data;

		if (pmid) {
			if (!ids) {
				ids = talloc_zero (mem_ctx, struct PropertyTagArray_r);
			}
			ids->cValues++;
			ids->aulPropTag = talloc_realloc (mem_ctx,
				ids->aulPropTag,
				uint32_t,
				ids->cValues + 1);
			ids->aulPropTag[ids->cValues - 1] = (uint32_t) (*pmid);
			ids->aulPropTag[ids->cValues] = 0;
		}
	}

	if (!ids) {
		ms = MAPI_E_INVALID_PARAMETER;
		make_mapi_error (perror, "gather valid mids", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (brp_cb) {
		propTagArray = set_SPropTagArray (mem_ctx, 1, PidTagObjectType);
		if (!brp_cb (conn, mem_ctx, propTagArray, brp_cb_user_data, cancellable, perror)) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "brp_cb", ms);
			goto cleanup;
		}
	} else {
		if (!e_mapi_book_utils_get_supported_mapi_proptags (mem_ctx, &propTagArray) || !propTagArray) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "e_mapi_book_utils_get_supported_mapi_proptags", ms);
			goto cleanup;
		}
	}

	for (ii = 0; ii < propTagArray->cValues; ii++) {
		maybe_add_named_id_tag (propTagArray->aulPropTag[ii], &named_ids_list, &named_ids_len);
	}

	if (named_ids_list) {
		GHashTable *replace_hash;

		/* use NULL for GAL as a folder ID parameter */
		if (!e_mapi_connection_resolve_named_props (conn, NULL, named_ids_list, named_ids_len, cancellable, perror)) {
			ms = MAPI_E_CALL_FAILED;
			make_mapi_error (perror, "e_mapi_connection_resolve_named_props", ms);
			goto cleanup;
		}

		replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, TRUE);

		if (replace_hash) {
			guint prop_count = propTagArray->cValues, jj;

			for (ii = 0, jj = 0; ii < prop_count; ii++) {
				uint32_t proptag = propTagArray->aulPropTag[ii];

				maybe_replace_named_id_tag (&proptag, replace_hash);

				propTagArray->aulPropTag[jj] = proptag;

				if (proptag == MAPI_E_RESERVED || proptag == 0)
					propTagArray->cValues--;
				else
					jj++;
			}

			if (jj < ii)
				propTagArray->aulPropTag[jj] = 0;

			reverse_replace_hash = g_hash_table_new (g_direct_hash, g_direct_equal);

			g_hash_table_foreach (replace_hash, fill_reverse_replace_hash, reverse_replace_hash);
			g_hash_table_destroy (replace_hash);
		}
	}

	/* fake rows, to start reading from the first mid */
	rows.cRows = 0;
	rows.aRow = NULL;

	tgo.cb = cb;
	tgo.cb_user_data = cb_user_data;
	tgo.reverse_replace_hash = reverse_replace_hash;

	ms = foreach_gal_tablerow (conn, mem_ctx, &rows, ids, propTagArray, e_mapi_transfer_gal_objects_cb, &tgo, cancellable, perror);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "foreach_gal_tablerow", ms);
		goto cleanup;
	}

 cleanup:
	if (reverse_replace_hash)
		g_hash_table_destroy (reverse_replace_hash);
	talloc_free (propTagArray);
	talloc_free (ids);
	talloc_free (mem_ctx);
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_transfer_gal_object (EMapiConnection *conn,
				       mapi_id_t message_id,
				       TransferObjectCB cb,
				       gpointer cb_user_data,
				       GCancellable *cancellable,
				       GError **perror)
{
	GSList *mids;
	gboolean res;

	mids = g_slist_append (NULL, &message_id);
	res = e_mapi_connection_transfer_gal_objects (conn, mids, NULL, NULL, cb, cb_user_data, cancellable, perror);
	g_slist_free (mids);

	return res;
}

gboolean
e_mapi_connection_create_folder (EMapiConnection *conn,
				 mapi_object_t *obj_parent_folder, /* in */
				 const gchar *name,
				 const gchar *new_folder_type, /* usually IPF_NOTE and similar */
				 mapi_id_t *new_fid, /* out */
				 GCancellable *cancellable,
				 GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_folder;
	struct SPropValue vals[1];
	mapi_id_t fid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_parent_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (name != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (new_folder_type != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (new_fid != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);
	mapi_object_init (&obj_folder);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Attempt to create the folder */
	ms = CreateFolder (obj_parent_folder, FOLDER_GENERIC, name, "Created using Evolution/LibMAPI", OPEN_IF_EXISTS | MAPI_UNICODE, &obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "CreateFolder", ms);
		goto cleanup;
	}

	vals[0].value.lpszW = new_folder_type;
	vals[0].ulPropTag = PidTagContainerClass;

	ms = SetProps (&obj_folder, MAPI_PROPS_SKIP_NAMEDID_CHECK, vals, 1);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetProps", ms);
		goto cleanup;
	}

	fid = mapi_object_get_id (&obj_folder);
	if (fid == 0) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "mapi_object_get_id", ms);
	} else {
		*new_fid = fid;
	}

 cleanup:
	mapi_object_release (&obj_folder);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_empty_folder (EMapiConnection *conn,
				mapi_object_t *obj_folder,
				GCancellable *cancellable,
				GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Empty the contents of the folder */
	ms = EmptyFolder (obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "EmptyFolder", ms);
		goto cleanup;
	}

 cleanup:
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gboolean
add_parent_fid_prop_cb (EMapiConnection *conn,
			TALLOC_CTX *mem_ctx,
			struct SPropTagArray *props,
			gpointer data,
			GCancellable *cancellable,
			GError **perror)
{
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);

	SPropTagArray_add (mem_ctx, props, PidTagParentFolderId);

	return TRUE;
}

static gboolean
read_parent_fid_prop_cb (EMapiConnection *conn,
			 TALLOC_CTX *mem_ctx,
			 /* const */ struct mapi_SPropValue_array *properties,
			 gpointer user_data,
			 GCancellable *cancellable,
			 GError **perror)
{
	mapi_id_t *pmid = user_data;
	const mapi_id_t *cmid;

	g_return_val_if_fail (properties != NULL, FALSE);
	g_return_val_if_fail (pmid != NULL, FALSE);

	cmid = e_mapi_util_find_array_propval (properties, PidTagParentFolderId);
	g_return_val_if_fail (cmid != NULL, FALSE);

	*pmid = *cmid;

	return TRUE;
}

static gboolean
emc_open_folders (EMapiConnection *conn,
		  mapi_object_t *obj_store, /* in */
		  mapi_id_t child_fid,
		  mapi_object_t *obj_child_folder, /* out */
		  mapi_object_t *obj_parent_folder, /* out */
		  GCancellable *cancellable,
		  GError **perror)
{
	enum MAPISTATUS ms;
	mapi_id_t parent_fid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (obj_store != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_child_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_parent_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	mapi_object_init (obj_child_folder);
	mapi_object_init (obj_parent_folder);

	ms = OpenFolder (obj_store, child_fid, obj_child_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenFolder-1", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		mapi_object_release (obj_child_folder);
		mapi_object_init (obj_child_folder);
		goto cleanup;
	}

	if (!e_mapi_connection_get_folder_properties (conn, obj_child_folder, add_parent_fid_prop_cb, NULL, read_parent_fid_prop_cb, &parent_fid, cancellable, perror) ||
	    parent_fid == 0) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "GetFolderProperties", ms);
		mapi_object_release (obj_child_folder);
		mapi_object_init (obj_child_folder);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		mapi_object_release (obj_child_folder);
		mapi_object_init (obj_child_folder);
		goto cleanup;
	}

	ms = OpenFolder (obj_store, parent_fid, obj_parent_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenFolder-2", ms);
		mapi_object_release (obj_child_folder);
		mapi_object_init (obj_child_folder);
		goto cleanup;
	}

 cleanup:
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_remove_folder (EMapiConnection *conn,
				 mapi_object_t *obj_store, /* in, store, to which folder belongs */
				 mapi_id_t fid_to_remove,
				 GCancellable *cancellable,
				 GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_parent;
	mapi_object_t obj_folder;
	EMapiFolder *folder;
	GSList *l;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_store != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (fid_to_remove != 0, MAPI_E_INVALID_PARAMETER, FALSE);

	e_mapi_debug_print("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	folder = NULL;
	for (l = e_mapi_connection_peek_folders_list (conn); l; l = l->next) {
		folder = l->data;
		if (folder && folder->folder_id == fid_to_remove)
			break;
		else
			folder = NULL;
	}

	LOCK (cancellable, perror, FALSE);

	mapi_object_init (&obj_folder);
	mapi_object_init (&obj_parent);

	if (!emc_open_folders (conn, obj_store, fid_to_remove, &obj_folder, &obj_parent, cancellable, perror)) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "emc_open_folders", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Empty the contents of the folder */
	ms = EmptyFolder (&obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "EmptyFolder", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Call DeleteFolder on the folder to be removed */
	ms = DeleteFolder (&obj_parent, fid_to_remove, DEL_FOLDERS, NULL);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "DeleteFolder", ms);
		goto cleanup;
	}

 cleanup:
	mapi_object_release (&obj_folder);
	mapi_object_release (&obj_parent);

	if (folder) {
		g_rec_mutex_lock (&priv->folders_lock);
		priv->folders = g_slist_remove (priv->folders, folder);
		e_mapi_folder_free (folder);
		g_rec_mutex_unlock (&priv->folders_lock);
	}

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_rename_folder (EMapiConnection *conn,
				 mapi_object_t *obj_folder,
				 const gchar *new_name,
				 GCancellable *cancellable,
				 GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_RESERVED;
	struct SPropValue *props = NULL;
	TALLOC_CTX *mem_ctx;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (new_name != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_mapi_debug_print ("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	props = talloc_zero(mem_ctx, struct SPropValue);
	set_SPropValue_proptag (props, PidTagDisplayName, new_name);

	ms = SetProps (obj_folder, MAPI_PROPS_SKIP_NAMEDID_CHECK, props, 1);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetProps", ms);
		goto cleanup;
	}

 cleanup:
	talloc_free (mem_ctx);
	UNLOCK ();

	e_mapi_debug_print ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return ms == MAPI_E_SUCCESS;
}

/* moves folder 'src_fid' to folder 'des_fid' under name 'new_name' (no path in a new_name),
   'src_parent_fid' is folder ID of a parent of the src_fid */
gboolean
e_mapi_connection_move_folder  (EMapiConnection *conn,
				mapi_object_t *src_obj_folder,
				mapi_object_t *src_parent_obj_folder,
				mapi_object_t *des_obj_folder,
				const gchar *new_name,
				GCancellable *cancellable,
				GError **perror)
{
	enum MAPISTATUS ms = MAPI_E_RESERVED;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (src_obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (src_parent_obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (des_obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (new_name != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (strchr (new_name, '/') == NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
	} else {
		ms = MoveFolder (src_obj_folder, src_parent_obj_folder, des_obj_folder, (gchar *) new_name, TRUE);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "MoveFolder", ms);
		}
	}

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

/* named_ids_list contains pointers to EResolveNamedIDsData structure;
   obj_folder NULL is reserved for lookup in GAL */
gboolean
e_mapi_connection_resolve_named_props  (EMapiConnection *conn,
					mapi_object_t *obj_folder,
					EResolveNamedIDsData *named_ids_list,
					guint named_ids_n_elems,
					GCancellable *cancellable,
					GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_id_t fid;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray;
	guint i, j;
	GPtrArray *todo = NULL;
	gboolean res = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (named_ids_list != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (named_ids_n_elems > 0, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_mapi_debug_print ("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK (cancellable, perror, FALSE);

	fid = 0;
	if (obj_folder)
		fid = mapi_object_get_id (obj_folder);

	if (priv->named_ids) {
		gint64 i64 = fid;
		GHashTable *ids = g_hash_table_lookup (priv->named_ids, &i64);

		if (ids) {
			for (i = 0; i < named_ids_n_elems; i++) {
				EResolveNamedIDsData *data = &named_ids_list[i];
				uint32_t propid;

				propid = GPOINTER_TO_UINT (g_hash_table_lookup (ids, GUINT_TO_POINTER (data->pidlid_propid)));
				if (propid) {
					data->propid = propid;
				} else {
					if (!todo)
						todo = g_ptr_array_new ();
					g_ptr_array_add (todo, data);
				}
			}

			if (!todo) {
				UNLOCK ();
				e_mapi_debug_print ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);
				return TRUE;
			}
		}
	}

	mem_ctx = talloc_new (priv->session);

	nameid = mapi_nameid_new (mem_ctx);
	SPropTagArray = talloc_zero (mem_ctx, struct SPropTagArray);

	if (!obj_folder) {
		if (!priv->session->nspi || !priv->session->nspi->ctx) {
			ms = MAPI_E_UNCONFIGURED;
			goto cleanup;
		}
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (!todo) {
		todo = g_ptr_array_new ();
		for (i = 0; i < named_ids_n_elems; i++) {
			g_ptr_array_add (todo, &named_ids_list[i]);
		}
	}

	for (i = 0; i < todo->len; i++) {
		EResolveNamedIDsData *data = todo->pdata[i];

		if (mapi_nameid_canonical_add (nameid, data->pidlid_propid) != MAPI_E_SUCCESS)
			data->propid = MAPI_E_RESERVED;
		else
			data->propid = 0;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	if (obj_folder) {
		ms = mapi_nameid_GetIDsFromNames (nameid, obj_folder, SPropTagArray);
	} else {
		/* lookup in GAL */
		struct SPropTagArray *gal_tags;
		uint32_t prop_count = nameid->count;
		struct PropertyName_r *names = talloc_zero_array (mem_ctx, struct PropertyName_r, prop_count + 1);

		g_assert (names != NULL);

		SPropTagArray = talloc_zero (mem_ctx, struct SPropTagArray);
		g_assert (SPropTagArray != NULL);

		SPropTagArray->cValues = nameid->count;
		SPropTagArray->aulPropTag = talloc_zero_array (mem_ctx, enum MAPITAGS, SPropTagArray->cValues + 1);
		g_assert (SPropTagArray->aulPropTag != NULL);

		j = 0;
		for (i = 0; i < nameid->count; i++) {
			guint ab[16];

			SPropTagArray->aulPropTag[i] = nameid->entries[i].proptag;

			if (nameid->entries[i].ulKind == MNID_ID &&
			    16 == sscanf (nameid->entries[i].OLEGUID,
					"%02x%02x%02x%02x-"
					"%02x%02x-"
					"%02x%02x-"
					"%02x%02x-"
					"%02x%02x%02x%02x%02x%02x",
					&ab[0], &ab[1], &ab[2], &ab[3],
					&ab[4], &ab[5],
					&ab[6], &ab[7],
					&ab[8], &ab[9],
					&ab[10], &ab[11], &ab[12], &ab[13], &ab[14], &ab[15])) {
				gint k;

				names[j].ulReserved = 0;
				names[j].lID = nameid->entries[i].lid;
				names[j].lpguid = talloc_zero (mem_ctx, struct FlatUID_r);

				for (k = 0; k < 16; k++) {
					names[j].lpguid->ab[k] = (ab[k] & 0xFF);
				}

				j++;
			} else {
				SPropTagArray->aulPropTag[i] = (SPropTagArray->aulPropTag[i] & (~0xFFFF)) | PT_ERROR;
				prop_count--;
			}
		}

		if (prop_count > 0) {
			ms = nspi_GetIDsFromNames (priv->session->nspi->ctx, mem_ctx, 0, prop_count, names, &gal_tags);
			if (ms == MAPI_E_SUCCESS && gal_tags) {
				if (gal_tags->cValues != prop_count)
					g_warning ("%s: Requested (%d) and returned (%d) property names don't match", G_STRFUNC, prop_count, gal_tags->cValues);

				j = 0;
				for (i = 0; i < gal_tags->cValues; i++) {
					while (j < SPropTagArray->cValues && (SPropTagArray->aulPropTag[j] & 0xFFFF) == PT_ERROR) {
						j++;
					}

					if (j >= SPropTagArray->cValues)
						break;

					SPropTagArray->aulPropTag[j] = gal_tags->aulPropTag[i];
				}

				while (j < SPropTagArray->cValues) {
					SPropTagArray->aulPropTag[j] = (SPropTagArray->aulPropTag[j] & (~0xFFFF)) | PT_ERROR;
					j++;
				}
			}

			/* 2010 server can return call_failed or no_support when didn't find any properties */
			if (ms == MAPI_E_CALL_FAILED || ms == MAPI_E_NO_SUPPORT)
				ms = MAPI_E_NOT_FOUND;

			if (ms == MAPI_E_NOT_FOUND || ms == MAPI_E_SUCCESS) {
				for (j = 0; j < SPropTagArray->cValues; j++) {
					/* if not found then 0 is returned in the array */
					if (SPropTagArray->aulPropTag[j] != 0 &&
					    (SPropTagArray->aulPropTag[j] & 0xFFFF) != PT_ERROR)
						break;
				}

				/* all of them failed to read, try the Contacts folder in hope
				   the named properties has the same numbers there as in GAL */
				if (j == SPropTagArray->cValues) {
					mapi_object_t obj_contacts;

					if (e_mapi_connection_open_default_folder (conn, olFolderContacts, &obj_contacts, cancellable, NULL)) {
						/* always keep MAPI_E_NOT_FOUND, thus the later processing on the storing of saved items is skipped */
						e_mapi_connection_resolve_named_props (conn, &obj_contacts, named_ids_list, named_ids_n_elems, cancellable, NULL);
						e_mapi_connection_close_folder (conn, &obj_contacts, cancellable, NULL);
					}
				}
			}
		} else {
			ms = MAPI_E_NOT_FOUND;
		}

		talloc_free (names);
	}

	if (ms == MAPI_E_NOT_FOUND) {
		res = TRUE;
		goto cleanup;
	}

	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "mapi_nameid_GetIDsFromNames", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	for (i = 0, j = 0; i < SPropTagArray->cValues && j < todo->len; i++) {
		while (j < todo->len) {
			EResolveNamedIDsData *data = todo->pdata[j];
			if (data && data->propid == 0) {
				if ((SPropTagArray->aulPropTag[i] & 0xFFFF) == PT_ERROR)
					data->propid = MAPI_E_RESERVED;
				else
					data->propid = SPropTagArray->aulPropTag[i];
				break;
			}

			j++;
		}
	}

	if (priv->named_ids) {
		gint64 i64 = fid;
		GHashTable *ids = g_hash_table_lookup (priv->named_ids, &i64);

		if (!ids) {
			gint64 *i64ptr = g_malloc (sizeof (gint64));

			*i64ptr = fid;
			ids = g_hash_table_new (g_direct_hash, g_direct_equal);

			g_hash_table_insert (priv->named_ids, i64ptr, ids);
		}

		for (i = 0; i < todo->len; i++) {
			EResolveNamedIDsData *data = todo->pdata[i];

			g_hash_table_insert (ids, GUINT_TO_POINTER (data->pidlid_propid), GUINT_TO_POINTER (data->propid));
		}
	}

	res = TRUE;

 cleanup:
	if (todo)
		g_ptr_array_free (todo, TRUE);
	talloc_free (mem_ctx);

	UNLOCK ();

	e_mapi_debug_print ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return res;
}

/* returns MAPI_E_RESERVED on any error */
uint32_t
e_mapi_connection_resolve_named_prop (EMapiConnection *conn,
				      mapi_object_t *obj_folder,
				      uint32_t pidlid_propid,
				      GCancellable *cancellable,
				      GError **perror)
{
	EResolveNamedIDsData named_ids_list[1];

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, MAPI_E_RESERVED);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_RESERVED);

	named_ids_list[0].pidlid_propid = pidlid_propid;
	named_ids_list[0].propid = MAPI_E_RESERVED;

	if (!e_mapi_connection_resolve_named_props (conn, obj_folder, named_ids_list, 1, cancellable, perror))
		return MAPI_E_RESERVED;

	return named_ids_list[0].propid;
}

/* returns named id, aka PidLid/PidName for a given proptag, which might be previously
   obtained as a result of e_mapi_connection_resolve_named_prop/s.
   Returns MAPI_E_RESERVED when not found.
*/
uint32_t
e_mapi_connection_unresolve_proptag_to_nameid (EMapiConnection *conn, mapi_id_t fid, uint32_t proptag)
{
	uint32_t res = MAPI_E_RESERVED;
	/* to have this used in the below macros */
	GError **perror = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, res);

	if (priv->named_ids) {
		gint64 i64 = fid;
		GHashTable *ids = g_hash_table_lookup (priv->named_ids, &i64);

		if (ids) {
			GHashTableIter iter;
			gpointer stored_pidlid, stored_proptag, lookup_proptag = GUINT_TO_POINTER (proptag);
			gboolean is_error = PT_ERROR == (proptag & 0xFFFF);

			g_hash_table_iter_init (&iter, ids);
			while (g_hash_table_iter_next (&iter, &stored_pidlid, &stored_proptag)) {
				if (stored_proptag == lookup_proptag || (is_error && (GPOINTER_TO_UINT (stored_proptag) & ~0xFFFF) == (proptag & ~0xFFFF))) {
					res = GPOINTER_TO_UINT (stored_pidlid);
					break;
				}
			}
		}
	}

	return res;
}

mapi_id_t
e_mapi_connection_get_default_folder_id (EMapiConnection *conn,
					 uint32_t olFolder,
					 GCancellable *cancellable,
					 GError **perror)
{
	enum MAPISTATUS ms;
	mapi_id_t fid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, 0);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, 0);

	e_mapi_debug_print("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK (cancellable, perror, 0);

	ms = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultFolder", ms);
		goto cleanup;
	}

 cleanup:
	UNLOCK ();

	e_mapi_debug_print("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return (ms == MAPI_E_SUCCESS ? fid : 0);
}

gboolean
e_mapi_connection_set_flags (EMapiConnection *conn,
			     mapi_object_t *obj_folder,
			     GSList *mids,
			     uint32_t flag,
			     GCancellable *cancellable,
			     GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	uint32_t i;
	mapi_id_t *id_messages;
	GSList *tmp = mids;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_mapi_debug_print("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	id_messages = talloc_array (mem_ctx, mapi_id_t, g_slist_length (mids));
	for (i = 0; tmp; tmp = tmp->next, i++)
		id_messages[i] = *((mapi_id_t *)tmp->data);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = SetReadFlags (obj_folder, flag, i, id_messages);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetReadFlags", ms);
		goto cleanup;
	}

	result = TRUE;

 cleanup:
	talloc_free (mem_ctx);

	UNLOCK ();

	e_mapi_debug_print("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
e_mapi_connection_copymove_items (EMapiConnection *conn,
				  mapi_object_t *src_obj_folder,
				  mapi_object_t *des_obj_folder,
				  gboolean do_copy,
				  GSList *mid_list,
				  GCancellable *cancellable,
				  GError **perror)
{
	enum MAPISTATUS	ms = MAPI_E_RESERVED;
	TALLOC_CTX *mem_ctx;
	GSList *l;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	while (mid_list) {
		mapi_id_array_t msg_id_array;
		gint count = 0;

		mapi_id_array_init (mem_ctx, &msg_id_array);

		for (l = mid_list; l != NULL && count < 500; l = g_slist_next (l), count++)
			mapi_id_array_add_id (&msg_id_array, *((mapi_id_t *)l->data));

		mid_list = l;

		ms = MoveCopyMessages (src_obj_folder, des_obj_folder, &msg_id_array, do_copy);
		mapi_id_array_release (&msg_id_array);

		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "MoveCopyMessages", ms);
			break;
		}

		if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}
	}

 cleanup:
	talloc_free (mem_ctx);
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_remove_items (EMapiConnection *conn,
				mapi_object_t *obj_folder,
				const GSList *mids,
				GCancellable *cancellable,
				GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	uint32_t i;
	mapi_id_t *id_messages;
	const GSList *tmp = mids;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_mapi_debug_print("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK (cancellable, perror, FALSE);

	mem_ctx = talloc_new (priv->session);

	id_messages = talloc_array (mem_ctx, mapi_id_t, g_slist_length ((GSList *) mids));
	for (i = 0; tmp; tmp = tmp->next, i++) {
		mapi_id_t *data = tmp->data;
		id_messages[i] = *data;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Delete the messages from the folder */
	ms = DeleteMessage (obj_folder, id_messages, i);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "DeleteMessage", ms);
		goto cleanup;
	}

	result = TRUE;

 cleanup:
	talloc_free(mem_ctx);

	UNLOCK ();

	e_mapi_debug_print("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

struct GetFolderHierarchyCBData
{
	EMapiFolderCategory folder_hier;
	mapi_id_t folder_id;
	GSList **mapi_folders;
	ProgressNotifyCB cb;
	gpointer cb_user_data;
};

static gboolean
get_folder_hierarchy_cb (EMapiConnection *conn,
			 TALLOC_CTX *mem_ctx,
			 struct SRow *srow,
			 guint32 row_index,
			 guint32 rows_total,
			 gpointer user_data,
			 GCancellable *cancellable,
			 GError **perror)
{
	struct GetFolderHierarchyCBData *gfh = user_data;

	g_return_val_if_fail (gfh != NULL, FALSE);

	if (srow) {
		EMapiFolder *folder = NULL;
		const mapi_id_t *fid = e_mapi_util_find_row_propval (srow, PR_FID);
		const mapi_id_t *pid = e_mapi_util_find_row_propval (srow, PR_PARENT_FID);
		const gchar *klass = e_mapi_util_find_row_propval (srow, PR_CONTAINER_CLASS);
		const gchar *name = e_mapi_util_find_row_propval (srow, PR_DISPLAY_NAME_UNICODE);
		const uint32_t *unread = e_mapi_util_find_row_propval (srow, PR_CONTENT_UNREAD);
		const uint32_t *total = e_mapi_util_find_row_propval (srow, PR_CONTENT_COUNT);
		const uint32_t *child = e_mapi_util_find_row_propval (srow, PR_FOLDER_CHILD_COUNT);
		const uint32_t *folder_size = e_mapi_util_find_row_propval (srow, PR_MESSAGE_SIZE);

		if (!klass)
			klass = IPF_NOTE;

		e_mapi_debug_print("|---+ %-15s : (Container class: %s %016" G_GINT64_MODIFIER "X) UnRead : %d Total : %d size : %d",
			name, klass, *fid, unread ? *unread : 0, total ? *total : 0, folder_size ? *folder_size : 0);

		folder = e_mapi_folder_new (name, klass, gfh->folder_hier, *fid, pid ? *pid : gfh->folder_id,
						   child ? *child : 0, unread ? *unread : 0, total ? *total : 0);

		folder->size = folder_size ? *folder_size : 0;

		*gfh->mapi_folders = g_slist_prepend (*gfh->mapi_folders, folder);
	}

	if (gfh->cb)
		return gfh->cb (conn, row_index, rows_total, gfh->cb_user_data, cancellable, perror);

	return TRUE;
}

static gboolean
get_child_folders (EMapiConnection *conn,
		   TALLOC_CTX *mem_ctx,
		   EMapiFolderCategory folder_hier,
		   mapi_object_t *parent,
		   mapi_id_t folder_id,
		   GSList **mapi_folders,
		   ProgressNotifyCB cb,
		   gpointer cb_user_data,
		   GCancellable *cancellable,
		   GError **perror)
{
	enum MAPISTATUS		ms;
	mapi_object_t		obj_folder;
	mapi_object_t		obj_table;
	struct SPropTagArray	*spropTagArray = NULL;
	uint32_t row_count = 0;
	struct GetFolderHierarchyCBData gfh;

	/* sanity check */
	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (parent != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mapi_object_init (&obj_folder);
	mapi_object_init (&obj_table);

	/* Attempt to open the folder */
	ms = OpenFolder (parent, folder_id, &obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenFolder", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Get the hierarchy table */
	ms = GetHierarchyTable (&obj_folder, &obj_table, TableFlags_Depth | TableFlags_NoNotifications, &row_count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetHierarchyTable", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror) || !row_count) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	spropTagArray = set_SPropTagArray (mem_ctx, 8,
					   PR_FID,
					   PR_PARENT_FID,
					   PR_CONTAINER_CLASS,
					   PR_DISPLAY_NAME_UNICODE,
					   PR_CONTENT_UNREAD,
					   PR_CONTENT_COUNT,
					   PR_MESSAGE_SIZE,
					   PR_FOLDER_CHILD_COUNT);

	ms = SetColumns (&obj_table, spropTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	gfh.folder_hier = folder_hier;
	gfh.folder_id = folder_id;
	gfh.mapi_folders = mapi_folders;
	gfh.cb = cb;
	gfh.cb_user_data = cb_user_data;

	ms = foreach_tablerow (conn, mem_ctx, &obj_table, get_folder_hierarchy_cb, &gfh, cancellable, perror);

 cleanup:
	talloc_free (spropTagArray);
	mapi_object_release (&obj_folder);
	mapi_object_release (&obj_table);

	return ms == MAPI_E_SUCCESS;
}

/* TODO : Find a right place for this.
 * The following are only defined in openchange fairly recently, so
 * we will conditionally define them here otherwise
 */
#ifndef PR_ADDITIONAL_REN_ENTRYIDS
	#define PR_ADDITIONAL_REN_ENTRYIDS    PROP_TAG(PT_MV_BINARY, 0x36D8)
#endif
#ifndef PidTagMailboxOwnerName
	#define PidTagMailboxOwnerName PR_USER_NAME_UNICODE
#endif

/*NOTE : This should be called when you hold the connection lock*/
/*NOTE : IsMailboxFolder doesn't support this yet. */
/* Ticket : http://trac.openchange.org/ticket/134  */
static gboolean
mapi_get_ren_additional_fids (TALLOC_CTX *mem_ctx,
			      mapi_object_t *obj_store,
			      GHashTable **folder_list,
			      GCancellable *cancellable,
			      GError **perror)
{
	mapi_id_t inbox_id, fid;
	mapi_object_t obj_folder_inbox;
	struct SPropTagArray *SPropTagArray;
	struct SPropValue *lpProps = NULL;
	struct SRow aRow;
	const struct BinaryArray_r *entryids;
	struct Binary_r entryid;
	enum MAPISTATUS ms;

	guint32 count, *folder_type;
	guint i = 0;

	/*Note : Do not change the order.*/
	const guint32 olfolder_defaults[] = {
		olFolderConflicts,
		olFolderSyncIssues,
		olFolderLocalFailures,
		olFolderServerFailures,
		olFolderJunk
	};

	mapi_object_init (&obj_folder_inbox);

	/* Get Inbox FID using GetDefaultFolder. */
	ms = GetDefaultFolder (obj_store, &inbox_id, olFolderInbox);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultFolder", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Open InboxFolder. */
	ms = OpenFolder (obj_store, inbox_id, &obj_folder_inbox);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenFolder", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* GetProps on Inbox for PR_ADDITIONAL_REN_ENTRYIDS */
	SPropTagArray = set_SPropTagArray(mem_ctx, 0x1, PR_ADDITIONAL_REN_ENTRYIDS);

	ms = GetProps (&obj_folder_inbox, MAPI_PROPS_SKIP_NAMEDID_CHECK | MAPI_UNICODE, SPropTagArray, &lpProps, &count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetProps", ms);
		goto cleanup;
	} else if (!lpProps) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "GetProps", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Build a SRow structure */
	aRow.ulAdrEntryPad = 0;
	aRow.cValues = count;
	aRow.lpProps = lpProps;

	entryids = (const struct BinaryArray_r *) e_mapi_util_find_row_propval (&aRow, PR_ADDITIONAL_REN_ENTRYIDS);

	/* Iterate through MV_BINARY */
	if (entryids) {
		for (i = 0; i < G_N_ELEMENTS (olfolder_defaults); i++) {
			fid = 0;
			entryid = entryids->lpbin [i];
			ms = GetFIDFromEntryID(entryid.cb, entryid.lpb, inbox_id, &fid);

			if (ms == MAPI_E_SUCCESS && fid) {
				folder_type = g_new0 (guint32, 1);
				*folder_type = olfolder_defaults[i];

				g_hash_table_insert (*folder_list,
						     e_mapi_util_mapi_id_to_string (fid),
						     folder_type);
			}
		}
	}

 cleanup:
	mapi_object_release (&obj_folder_inbox);
	talloc_free (lpProps);

	return ms == MAPI_E_SUCCESS;
}

static gboolean
set_default_folders (TALLOC_CTX *mem_ctx,
		     mapi_object_t *obj_store,
		     GSList **mapi_folders,
		     GCancellable *cancellable,
		     GError **perror)
{
	GSList *folder_list = *mapi_folders;

	GHashTable *default_folders = g_hash_table_new_full (g_str_hash, g_str_equal,
							     g_free, g_free);

	if (!mapi_get_ren_additional_fids (mem_ctx, obj_store, &default_folders, cancellable, perror)) {
		g_hash_table_destroy (default_folders);
		return FALSE;
	}

	while (folder_list != NULL) {
		EMapiFolder *folder = NULL;
		guint32 default_type = 0;
		gchar *key_fid = NULL;
		gpointer value = NULL;

		folder = folder_list->data;
		key_fid = e_mapi_util_mapi_id_to_string (folder->folder_id);

		if ((value = g_hash_table_lookup (default_folders, key_fid)) != NULL)
			default_type = *(guint32 *)value;
		g_free (key_fid);

		if (default_type != 0 || IsMailboxFolder (obj_store,folder->folder_id, &default_type)) {
			folder->is_default = TRUE; /* TODO : Clean up. Redundant.*/
			folder->default_type = default_type;
		}

		folder_list = g_slist_next (folder_list);
	}

	g_hash_table_destroy (default_folders);

	return TRUE;
}

static void
set_owner_name (gpointer data, gpointer user_data)
{
	EMapiFolder *folder = (EMapiFolder *)(data);
	folder->owner_name = g_strdup (user_data);
}

static void
set_user_name (gpointer data, gpointer user_data)
{
	EMapiFolder *folder = (EMapiFolder *)(data);
	folder->user_name = g_strdup (user_data);
}

gboolean
e_mapi_connection_get_folders_list (EMapiConnection *conn,
				    GSList **mapi_folders,
				    ProgressNotifyCB cb,
				    gpointer cb_user_data,
				    GCancellable *cancellable,
				    GError **perror)
{
	enum MAPISTATUS	ms;
	TALLOC_CTX		*mem_ctx;
	struct SPropTagArray	*SPropTagArray = NULL;
	struct SPropValue	*lpProps = NULL;
	struct SRow		aRow;
	gboolean		result = FALSE;
	mapi_id_t		mailbox_id;
	EMapiFolder	*folder;
	uint32_t		count = 0;
	const gchar		*mailbox_name = NULL;
	const gchar		*mailbox_owner_name = NULL;
	const gchar		*mailbox_user_name = NULL;
	const uint32_t          *mailbox_size = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_mapi_debug_print("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK (cancellable, perror, FALSE);

	mem_ctx = talloc_new (priv->session);

	/* Build the array of Mailbox properties we want to fetch */
	SPropTagArray = set_SPropTagArray(mem_ctx, 0x4,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_MAILBOX_OWNER_NAME_UNICODE,
					  PR_MESSAGE_SIZE,
					  PidTagMailboxOwnerName);

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = GetProps (&priv->msg_store, MAPI_PROPS_SKIP_NAMEDID_CHECK | MAPI_UNICODE, SPropTagArray, &lpProps, &count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetProps", ms);
		goto cleanup;
	} else if (!lpProps) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "GetProps", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* Build a SRow structure */
	aRow.ulAdrEntryPad = 0;
	aRow.cValues = count;
	aRow.lpProps = lpProps;

	/* betting that these will never fail */
	mailbox_name = (const gchar *) e_mapi_util_find_row_propval (&aRow, PR_DISPLAY_NAME_UNICODE);
	mailbox_owner_name = (const gchar *) e_mapi_util_find_row_propval (&aRow, PR_MAILBOX_OWNER_NAME_UNICODE);
	mailbox_user_name = (const gchar *) e_mapi_util_find_row_propval (&aRow, PidTagMailboxOwnerName);
	mailbox_size = (const uint32_t *)e_mapi_util_find_row_propval  (&aRow, PR_MESSAGE_SIZE);

	/* Prepare the directory listing */
	ms = GetDefaultFolder (&priv->msg_store, &mailbox_id, olFolderTopInformationStore);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultFolder", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	/* FIXME: May have to get the child folders count? Do we need/use it? */
	folder = e_mapi_folder_new (mailbox_name, IPF_NOTE,
					   E_MAPI_FOLDER_CATEGORY_PERSONAL, mailbox_id, 0, 0, 0 ,0);
	folder->is_default = TRUE;
	folder->default_type = olFolderTopInformationStore; /*Is this correct ?*/
	folder->size = mailbox_size ? *mailbox_size : 0;

	*mapi_folders = g_slist_prepend (*mapi_folders, folder);

	/* FIXME: check status of get_child_folders */
	result = get_child_folders (conn, mem_ctx, E_MAPI_FOLDER_CATEGORY_PERSONAL, &priv->msg_store, mailbox_id, mapi_folders, cb, cb_user_data, cancellable, perror);

	*mapi_folders = g_slist_reverse (*mapi_folders);

	if (result && !set_default_folders (mem_ctx, &priv->msg_store, mapi_folders, cancellable, perror)) {
		goto cleanup;
	}

	g_slist_foreach (*mapi_folders, (GFunc) set_owner_name, (gpointer) mailbox_owner_name);
	g_slist_foreach (*mapi_folders, (GFunc) set_user_name, (gpointer) mailbox_user_name);

 cleanup:
	talloc_free (SPropTagArray);
	talloc_free (lpProps);
	talloc_free (mem_ctx);

	UNLOCK ();

	e_mapi_debug_print("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
e_mapi_connection_get_pf_folders_list (EMapiConnection *conn,
				       GSList **mapi_folders,
				       ProgressNotifyCB cb,
				       gpointer cb_user_data,
				       GCancellable *cancellable,
				       GError **perror)
{
	enum MAPISTATUS		ms;
	TALLOC_CTX		*mem_ctx;
	gboolean		result = FALSE;
	mapi_id_t		mailbox_id;
	EMapiFolder	*folder;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_mapi_debug_print("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK (cancellable, perror, FALSE);
	mem_ctx = talloc_new (priv->session);

	if (!ensure_public_store (priv, perror))
		goto cleanup;

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	ms = GetDefaultPublicFolder (&priv->public_store, &mailbox_id, olFolderPublicIPMSubtree);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultPublicFolder", ms);
		goto cleanup;
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
		goto cleanup;
	}

	folder = e_mapi_folder_new (_("All Public Folders"), IPF_NOTE, 0, mailbox_id, 0, 0, 0, 0);
	folder->is_default = TRUE;
	folder->default_type = olPublicFoldersAllPublicFolders;
	*mapi_folders = g_slist_prepend (*mapi_folders, folder);
	result = get_child_folders (conn, mem_ctx, E_MAPI_FOLDER_CATEGORY_PUBLIC, &priv->public_store, mailbox_id, mapi_folders, cb, cb_user_data, cancellable, perror);
	*mapi_folders = g_slist_reverse (*mapi_folders);

 cleanup:
	talloc_free (mem_ctx);

	UNLOCK ();

	e_mapi_debug_print("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

GSList *
e_mapi_connection_peek_folders_list (EMapiConnection *conn)
{
	/* to have this used in the below macros */
	GError **perror = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, NULL);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	g_rec_mutex_lock (&priv->folders_lock);

	if (!priv->folders) {
		LOCK (NULL, NULL, NULL);
		e_mapi_connection_get_folders_list (conn, &priv->folders, NULL, NULL, NULL, perror);
		UNLOCK ();
	}

	g_rec_mutex_unlock (&priv->folders_lock);

	return priv->folders;
}

/* free returned pointer with g_free() */
gchar *
e_mapi_connection_ex_to_smtp (EMapiConnection *conn,
			      const gchar *ex_address,
			      gchar **display_name,
			      GCancellable *cancellable,
			      GError **perror)
{
	enum MAPISTATUS	ms;
	TALLOC_CTX		*mem_ctx;
	struct SPropTagArray	*SPropTagArray;
	struct PropertyRowSet_r *rowSet = NULL;
	struct PropertyTagArray_r *flaglist = NULL;
	const gchar		*str_array[2];
	gchar			*smtp_addr = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, NULL);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	e_return_val_mapi_error_if_fail (ex_address != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	str_array[0] = ex_address;
	str_array[1] = NULL;

	LOCK (cancellable, perror, NULL);

	mem_ctx = talloc_new (priv->session);

	SPropTagArray = set_SPropTagArray (mem_ctx, 0x2,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_SMTP_ADDRESS_UNICODE);

	ms = ResolveNames (priv->session, (const gchar **) str_array, SPropTagArray, &rowSet, &flaglist, MAPI_UNICODE);
	if (ms != MAPI_E_SUCCESS) {
		talloc_free (rowSet);
		talloc_free (flaglist);

		rowSet = NULL;
		flaglist = NULL;

		ms = ResolveNames (priv->session, (const gchar **)str_array, SPropTagArray, &rowSet, &flaglist, 0);
	}

	if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
		ms = MAPI_E_USER_CANCEL;
	}

	if (ms == MAPI_E_SUCCESS && rowSet && rowSet->cRows == 1) {
		smtp_addr = g_strdup (e_mapi_util_find_propertyrow_propval (rowSet->aRow, PR_SMTP_ADDRESS_UNICODE));
		if (display_name)
			*display_name = g_strdup (e_mapi_util_find_propertyrow_propval (rowSet->aRow, PR_DISPLAY_NAME_UNICODE));
	}

	talloc_free (rowSet);
	talloc_free (flaglist);
	talloc_free (mem_ctx);

	UNLOCK ();

	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "ResolveNames", ms);

	return smtp_addr;
}

gboolean
e_mapi_connection_resolve_username (EMapiConnection *conn,
				    const gchar *to_resolve,
				    BuildReadPropsCB brp_cb,
				    gpointer brp_cb_user_data,
				    GetPropertiesCB cb,
				    gpointer cb_user_data,
				    GCancellable *cancellable,
				    GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	struct SPropTagArray *tag_array;
	struct PropertyRowSet_r *rows = NULL;
	struct PropertyTagArray_r *flaglist = NULL;
	const gchar *str_array[2];
	EResolveNamedIDsData *named_ids_list = NULL;
	guint named_ids_len = 0, ii, jj, qq;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (to_resolve != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	str_array[0] = to_resolve;
	str_array[1] = NULL;

	LOCK (cancellable, perror, FALSE);

	mem_ctx = talloc_new (priv->session);

	tag_array = set_SPropTagArray (mem_ctx, 3,
		PidTagEntryId,
		PidTagDisplayName,
		PidTagSmtpAddress);

	ms = MAPI_E_SUCCESS;
	if (brp_cb != NULL && !brp_cb (conn, mem_ctx, tag_array, brp_cb_user_data, cancellable, perror)) {
		ms = MAPI_E_CALL_FAILED;
		make_mapi_error (perror, "build_read_props_callback", ms);
	}

	if (ms == MAPI_E_SUCCESS) {
		for (ii = 0; ii < tag_array->cValues; ii++) {
			uint32_t proptag = tag_array->aulPropTag[ii];

			if (may_skip_property (proptag)) {
				const gchar *name = get_proptag_name (proptag);
				if (!name)
					name = "";

				g_debug ("%s: Cannot fetch property 0x%08x %s", G_STRFUNC, proptag, name);
			} else {
				maybe_add_named_id_tag (proptag, &named_ids_list, &named_ids_len);
			}
		}

		if (named_ids_list) {
			GHashTable *replace_hash;

			if (!e_mapi_connection_resolve_named_props (conn, NULL, named_ids_list, named_ids_len, cancellable, perror)) {
				goto cleanup;
			}

			if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
				goto cleanup;
			}

			replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, TRUE);
			if (replace_hash) {
				for (ii = 0; ii < tag_array->cValues; ii++) {
					uint32_t proptag = tag_array->aulPropTag[ii];

					maybe_replace_named_id_tag (&proptag, replace_hash);

					tag_array->aulPropTag[ii] = proptag;
				}

				g_hash_table_destroy (replace_hash);
				replace_hash = NULL;
			}
		}

		ms = ResolveNames (priv->session, str_array, tag_array, &rows, &flaglist, MAPI_UNICODE);
		if (ms != MAPI_E_SUCCESS && ms != MAPI_E_USER_CANCEL) {
			if (g_cancellable_set_error_if_cancelled (cancellable, perror)) {
				ms = MAPI_E_USER_CANCEL;
			} else {
				talloc_free (rows);
				talloc_free (flaglist);

				rows = NULL;
				flaglist = NULL;

				ms = ResolveNames (priv->session, str_array, tag_array, &rows, &flaglist, 0);
			}
		}

		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "ResolveNames", ms);
			goto cleanup;
		}
	}

	if (ms == MAPI_E_SUCCESS && rows) {
		GHashTable *replace_hash = NULL;

		if (named_ids_list)
			replace_hash = prepare_maybe_replace_hash (named_ids_list, named_ids_len, FALSE);

		for (qq = 0; qq < rows->cRows; qq++) {
			struct mapi_SPropValue_array *properties;
			struct SRow *row;

			row = talloc_zero (mem_ctx, struct SRow);
			if (!row) {
				UNLOCK();
				e_return_val_mapi_error_if_fail (properties != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
			}

			cast_PropertyRow_to_SRow (mem_ctx, &rows->aRow[qq], row);

			properties = talloc_zero (mem_ctx, struct mapi_SPropValue_array);
			if (!properties) {
				UNLOCK();
				talloc_free (row);
				e_return_val_mapi_error_if_fail (properties != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
			}

			/* Conversion from SPropValue to mapi_SPropValue. (no padding here) */
			properties->cValues = row->cValues;
			properties->lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, properties->cValues + 1);
			for (ii = 0, jj = 0; ii < row->cValues; ii++, jj++) {
				if (may_skip_property (row->lpProps[ii].ulPropTag)) {
					jj--;
					properties->cValues--;
				} else {
					uint32_t proptag = row->lpProps[ii].ulPropTag;

					maybe_replace_named_id_tag (&proptag, replace_hash);
					row->lpProps[ii].ulPropTag = proptag;

					cast_mapi_SPropValue (mem_ctx, &properties->lpProps[jj], &row->lpProps[ii]);
				}
			}

			if (!cb (conn, mem_ctx, properties, cb_user_data, cancellable, perror)) {
				ms = MAPI_E_CALL_FAILED;
				make_mapi_error (perror, "callback", ms);
				talloc_free (properties);
				talloc_free (row);
				break;
			}

			talloc_free (properties);
			talloc_free (row);
		}

		if (replace_hash)
			g_hash_table_destroy (replace_hash);
	} else if (ms == MAPI_E_SUCCESS) {
		if (flaglist && flaglist->aulPropTag[0] == MAPI_AMBIGUOUS) {
			ms = MAPI_E_AMBIGUOUS_RECIP;
			g_set_error (perror, E_MAPI_ERROR, ms, _("User name '%s' is ambiguous"), to_resolve);
		} else {
			ms = MAPI_E_NOT_FOUND;
			g_set_error (perror, E_MAPI_ERROR, ms, _("User name '%s' not found"), to_resolve);
		}
	}

 cleanup:
	g_free (named_ids_list);
	talloc_free (rows);
	talloc_free (flaglist);
	talloc_free (mem_ctx);

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

static gint
emit_server_notification_signal (uint16_t event_type, gpointer event_data, gpointer user_data)
{
	EMapiConnection *conn = user_data;
	guint uint_event_type = event_type;

	g_signal_emit (conn, signals[SERVER_NOTIFICATION], 0, uint_event_type, event_data);

	return MAPI_E_SUCCESS;
}

static gpointer
e_mapi_connection_notification_thread (gpointer user_data)
{
	EMapiConnection *conn = user_data;
	EMapiConnectionPrivate *priv;

	g_return_val_if_fail (conn != NULL, NULL);
	g_return_val_if_fail (conn->priv != NULL, NULL);
	g_return_val_if_fail (conn->priv->session != NULL, NULL);

	priv = conn->priv;

	while (g_hash_table_size (priv->known_notifications) > 0) {
		gint64 end_time;

		LOCK (NULL, NULL, NULL);
		/* this returns MAPI_E_INVALID_PARAMETER when there
		   is no pending notification
		*/
		DispatchNotifications (priv->session);
		UNLOCK ();

		/* poll not so often */
		end_time = g_get_monotonic_time () + (G_TIME_SPAN_SECOND * priv->notification_poll_seconds);

		e_flag_clear (priv->notification_flag);
		e_flag_wait_until (priv->notification_flag, end_time);
	}

	return NULL;
}

/* enables server notifications on a folder, or on a whole store, if obj_folder is NULL.
   the event_mask can be 0 to obtain all notifications;
   Pair function for this is e_mapi_connection_disable_notifications().
   The notification is received to the caller with the "server-notification" signal.
   Note that the signal is used for each notification, without distinction on the enable
   object.
*/
gboolean
e_mapi_connection_enable_notifications (EMapiConnection *conn,
					mapi_object_t *obj_folder,
					uint32_t event_mask,
					GCancellable *cancellable,
					GError **perror)
{
	enum MAPISTATUS	ms;
	mapi_id_t fid = 0;
	uint32_t conn_id;
	gint64 i64;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	if (event_mask == 0)
		event_mask = fnevNewMail |
			     fnevObjectCreated |
			     fnevObjectDeleted |
			     fnevObjectModified |
			     fnevObjectMoved;

	if (obj_folder)
		fid = mapi_object_get_id (obj_folder);

	i64 = (gint64) fid;
	conn_id = GPOINTER_TO_UINT (g_hash_table_lookup (priv->known_notifications, &i64));
	if (conn_id) {
		stop_notification (priv, conn_id, cancellable, perror);
		g_hash_table_remove (priv->known_notifications, &i64);
	}

	if (priv->register_notification_result == MAPI_E_RESERVED)
		priv->register_notification_result = RegisterNotification (priv->session);

	if (priv->register_notification_result != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "RegisterNotification", priv->register_notification_result);
		UNLOCK ();

		return FALSE;
	}

	conn_id = 0;
	ms = Subscribe (obj_folder ? obj_folder : &priv->msg_store, &conn_id, event_mask, obj_folder == NULL, emit_server_notification_signal, conn);
	if (ms == MAPI_E_SUCCESS) {
		gint64 *pi64;

		pi64 = g_new0 (gint64, 1);
		*pi64 = i64;

		g_hash_table_insert (priv->known_notifications, pi64, GUINT_TO_POINTER (conn_id));

		if (priv->notification_thread) {
			e_flag_set (priv->notification_flag);
		} else {
			priv->notification_thread = g_thread_new (NULL, e_mapi_connection_notification_thread, conn);
		}
	} else {
		make_mapi_error (perror, "Subscribe", ms);
	}

	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

gboolean
e_mapi_connection_disable_notifications	(EMapiConnection *conn,
					 mapi_object_t *obj_folder,
					 GCancellable *cancellable,
					 GError **perror)
{
	mapi_id_t fid = 0;
	uint32_t conn_id;
	gint64 i64;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK (cancellable, perror, FALSE);

	if (!priv->notification_thread) {
		/* no notifications started, just return */
		UNLOCK ();

		return TRUE;
	}

	if (priv->register_notification_result != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "RegisterNotification", priv->register_notification_result);
		UNLOCK ();

		return FALSE;
	}

	if (obj_folder)
		fid = mapi_object_get_id (obj_folder);

	i64 = (gint64) fid;
	conn_id = GPOINTER_TO_UINT (g_hash_table_lookup (priv->known_notifications, &i64));
	if (conn_id) {
		gboolean stopped = stop_notification (priv, conn_id, cancellable, perror);
		g_hash_table_remove (priv->known_notifications, &i64);

		if (!stopped) {
			UNLOCK ();
			return FALSE;
		}
	} else {
		make_mapi_error (perror, "e_mapi_connection_disable_notifications", MAPI_E_NOT_FOUND);
		UNLOCK ();

		return FALSE;
	}

	if (g_hash_table_size (priv->known_notifications) == 0) {
		stop_all_notifications (priv);
	}

	UNLOCK ();

	return TRUE;
}

/* profile related functions - begin */

struct tcp_data
{
	ESourceRegistry *registry;
	struct mapi_context *mapi_ctx;
	const gchar *profname;
	const gchar *password;
	GCancellable *cancellable;
	GError **perror;

	EFlag *eflag;
	gboolean has_profile;
};

static gboolean
try_create_profile_main_thread_cb (struct tcp_data *data)
{
	EMapiProfileData empd = { 0 };
	GList *all_sources;
	ESource *source;

	g_return_val_if_fail (data != NULL, FALSE);
	if (!data->registry) {
		e_flag_set (data->eflag);
		return FALSE;
	}

	all_sources = e_source_registry_list_sources (data->registry, NULL);
	source = e_mapi_utils_get_master_source (all_sources, data->profname);

	if (source) {
		ESourceCamel *extension;
		CamelSettings *settings;
		const gchar *extension_name;
		CamelNetworkSettings *network_settings;

		extension_name = e_source_camel_get_extension_name ("mapi");
		extension = e_source_get_extension (source, extension_name);
		settings = e_source_camel_get_settings (extension);

		network_settings = CAMEL_NETWORK_SETTINGS (settings);

		empd.server = camel_network_settings_get_host (network_settings);
		empd.username = camel_network_settings_get_user (network_settings);
		e_mapi_util_profiledata_from_settings (&empd, CAMEL_MAPI_SETTINGS (settings));

		if (data->password)
			empd.password = g_string_new (data->password);
		else
			data->password = NULL;

		if (COMPLETE_PROFILEDATA (&empd)) {
			gchar *profname = e_mapi_util_profile_name (data->mapi_ctx, &empd, FALSE);

			if (profname && g_str_equal (profname, data->profname)) {
				/* do not use locking here, because when this is called then other thread is holding the lock */
				data->has_profile = mapi_profile_create (data->mapi_ctx, &empd, NULL, NULL, NULL, data->perror, FALSE);
			}

			g_free (profname);
		}

		if (empd.password) {
			if (empd.password->len)
				memset (empd.password->str, 0, empd.password->len);
			g_string_free (empd.password, TRUE);
		}
	}

	g_list_free_full (all_sources, g_object_unref);

	e_flag_set (data->eflag);

	return FALSE;
}

static gboolean
try_create_profile (ESourceRegistry *registry,
		    struct mapi_context *mapi_ctx,
		    const gchar *profname,
		    const gchar *password,
		    GCancellable *cancellable,
		    GError **perror)
{
	struct tcp_data data;

	g_return_val_if_fail (mapi_ctx != NULL, FALSE);
	g_return_val_if_fail (profname != NULL, FALSE);
	g_return_val_if_fail (*profname != 0, FALSE);

	data.registry = registry;
	data.mapi_ctx = mapi_ctx;
	data.profname = profname;
	data.password = password;
	data.eflag = e_flag_new ();
	data.has_profile = FALSE;
	data.cancellable = cancellable;
	data.perror = perror;

	if (!g_main_context_is_owner (g_main_context_default ())) {
		/* function called from other than main thread */
		g_timeout_add (10, (GSourceFunc) try_create_profile_main_thread_cb, &data);
		e_flag_wait (data.eflag);
	} else {
		try_create_profile_main_thread_cb (&data);
	}

	e_flag_free (data.eflag);

	return data.has_profile;
}

static struct mapi_session *
mapi_profile_load (ESourceRegistry *registry,
		   struct mapi_context *mapi_ctx,
		   const gchar *profname,
		   const gchar *password,
		   GCancellable *cancellable,
		   GError **perror)
{
	enum MAPISTATUS	ms = MAPI_E_SUCCESS;
	struct mapi_session *session = NULL;
	struct mapi_profile *profile;

	e_return_val_mapi_error_if_fail (mapi_ctx != NULL, MAPI_E_INVALID_PARAMETER, NULL);
	e_return_val_mapi_error_if_fail (profname != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	if (!e_mapi_utils_global_lock (cancellable, perror))
		return NULL;

	e_mapi_debug_print("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	profile = talloc_zero (mapi_ctx, struct mapi_profile);
	if (MAPI_E_SUCCESS == OpenProfile (mapi_ctx, profile, profname, NULL)) {
		if (!can_reach_mapi_server (profile->server, cancellable, perror)) {
			ShutDown (profile);
			goto cleanup;
		}

		ShutDown (profile);
	}

	e_mapi_debug_print("Loading profile %s ", profname);

	ms = MapiLogonEx (mapi_ctx, &session, profname, password);
	if (ms == MAPI_E_NOT_FOUND && try_create_profile (registry, mapi_ctx, profname, password, cancellable, perror))
		ms = MapiLogonEx (mapi_ctx, &session, profname, password);

	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MapiLogonEx", ms);
		goto cleanup;
	}

 cleanup:
	talloc_free (profile);
	e_mapi_utils_global_unlock ();
	e_mapi_debug_print ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return session;
}

static int
create_profile_fallback_callback (struct PropertyRowSet_r *rowset,
				  gconstpointer data)
{
	guint32	ii;
	const gchar *username = (const gchar *) data;

	/* If we can find the exact username, then find & return its index. */
	for (ii = 0; ii < rowset->cRows; ii++) {
		const gchar *account_name;

		account_name = e_mapi_util_find_propertyrow_propval (&(rowset->aRow[ii]), PR_ACCOUNT_UNICODE);

		if (account_name && g_strcmp0 (username, account_name) == 0)
			return ii;
	}

	/* cancel it, do authenticate again */
	return rowset->cRows + 1;
}

static gboolean
mapi_profile_create (struct mapi_context *mapi_ctx,
		     const EMapiProfileData *empd,
		     mapi_profile_callback_t callback, gconstpointer data,
		     GCancellable *cancellable,
		     GError **perror,
		     gboolean use_locking)
{
	enum MAPISTATUS	ms;
	gboolean result = FALSE;
	const gchar *workstation = "localhost";
	gchar *profname = NULL;
	struct mapi_session *session = NULL;

	e_return_val_mapi_error_if_fail (mapi_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	if (!callback) {
		callback = create_profile_fallback_callback;
		data = (gpointer) empd->username;
	}

	/*We need all the params before proceeding.*/
	e_return_val_mapi_error_if_fail (COMPLETE_PROFILEDATA (empd) && (empd->krb_sso || (empd->password && empd->password->len)),
					 MAPI_E_INVALID_PARAMETER, FALSE);

	if (!can_reach_mapi_server (empd->server, cancellable, perror))
		return FALSE;

	if (use_locking) {
		if (!e_mapi_utils_global_lock (cancellable, perror))
			return FALSE;
	}

	e_mapi_debug_print ("Create profile with %s %s %s\n", empd->username,
		 empd->domain, empd->server);

	profname = e_mapi_util_profile_name (mapi_ctx, empd, TRUE);

	/* Delete any existing profiles with the same profilename */
	ms = DeleteProfile (mapi_ctx, profname);
	/* don't bother to check error - it would be valid if we got an error */

	ms = CreateProfile (mapi_ctx, profname, empd->username,
			    empd->krb_sso ? NULL : empd->password->str, OC_PROFILE_NOPASSWORD);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "CreateProfile", ms);
		goto cleanup;
	}

	#define add_string_attr(_prof,_aname,_val)				\
		mapi_profile_add_string_attr (mapi_ctx, _prof, _aname, _val)

	add_string_attr (profname, "binding", empd->server);
	add_string_attr (profname, "workstation", workstation);
	add_string_attr (profname, "kerberos", empd->krb_sso ? "yes" : "no");

	/* note: domain and realm are intentially not added to
	 *       the libmapi profile in the case of SSO enabled,
	 *       as it changes the behavior, and breaks SSO support. */
	if (!empd->krb_sso) {
		add_string_attr (profname, "domain", empd->domain);
	}

	if (empd->use_ssl)
		add_string_attr (profname, "seal", "true");

	/* This is only convenient here and should be replaced at some point */
	add_string_attr (profname, "codepage", "1252");
	add_string_attr (profname, "language", "1033");
	add_string_attr (profname, "method", "1033");

	#undef add_string_attr

	/* Login now */
	e_mapi_debug_print("Logging into the server... ");
	ms = MapiLogonProvider (mapi_ctx, &session, profname, empd->krb_sso ? NULL : empd->password->str,
				PROVIDER_ID_NSPI);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MapiLogonProvider", ms);
		e_mapi_debug_print ("Deleting profile %s ", profname);
		DeleteProfile (mapi_ctx, profname);
		goto cleanup;
	}
	e_mapi_debug_print("MapiLogonProvider : succeeded \n");

	if (g_cancellable_set_error_if_cancelled (cancellable, perror))
		goto cleanup;

	ms = ProcessNetworkProfile (session, empd->username, callback, data);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "ProcessNetworkProfile", ms);
		e_mapi_debug_print ("Deleting profile %s ", profname);
		DeleteProfile (mapi_ctx, profname);
		goto cleanup;
	}
	e_mapi_debug_print("ProcessNetworkProfile : succeeded \n");

	result = TRUE;

 cleanup:
	g_free (profname);

	/* this is causing segfault in openchange */
	/*if (session && result) {
		mapi_object_t msg_store;

		mapi_object_init (&msg_store);

		ms = OpenMsgStore (session, &msg_store);
		if (ms == MAPI_E_SUCCESS) {
			Logoff (&msg_store);
		} else {
			/ * how to close and free session without store? * /
			make_mapi_error (perror, "OpenMsgStore", ms);
		}

		mapi_object_release (&msg_store);
	}*/

	if (use_locking)
		e_mapi_utils_global_unlock ();

	return result;
}

gboolean
e_mapi_create_profile (struct mapi_context *mapi_ctx,
		       EMapiProfileData *empd,
		       mapi_profile_callback_t callback,
		       gconstpointer data,
		       GCancellable *cancellable,
		       GError **perror)
{
	return mapi_profile_create (mapi_ctx, empd, callback, data, cancellable, perror, TRUE);
}

gboolean
e_mapi_delete_profile (struct mapi_context *mapi_ctx,
		       const gchar *profile,
		       GError **perror)
{
	gboolean result = FALSE;
	enum MAPISTATUS ms;

	e_return_val_mapi_error_if_fail (mapi_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	if (!e_mapi_utils_global_lock (NULL, perror))
		return FALSE;

	e_mapi_debug_print ("Deleting profile %s ", profile);

	ms = DeleteProfile (mapi_ctx, profile);
	if (ms == MAPI_E_SUCCESS || ms == MAPI_E_NOT_FOUND) {
		result = TRUE;
	} else {
		make_mapi_error (perror, "DeleteProfile", ms);
	}

	e_mapi_utils_global_unlock ();

	return result;
}

void
e_mapi_rename_profile (struct mapi_context *mapi_ctx,
		       const gchar *old_name,
		       const gchar *new_name,
		       GError **perror)
{
	g_return_if_fail (mapi_ctx != NULL);
	g_return_if_fail (old_name != NULL);
	g_return_if_fail (new_name != NULL);

	/* do not use locking here, it's called with a lock held already */
	/* if (!e_mapi_utils_global_lock (NULL, perror))
		return; */

	RenameProfile (mapi_ctx, old_name, new_name);

	/* e_mapi_utils_global_unlock (); */
}

/* profile related functions - end */

EMapiRecipient *
e_mapi_recipient_new (TALLOC_CTX *mem_ctx)
{
	EMapiRecipient *recipient;

	recipient = talloc_zero (mem_ctx, EMapiRecipient);
	g_assert (recipient != NULL);

	recipient->properties.cValues = 0;
	recipient->properties.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, 1);
	recipient->next = NULL;

	g_assert (recipient->properties.lpProps != NULL);

	return recipient;
}

void
e_mapi_recipient_free (EMapiRecipient *recipient)
{
	if (!recipient)
		return;

	talloc_free (recipient->properties.lpProps);
	talloc_free (recipient);
}

EMapiAttachment *
e_mapi_attachment_new (TALLOC_CTX *mem_ctx)
{
	EMapiAttachment *attachment;

	attachment = talloc_zero (mem_ctx, EMapiAttachment);
	g_assert (attachment != NULL);

	attachment->properties.cValues = 0;
	attachment->properties.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, 1);
	attachment->streamed_properties = NULL;
	attachment->streamed_properties_count = 0;
	attachment->embedded_object = NULL;
	attachment->next = NULL;

	g_assert (attachment->properties.lpProps != NULL);

	return attachment;
}

void
e_mapi_attachment_free (EMapiAttachment *attachment)
{
	if (!attachment)
		return;

	e_mapi_object_free (attachment->embedded_object);
	talloc_free (attachment->properties.lpProps);
	talloc_free (attachment->streamed_properties);
	talloc_free (attachment);
}

void
e_mapi_attachment_add_streamed (EMapiAttachment *attachment,
				uint32_t proptag,
				uint64_t cb,
				const uint8_t *lpb)
{
	guint32 index;

	g_return_if_fail (attachment != NULL);
	g_return_if_fail (proptag != 0);
	g_return_if_fail (e_mapi_attachment_get_streamed (attachment, proptag) == NULL);

	attachment->streamed_properties = talloc_realloc (attachment,
		attachment->streamed_properties,
		EMapiStreamedProp,
		attachment->streamed_properties_count + 1);
	g_return_if_fail (attachment->streamed_properties != NULL);

	index = attachment->streamed_properties_count;
	attachment->streamed_properties_count++;
	attachment->streamed_properties[index].proptag = proptag;
	attachment->streamed_properties[index].cb = cb;
	attachment->streamed_properties[index].lpb = lpb;
	attachment->streamed_properties[index].orig_value = lpb;
}

EMapiStreamedProp *
e_mapi_attachment_get_streamed (EMapiAttachment *attachment,
				uint32_t proptag)
{
	guint32 ii;

	g_return_val_if_fail (attachment != NULL, NULL);

	if (!attachment->streamed_properties_count || !attachment->streamed_properties)
		return NULL;

	for (ii = 0; ii < attachment->streamed_properties_count; ii++) {
		if (attachment->streamed_properties[ii].proptag == proptag)
			return &attachment->streamed_properties[ii];
	}

	return NULL;
}

gboolean
e_mapi_attachment_get_bin_prop (EMapiAttachment *attachment,
				uint32_t proptag,
				uint64_t *cb,
				const uint8_t **lpb)
{
	EMapiStreamedProp *streamed;
	const struct SBinary_short *bin;

	g_return_val_if_fail (attachment != NULL, FALSE);
	g_return_val_if_fail (cb != NULL, FALSE);
	g_return_val_if_fail (lpb != NULL, FALSE);

	*cb = 0;
	*lpb = NULL;

	streamed = e_mapi_attachment_get_streamed (attachment, proptag);
	if (streamed) {
		*cb = streamed->cb;
		*lpb = streamed->lpb;

		return TRUE;
	}

	bin = e_mapi_util_find_array_propval (&attachment->properties, proptag);
	if (bin) {
		*cb = bin->cb;
		*lpb = bin->lpb;

		return TRUE;
	}

	return FALSE;
}

gboolean
e_mapi_attachment_contains_prop (EMapiAttachment *attachment,
				 uint32_t proptag)
{
	g_return_val_if_fail (attachment != NULL, FALSE);

	return e_mapi_attachment_get_streamed (attachment, proptag) != NULL ||
	       e_mapi_util_find_array_propval (&attachment->properties, proptag) != NULL;
}

EMapiObject *
e_mapi_object_new (TALLOC_CTX *mem_ctx)
{
	EMapiObject *object;

	object = talloc_zero (mem_ctx, EMapiObject);
	g_assert (object != NULL);

	object->properties.cValues = 0;
	object->properties.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, 1);
	object->streamed_properties = NULL;
	object->streamed_properties_count = 0;
	object->recipients = NULL;
	object->attachments = NULL;
	object->parent = NULL;

	g_assert (object->properties.lpProps != NULL);

	return object;
}

void
e_mapi_object_free (EMapiObject *object)
{
	EMapiRecipient *recipient;
	EMapiAttachment *attachment;

	if (!object)
		return;

	recipient = object->recipients;
	while (recipient) {
		EMapiRecipient *r = recipient;

		recipient = recipient->next;
		e_mapi_recipient_free (r);
	}

	attachment = object->attachments;
	while (attachment) {
		EMapiAttachment *a = attachment;

		attachment = attachment->next;
		e_mapi_attachment_free (a);
	}

	talloc_free (object->streamed_properties);
	talloc_free (object->properties.lpProps);
	talloc_free (object);
}

void
e_mapi_object_add_recipient (EMapiObject *object,
			     EMapiRecipient *recipient)
{
	g_return_if_fail (object != NULL);
	g_return_if_fail (recipient != NULL);
	g_return_if_fail (recipient->next == NULL);

	if (!object->recipients) {
		object->recipients = recipient;
	} else {
		EMapiRecipient *recip = object->recipients;

		while (recip->next) {
			recip = recip->next;
		}

		recip->next = recipient;
	}
}

void
e_mapi_object_add_attachment (EMapiObject *object,
			      EMapiAttachment *attachment)
{
	g_return_if_fail (object != NULL);
	g_return_if_fail (attachment != NULL);
	g_return_if_fail (attachment->next == NULL);

	if (!object->attachments) {
		object->attachments = attachment;
	} else {
		EMapiAttachment *attach = object->attachments;

		while (attach->next) {
			attach = attach->next;
		}

		attach->next = attachment;
	}
}

void
e_mapi_object_add_streamed (EMapiObject *object,
			    uint32_t proptag,
			    uint64_t cb,
			    const uint8_t *lpb)
{
	guint32 index;

	g_return_if_fail (object != NULL);
	g_return_if_fail (proptag != 0);
	g_return_if_fail (e_mapi_object_get_streamed (object, proptag) == NULL);

	object->streamed_properties = talloc_realloc (object,
		object->streamed_properties,
		EMapiStreamedProp,
		object->streamed_properties_count + 1);
	g_return_if_fail (object->streamed_properties != NULL);

	index = object->streamed_properties_count;
	object->streamed_properties_count++;
	object->streamed_properties[index].proptag = proptag;
	object->streamed_properties[index].cb = cb;
	object->streamed_properties[index].lpb = lpb;
	object->streamed_properties[index].orig_value = lpb;
}

EMapiStreamedProp *
e_mapi_object_get_streamed (EMapiObject *object,
			    uint32_t proptag)
{
	guint32 ii;

	g_return_val_if_fail (object != NULL, NULL);

	if (!object->streamed_properties_count || !object->streamed_properties)
		return NULL;

	for (ii = 0; ii < object->streamed_properties_count; ii++) {
		if (object->streamed_properties[ii].proptag == proptag)
			return &object->streamed_properties[ii];
	}

	return NULL;
}

gboolean
e_mapi_object_get_bin_prop (EMapiObject *object,
			    uint32_t proptag,
			    uint64_t *cb,
			    const uint8_t **lpb)
{
	EMapiStreamedProp *streamed;
	gconstpointer value;

	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (cb != NULL, FALSE);
	g_return_val_if_fail (lpb != NULL, FALSE);

	*cb = 0;
	*lpb = NULL;

	streamed = e_mapi_object_get_streamed (object, proptag);
	if (streamed) {
		*cb = streamed->cb;
		*lpb = streamed->lpb;

		return TRUE;
	}

	value = e_mapi_util_find_array_propval (&object->properties, proptag);
	if (value) {
		if ((proptag & 0xFFFF) == PT_BINARY) {
			const struct SBinary_short *bin = value;

			*cb = bin->cb;
			*lpb = bin->lpb;

			return TRUE;
		}

		if ((proptag & 0xFFFF) == PT_STRING8 ||
		    (proptag & 0xFFFF) == PT_UNICODE) {
			*cb = strlen (value);
			*lpb = value;

			return TRUE;
		}
	}

	return FALSE;
}

gboolean
e_mapi_object_contains_prop (EMapiObject *object,
			     uint32_t proptag)
{
	g_return_val_if_fail (object != NULL, FALSE);

	return e_mapi_object_get_streamed (object, proptag) != NULL ||
	       e_mapi_util_find_array_propval (&object->properties, proptag) != NULL;
}

EMapiPermissionEntry *
e_mapi_permission_entry_new (const gchar *username,
			     const struct SBinary_short *entry_id,
			     uint64_t member_id,
			     uint32_t member_rights)
{
	EMapiPermissionEntry *entry;

	entry = g_new0 (EMapiPermissionEntry, 1);
	entry->username = g_strdup (username);

	if (entry_id && entry_id->lpb) {
		entry->entry_id.cb = entry_id->cb;
		entry->entry_id.lpb = g_memdup (entry_id->lpb, entry_id->cb);
	} else {
		entry->entry_id.cb = 0;
		entry->entry_id.lpb = NULL;
	}

	entry->member_id = member_id;
	entry->member_rights = member_rights;

	return entry;
}

void
e_mapi_permission_entry_free (EMapiPermissionEntry *entry)
{
	if (!entry)
		return;

	g_free (entry->username);
	g_free (entry->entry_id.lpb);
	g_free (entry);
}
