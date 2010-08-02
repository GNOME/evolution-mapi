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
#include <libedataserver/e-data-server-util.h>

#include "exchange-mapi-connection.h"
#include "exchange-mapi-folder.h"
#include "exchange-mapi-utils.h"
#include "exchange-mapi-mail-utils.h"
#include <param.h>

#define DEFAULT_PROF_NAME "mapi-profiles.ldb"

static void register_connection (ExchangeMapiConnection *conn);
static void unregister_connection (ExchangeMapiConnection *conn);
static struct mapi_session *mapi_profile_load (const gchar *profname, const gchar *password, GError **perror);

/* GObject foo - begin */

G_DEFINE_TYPE (ExchangeMapiConnection, exchange_mapi_connection, G_TYPE_OBJECT)

#define EXCHANGE_MAPI_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), EXCHANGE_TYPE_MAPI_CONNECTION, ExchangeMapiConnectionPrivate))

/* These two macros require 'priv' variable of type ExchangeMapiConnectionPrivate */
#define LOCK()		g_debug ("%s: %s: lock(session_lock)", G_STRLOC, G_STRFUNC); g_static_rec_mutex_lock (&priv->session_lock);
#define UNLOCK()	g_debug ("%s: %s: unlock(session_lock)", G_STRLOC, G_STRFUNC); g_static_rec_mutex_unlock (&priv->session_lock);

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
	GError *error;

	if (!perror)
		return;

	g_return_if_fail (*perror == NULL);

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

	#undef err

	default:
		status_name = mapi_get_errstr (mapi_status);
		if (!status_name)
			status_name = "";
		to_free = g_strdup_printf (_("MAPI error %s (0x%x) occurred"), status_name, mapi_status);
		error_msg = to_free;
	}

	g_return_if_fail (error_msg != NULL);

	if (context && *context) {
		/* Translators: The first '%s' is replaced with an error context,
		   aka where the error occurred, the second '%s' is replaced with
		   the error message. */
		error = g_error_new (E_MAPI_ERROR, mapi_status, C_("EXCHANGEMAPI_ERROR", "%s: %s"), context, error_msg);
	} else {
		error = g_error_new_literal (E_MAPI_ERROR, mapi_status, error_msg);
	}

	g_free (to_free);

	g_propagate_error (perror, error);
}

typedef struct _ExchangeMapiConnectionPrivate ExchangeMapiConnectionPrivate;

struct _ExchangeMapiConnectionPrivate {
	struct mapi_session *session;
	GStaticRecMutex session_lock;

	gchar *profile;			/* profile name, where the session is connected to */
	mapi_object_t msg_store;	/* valid only when session != NULL */

	gboolean has_public_store;	/* whether is 'public_store' filled */
	mapi_object_t public_store;

	GSList *folders;		/* list of ExchangeMapiFolder pointers */

	GHashTable *named_ids;		/* cache of named ids; key is a folder ID, value is a hash table
					   of named_id to prop_id in that respective folder */
};

/* should have session_lock locked already, when calling this function */
static void
disconnect (ExchangeMapiConnectionPrivate *priv)
{
	g_return_if_fail (priv != NULL);

	if (!priv->session)
		return;

	if (priv->folders)
		exchange_mapi_folder_free_list (priv->folders);

	if (priv->has_public_store)
		mapi_object_release (&priv->public_store);
	Logoff (&priv->msg_store);
	mapi_object_release (&priv->msg_store);

	if (priv->named_ids)
		g_hash_table_remove_all (priv->named_ids);

	priv->session = NULL;
	priv->has_public_store = FALSE;
	priv->folders = NULL;
}

/* should have session_lock locked already, when calling this function */
static gboolean
ensure_public_store (ExchangeMapiConnectionPrivate *priv, GError **perror)
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

static void
exchange_mapi_connection_finalize (GObject *object)
{
	ExchangeMapiConnectionPrivate *priv;

	unregister_connection (EXCHANGE_MAPI_CONNECTION (object));

	priv = EXCHANGE_MAPI_CONNECTION_GET_PRIVATE (object);

	if (priv) {
		LOCK ();
		disconnect (priv);
		g_free (priv->profile);
		priv->profile = NULL;

		if (priv->named_ids)
			g_hash_table_destroy (priv->named_ids);
		priv->named_ids = NULL;

		UNLOCK ();
		g_static_rec_mutex_free (&priv->session_lock);
	}

	if (G_OBJECT_CLASS (exchange_mapi_connection_parent_class)->finalize)
		G_OBJECT_CLASS (exchange_mapi_connection_parent_class)->finalize (object);
}

static void
exchange_mapi_connection_class_init (ExchangeMapiConnectionClass *klass)
{
	GObjectClass *object_class;

	g_type_class_add_private (klass, sizeof (ExchangeMapiConnectionPrivate));

	object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = exchange_mapi_connection_finalize;
}

static void
exchange_mapi_connection_init (ExchangeMapiConnection *conn)
{
	ExchangeMapiConnectionPrivate *priv;

	priv = EXCHANGE_MAPI_CONNECTION_GET_PRIVATE (conn);
	g_return_if_fail (priv != NULL);

	priv->session = NULL;
	priv->profile = NULL;
	priv->has_public_store = FALSE;
	priv->folders = NULL;

	priv->named_ids = g_hash_table_new_full (g_int64_hash, g_int64_equal, g_free, (GDestroyNotify) g_hash_table_destroy);

	register_connection (conn);
}

/* GObject foo - end */

/* tracking alive connections - begin  */

static GSList *known_connections = NULL;
G_LOCK_DEFINE_STATIC (known_connections);

static void
register_connection (ExchangeMapiConnection *conn)
{
	g_return_if_fail (conn != NULL);
	g_return_if_fail (EXCHANGE_IS_MAPI_CONNECTION (conn));

	G_LOCK (known_connections);
	/* append to prefer older connections when searching with exchange_mapi_connection_find() */
	known_connections = g_slist_append (known_connections, conn);
	G_UNLOCK (known_connections);
}

static void
unregister_connection (ExchangeMapiConnection *conn)
{
	g_return_if_fail (conn != NULL);
	g_return_if_fail (EXCHANGE_IS_MAPI_CONNECTION (conn));

	G_LOCK (known_connections);
	if (!g_slist_find (known_connections, conn)) {
		G_UNLOCK (known_connections);
		g_return_if_reached ();
	}

	known_connections = g_slist_remove (known_connections, conn);
	G_UNLOCK (known_connections);
}

/* Tries to find a connection associated with the 'profile'.
   If there are more, then the first created is returned.
   Note if it doesn't return NULL, then the returned pointer
   should be g_object_unref-ed, when done with it.
*/
ExchangeMapiConnection *
exchange_mapi_connection_find (const gchar *profile)
{
	GSList *l;
	ExchangeMapiConnection *res = NULL;

	g_return_val_if_fail (profile != NULL, NULL);

	G_LOCK (known_connections);
	for (l = known_connections; l != NULL && res == NULL; l = l->next) {
		ExchangeMapiConnection *conn = EXCHANGE_MAPI_CONNECTION (l->data);
		ExchangeMapiConnectionPrivate *priv = EXCHANGE_MAPI_CONNECTION_GET_PRIVATE (conn);

		if (priv && priv->profile && g_str_equal (profile, priv->profile))
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
#define STREAM_ACCESS_READ      0x0000
#define STREAM_ACCESS_WRITE     0x0001
#define STREAM_ACCESS_READWRITE 0x0002

#define CHECK_CORRECT_CONN_AND_GET_PRIV(_conn, _val)								\
	ExchangeMapiConnectionPrivate *priv;									\
														\
	e_return_val_mapi_error_if_fail (_conn != NULL, MAPI_E_INVALID_PARAMETER, _val);			\
	e_return_val_mapi_error_if_fail (EXCHANGE_IS_MAPI_CONNECTION (_conn), MAPI_E_INVALID_PARAMETER, _val);	\
														\
	priv = EXCHANGE_MAPI_CONNECTION_GET_PRIVATE (_conn);							\
	e_return_val_mapi_error_if_fail (priv != NULL, MAPI_E_INVALID_PARAMETER, _val);

/* Creates a new connection object and connects to a server as defined in 'profile' */
ExchangeMapiConnection *
exchange_mapi_connection_new (const gchar *profile, const gchar *password, GError **perror)
{
	ExchangeMapiConnection *conn;
	ExchangeMapiConnectionPrivate *priv;
	struct mapi_session *session;
	enum MAPISTATUS ms;

	e_return_val_mapi_error_if_fail (profile != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	session = mapi_profile_load (profile, password, perror);
	if (!session) {
		g_debug ("%s: %s: Login failed ", G_STRLOC, G_STRFUNC);
		return NULL;
	}

	conn = g_object_new (EXCHANGE_TYPE_MAPI_CONNECTION, NULL);
	priv = EXCHANGE_MAPI_CONNECTION_GET_PRIVATE (conn);
	e_return_val_mapi_error_if_fail (priv != NULL, MAPI_E_INVALID_PARAMETER, conn);

	LOCK ();
	mapi_object_init (&priv->msg_store);
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

	priv->profile = g_strdup (profile);
	priv->has_public_store = FALSE;
	UNLOCK ();

	g_debug ("%s: %s: Connected ", G_STRLOC, G_STRFUNC);

	return conn;
}

gboolean
exchange_mapi_connection_close (ExchangeMapiConnection *conn)
{
	gboolean res = FALSE;
	/* to have this used in the below macros */
	GError **perror = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	LOCK ();

	res = priv->session != NULL;
	disconnect (priv);

	UNLOCK ();

	return res;
}

gboolean
exchange_mapi_connection_reconnect (ExchangeMapiConnection *conn, const gchar *password, GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	e_return_val_mapi_error_if_fail (priv->profile != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();
	if (priv->session)
		exchange_mapi_connection_close (conn);

	priv->session = mapi_profile_load (priv->profile, password, perror);
	if (!priv->session) {
		g_debug ("%s: %s: Login failed ", G_STRLOC, G_STRFUNC);
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

	UNLOCK ();

	g_debug ("%s: %s: Connected ", G_STRLOC, G_STRFUNC);

	return priv->session != NULL;
}

gboolean
exchange_mapi_connection_connected (ExchangeMapiConnection *conn)
{
	/* to have this used in the below macros */
	GError **perror = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	return priv->session != NULL;
}

/* proptag should be already set for this stream */
static void
set_stream_value (ExchangeMAPIStream *stream, const uint32_t *cpid, const guint8 *buf_data, guint32 buf_len, gboolean converted)
{
	g_return_if_fail (stream != NULL);

	stream->value = NULL;

	if (!converted && stream->proptag == PR_HTML && ((cpid && (*cpid == 1200 || *cpid == 1201)) || (buf_len > 5 && buf_data[3] == '\0'))) {
		/* this is special, get the CPID and transform to utf8 when it's utf16 */
		gsize written = 0;
		gchar *in_utf8;

		in_utf8 = g_convert ((const gchar *) buf_data, buf_len, "UTF-8", "UTF-16", NULL, &written, NULL);
		if (in_utf8 && written > 0) {
			stream->value = g_byte_array_sized_new (written + 1);
			g_byte_array_append (stream->value, (const guint8 *) in_utf8, written);

			if (in_utf8[written] != '\0')
				g_byte_array_append (stream->value, (const guint8 *) "", 1);
		}
	}

	if (!stream->value) {
		stream->value = g_byte_array_sized_new (buf_len);
		g_byte_array_append (stream->value, buf_data, buf_len);
	}
}

/* returns whether found that property */
static gboolean
add_stream_from_properties (GSList **stream_list, struct mapi_SPropValue_array *properties, uint32_t proptag, const uint32_t *cpid)
{
	if (exchange_mapi_util_find_stream (*stream_list, proptag)) {
		return TRUE;
	} else if (properties) {
		gconstpointer data;

		data = exchange_mapi_util_find_array_propval (properties, proptag);
		if (data) {
			const struct SBinary_short *bin;
			const gchar *str;
			ExchangeMAPIStream *stream;

			switch (proptag & 0xFFFF) {
			case PT_BINARY:
				bin = data;
				if (bin->cb) {
					stream = g_new0 (ExchangeMAPIStream, 1);

					stream->proptag = proptag;
					set_stream_value (stream, cpid, bin->lpb, bin->cb, FALSE);

					*stream_list = g_slist_append (*stream_list, stream);
				}

				return TRUE;
			case PT_STRING8:
			case PT_UNICODE:
				str = data;
				stream = g_new0 (ExchangeMAPIStream, 1);

				stream->proptag = proptag;
				set_stream_value (stream, cpid, (const guint8 *) str, strlen (str) + 1, FALSE);

				*stream_list = g_slist_append (*stream_list, stream);

				return TRUE;
			}
		}
	}

	return FALSE;
}

static gboolean
exchange_mapi_util_read_generic_stream (mapi_object_t *obj_message, const uint32_t *cpid, uint32_t proptag, GSList **stream_list, struct mapi_SPropValue_array *properties, GError **perror)
{
	enum MAPISTATUS	ms;
	TALLOC_CTX	*mem_ctx;
	mapi_object_t	obj_stream;
	uint16_t	cn_read = 0, max_read;
	uint32_t	off_data = 0;
	uint8_t		*buf_data = NULL;
	uint32_t	buf_size = 0;
	gboolean	done = FALSE;

	/* sanity */
	e_return_val_mapi_error_if_fail (obj_message, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (((proptag & 0xFFFF) == PT_BINARY), MAPI_E_INVALID_PARAMETER, FALSE);

	/* if compressed RTF stream, then return */
	if (proptag == PR_RTF_COMPRESSED)
		return FALSE;

	if (add_stream_from_properties (stream_list, properties, proptag, cpid))
		return TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);
	g_debug("Attempt to read stream for proptag 0x%08X ", proptag);

	mem_ctx = talloc_init ("ExchangeMAPI_ReadGenericStream");
	mapi_object_init(&obj_stream);

	/* get a stream on specified proptag */
	ms = OpenStream(obj_message, proptag, STREAM_ACCESS_READ, &obj_stream);
	if (ms != MAPI_E_SUCCESS) {
	/* If OpenStream failed, should we attempt any other call(s) to fetch the blob? */
		make_mapi_error (perror, "OpenStream", ms);
		goto cleanup;
	}

	/* NOTE: This may prove unreliable for streams larger than 4GB length */
	ms = GetStreamSize(&obj_stream, &buf_size);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetStreamSize", ms);
		goto cleanup;
	}

	buf_data = talloc_size (mem_ctx, buf_size);
	if (!buf_data)
		goto cleanup;

	/* determine max_read first, to read by chunks as long as possible */
	max_read = buf_size > STREAM_MAX_READ_SIZE ? STREAM_MAX_READ_SIZE : buf_size;
	do {
		ms = ReadStream (&obj_stream, (buf_data) + off_data, max_read, &cn_read);
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

	/* Read from the stream */
	while (!done) {
		ms = ReadStream (&obj_stream, (buf_data) + off_data, max_read, &cn_read);
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

	if (ms == MAPI_E_SUCCESS) {
		ExchangeMAPIStream		*stream = g_new0 (ExchangeMAPIStream, 1);
		struct mapi_SPropValue_array	properties_array;

		/* Build a mapi_SPropValue_array structure */
		properties_array.cValues = 1;
		properties_array.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, properties_array.cValues + 1);
		properties_array.lpProps[0].ulPropTag = proptag;
		/* This call is needed in case the read stream was a named prop. */
		mapi_SPropValue_array_named (obj_message, &properties_array);

		stream->proptag = properties_array.lpProps[0].ulPropTag;
		set_stream_value (stream, cpid, buf_data, off_data, FALSE);

		g_debug("Attempt succeeded for proptag 0x%08X (after name conversion) ", stream->proptag);

		*stream_list = g_slist_append (*stream_list, stream);
	}

cleanup:
	mapi_object_release(&obj_stream);
	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return (ms == MAPI_E_SUCCESS);
}

static void
exchange_mapi_util_read_body_stream (mapi_object_t *obj_message, GSList **stream_list, struct mapi_SPropValue_array *properties, gboolean by_best_body)
{
	const uint32_t *cpid = exchange_mapi_util_find_array_propval (properties, PR_INTERNET_CPID);
	gboolean can_html = FALSE;

	if (!add_stream_from_properties (stream_list, properties, PR_BODY_UNICODE, cpid))
		add_stream_from_properties (stream_list, properties, PR_BODY, cpid);

	if (by_best_body) {
		uint8_t best_body = 0;

		can_html = GetBestBody (obj_message, &best_body) == MAPI_E_SUCCESS && best_body == olEditorHTML;
	} else {
		const uint32_t *ui32 = exchange_mapi_util_find_array_propval (properties, PR_MSG_EDITOR_FORMAT);
		can_html = ui32 && *ui32 == olEditorHTML;
	}

	if (can_html)
		exchange_mapi_util_read_generic_stream (obj_message, cpid, PR_HTML, stream_list, properties, NULL);
}

/* Returns TRUE if all streams were written succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_write_generic_streams (mapi_object_t *obj_message, GSList *stream_list, GError **perror)
{
	GSList		*l;
	enum MAPISTATUS	ms;
	gboolean	status = TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	for (l = stream_list; l; l = l->next) {
		ExchangeMAPIStream	*stream = (ExchangeMAPIStream *) (l->data);
		uint32_t		total_written;
		gboolean		done = FALSE;
		mapi_object_t		obj_stream;

		mapi_object_init(&obj_stream);

		/* OpenStream on required proptag */
		ms = OpenStream (obj_message, stream->proptag, STREAM_ACCESS_READWRITE, &obj_stream);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "OpenStream", ms);
			goto cleanup;
		}

		/* Set the stream size */
		ms = SetStreamSize (&obj_stream, stream->value->len);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SetStreamSize", ms);
			goto cleanup;
		}

		total_written = 0;
		/* Write attachment */
		while (!done) {
			uint16_t	cn_written = 0;
			DATA_BLOB	blob;

			blob.length = (stream->value->len - total_written) < STREAM_MAX_WRITE_SIZE ?
					(stream->value->len - total_written) : STREAM_MAX_WRITE_SIZE;
			blob.data = (stream->value->data) + total_written;

			ms = WriteStream (&obj_stream, &blob, &cn_written);

			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "WriteStream", ms);
				done = TRUE;
			} else if (cn_written == 0) {
				done = TRUE;
			} else {
				total_written += cn_written;
				if (total_written >= stream->value->len)
					done = TRUE;
			}
		}

		/* Commit the stream */
		ms = CommitStream (&obj_stream);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "CommitStream", ms);
			goto cleanup;
		}

	cleanup:
		if (ms != MAPI_E_SUCCESS)
			status = FALSE;
		mapi_object_release(&obj_stream);
	}

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

static gboolean
exchange_mapi_util_delete_attachments (mapi_object_t *obj_message, GError **perror)
{
	enum MAPISTATUS		ms;
	TALLOC_CTX		*mem_ctx;
	mapi_object_t		obj_tb_attach;
	struct SPropTagArray	*proptags;
	struct SRowSet		rows_attach;
	uint32_t		attach_count;
	uint32_t		i_row_attach;
	gboolean		status = TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	mem_ctx = talloc_init ("ExchangeMAPI_DeleteAttachments");

	proptags = set_SPropTagArray(mem_ctx, 0x4,
				     PR_ATTACH_NUM,
				     PR_INSTANCE_KEY,
				     PR_RECORD_KEY,
				     PR_RENDERING_POSITION);

	mapi_object_init(&obj_tb_attach);

	/* open attachment table */
	ms = GetAttachmentTable (obj_message, &obj_tb_attach);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetAttachmentTable", ms);
		goto cleanup;
	}

	ms = SetColumns (&obj_tb_attach, proptags);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	ms = QueryPosition (&obj_tb_attach, NULL, &attach_count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "QueryPosition", ms);
		goto cleanup;
	}

	ms = QueryRows (&obj_tb_attach, attach_count, TBL_ADVANCE, &rows_attach);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "QueryRows", ms);
		goto cleanup;
	}

	/* foreach attachment, delete by PR_ATTACH_NUM */
	for (i_row_attach = 0; i_row_attach < rows_attach.cRows; i_row_attach++) {
		const uint32_t	*num_attach;

		num_attach = (const uint32_t *) get_SPropValue_SRow_data(&rows_attach.aRow[i_row_attach], PR_ATTACH_NUM);

		ms = DeleteAttach (obj_message, *num_attach);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "DeleteAttach", ms);
			status = FALSE;
		}
	}

cleanup:
	if (ms != MAPI_E_SUCCESS)
		status = FALSE;
	mapi_object_release(&obj_tb_attach);
	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

/* Returns TRUE if all attachments were written succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_set_attachments (mapi_object_t *obj_message, GSList *attach_list, gboolean remove_existing, GError **perror)
{
//	TALLOC_CTX	*mem_ctx;
	GSList		*l;
	enum MAPISTATUS	ms;
	gboolean	status = FALSE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	if (remove_existing)
		exchange_mapi_util_delete_attachments (obj_message, NULL);

//	mem_ctx = talloc_init ("ExchangeMAPI_SetAttachments");

	for (l = attach_list; l; l = l->next) {
		ExchangeMAPIAttachment *attachment = (ExchangeMAPIAttachment *) (l->data);
		mapi_object_t		obj_attach;

		mapi_object_init(&obj_attach);

		/* CreateAttach */
		ms = CreateAttach (obj_message, &obj_attach);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "CreateAttach", ms);
			goto cleanup;
		}

		/* SetProps */
		ms = SetProps (&obj_attach, attachment->lpProps, attachment->cValues);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SetProps", ms);
			goto cleanup;
		}

		/* If there are any streams to be set, write them. */
		if (!exchange_mapi_util_write_generic_streams (&obj_attach, attachment->streams, perror))
			goto cleanup;

		/* message->SaveChangesAttachment() */
		ms = SaveChangesAttachment (obj_message, &obj_attach, KeepOpenReadWrite);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SaveChangesAttachment", ms);
			goto cleanup;
		}

		status = TRUE;

	cleanup:
		mapi_object_release(&obj_attach);
	}

//	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

static GByteArray *
obj_message_to_camel_mime (ExchangeMapiConnection *conn, mapi_id_t fid, mapi_object_t *obj_msg)
{
	GByteArray *res = NULL;
	MailItem *item = NULL;
	CamelMimeMessage *msg;

	g_return_val_if_fail (conn != NULL, NULL);
	g_return_val_if_fail (obj_msg != NULL, NULL);

	if (!exchange_mapi_connection_fetch_object_props (conn, NULL, fid, 0, obj_msg, mapi_mail_get_item_prop_list, NULL,
					fetch_props_to_mail_item_cb, &item,
					MAPI_OPTIONS_FETCH_ALL | MAPI_OPTIONS_GETBESTBODY, NULL)
	    || item == NULL) {
		if (item)
			mail_item_free (item);

		return NULL;
	}

	msg = mapi_mail_item_to_mime_message (conn, item);
	mail_item_free (item);

	if (msg) {
		CamelStream *mem = camel_stream_mem_new ();

		res = g_byte_array_new ();

		mem = camel_stream_mem_new ();
		camel_stream_mem_set_byte_array (CAMEL_STREAM_MEM (mem), res);
		camel_data_wrapper_write_to_stream (CAMEL_DATA_WRAPPER (msg), mem, NULL);

		g_object_unref (mem);
		g_object_unref (msg);
	}

	return res;
}

/* Returns TRUE if all attachments were read succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_get_attachments (ExchangeMapiConnection *conn, mapi_id_t fid, mapi_object_t *obj_message, GSList **attach_list, GError **perror)
{
	enum MAPISTATUS		ms;
	TALLOC_CTX		*mem_ctx;
	mapi_object_t		obj_tb_attach;
	struct SPropTagArray	*proptags;
	struct SRowSet		rows_attach;
	uint32_t		attach_count;
	uint32_t		i_row_attach;
	gboolean		status = TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	mem_ctx = talloc_init ("ExchangeMAPI_GetAttachments");

	proptags = set_SPropTagArray(mem_ctx, 0x5,
				     PR_ATTACH_NUM,
				     PR_INSTANCE_KEY,
				     PR_RECORD_KEY,
				     PR_RENDERING_POSITION,
				     PR_ATTACH_METHOD);

	mapi_object_init(&obj_tb_attach);

	/* open attachment table */
	ms = GetAttachmentTable (obj_message, &obj_tb_attach);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetAttachmentTable", ms);
		goto cleanup;
	}

	ms = SetColumns (&obj_tb_attach, proptags);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	ms = QueryPosition (&obj_tb_attach, NULL, &attach_count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "QueryPosition", ms);
		goto cleanup;
	}

	ms = QueryRows (&obj_tb_attach, attach_count, TBL_ADVANCE, &rows_attach);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "QueryRows", ms);
		goto cleanup;
	}

	/* foreach attachment, open by PR_ATTACH_NUM */
	for (i_row_attach = 0; i_row_attach < rows_attach.cRows; i_row_attach++) {
		ExchangeMAPIAttachment	*attachment;
		struct mapi_SPropValue_array properties;
		const uint32_t	*ui32;
		mapi_object_t	obj_attach;
		uint32_t	z;

		mapi_object_init(&obj_attach);

		ui32 = (const uint32_t *) get_SPropValue_SRow_data(&rows_attach.aRow[i_row_attach], PR_ATTACH_NUM);

		ms = OpenAttach (obj_message, *ui32, &obj_attach);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "OpenAttach", ms);
			goto loop_cleanup;
		}

		ms = GetPropsAll (&obj_attach, &properties);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "GetPropsAll", ms);
			goto loop_cleanup;
		}

		attachment = g_new0 (ExchangeMAPIAttachment, 1);
		attachment->cValues = properties.cValues;
		attachment->lpProps = g_new0 (struct SPropValue, attachment->cValues + 1);
		for (z=0; z < properties.cValues; z++) {
			cast_SPropValue (
				#ifdef HAVE_MEMCTX_ON_CAST_SPROPVALUE
				mem_ctx,
				#endif
				&properties.lpProps[z], &(attachment->lpProps[z]));

			if ((attachment->lpProps[z].ulPropTag & 0xFFFF) == PT_STRING8) {
				struct SPropValue *lpProps;
				struct SPropTagArray *tags;
				uint32_t prop_count = 0;

				/* prefer unicode strings, if available */
				tags = set_SPropTagArray (mem_ctx, 0x1, (attachment->lpProps[z].ulPropTag & 0xFFFF0000) | PT_UNICODE);
				if (MAPI_E_SUCCESS == GetProps (&obj_attach, tags, &lpProps, &prop_count) && prop_count == 1 && lpProps) {
					if ((lpProps->ulPropTag & 0xFFFF) == PT_UNICODE)
						attachment->lpProps[z] = *lpProps;
				}
				MAPIFreeBuffer (tags);
			}
		}

		/* just to get all the other streams */
		for (z = 0; z < properties.cValues; z++) {
			if ((properties.lpProps[z].ulPropTag & 0xFFFF) == PT_BINARY) {
				exchange_mapi_util_read_generic_stream (&obj_attach, exchange_mapi_util_find_array_propval (&properties, PR_INTERNET_CPID), properties.lpProps[z].ulPropTag, &(attachment->streams), &properties, NULL);
			}
		}

		ui32 = (const uint32_t *) get_SPropValue_SRow_data(&rows_attach.aRow[i_row_attach], PR_ATTACH_METHOD);
		if (ui32 && *ui32 == ATTACH_BY_VALUE) {
			exchange_mapi_util_read_generic_stream (&obj_attach, exchange_mapi_util_find_array_propval (&properties, PR_INTERNET_CPID), PR_ATTACH_DATA_BIN, &(attachment->streams), &properties, NULL);
		} else if (ui32 && *ui32 == ATTACH_EMBEDDED_MSG) {
			mapi_object_t obj_emb_msg;

			mapi_object_init (&obj_emb_msg);

			if (OpenEmbeddedMessage (&obj_attach, &obj_emb_msg, MAPI_READONLY) == MAPI_E_SUCCESS) {
				/* very the same is in camel-mapi-folder.c, how I hate diplicating the code */
				GByteArray *bytes;

				bytes = obj_message_to_camel_mime (conn, fid, &obj_emb_msg);
				if (bytes) {
					ExchangeMAPIStream *stream = g_new0 (ExchangeMAPIStream, 1);

					stream->value = bytes;
					stream->proptag = PR_ATTACH_DATA_BIN;

					attachment->streams = g_slist_append (attachment->streams, stream);
				}
			}

			mapi_object_release (&obj_emb_msg);
		}

		*attach_list = g_slist_append (*attach_list, attachment);

	loop_cleanup:
		if (ms != MAPI_E_SUCCESS)
			status = FALSE;
		mapi_object_release(&obj_attach);
	}

cleanup:
	if (ms != MAPI_E_SUCCESS)
		status = FALSE;
	mapi_object_release(&obj_tb_attach);
	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

gboolean
exchange_mapi_connection_fetch_gal (ExchangeMapiConnection *conn, struct mapi_SRestriction *restrictions, BuildReadPropsCB build_props, gpointer brp_data, FetchGALCallback cb, gpointer data, GError **perror)
{
	struct SPropTagArray	*propsTagArray;
	struct SRowSet		*aRowSet;
	enum MAPISTATUS		ms;
	uint32_t		i, count, n_rows = 0;
	uint8_t			ulFlags;
	TALLOC_CTX *mem_ctx;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (build_props != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (cb != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mem_ctx = talloc_init ("ExchangeMAPI_FetchGAL");

	LOCK ();

	#ifdef HAVE_GETGALTABLECOUNT
	ms = GetGALTableCount (priv->session, &n_rows);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetGALTableCount", ms);
		n_rows = 0;
	}
	#endif

	propsTagArray = set_SPropTagArray (mem_ctx, 0x1, PR_MESSAGE_CLASS);
	if (!build_props (conn, 0, mem_ctx, propsTagArray, brp_data)) {
		make_mapi_error (perror, "build_props", MAPI_E_CALL_FAILED);
		UNLOCK();
		talloc_free (mem_ctx);
		return FALSE;
	}

	ms = MAPI_E_SUCCESS;
	count = 0;
	ulFlags = TABLE_START;
	while (ms == MAPI_E_SUCCESS) {
		aRowSet = NULL;
		/* fetch per 100 items */
		ms = GetGALTable (priv->session, propsTagArray, &aRowSet, 100, ulFlags);
		if ((!aRowSet) || (!(aRowSet->aRow)) || ms != MAPI_E_SUCCESS) {
			break;
		}
		if (aRowSet->cRows) {
			for (i = 0; i < aRowSet->cRows; i++, count++) {
				if (!cb (conn, count, n_rows, &aRowSet->aRow[i], data)) {
					ms = MAPI_E_RESERVED;
					break;
				}
			}
		} else {
			MAPIFreeBuffer (aRowSet);
			break;
		}

		ulFlags = TABLE_CUR;
		MAPIFreeBuffer (aRowSet);
	}

	talloc_free (mem_ctx);

	UNLOCK ();

	if (ms != MAPI_E_SUCCESS && ms != MAPI_E_RESERVED)
		make_mapi_error (perror, "GetGALTable", ms);

	return ms == MAPI_E_SUCCESS;
}

gboolean
exchange_mapi_connection_get_public_folder (ExchangeMapiConnection *conn, mapi_object_t *obj_store, GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();

	mapi_object_init (&priv->public_store);

	ms = OpenPublicFolder (priv->session, &priv->public_store);

	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenPublicFolder", ms);
	}

	*obj_store = priv->public_store;
	UNLOCK ();

	return ms == MAPI_E_SUCCESS;
}

/* Returns TRUE if all recipients were read succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_get_recipients (mapi_object_t *obj_message, GSList **recip_list, GError **perror)
{
	enum MAPISTATUS		ms;
	struct SPropTagArray	proptags;
	struct SRowSet		rows_recip;
	uint32_t		i_row_recip;
	gboolean		status = TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	/* fetch recipient table */
	ms = GetRecipientTable (obj_message, &rows_recip, &proptags);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetRecipientTable", ms);
		goto cleanup;
	}

	for (i_row_recip = 0; i_row_recip < rows_recip.cRows; i_row_recip++) {
		ExchangeMAPIRecipient	*recipient = g_new0 (ExchangeMAPIRecipient, 1);

		recipient->mem_ctx = talloc_init ("ExchangeMAPI_GetRecipients");

		recipient->email_id = talloc_steal (recipient->mem_ctx, (const gchar *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_SMTP_ADDRESS_UNICODE));
		/* fallback */
		if (!recipient->email_id) {
			const gchar *addrtype = talloc_steal (recipient->mem_ctx, (const gchar *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_ADDRTYPE_UNICODE));
			if (addrtype && !g_ascii_strcasecmp(addrtype, "SMTP"))
				recipient->email_id = talloc_steal (recipient->mem_ctx, (const gchar *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_EMAIL_ADDRESS_UNICODE));
		}

		recipient->out_SRow.ulAdrEntryPad = rows_recip.aRow[i_row_recip].ulAdrEntryPad;
		recipient->out_SRow.cValues = rows_recip.aRow[i_row_recip].cValues;
		recipient->out_SRow.lpProps = talloc_steal ((TALLOC_CTX *)recipient->mem_ctx, rows_recip.aRow[i_row_recip].lpProps);

		*recip_list = g_slist_append (*recip_list, recipient);
	}

cleanup:
	if (ms != MAPI_E_SUCCESS)
		status = FALSE;

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

static void
set_recipient_properties (TALLOC_CTX *mem_ctx, struct SRow *aRow, ExchangeMAPIRecipient *recipient, gboolean is_external)
{
	uint32_t i;

	if (is_external && recipient->in.ext_lpProps) {
	/* FIXME: Setting PR_ENTRYID property seems to create problems for now. We should take
	 * another look at this after the CreateOneoffEntryId API is provided by LibMAPI. */
#if 0
		struct Binary_r oneoff_eid;
		struct SPropValue sprop;
		const gchar *dn = NULL, *email = NULL;

		dn = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (recipient->in.ext_lpProps, PR_DISPLAY_NAME_UNICODE);
		dn = (dn) ? dn : "";
		email = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (recipient->in.ext_lpProps, PR_SMTP_ADDRESS_UNICODE);
		email = (email) ? email : "";
		exchange_mapi_util_entryid_generate_oneoff (mem_ctx, &oneoff_eid, dn, email);
		set_SPropValue_proptag (&sprop, PR_ENTRYID, (gconstpointer )(oneoff_eid));
		SRow_addprop (aRow, sprop);
#endif

	/* Now, add the properties which are specified for unresolved recipients alone. */
		for (i = 0; i < recipient->in.ext_cValues; ++i)
			SRow_addprop (aRow, recipient->in.ext_lpProps[i]);
	}

	/* Now, add the properties which are specified for each recipient
	 * irrespective of whether it was resolved or not. */
	for (i = 0; i < recipient->in.req_cValues; ++i)
		SRow_addprop (aRow, recipient->in.req_lpProps[i]);
}

static gboolean
exchange_mapi_util_modify_recipients (ExchangeMapiConnection *conn, TALLOC_CTX *mem_ctx, mapi_object_t *obj_message , GSList *recipients, gboolean remove_existing, GError **perror)
{
	enum MAPISTATUS	ms;
	struct SPropTagArray	*SPropTagArray = NULL;
	struct SRowSet		*SRowSet = NULL;
	struct SPropTagArray	*FlagList = NULL;
	GSList			*l;
	const gchar		**users = NULL;
	uint32_t		i, j, count = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	SPropTagArray = set_SPropTagArray(mem_ctx, 0xA,
					  PR_ENTRYID,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_OBJECT_TYPE,
					  PR_DISPLAY_TYPE,
					  PR_TRANSMITTABLE_DISPLAY_NAME_UNICODE,
					  PR_EMAIL_ADDRESS_UNICODE,
					  PR_ADDRTYPE_UNICODE,
					  PR_SEND_RICH_INFO,
					  PR_7BIT_DISPLAY_NAME_UNICODE,
					  PR_SMTP_ADDRESS_UNICODE);

	count = g_slist_length (recipients);
	users = g_new0 (const gchar *, count + 1);

	for (i = 0, l = recipients; (i < count && l != NULL); ++i, l = l->next) {
		ExchangeMAPIRecipient *recipient = (ExchangeMAPIRecipient *)(l->data);
		users[i] = recipient->email_id;
	}

	/* Attempt to resolve names from the server */
	LOCK ();
	ms = ResolveNames (priv->session, users, SPropTagArray, &SRowSet, &FlagList, MAPI_UNICODE);
	UNLOCK ();
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "ResolveNames", ms);
		goto cleanup;
	}

	g_assert (count == FlagList->cValues);

	if (!SRowSet) /* This happens when there are ZERO RESOLVED recipients */
		SRowSet = talloc_zero(mem_ctx, struct SRowSet);

	for (i = 0, l = recipients, j = 0; (i < count && l != NULL); ++i, l = l->next) {
		ExchangeMAPIRecipient *recipient = (ExchangeMAPIRecipient *)(l->data);
		uint32_t last;

		if (FlagList->aulPropTag[i] == MAPI_AMBIGUOUS) {
			/* We should never get an ambiguous resolution as we use the email-id for resolving.
			 * However, if we do still get an ambiguous entry, we can't handle it :-( */
			g_debug ("%s: %s() - '%s' is ambiguous ", G_STRLOC, G_STRFUNC, recipient->email_id);
		} else if (FlagList->aulPropTag[i] == MAPI_UNRESOLVED) {
			/* If the recipient is unresolved, consider it is a SMTP one */
			SRowSet->aRow = talloc_realloc(mem_ctx, SRowSet->aRow, struct SRow, SRowSet->cRows + 1);
			last = SRowSet->cRows;
			SRowSet->aRow[last].cValues = 0;
			SRowSet->aRow[last].lpProps = talloc_zero(mem_ctx, struct SPropValue);
			set_recipient_properties(mem_ctx, &SRowSet->aRow[last], recipient, TRUE);
			SRowSet->cRows += 1;
		} else if (FlagList->aulPropTag[i] == MAPI_RESOLVED) {
			set_recipient_properties (mem_ctx, &SRowSet->aRow[j], recipient, FALSE);
			j += 1;
		}
	}

	if (remove_existing) {
		ms = RemoveAllRecipients (obj_message);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "RemoveAllRecipients", ms);
			goto cleanup;
		}
	}

	/* Modify the recipient table */
	ms = ModifyRecipients (obj_message, SRowSet);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "ModifyRecpients", ms);
		goto cleanup;
	}

cleanup:
	g_free (users);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return TRUE;
}

static enum MAPISTATUS
open_folder (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t *fid, guint32 fid_options, mapi_object_t *obj_folder, GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (obj_folder != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (fid != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);

	if (*fid == 0) {
		ms = GetDefaultFolder (&priv->msg_store, fid, olFolder);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "GetDefaultFolder", ms);
			return ms;
		}

		fid_options = 0;
	}

	if ((fid_options & MAPI_OPTIONS_USE_PFSTORE) != 0) {
		if (!ensure_public_store (priv, perror)) {
			return MAPI_E_CALL_FAILED;
		}
	}

	ms = OpenFolder (((fid_options & MAPI_OPTIONS_USE_PFSTORE) != 0 ? &priv->public_store : &priv->msg_store), *fid, obj_folder);
	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "OpenFolder", ms);

	return ms;
}

GSList *
exchange_mapi_connection_check_restriction (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, struct mapi_SRestriction *res, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_table;
	struct SPropTagArray *SPropTagArray, *GetPropsTagArray;
	struct SRowSet SRowSet;
	uint32_t count, i;
	GSList *mids = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, NULL);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	g_debug("%s: Entering %s: folder-id %016" G_GINT64_MODIFIER "X ", G_STRLOC, G_STRFUNC, fid);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_CheckRestriction");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	/* Attempt to open the folder */
	ms = open_folder (conn, 0, &fid, fid_options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Get a handle on the container */
	ms = GetContentsTable (&obj_folder, &obj_table, 0, NULL);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetContentsTable", ms);
		goto cleanup;
	}

	GetPropsTagArray = talloc_zero(mem_ctx, struct SPropTagArray);
	GetPropsTagArray->cValues = 0;

	// FIXME : Why are we fetching all these props ?

	SPropTagArray = set_SPropTagArray(mem_ctx, 0xA,
					  PR_FID,
					  PR_MID,
					  PR_INST_ID,
					  PR_INSTANCE_NUM,
					  PR_SUBJECT_UNICODE,
					  PR_MESSAGE_CLASS,
					  PR_LAST_MODIFICATION_TIME,
					  PR_HASATTACH,
					  PR_RULE_MSG_PROVIDER,
					  PR_RULE_MSG_NAME);

	/* Set primary columns to be fetched */
	ms = SetColumns (&obj_table, SPropTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	if (res) {
		/* Applying any restriction that are set. */
		ms = Restrict (&obj_table, res, NULL);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "Restrict", ms);
			goto cleanup;
		}
	}

	/* Number of items in the container */
	ms = QueryPosition (&obj_table, NULL, &count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetRowCount", ms);
		goto cleanup;
	}

	/* Fill the table columns with data from the rows */
	ms = QueryRows (&obj_table, count, TBL_ADVANCE, &SRowSet);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "QueryRows", ms);
		goto cleanup;
	}

	for (i = 0; i < SRowSet.cRows; i++) {
		mapi_id_t *pmid = (mapi_id_t *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_MID);
		struct id_list *id_list = g_new0 (struct id_list, 1);
		id_list->id = *pmid;
		mids = g_slist_prepend (mids, id_list);
	}

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_table);
	talloc_free (mem_ctx);
	UNLOCK();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return mids;
}

gboolean
exchange_mapi_connection_fetch_items   (ExchangeMapiConnection *conn, mapi_id_t fid,
					struct mapi_SRestriction *res, struct SSortOrderSet *sort_order,
					BuildReadPropsCB build_props, gpointer brp_data,
					FetchCallback cb, gpointer data,
					guint32 options, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_table;
	struct SPropTagArray *SPropTagArray, *propsTagArray = NULL;
	struct SRowSet SRowSet;
	uint32_t count, i, cursor_pos = 0;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s: folder-id %016" G_GINT64_MODIFIER "X ", G_STRLOC, G_STRFUNC, fid);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_FetchItems");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	/* Attempt to open the folder */
	ms = open_folder (conn, 0, &fid, options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Get a handle on the container */
	ms = GetContentsTable (&obj_folder, &obj_table, TableFlags_UseUnicode, NULL);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetContentsTable", ms);
		goto cleanup;
	}

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x5,
					  PR_FID,
					  PR_MID,
					  PR_LAST_MODIFICATION_TIME,
					  PR_HASATTACH,
					  PR_MESSAGE_FLAGS);

	/* Set primary columns to be fetched */
	ms = SetColumns (&obj_table, SPropTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		goto cleanup;
	}

	if (res) {
		/* Applying any restriction that are set. */
		ms = Restrict (&obj_table, res, NULL);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "Restrict", ms);
			goto cleanup;
		}
	}

	if (sort_order) {
		ms = SortTable (&obj_table, sort_order);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SortTable", ms);
			goto cleanup;
		}
	}

	if (build_props) {
		propsTagArray = set_SPropTagArray (mem_ctx, 0x1, PR_MESSAGE_CLASS);
		if (!build_props (conn, fid, mem_ctx, propsTagArray, brp_data)) {
			make_mapi_error (perror, "build_props", MAPI_E_CALL_FAILED);
			goto cleanup;
		}
	}

	/* Note : We maintain a cursor position. count parameter in QueryRows */
	/* is more of a request and not gauranteed  */
	do {
		/* Number of items in the container */
		ms = QueryPosition (&obj_table, &cursor_pos, &count);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "QueryPosition", ms);
			goto cleanup;
		}

		/* Fill the table columns with data from the rows */
		ms = QueryRows (&obj_table, count, TBL_ADVANCE, &SRowSet);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "QueryRows", ms);
			goto cleanup;
		}

		for (i = 0; i < SRowSet.cRows; i++) {
			mapi_object_t obj_message;
			struct mapi_SPropValue_array properties_array = {0};
			const mapi_id_t *pfid;
			const mapi_id_t	*pmid;
			const bool *has_attach = NULL;
			const uint32_t *msg_flags;
			GSList *attach_list = NULL;
			GSList *recip_list = NULL;
			GSList *stream_list = NULL;
			gboolean cb_retval = false;

			mapi_object_init(&obj_message);

			pfid = (const uint64_t *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_FID);
			pmid = (const uint64_t *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_MID);

			has_attach = (const bool *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_HASATTACH);
			msg_flags = get_SPropValue_SRow_data (&SRowSet.aRow[i], PR_MESSAGE_FLAGS);

			if (options & MAPI_OPTIONS_DONT_OPEN_MESSAGE)
				goto relax;

			ms = OpenMessage (&obj_folder, *pfid, *pmid, &obj_message, 0);
			if (ms != MAPI_E_SUCCESS) {
				make_mapi_error (perror, "OpenMessage", ms);
				goto loop_cleanup;
			}

			if (propsTagArray && propsTagArray->cValues) {
				struct SPropValue *lpProps;
				struct SPropTagArray *tags;
				uint32_t prop_count = 0, k;
				/* we need to make a local copy of the tag array
				 * since GetProps will modify the array on any
				 * errors */
				tags = set_SPropTagArray (mem_ctx, 0x1, PR_MSG_EDITOR_FORMAT);
				for (k = 0; k < propsTagArray->cValues; k++)
					SPropTagArray_add (mem_ctx, tags, propsTagArray->aulPropTag[k]);

				ms = GetProps (&obj_message, tags, &lpProps, &prop_count);
				if (ms != MAPI_E_SUCCESS)
					make_mapi_error (perror, "GetProps", ms);

				MAPIFreeBuffer (tags);
				properties_array.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue,
									 prop_count + 1);
				properties_array.cValues = prop_count;
				for (k = 0; k < prop_count; k++) {
					if ((lpProps[k].ulPropTag & 0xFFFF) == PT_MV_BINARY) {
						uint32_t ci;

						properties_array.lpProps[k].ulPropTag = lpProps[k].ulPropTag;
						properties_array.lpProps[k].value.MVbin.cValues = lpProps[k].value.MVbin.cValues;
						properties_array.lpProps[k].value.MVbin.bin = (struct SBinary_short *) talloc_array (mem_ctx, struct Binary_r, properties_array.lpProps[k].value.MVbin.cValues);
						for (ci = 0; ci < properties_array.lpProps[k].value.MVbin.cValues; ci++) {
							properties_array.lpProps[k].value.MVbin.bin[ci].cb = lpProps[k].value.MVbin.lpbin[ci].cb;
							properties_array.lpProps[k].value.MVbin.bin[ci].lpb = lpProps[k].value.MVbin.lpbin[ci].lpb;
						}
					} else {
						cast_mapi_SPropValue (
							#ifdef HAVE_MEMCTX_ON_CAST_MAPI_SPROPVALUE
							mem_ctx,
							#endif
							&properties_array.lpProps[k], &lpProps[k]);
					}
				}
			} else {
				ms = GetPropsAll (&obj_message, &properties_array);
				if (ms != MAPI_E_SUCCESS)
					make_mapi_error (perror, "GetPropsAll", ms);
			}

			if (has_attach && *has_attach && (MAPI_OPTIONS_FETCH_ATTACHMENTS & options)) {
				exchange_mapi_util_get_attachments (conn, fid, &obj_message, &attach_list, NULL);
			}

			if (options & MAPI_OPTIONS_FETCH_RECIPIENTS) {
				exchange_mapi_util_get_recipients (&obj_message, &recip_list, perror);
			}

			/* get the main body stream no matter what */
			if (options & MAPI_OPTIONS_FETCH_BODY_STREAM) {
				exchange_mapi_util_read_body_stream (&obj_message, &stream_list, &properties_array, (options & MAPI_OPTIONS_GETBESTBODY) != 0);
			}

 relax:
			if (ms == MAPI_E_SUCCESS) {
				FetchItemsCallbackData *item_data;

				if ((options & MAPI_OPTIONS_DONT_OPEN_MESSAGE) == 0) {
					if ((options & MAPI_OPTIONS_FETCH_GENERIC_STREAMS) != 0) {
						uint32_t z;
						const uint32_t *cpid = exchange_mapi_util_find_array_propval (&properties_array, PR_INTERNET_CPID);

						/* just to get all the other streams */
						for (z = 0; z < properties_array.cValues; z++) {
							if ((properties_array.lpProps[z].ulPropTag & 0xFFFF) == PT_BINARY)
								exchange_mapi_util_read_generic_stream (&obj_message, cpid, properties_array.lpProps[z].ulPropTag, &stream_list, &properties_array, NULL);
						}
					}

					mapi_SPropValue_array_named(&obj_message, &properties_array);
				}

				/* NOTE: stream_list, recipient_list and attach_list
				   should be freed by the callback */
				item_data = g_new0 (FetchItemsCallbackData, 1);
				item_data->conn = conn;
				item_data->fid = *pfid;
				item_data->mid = *pmid;
				item_data->msg_flags = msg_flags ? *msg_flags : 0;
				item_data->properties = &properties_array;
				item_data->streams = stream_list;
				item_data->recipients = recip_list;
				item_data->attachments = attach_list;
				item_data->total = count; //Total entries in the table.
				item_data->index = cursor_pos + i; //cursor_pos + current_table_index

				cb_retval = cb (item_data, data);

				g_free (item_data);
			} else {
				exchange_mapi_util_free_stream_list (&stream_list);
				exchange_mapi_util_free_recipient_list (&recip_list);
				exchange_mapi_util_free_attachment_list (&attach_list);
			}

			if (propsTagArray && propsTagArray->cValues)
				talloc_free (properties_array.lpProps);

		loop_cleanup:
			if ((options & MAPI_OPTIONS_DONT_OPEN_MESSAGE) == 0)
				mapi_object_release (&obj_message);

			if (!cb_retval) break;
		}

	} while (cursor_pos < count && ms == MAPI_E_SUCCESS);

	result = ms == MAPI_E_SUCCESS;

 cleanup:
	if (propsTagArray)
		MAPIFreeBuffer (propsTagArray);
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_table);
	talloc_free (mem_ctx);
	UNLOCK ();

	g_debug("%s: Leaving %s: folder-id %016" G_GINT64_MODIFIER "X ", G_STRLOC, G_STRFUNC, fid);

	return result;
}

/* obj_folder and obj_message are released only when obj_folder is not NULL and when returned TRUE */
gboolean
exchange_mapi_connection_fetch_object_props (ExchangeMapiConnection *conn, mapi_object_t *obj_folder, mapi_id_t fid, mapi_id_t mid, mapi_object_t *obj_message,
				     BuildReadPropsCB build_props, gpointer brp_data,
				     FetchCallback cb, gpointer data,
				     guint32 options, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	struct mapi_SPropValue_array properties_array;
	struct SPropTagArray *propsTagArray = NULL;
	GSList *attach_list = NULL;
	GSList *recip_list = NULL;
	GSList *stream_list = NULL;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s: folder %p message %p", G_STRLOC, G_STRFUNC, obj_folder, obj_message);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_FetchObjectProps");

	if (build_props) {
		propsTagArray = set_SPropTagArray (mem_ctx, 0x3,
			PR_MESSAGE_CLASS,
			PR_HASATTACH,
			PR_MSG_EDITOR_FORMAT);

		if (!build_props (conn, fid, mem_ctx, propsTagArray, brp_data)) {
			make_mapi_error (perror, "build_props", MAPI_E_CALL_FAILED);
			goto cleanup;
		}
	}

	if (propsTagArray && propsTagArray->cValues) {
		struct SPropValue *lpProps;
		uint32_t prop_count = 0, k;

		lpProps = talloc_zero(mem_ctx, struct SPropValue);

		ms = GetProps (obj_message, propsTagArray, &lpProps, &prop_count);
		if (ms != MAPI_E_SUCCESS)
			make_mapi_error (perror, "GetProps", ms);

		/* Conversion from SPropValue to mapi_SPropValue. (no padding here) */
		properties_array.cValues = prop_count;
		properties_array.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, prop_count + 1);
		for (k=0; k < prop_count; k++)
			cast_mapi_SPropValue (
				#ifdef HAVE_MEMCTX_ON_CAST_MAPI_SPROPVALUE
				mem_ctx,
				#endif
				&properties_array.lpProps[k], &lpProps[k]);
	} else {
		ms = GetPropsAll (obj_message, &properties_array);
		if (ms != MAPI_E_SUCCESS)
			make_mapi_error (perror, "GetPropsAll", ms);
	}

	/* Fetch attachments */
	if (options & MAPI_OPTIONS_FETCH_ATTACHMENTS) {
		const bool *has_attach = exchange_mapi_util_find_array_propval (&properties_array, PR_HASATTACH);

		if (has_attach && *has_attach)
			exchange_mapi_util_get_attachments (conn, fid, obj_message, &attach_list, NULL);
	}

	/* Fetch recipients */
	if (options & MAPI_OPTIONS_FETCH_RECIPIENTS) {
		exchange_mapi_util_get_recipients (obj_message, &recip_list, NULL);
	}

	/* get the main body stream no matter what */
	if (options & MAPI_OPTIONS_FETCH_BODY_STREAM) {
		exchange_mapi_util_read_body_stream (obj_message, &stream_list, &properties_array, (options & MAPI_OPTIONS_GETBESTBODY) != 0);
	}

	if (ms == MAPI_E_SUCCESS) {
		if ((options & MAPI_OPTIONS_FETCH_GENERIC_STREAMS)) {
			uint32_t z;

			/* just to get all the other streams */
			for (z = 0; z < properties_array.cValues; z++) {
				if ((properties_array.lpProps[z].ulPropTag & 0xFFFF) == PT_BINARY) {
					exchange_mapi_util_read_generic_stream (obj_message, exchange_mapi_util_find_array_propval (&properties_array, PR_INTERNET_CPID), properties_array.lpProps[z].ulPropTag, &stream_list, &properties_array, NULL);
				}
			}
		}

		mapi_SPropValue_array_named (obj_message, &properties_array);
	}

	/* Release the objects so that the callback may use the store. */
	if (obj_folder) {
		/* obj_folder is not NULL, thus can do this */
		mapi_object_release (obj_message);
		mapi_object_release (obj_folder);
	}

	if (ms == MAPI_E_SUCCESS) {
		FetchItemsCallbackData *item_data = g_new0 (FetchItemsCallbackData, 1);
		item_data->conn = conn;
		item_data->fid = fid;
		item_data->mid = mid;
		item_data->properties = &properties_array;
		item_data->streams = stream_list;
		item_data->recipients = recip_list;
		item_data->attachments = attach_list;

		/* NOTE: stream_list, recipient_list and attach_list should be freed by the callback */
		cb (item_data, data);

		g_free (item_data);
	} else {
		exchange_mapi_util_free_stream_list (&stream_list);
		exchange_mapi_util_free_recipient_list (&recip_list);
		exchange_mapi_util_free_attachment_list (&attach_list);
	}

	result = ms == MAPI_E_SUCCESS;

cleanup:
	talloc_free (mem_ctx);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_fetch_item (ExchangeMapiConnection *conn, mapi_id_t fid, mapi_id_t mid,
				     BuildReadPropsCB build_props, gpointer brp_data,
				     FetchCallback cb, gpointer data,
				     guint32 options, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s: folder-id %016" G_GINT64_MODIFIER "X message-id %016" G_GINT64_MODIFIER "X",
				G_STRLOC, G_STRFUNC, fid, mid);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_FetchItem");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	/* Attempt to open the folder */
	ms = open_folder (conn, 0, &fid, options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}
	/* Open the item */
	ms = OpenMessage (&obj_folder, fid, mid, &obj_message, 0x0);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenMessage", ms);
		goto cleanup;
	}

	result = exchange_mapi_connection_fetch_object_props (conn, &obj_folder, fid, mid, &obj_message, build_props, brp_data, cb, data, options, perror);

cleanup:
	if (!result) {
		mapi_object_release (&obj_message);
		mapi_object_release (&obj_folder);
	}
	talloc_free (mem_ctx);
	UNLOCK ();

	g_debug ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

mapi_id_t
exchange_mapi_connection_create_folder (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t pfid, guint32 fid_options, const gchar *name, GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_folder;
	mapi_object_t obj_top;
	struct SPropValue vals[1];
	const gchar *type;
	mapi_id_t fid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, 0);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, 0);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mapi_object_init(&obj_top);
	mapi_object_init(&obj_folder);

	/* We now open the top/parent folder */
	ms = open_folder (conn, olFolder, &pfid, fid_options, &obj_top, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Attempt to create the folder */
	ms = CreateFolder (&obj_top, FOLDER_GENERIC, name, "Created using Evolution/LibMAPI", OPEN_IF_EXISTS, &obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "CreateFolder", ms);
		goto cleanup;
	}

	switch (olFolder) {
		case olFolderInbox:
			type = IPF_NOTE;
			break;
		case olFolderCalendar:
			type = IPF_APPOINTMENT;
			break;
		case olFolderContacts:
			type = IPF_CONTACT;
			break;
		case olFolderTasks:
			type = IPF_TASK;
			break;
		case olFolderNotes:
			type = IPF_STICKYNOTE;
			break;
		default:
			type = IPF_NOTE;
	}

	vals[0].value.lpszA = type;
	vals[0].ulPropTag = PR_CONTAINER_CLASS;

	ms = SetProps (&obj_folder, vals, 1);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetProps", ms);
		goto cleanup;
	}

	fid = mapi_object_get_id (&obj_folder);
	g_debug("Folder %s created with id %016" G_GINT64_MODIFIER "X ", name, fid);

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_top);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	/* Shouldn't we return (ExchangeMAPIFolder *) instead of a plain fid ? */
	return fid;
}

gboolean
exchange_mapi_connection_empty_folder (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_folder;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mapi_object_init (&obj_folder);

	/* Attempt to open the folder to be emptied */
	ms = open_folder (conn, 0, &fid, fid_options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Empty the contents of the folder */
	ms = EmptyFolder (&obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "EmptyFolder", ms);
		goto cleanup;
	}

	g_debug("Folder with id %016" G_GINT64_MODIFIER "X was emptied ", fid);

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_remove_folder (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_top;
	mapi_object_t obj_folder;
	ExchangeMAPIFolder *folder;
	gboolean result = FALSE;
	GSList *l;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	folder = NULL;
	for (l = exchange_mapi_connection_peek_folders_list (conn); l && !folder; l = l->next) {
		folder = l->data;

		if (!folder || !folder->folder_id)
			folder = NULL;
	}

	e_return_val_mapi_error_if_fail (folder != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();
	mapi_object_init(&obj_top);
	mapi_object_init(&obj_folder);

	/* FIXME: If the folder has sub-folders, open each of them in turn, empty them and delete them.
	 * Note that this has to be done recursively, for the sub-folders as well.
	 */

	/* Attempt to open the folder to be removed */
	ms = open_folder (conn, 0, &fid, fid_options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Empty the contents of the folder */
	ms = EmptyFolder (&obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "EmptyFolder", ms);
		goto cleanup;
	}

	g_debug("Folder with id %016" G_GINT64_MODIFIER "X was emptied ", fid);

	/* Attempt to open the top/parent folder */
	ms = open_folder (conn, 0, &folder->parent_folder_id, fid_options, &obj_top, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Call DeleteFolder on the folder to be removed */
	ms = DeleteFolder (&obj_top, fid, DEL_FOLDERS, NULL);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "DeleteFolder", ms);
		goto cleanup;
	}

	g_debug("Folder with id %016" G_GINT64_MODIFIER "X was deleted ", fid);

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_top);

	priv->folders = g_slist_remove (priv->folders, folder);
	exchange_mapi_folder_free (folder);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_rename_folder (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, const gchar *new_name, GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_folder;
	struct SPropValue *props = NULL;
	TALLOC_CTX *mem_ctx;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_RenameFolder");
	mapi_object_init(&obj_folder);

	/* Open the folder to be renamed */
	ms = open_folder (conn, 0, &fid, fid_options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	props = talloc_zero(mem_ctx, struct SPropValue);
	set_SPropValue_proptag (props, PR_DISPLAY_NAME_UNICODE, new_name);

	ms = SetProps (&obj_folder, props, 1);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetProps", ms);
		goto cleanup;
	}

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

/* moves folder 'src_fid' to folder 'des_fid' under name 'new_name' (no path in a new_name),
   'src_parent_fid' is folder ID of a parent of the src_fid */
gboolean
exchange_mapi_connection_move_folder (ExchangeMapiConnection *conn, mapi_id_t src_fid, mapi_id_t src_parent_fid, guint32 src_fid_options, mapi_id_t des_fid, guint32 des_fid_options, const gchar *new_name, GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t obj_src, obj_src_parent, obj_des;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_return_val_mapi_error_if_fail (src_fid != 0, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (src_parent_fid != 0, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (des_fid != 0, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (new_name != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (strchr (new_name, '/') == NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();

	mapi_object_init (&obj_src);
	mapi_object_init (&obj_src_parent);
	mapi_object_init (&obj_des);

	ms = open_folder (conn, 0, &src_fid, src_fid_options, &obj_src, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	ms = open_folder (conn, 0, &src_parent_fid, src_fid_options, &obj_src_parent, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	ms = open_folder (conn, 0, &des_fid, des_fid_options, &obj_des, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	ms = MoveFolder (&obj_src, &obj_src_parent, &obj_des, (gchar *)new_name, TRUE);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MoveFolder", ms);
		goto cleanup;
	}

	result = TRUE;

cleanup:
	mapi_object_release (&obj_des);
	mapi_object_release (&obj_src_parent);
	mapi_object_release (&obj_src);

	UNLOCK ();

	return result;
}

/* named_ids_list contains pointers to ResolveNamedIDsData structure */
gboolean
exchange_mapi_connection_resolve_named_props (ExchangeMapiConnection *conn, mapi_id_t fid, ResolveNamedIDsData *named_ids_list, guint named_ids_n_elems, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray;
	guint i, j;
	GPtrArray *todo = NULL;
	gboolean res = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (named_ids_list != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (named_ids_n_elems > 0, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug ("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	if (priv->named_ids) {
		gint64 i64 = fid;
		GHashTable *ids = g_hash_table_lookup (priv->named_ids, &i64);

		if (ids) {
			for (i = 0; i < named_ids_n_elems; i++) {
				ResolveNamedIDsData *data = &named_ids_list[i];
				uint32_t propid;

				propid = GPOINTER_TO_INT (g_hash_table_lookup (ids, GINT_TO_POINTER (data->pidlid_propid)));
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
				g_debug ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);
				return TRUE;
			}
		}
	}

	mem_ctx = talloc_init ("ExchangeMAPI_ResolveNamedProps");
	mapi_object_init (&obj_folder);

	nameid = mapi_nameid_new (mem_ctx);
	SPropTagArray = talloc_zero (mem_ctx, struct SPropTagArray);

	/* Attempt to open the folder */
	ms = open_folder (conn, 0, &fid, 0, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	if (!todo) {
		todo = g_ptr_array_new ();
		for (i = 0; i < named_ids_n_elems; i++) {
			g_ptr_array_add (todo, &named_ids_list[i]);
		}
	}

	for (i = 0; i < todo->len; i++) {
		ResolveNamedIDsData *data = todo->pdata[i];

		if (mapi_nameid_canonical_add (nameid, data->pidlid_propid) != MAPI_E_SUCCESS)
			data->propid = MAPI_E_RESERVED;
		else
			data->propid = 0;
	}

	ms = mapi_nameid_GetIDsFromNames (nameid, &obj_folder, SPropTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "mapi_nameid_GetIDsFromNames", ms);
		goto cleanup;
	}

	for (i = 0, j = 0; i < SPropTagArray->cValues && j < todo->len; i++) {
		while (j < todo->len) {
			ResolveNamedIDsData *data = todo->pdata[j];
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
			ResolveNamedIDsData *data = todo->pdata[i];

			g_hash_table_insert (ids, GINT_TO_POINTER (data->pidlid_propid), GINT_TO_POINTER (data->propid));
		}
	}

	res = TRUE;

 cleanup:
	if (todo)
		g_ptr_array_free (todo, TRUE);
	mapi_object_release (&obj_folder);
	talloc_free (mem_ctx);

	UNLOCK ();

	g_debug ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return res;
}

/* returns MAPI_E_RESERVED on any error */
uint32_t
exchange_mapi_connection_resolve_named_prop (ExchangeMapiConnection *conn, mapi_id_t fid, uint32_t pidlid_propid, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray;
	uint32_t res = MAPI_E_RESERVED;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, res);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, res);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	if (priv->named_ids) {
		gint64 i64 = fid;
		GHashTable *ids = g_hash_table_lookup (priv->named_ids, &i64);

		if (ids) {
			res = GPOINTER_TO_INT (g_hash_table_lookup (ids, GINT_TO_POINTER (pidlid_propid)));
			if (res != 0) {
				UNLOCK ();
				g_debug ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

				return res;
			}

			res = MAPI_E_RESERVED;
		}
	}

	mem_ctx = talloc_init("ExchangeMAPI_ResolveNamedProp");
	mapi_object_init(&obj_folder);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* Attempt to open the folder */
	ms = open_folder (conn, 0, &fid, 0, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	mapi_nameid_canonical_add (nameid, pidlid_propid);

	ms = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, SPropTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "mapi_nameid_GetIDsFromNames", ms);
		goto cleanup;
	}

	res = SPropTagArray->aulPropTag[0];
	if ((res & 0xFFFF) == PT_ERROR)
		res = MAPI_E_RESERVED;

	if (priv->named_ids) {
		gint64 i64 = fid;
		GHashTable *ids = g_hash_table_lookup (priv->named_ids, &i64);

		if (!ids) {
			gint64 *i64ptr = g_malloc (sizeof (gint64));

			*i64ptr = fid;
			ids = g_hash_table_new (g_direct_hash, g_direct_equal);

			g_hash_table_insert (priv->named_ids, i64ptr, ids);
		}

		g_hash_table_insert (ids, GINT_TO_POINTER (pidlid_propid), GINT_TO_POINTER (res));
	}

cleanup:
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return res;
}

mapi_id_t
exchange_mapi_connection_get_default_folder_id (ExchangeMapiConnection *conn, uint32_t olFolder, GError **perror)
{
	enum MAPISTATUS ms;
	mapi_id_t fid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, 0);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, 0);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	ms = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultFolder", ms);
		goto cleanup;
	}

cleanup:
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return (ms == MAPI_E_SUCCESS ? fid : 0);
}

mapi_id_t
exchange_mapi_connection_create_item (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid,
			   BuildWritePropsCB build_props, gpointer bwp_data,
			   GSList *recipients, GSList *attachments, GSList *generic_streams,
			   uint32_t options, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct SPropValue *props = NULL;
	uint32_t propslen = 0;
	mapi_id_t mid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, 0);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, 0);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_CreateItem");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	/* Attempt to open the folder */
	ms = open_folder (conn, olFolder, &fid, options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Create the item */
	ms = CreateMessage (&obj_folder, &obj_message);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "CreateMessage", ms);
		goto cleanup;
	}

//	d(mapi_object_debug (&obj_message));

	/* Add regular props using callback */
	if (build_props && !build_props (conn, fid, mem_ctx, &props, &propslen, bwp_data)) {
		g_debug ("%s: (%s): build_props failed! propslen = %d ", G_STRLOC, G_STRFUNC, propslen);
		make_mapi_error (perror, "build_props", MAPI_E_CALL_FAILED);
		goto cleanup;
	}

	/* set properties for the item */
	ms = SetProps (&obj_message, props, propslen);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetProps", ms);
		goto cleanup;
	}

	if (generic_streams) {
		if (!exchange_mapi_util_write_generic_streams (&obj_message, generic_streams, perror))
			goto cleanup;
	}

	/* Set attachments if any */
	if (attachments) {
		if (!exchange_mapi_util_set_attachments (&obj_message, attachments, FALSE, perror))
			goto cleanup;
	}

	/* Set recipients if any */
	if (recipients) {
		if (!exchange_mapi_util_modify_recipients (conn, mem_ctx, &obj_message, recipients, FALSE, perror))
			goto cleanup;
	}

	/* Finally, save all changes */
	ms = SaveChangesMessage (&obj_folder, &obj_message, KeepOpenReadWrite);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SaveChangesMessage", ms);
		goto cleanup;
	}

	if (recipients && !(options & MAPI_OPTIONS_DONT_SUBMIT)) {
		/* Mark message as ready to be sent */
		ms = SubmitMessage (&obj_message);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SubmitMessage", ms);

			/*
			The code is storing message right to Sent items instead of Outbox,
			because fetching PR_ENTRYID or PR_IPM_SENTMAIL_ENTRYID didn't seem
			to work in time of doing this change.

			For more information and other possible (correct) approaches see:
			https://bugzilla.gnome.org/show_bug.cgi?id=561794
			*/
			if ((options & MAPI_OPTIONS_DELETE_ON_SUBMIT_FAILURE) != 0) {
				mid = mapi_object_get_id (&obj_message);
				mapi_object_release(&obj_message);
				/* to not release a message object twice */
				mapi_object_init (&obj_message);

				ms = DeleteMessage (&obj_folder, &mid, 1);
				if (ms != MAPI_E_SUCCESS) {
					make_mapi_error (perror, "DeleteMessage", ms);
				}

				/* do not forget to set it back to 0, as the function failed */
				mid = 0;
			}

			goto cleanup;
		}
	}

	mid = mapi_object_get_id (&obj_message);

cleanup:
	mapi_object_release(&obj_message);
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return mid;
}

gboolean
exchange_mapi_connection_modify_item (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, mapi_id_t mid,
			   BuildWritePropsCB build_props, gpointer bwp_data,
			   GSList *recipients, GSList *attachments, GSList *generic_streams,
			   uint32_t options, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct SPropValue *props = NULL;
	uint32_t propslen = 0;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_ModifyItem");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	/* Attempt to open the folder */
	ms = open_folder (conn, olFolder, &fid, options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Open the item to be modified */
	ms = OpenMessage (&obj_folder, fid, mid, &obj_message, MAPI_MODIFY);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenMessage", ms);
		goto cleanup;
	}

//	d(mapi_object_debug (&obj_message));

	/* Add regular props using callback */
	if (build_props && !build_props (conn, fid, mem_ctx, &props, &propslen, bwp_data)) {
		g_debug ("%s: (%s): Could not build props ", G_STRLOC, G_STRFUNC);
		make_mapi_error (perror, "build_props", MAPI_E_CALL_FAILED);
		goto cleanup;
	}

	/* set properties for the item */
	ms = SetProps (&obj_message, props, propslen);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetProps", ms);
		goto cleanup;
	}

	if (generic_streams) {
		if (!exchange_mapi_util_write_generic_streams (&obj_message, generic_streams, perror))
			goto cleanup;
	}

	/* Set attachments if any */
	if (attachments) {
		if (!exchange_mapi_util_set_attachments (&obj_message, attachments, TRUE, perror))
			goto cleanup;
	} else {
		exchange_mapi_util_delete_attachments (&obj_message, NULL);
	}

	/* Set recipients if any */
	if (recipients) {
		if (!exchange_mapi_util_modify_recipients (conn, mem_ctx, &obj_message, recipients, TRUE, perror))
			goto cleanup;
	}

	/* Finally, save all changes */
	ms = SaveChangesMessage (&obj_folder, &obj_message, KeepOpenReadWrite);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SaveChangesMessage", ms);
		goto cleanup;
	}

	if (recipients && !(options & MAPI_OPTIONS_DONT_SUBMIT)) {
		/* Mark message as ready to be sent */
		ms = SubmitMessage (&obj_message);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "SubmitMessage", ms);
			goto cleanup;
		}
	}

	result = TRUE;

cleanup:
	mapi_object_release(&obj_message);
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_set_flags (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, guint32 fid_options, GSList *mids, uint32_t flag, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	uint32_t i;
	mapi_id_t *id_messages;
	GSList *tmp = mids;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_SetFlags");
	mapi_object_init(&obj_folder);

	id_messages = talloc_array(mem_ctx, mapi_id_t, g_slist_length (mids));
	for (i=0; tmp; tmp=tmp->next, i++)
		id_messages[i] = *((mapi_id_t *)tmp->data);

	/* Attempt to open the folder */
	ms = open_folder (conn, olFolder, &fid, fid_options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	ms = SetReadFlags (&obj_folder, flag, i, id_messages);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetReadFlags", ms);
		goto cleanup;
	}

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

static gboolean
mapi_move_items (ExchangeMapiConnection *conn, mapi_id_t src_fid, guint32 src_fid_options, mapi_id_t dest_fid, guint32 dest_fid_options, GSList *mid_list, gboolean do_copy, GError **perror)
{
	enum MAPISTATUS	ms;
	mapi_object_t obj_folder_src;
	mapi_object_t obj_folder_dst;
	mapi_id_array_t msg_id_array;
	GSList *l;

	e_return_val_mapi_error_if_fail (conn != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mapi_object_init(&obj_folder_src);
	mapi_object_init(&obj_folder_dst);
	mapi_id_array_init(&msg_id_array);

	for (l = mid_list; l != NULL; l = g_slist_next (l))
		mapi_id_array_add_id (&msg_id_array, *((mapi_id_t *)l->data));

	ms = open_folder (conn, 0, &src_fid, src_fid_options, &obj_folder_src, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	ms = open_folder (conn, 0, &dest_fid, dest_fid_options, &obj_folder_dst, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	ms = MoveCopyMessages (&obj_folder_src, &obj_folder_dst, &msg_id_array, do_copy);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MoveCopyMessages", ms);
		goto cleanup;
	}

cleanup:
	mapi_id_array_release(&msg_id_array);
	mapi_object_release(&obj_folder_dst);
	mapi_object_release(&obj_folder_src);

	return ms;
}

gboolean
exchange_mapi_connection_copy_items (ExchangeMapiConnection *conn, mapi_id_t src_fid, guint32 src_fid_options, mapi_id_t dest_fid, guint32 dest_fid_options, GSList *mids, GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	ms = mapi_move_items (conn, src_fid, src_fid_options, dest_fid, dest_fid_options, mids, TRUE, perror);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return ms == MAPI_E_SUCCESS;
}

gboolean
exchange_mapi_connection_move_items (ExchangeMapiConnection *conn, mapi_id_t src_fid, guint32 src_fid_options, mapi_id_t dest_fid, guint32 dest_fid_options, GSList *mids, GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, MAPI_E_INVALID_PARAMETER);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, MAPI_E_INVALID_PARAMETER);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	ms = mapi_move_items (conn, src_fid, src_fid_options, dest_fid, dest_fid_options, mids, FALSE, perror);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return ms == MAPI_E_SUCCESS;
}

gboolean
exchange_mapi_connection_remove_items (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, guint32 fid_options, GSList *mids, GError **perror)
{
	enum MAPISTATUS ms;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	uint32_t i;
	mapi_id_t *id_messages;
	GSList *tmp = mids;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_RemoveItems");
	mapi_object_init(&obj_folder);

	id_messages = talloc_array(mem_ctx, mapi_id_t, g_slist_length (mids));
	for (i=0; tmp; tmp=tmp->next, i++) {
		struct id_list *data = tmp->data;
		id_messages[i] = data->id;
	}

	/* Attempt to open the folder */
	ms = open_folder (conn, olFolder, &fid, fid_options, &obj_folder, perror);
	if (ms != MAPI_E_SUCCESS) {
		goto cleanup;
	}

	/* Delete the messages from the folder */
	ms = DeleteMessage (&obj_folder, id_messages, i);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "DeleteMessage", ms);
		goto cleanup;
	}

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

static gboolean
get_child_folders (TALLOC_CTX *mem_ctx, ExchangeMAPIFolderCategory folder_hier, mapi_object_t *parent,
		   mapi_id_t folder_id, GSList **mapi_folders, GError **perror)
{
	enum MAPISTATUS		ms;
	mapi_object_t		obj_folder;
	mapi_object_t		obj_table;
	struct SPropTagArray	*SPropTagArray = NULL;
	struct SRowSet		rowset;
	uint32_t		i, row_count = 0, cursor_pos, count;
	gboolean		result = TRUE;

	/* sanity check */
	e_return_val_mapi_error_if_fail (mem_ctx != NULL, MAPI_E_INVALID_PARAMETER, FALSE);
	e_return_val_mapi_error_if_fail (parent != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	/* Attempt to open the folder */
	ms = OpenFolder (parent, folder_id, &obj_folder);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenFolder", ms);
		result = FALSE;
		goto cleanup;
	}

	/* Get the hierarchy table */
	ms = GetHierarchyTable (&obj_folder, &obj_table, TableFlags_Depth | TableFlags_NoNotifications | TableFlags_UseUnicode, &row_count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetHierarchyTable", ms);
		result = FALSE;
		goto cleanup;
	}

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x8,
					  PR_FID,
					  PR_PARENT_FID,
					  PR_CONTAINER_CLASS,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_CONTENT_UNREAD,
					  PR_CONTENT_COUNT,
					  PR_MESSAGE_SIZE,
					  PR_FOLDER_CHILD_COUNT);

	ms = SetColumns (&obj_table, SPropTagArray);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "SetColumns", ms);
		result = FALSE;
		goto cleanup;
	}

	cursor_pos = 0;

	do {
		ms = QueryPosition (&obj_table, &cursor_pos, &count);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "QueryPosition", ms);
			result = FALSE;
			goto cleanup;
		}

		/* Fill the table columns with data from the rows */
		ms = QueryRows (&obj_table, 100, TBL_ADVANCE, &rowset);
		if (ms != MAPI_E_SUCCESS) {
			make_mapi_error (perror, "QueryRows", ms);
			result = FALSE;
			goto cleanup;
		}

		for (i = 0; i < rowset.cRows; i++) {
			ExchangeMAPIFolder *folder = NULL;
			gchar *newname = NULL;

			const mapi_id_t *fid = (const mapi_id_t *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_FID);
			const mapi_id_t *pid = (const mapi_id_t *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_PARENT_FID);
			const gchar *class = (const gchar *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_CONTAINER_CLASS);
			const gchar *name = (const gchar *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_DISPLAY_NAME_UNICODE);
			const uint32_t *unread = (const uint32_t *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_CONTENT_UNREAD);
			const uint32_t *total = (const uint32_t *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_CONTENT_COUNT);
			const uint32_t *child = (const uint32_t *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_FOLDER_CHILD_COUNT);
			const uint32_t *folder_size = (const uint32_t *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_MESSAGE_SIZE);

			if (!class)
				class = IPF_NOTE;

			newname = utf8tolinux (name);
			g_debug("|---+ %-15s : (Container class: %s %016" G_GINT64_MODIFIER "X) UnRead : %d Total : %d size : %d",
				newname, class, *fid, unread ? *unread : 0, total ? *total : 0, folder_size ? *folder_size : 0);

			folder = exchange_mapi_folder_new (newname, class, folder_hier, *fid, pid ? *pid : folder_id,
							   child ? *child : 0, unread ? *unread : 0, total ? *total : 0);

			folder->size = folder_size ? *folder_size : 0;

			*mapi_folders = g_slist_prepend (*mapi_folders, folder);

			g_free (newname);
		}

		cursor_pos += rowset.cRows;
	} while (cursor_pos < row_count && rowset.cRows);

cleanup:
	MAPIFreeBuffer (SPropTagArray);
	mapi_object_release (&obj_folder);
	mapi_object_release (&obj_table);

	return result;
}

/* TODO : Find a right place for this. */
#define PR_ADDITIONAL_REN_ENTRYIDS    PROP_TAG(PT_MV_BINARY, 0x36D8)

/*NOTE : This should be called when you hold the connection lock*/
/*NOTE : IsMailboxFolder doesn't support this yet. */
/* Ticket : http://trac.openchange.org/ticket/134  */
static gboolean
mapi_get_ren_additional_fids (mapi_object_t *obj_store, GHashTable **folder_list, GError **perror)
{
	mapi_id_t inbox_id, fid;
	mapi_object_t obj_folder_inbox;
	struct SPropTagArray *SPropTagArray;
	struct SPropValue *lpProps;
	struct SRow aRow;
	const struct BinaryArray_r *entryids;
	struct Binary_r entryid;
	enum MAPISTATUS ms;

	guint32 count, *folder_type;
	guint i = 0;

	TALLOC_CTX *mem_ctx;

	/*Note : Do not change the order.*/
	const guint32 olfolder_defaults[] = {
		olFolderConflicts,
		olFolderSyncIssues,
		olFolderLocalFailures,
		olFolderServerFailures,
		olFolderJunk
	};

	mem_ctx = talloc_init("ExchangeMAPI_GetAdditionalFIDs");
	mapi_object_init(&obj_folder_inbox);

	/* Get Inbox FID using GetDefaultFolder. */
	ms = GetDefaultFolder (obj_store, &inbox_id, olFolderInbox);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultFolder", ms);
		goto cleanup;
	}

	/* Open InboxFolder. */
	ms = OpenFolder (obj_store, inbox_id, &obj_folder_inbox);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "OpenFolder", ms);
		goto cleanup;
	}

	/* GetProps on Inbox for PR_ADDITIONAL_REN_ENTRYIDS */
	SPropTagArray = set_SPropTagArray(mem_ctx, 0x1, PR_ADDITIONAL_REN_ENTRYIDS);

	lpProps = talloc_zero(mem_ctx, struct SPropValue);
	ms = GetProps (&obj_folder_inbox, SPropTagArray, &lpProps, &count);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetProps", ms);
		goto cleanup;
	}

	/* Build a SRow structure */
	aRow.ulAdrEntryPad = 0;
	aRow.cValues = count;
	aRow.lpProps = lpProps;

	entryids = (const struct BinaryArray_r *) exchange_mapi_util_find_row_propval (&aRow, PR_ADDITIONAL_REN_ENTRYIDS);

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
						     exchange_mapi_util_mapi_id_to_string (fid),
						     folder_type);
			}
		}
	}

cleanup:
	mapi_object_release(&obj_folder_inbox);
	talloc_free (mem_ctx);

	return ms == MAPI_E_SUCCESS;
}

static gboolean
set_default_folders (mapi_object_t *obj_store, GSList **mapi_folders, GError **perror)
{
	GSList *folder_list = *mapi_folders;

	GHashTable *default_folders = g_hash_table_new_full (g_str_hash, g_str_equal,
							     g_free, g_free);

	if (!mapi_get_ren_additional_fids (obj_store, &default_folders, perror)) {
		g_hash_table_destroy (default_folders);
		return FALSE;
	}

	while (folder_list != NULL) {
		ExchangeMAPIFolder *folder = NULL;
		guint32 default_type = 0;
		gchar *key_fid = NULL;
		gpointer value = NULL;

		folder = folder_list->data;
		key_fid = exchange_mapi_util_mapi_id_to_string (folder->folder_id);

		if ((value = g_hash_table_lookup (default_folders, key_fid)) != NULL)
			default_type = *(guint32 *)value;
		g_free (key_fid);

		if (default_type != 0 || IsMailboxFolder (obj_store,folder->folder_id, &default_type)) {
			folder->is_default = true; /* TODO : Clean up. Redundant.*/
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
	ExchangeMAPIFolder *folder = (ExchangeMAPIFolder *)(data);
	folder->owner_name = (gchar *)(user_data);
}

static void
set_user_name (gpointer data, gpointer user_data)
{
	ExchangeMAPIFolder *folder = (ExchangeMAPIFolder *)(data);
	folder->user_name = (gchar *)(user_data);
}

gboolean
exchange_mapi_connection_get_folders_list (ExchangeMapiConnection *conn, GSList **mapi_folders, GError **perror)
{
	enum MAPISTATUS	ms;
	TALLOC_CTX		*mem_ctx;
	struct SPropTagArray	*SPropTagArray;
	struct SPropValue	*lpProps;
	struct SRow		aRow;
	gboolean		result = FALSE;
	mapi_id_t		mailbox_id;
	ExchangeMAPIFolder	*folder;
	uint32_t		count = 0;
	const gchar		*mailbox_name = NULL;
	gchar			*utf8_mailbox_name = NULL;
	const gchar		*mailbox_owner_name = NULL;
	const gchar		*mailbox_user_name = NULL;
	const uint32_t          *mailbox_size = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_GetFoldersList");

	/* Build the array of Mailbox properties we want to fetch */
	SPropTagArray = set_SPropTagArray(mem_ctx, 0x4,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_MAILBOX_OWNER_NAME_UNICODE,
					  PR_MESSAGE_SIZE,
					  PR_USER_NAME_UNICODE);

	lpProps = talloc_zero(mem_ctx, struct SPropValue);
	ms = GetProps (&priv->msg_store, SPropTagArray, &lpProps, &count);
	MAPIFreeBuffer(SPropTagArray);

	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetProps", ms);
		goto cleanup;
	}

	/* Build a SRow structure */
	aRow.ulAdrEntryPad = 0;
	aRow.cValues = count;
	aRow.lpProps = lpProps;

	/* betting that these will never fail */
	mailbox_name = (const gchar *) exchange_mapi_util_find_row_propval (&aRow, PR_DISPLAY_NAME_UNICODE);
	mailbox_owner_name = (const gchar *) exchange_mapi_util_find_row_propval (&aRow, PR_MAILBOX_OWNER_NAME_UNICODE);
	mailbox_user_name = (const gchar *) exchange_mapi_util_find_row_propval (&aRow, PR_USER_NAME_UNICODE);
	mailbox_size = (const uint32_t *)exchange_mapi_util_find_row_propval  (&aRow, PR_MESSAGE_SIZE);

	/* Prepare the directory listing */
	ms = GetDefaultFolder (&priv->msg_store, &mailbox_id, olFolderTopInformationStore);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultFolder", ms);
		goto cleanup;
	}

	utf8_mailbox_name = utf8tolinux (mailbox_name);

	/* FIXME: May have to get the child folders count? Do we need/use it? */
	folder = exchange_mapi_folder_new (utf8_mailbox_name, IPF_NOTE,
					   MAPI_PERSONAL_FOLDER, mailbox_id, 0, 0, 0 ,0);
	folder->is_default = true;
	folder->default_type = olFolderTopInformationStore; /*Is this correct ?*/
	folder->size = *mailbox_size;

	*mapi_folders = g_slist_prepend (*mapi_folders, folder);

	/* FIXME: check status of get_child_folders */
	result = get_child_folders (mem_ctx, MAPI_PERSONAL_FOLDER, &priv->msg_store, mailbox_id, mapi_folders, perror);

	g_free(utf8_mailbox_name);

	*mapi_folders = g_slist_reverse (*mapi_folders);

	if (!set_default_folders (&priv->msg_store, mapi_folders, perror)) {
		goto cleanup;
	}

	g_slist_foreach (*mapi_folders, (GFunc) set_owner_name, (gpointer) mailbox_owner_name);
	g_slist_foreach (*mapi_folders, (GFunc) set_user_name, (gpointer) mailbox_user_name);

cleanup:
	talloc_free (mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_get_pf_folders_list (ExchangeMapiConnection *conn, GSList **mapi_folders, GError **perror)
{
	enum MAPISTATUS		ms;
	TALLOC_CTX		*mem_ctx;
	gboolean		result = FALSE;
	mapi_id_t		mailbox_id;
	ExchangeMAPIFolder	*folder;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_PF_GetFoldersList");

	if (!ensure_public_store (priv, perror))
		goto cleanup;

	ms = GetDefaultPublicFolder (&priv->public_store, &mailbox_id, olFolderPublicIPMSubtree);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "GetDefaultPublicFolder", ms);
		goto cleanup;
	}

	folder = exchange_mapi_folder_new (_("All Public Folders"), IPF_NOTE, 0, mailbox_id, 0, 0, 0 ,0);
	folder->is_default = true;
	folder->default_type = olPublicFoldersAllPublicFolders;
	*mapi_folders = g_slist_prepend (*mapi_folders, folder);
	result = get_child_folders (mem_ctx, MAPI_FAVOURITE_FOLDER, &priv->public_store, mailbox_id, mapi_folders, perror);
	*mapi_folders = g_slist_reverse (*mapi_folders);

cleanup:
	talloc_free (mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

GSList *
exchange_mapi_connection_peek_folders_list (ExchangeMapiConnection *conn)
{
	/* to have this used in the below macros */
	GError **perror = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();
	if (!priv->folders)
		exchange_mapi_connection_get_folders_list (conn, &priv->folders, perror);
	UNLOCK ();

	return priv->folders;
}

/* free returned pointer with g_free() */
gchar *
exchange_mapi_connection_ex_to_smtp (ExchangeMapiConnection *conn, const gchar *ex_address, GError **perror)
{
	enum MAPISTATUS	ms;
	TALLOC_CTX		*mem_ctx;
	struct SPropTagArray	*SPropTagArray;
	struct SRowSet		*SRowSet = NULL;
	struct SPropTagArray	*flaglist = NULL;
	const gchar		*str_array[2];
	gchar			*smtp_addr = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	e_return_val_mapi_error_if_fail (ex_address != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	str_array[0] = ex_address;
	str_array[1] = NULL;

	mem_ctx = talloc_init("ExchangeMAPI_EXtoSMTP");

	LOCK ();

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x1,
					  PR_SMTP_ADDRESS_UNICODE);

	ms = ResolveNames (priv->session, (const gchar **)str_array, SPropTagArray, &SRowSet, &flaglist, MAPI_UNICODE);
	if (ms != MAPI_E_SUCCESS)
		ms = ResolveNames (priv->session, (const gchar **)str_array, SPropTagArray, &SRowSet, &flaglist, 0);

	if (ms == MAPI_E_SUCCESS && SRowSet && SRowSet->cRows == 1) {
		smtp_addr = g_strdup (exchange_mapi_util_find_row_propval (SRowSet->aRow, PR_SMTP_ADDRESS_UNICODE));
	}

	talloc_free (mem_ctx);

	UNLOCK ();

	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "ResolveNames", ms);

	return smtp_addr;
}

gboolean
exchange_mapi_connection_events_init (ExchangeMapiConnection *conn, GError **perror)
{
	enum MAPISTATUS ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();
	#ifdef HAVE_CORRECT_REGISTERNOTIFICATION
	ms = RegisterNotification (priv->session, 0);
	#else
	ms = MAPI_E_INTERFACE_NO_SUPPORT;
	#endif
	UNLOCK ();

	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "RegisterNotification", ms);

	return ms == MAPI_E_SUCCESS;
}

gboolean
exchange_mapi_connection_events_subscribe (ExchangeMapiConnection *conn, guint32 options,
				guint16 event_mask, guint32 *events_conn_id,
				mapi_notify_callback_t callback, gpointer data, GError **perror)
{
	enum MAPISTATUS	ms = MAPI_E_CALL_FAILED;
	gboolean use_store = ((options & MAPI_EVENTS_USE_STORE) ||
			      (options & MAPI_EVENTS_USE_PF_STORE));

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();

	if (options & MAPI_EVENTS_USE_STORE) {
		ms = Subscribe (&priv->msg_store, events_conn_id, event_mask, use_store, (mapi_notify_callback_t) callback, data);
	} else if (options & MAPI_EVENTS_USE_PF_STORE) {
		if (!ensure_public_store (priv, perror)) {
			UNLOCK ();
			return FALSE;
		}

		ms = Subscribe (&priv->public_store, events_conn_id, event_mask, use_store, (mapi_notify_callback_t) callback, data);
	} else if (options & MAPI_EVENTS_FOLDER) {
		/* TODO */
	}

	UNLOCK ();

	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "Subscribe", ms);

	return (ms == MAPI_E_SUCCESS);
}

gboolean
exchange_mapi_connection_events_unsubscribe (ExchangeMapiConnection *conn, guint32 events_conn_id, GError **perror)
{
	enum MAPISTATUS	ms;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	LOCK ();
	ms = Unsubscribe (priv->session, events_conn_id);
	UNLOCK ();

	if (ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, "Unsubscribe", ms);

	return (ms == MAPI_E_SUCCESS);
}

/* Note : Blocking infinite loop. */
gboolean
exchange_mapi_connection_events_monitor (ExchangeMapiConnection *conn, struct mapi_notify_continue_callback_data *cb_data)
{
	enum MAPISTATUS	ms;
	/* to have this used in the below macros */
	GError **perror = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	e_return_val_mapi_error_if_fail (priv->session != NULL, MAPI_E_INVALID_PARAMETER, FALSE);

	ms = MonitorNotification (priv->session, NULL, cb_data);

	return ms == MAPI_E_SUCCESS;
}

/* profile related functions - begin */

static void
mapi_debug_logger (const gchar * domain, GLogLevelFlags level, const gchar * message, gpointer data)
{
	g_print ("[DEBUG] %s\n", message);
}

static void
mapi_debug_logger_muted (const gchar * domain, GLogLevelFlags level, const gchar * message, gpointer data)
{
	/*Nothing here. Just a dummy function*/
}

static gboolean
ensure_mapi_init_called (GError **perror)
{
	static gboolean called = FALSE;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	const gchar *user_data_dir;
	gchar *profpath;
	enum MAPISTATUS ms;

	g_static_mutex_lock (&mutex);
	if (called) {
		g_static_mutex_unlock (&mutex);
		return TRUE;
	}

	user_data_dir = e_get_user_data_dir ();
	profpath = g_build_filename (user_data_dir, DEFAULT_PROF_NAME, NULL);

	if (!g_file_test (profpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		/* Create a ProfileStore */
		ms = CreateProfileStore (profpath, LIBMAPI_LDIF_DIR);
		if (ms != MAPI_E_SUCCESS && (ms != MAPI_E_NO_ACCESS || !g_file_test (profpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
			make_mapi_error (perror, "CreateProfileStore", ms);
			g_free (profpath);

			g_static_mutex_unlock (&mutex);
			return FALSE;
		}
	}

	ms = MAPIInitialize (profpath);
	if (ms == MAPI_E_SESSION_LIMIT) {
		/* do nothing, the profile store is already initialized */
		/* but this shouldn't happen */
	} else if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MAPIInitialize", ms);
		g_free (profpath);

		g_static_mutex_unlock (&mutex);
		return FALSE;
	}

	g_free (profpath);

	called = TRUE;
	g_static_mutex_unlock (&mutex);

	return TRUE;
}

/* used when dealing with profiles */
static GStaticMutex profile_mutex = G_STATIC_MUTEX_INIT;

static struct mapi_session *
mapi_profile_load (const gchar *profname, const gchar *password, GError **perror)
{
	enum MAPISTATUS	ms = MAPI_E_SUCCESS;
	struct mapi_session *session = NULL;
	guint32 debug_log_level = 0;

	e_return_val_mapi_error_if_fail (profname != NULL, MAPI_E_INVALID_PARAMETER, NULL);

	g_static_mutex_lock (&profile_mutex);

	/* Initialize libexchangemapi logger*/
	if (g_getenv ("EXCHANGEMAPI_DEBUG")) {
		g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, mapi_debug_logger, NULL);
	} else
		g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, mapi_debug_logger_muted, NULL);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	if (!ensure_mapi_init_called (perror))
		goto cleanup;

	/* Initialize libmapi logger*/
	if (g_getenv ("MAPI_DEBUG")) {
		debug_log_level = atoi (g_getenv ("MAPI_DEBUG"));
		SetMAPIDumpData(TRUE);
		SetMAPIDebugLevel(debug_log_level);
	}

	g_debug("Loading profile %s ", profname);

	ms = MapiLogonEx (&session, profname, password);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MapiLogonEx", ms);
		goto cleanup;
	}

 cleanup:
	g_static_mutex_unlock (&profile_mutex);
	g_debug ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return session;
}

gboolean
exchange_mapi_create_profile (const gchar *username, const gchar *password, const gchar *domain,
			      const gchar *server, guint32 flags,
			      mapi_profile_callback_t callback, gpointer data,
			      GError **perror)
{
	enum MAPISTATUS	ms;
	gboolean result = FALSE;
	const gchar *workstation = "localhost";
	gchar *profname = NULL;
	struct mapi_session *session = NULL;

	/*We need all the params before proceeding.*/
	e_return_val_mapi_error_if_fail (username && *username && password && *password &&
			      domain && *domain && server && *server, MAPI_E_INVALID_PARAMETER, FALSE);

	g_static_mutex_lock (&profile_mutex);

	g_debug ("Create profile with %s %s %s\n", username, domain, server);

	if (!ensure_mapi_init_called (perror)) {
		g_static_mutex_unlock (&profile_mutex);
		return FALSE;
	}

	profname = exchange_mapi_util_profile_name (username, domain, server, TRUE);

	/* Delete any existing profiles with the same profilename */
	ms = DeleteProfile (profname);
	/* don't bother to check error - it would be valid if we got an error */

	ms = CreateProfile (profname, username, password, OC_PROFILE_NOPASSWORD);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "CreateProfile", ms);
		goto cleanup;
	}

	mapi_profile_add_string_attr(profname, "binding", server);
	mapi_profile_add_string_attr(profname, "workstation", workstation);
	mapi_profile_add_string_attr(profname, "domain", domain);

	if ((flags & CREATE_PROFILE_FLAG_USE_SSL) != 0)
		mapi_profile_add_string_attr (profname, "seal", "true");

	/* This is only convenient here and should be replaced at some point */
	mapi_profile_add_string_attr(profname, "codepage", "0x4e4");
	mapi_profile_add_string_attr(profname, "language", "0x409");
	mapi_profile_add_string_attr(profname, "method", "0x409");

	/* Login now */
	g_debug("Logging into the server... ");
	ms = MapiLogonProvider (&session, profname, password, PROVIDER_ID_NSPI);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MapiLogonProvider", ms);
		g_debug ("Deleting profile %s ", profname);
		DeleteProfile (profname);
		goto cleanup;
	}
	g_debug("MapiLogonProvider : succeeded \n");

	ms = ProcessNetworkProfile (session, username, callback, data);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "ProcessNetworkProfile", ms);
		g_debug ("Deleting profile %s ", profname);
		DeleteProfile (profname);
		goto cleanup;
	}
	g_debug("ProcessNetworkProfile : succeeded \n");

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

	g_static_mutex_unlock (&profile_mutex);

	return result;
}

gboolean
exchange_mapi_delete_profile (const gchar *profile, GError **perror)
{
	gboolean result = FALSE;

	g_static_mutex_lock (&profile_mutex);

	if (ensure_mapi_init_called (perror)) {
		enum MAPISTATUS ms;

		g_debug ("Deleting profile %s ", profile);

		ms = DeleteProfile (profile);
		if (ms == MAPI_E_SUCCESS) {
			result = TRUE;
		} else {
			make_mapi_error (perror, "DeleteProfile", ms);
		}
	}

	g_static_mutex_unlock (&profile_mutex);

	return result;
}

/* profile related functions - end */
