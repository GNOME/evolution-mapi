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

#include "exchange-mapi-connection.h"
#include "exchange-mapi-folder.h"
#include "exchange-mapi-utils.h"
#include <param.h>

#define DEFAULT_PROF_PATH ".evolution/mapi-profiles.ldb"

static void register_connection (ExchangeMapiConnection *conn);
static void unregister_connection (ExchangeMapiConnection *conn);
static struct mapi_session *mapi_profile_load (const gchar *profname, const gchar *password);

/* GObject foo - begin */

G_DEFINE_TYPE (ExchangeMapiConnection, exchange_mapi_connection, G_TYPE_OBJECT)

#define EXCHANGE_MAPI_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), EXCHANGE_TYPE_MAPI_CONNECTION, ExchangeMapiConnectionPrivate))

/* These two macros require 'priv' variable of type ExchangeMapiConnectionPrivate */
#define LOCK()		g_debug ("%s: %s: lock(session_lock)", G_STRLOC, G_STRFUNC); g_static_rec_mutex_lock (&priv->session_lock);
#define UNLOCK()	g_debug ("%s: %s: unlock(session_lock)", G_STRLOC, G_STRFUNC); g_static_rec_mutex_unlock (&priv->session_lock);

typedef struct _ExchangeMapiConnectionPrivate ExchangeMapiConnectionPrivate;

struct _ExchangeMapiConnectionPrivate {
	struct mapi_session *session;
	GStaticRecMutex session_lock;

	gchar *profile;			/* profile name, where the session is connected to */
	mapi_object_t msg_store;	/* valid only when session != NULL */

	gboolean has_public_store;	/* whether is 'public_store' filled */
	mapi_object_t public_store;

	GSList *folders;		/* list of ExchangeMapiFolder pointers */
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

	priv->session = NULL;
	priv->has_public_store = FALSE;
	priv->folders = NULL;
}

/* should have session_lock locked already, when calling this function */
static gboolean
ensure_public_store (ExchangeMapiConnectionPrivate *priv)
{
	g_return_val_if_fail (priv != NULL, FALSE);

	if (!priv->session)
		return FALSE;

	if (!priv->has_public_store) {
		mapi_object_init (&priv->public_store);

		if (OpenPublicFolder (priv->session, &priv->public_store) == MAPI_E_SUCCESS) {
			priv->has_public_store = TRUE;
		} else {
			mapi_errstr ("OpenPublicFolder", GetLastError());
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
#define STREAM_MAX_READ_SIZE    0x1000
#define STREAM_MAX_WRITE_SIZE   0x1000
#define STREAM_ACCESS_READ      0x0000
#define STREAM_ACCESS_WRITE     0x0001
#define STREAM_ACCESS_READWRITE 0x0002

#define CHECK_CORRECT_CONN_AND_GET_PRIV(_conn, _val)				\
	ExchangeMapiConnectionPrivate *priv;					\
										\
	g_return_val_if_fail (_conn != NULL, _val);				\
	g_return_val_if_fail (EXCHANGE_IS_MAPI_CONNECTION (_conn), _val);	\
										\
	priv = EXCHANGE_MAPI_CONNECTION_GET_PRIVATE (_conn);			\
	g_return_val_if_fail (priv != NULL, _val);

/* Creates a new connection object and connects to a server as defined in 'profile' */
ExchangeMapiConnection *
exchange_mapi_connection_new (const gchar *profile, const gchar *password)
{
	ExchangeMapiConnection *conn;
	ExchangeMapiConnectionPrivate *priv;
	struct mapi_session *session;

	g_return_val_if_fail (profile != NULL, NULL);

	session = mapi_profile_load (profile, password);
	if (!session) {
		g_debug ("%s: %s: Login failed ", G_STRLOC, G_STRFUNC);
		return NULL;
	}

	conn = g_object_new (EXCHANGE_TYPE_MAPI_CONNECTION, NULL);
	priv = EXCHANGE_MAPI_CONNECTION_GET_PRIVATE (conn);
	g_return_val_if_fail (priv != NULL, conn);

	LOCK ();
	mapi_object_init (&priv->msg_store);
	priv->session = session;

	/* Open the message store and keep it opened for all the life-time for this connection */
	if (OpenMsgStore (priv->session, &priv->msg_store) != MAPI_E_SUCCESS) {
		mapi_errstr ("OpenMsgStore", GetLastError());

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

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	LOCK ();

	res = priv->session != NULL;
	disconnect (priv);

	UNLOCK ();

	return res;
}

gboolean
exchange_mapi_connection_reconnect (ExchangeMapiConnection *conn, const gchar *password)
{
	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	g_return_val_if_fail (priv->profile != NULL, FALSE);

	LOCK ();
	if (priv->session)
		exchange_mapi_connection_close (conn);

	priv->session = mapi_profile_load (priv->profile, password);
	if (!priv->session) {
		g_debug ("%s: %s: Login failed ", G_STRLOC, G_STRFUNC);
		UNLOCK ();
		return FALSE;
	}

	mapi_object_init (&priv->msg_store);

	/* Open the message store and keep it opened for all the life-time for this connection */
	if (OpenMsgStore (priv->session, &priv->msg_store) != MAPI_E_SUCCESS) {
		mapi_errstr ("OpenMsgStore", GetLastError());

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
	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	return priv->session != NULL;
}

static gboolean
exchange_mapi_util_read_generic_stream (mapi_object_t *obj_message, uint32_t proptag, GSList **stream_list)
{
	enum MAPISTATUS	retval;
	TALLOC_CTX	*mem_ctx;
	mapi_object_t	obj_stream;
	uint16_t	cn_read = 0;
	uint32_t	off_data = 0;
	uint8_t		*buf_data = NULL;
	uint32_t	buf_size = 0;
	gboolean	done = FALSE;

	/* sanity */
	g_return_val_if_fail (obj_message, FALSE);
	g_return_val_if_fail (((proptag & 0xFFFF) == PT_BINARY), FALSE);

	/* if compressed RTF stream, then return */
	g_return_val_if_fail (proptag != PR_RTF_COMPRESSED, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);
	g_debug("Attempt to read stream for proptag 0x%08X ", proptag);

	mem_ctx = talloc_init ("ExchangeMAPI_ReadGenericStream");
	mapi_object_init(&obj_stream);

	/* get a stream on specified proptag */
	retval = OpenStream(obj_message, proptag, STREAM_ACCESS_READ, &obj_stream);
	if (retval != MAPI_E_SUCCESS) {
	/* If OpenStream failed, should we attempt any other call(s) to fetch the blob? */
		mapi_errstr("OpenStream", GetLastError());
		goto cleanup;
	}

	/* NOTE: This may prove unreliable for streams larger than 4GB length */
	retval = GetStreamSize(&obj_stream, &buf_size);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetStreamSize", GetLastError());
		goto cleanup;
	}

	buf_data = talloc_size (mem_ctx, buf_size);
	if (!buf_data)
		goto cleanup;

	/* Read from the stream */
	while (!done) {
		retval = ReadStream(&obj_stream,
				    (buf_data) + off_data,
				    STREAM_MAX_READ_SIZE,
				    &cn_read);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("ReadStream", GetLastError());
			done = TRUE;
		} else if (cn_read == 0) {
			done = TRUE;
		} else {
			off_data += cn_read;
			if (off_data >= buf_size)
				done = TRUE;
		}
	};

	if (retval == MAPI_E_SUCCESS) {
		ExchangeMAPIStream		*stream = g_new0 (ExchangeMAPIStream, 1);
		struct mapi_SPropValue_array	properties_array;

		stream->value = g_byte_array_sized_new (off_data);
		stream->value = g_byte_array_append (stream->value, buf_data, off_data);

		/* Build a mapi_SPropValue_array structure */
		properties_array.cValues = 1;
		properties_array.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, properties_array.cValues + 1);
		properties_array.lpProps[0].ulPropTag = proptag;
		/* This call is needed in case the read stream was a named prop. */
		mapi_SPropValue_array_named (obj_message, &properties_array);

		stream->proptag = properties_array.lpProps[0].ulPropTag;

		g_debug("Attempt succeeded for proptag 0x%08X (after name conversion) ", stream->proptag);

		*stream_list = g_slist_append (*stream_list, stream);
	}

cleanup:
	mapi_object_release(&obj_stream);
	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return (retval == MAPI_E_SUCCESS);
}

static gboolean
exchange_mapi_util_read_body_stream (mapi_object_t *obj_message, GSList **stream_list, gboolean getbestbody)
{
	enum MAPISTATUS			retval;
	TALLOC_CTX			*mem_ctx;
	struct SPropTagArray		*SPropTagArray;
	struct SPropValue		*lpProps;
	uint32_t			count;
	DATA_BLOB			body;
	uint8_t			editor;
	const gchar			*data = NULL;
	const bool			*rtf_in_sync;
	uint32_t			proptag = 0;

	/* sanity check */
	g_return_val_if_fail (obj_message, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	mem_ctx = talloc_init ("ExchangeMAPI_ReadBodyStream");

	/* Build the array of properties we want to fetch */
	SPropTagArray = set_SPropTagArray(mem_ctx, 0x6,
					  PR_MSG_EDITOR_FORMAT,
					  PR_BODY,
					  PR_BODY_UNICODE,
					  PR_HTML,
					  PR_RTF_COMPRESSED,
					  PR_RTF_IN_SYNC);

	lpProps = talloc_zero(mem_ctx, struct SPropValue);
	retval = GetProps(obj_message, SPropTagArray, &lpProps, &count);
	MAPIFreeBuffer(SPropTagArray);

	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetProps", GetLastError());
		return FALSE;
	}

	if (getbestbody) {
		/* Use BestBody Algo */
		retval = GetBestBody(obj_message, &editor);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetBestBody", GetLastError());
			/* On failure, fallback to Plain Text */
			editor = olEditorText;
		}

		/* HACK : We can't handle RTF. So default to HTML */
		if (editor != olEditorText && editor != olEditorHTML)
			editor = olEditorHTML;
	} else {
		const uint32_t *ui32 = (const uint32_t *) exchange_mapi_util_find_SPropVal_array_propval(lpProps, PR_MSG_EDITOR_FORMAT);
		/* if PR_MSG_EDITOR_FORMAT doesn't exist, set it to PLAINTEXT */
		editor = ui32 ? *ui32 : olEditorText;
	}

	/* initialize body DATA_BLOB */
	body.data = NULL;
	body.length = 0;

	retval = -1;
	switch (editor) {
		case olEditorText:
			if ((data = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (lpProps, PR_BODY_UNICODE)) != NULL)
				proptag = PR_BODY_UNICODE;
			else if ((data = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (lpProps, PR_BODY)) != NULL)
				proptag = PR_BODY;
			if (data) {
				gsize size = strlen(data)+1;
				body.data = talloc_memdup(mem_ctx, data, size);
				body.length = size;
				retval = MAPI_E_SUCCESS;
			}
			break;
		case olEditorHTML:
			/* Fixme : */
			/*if ((data = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (lpProps, PR_BODY_HTML_UNICODE)) != NULL) */
			/*	proptag = PR_BODY_HTML_UNICODE; */
			if ((data = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (lpProps, PR_BODY_HTML)) != NULL)
				proptag = PR_BODY_HTML;

			if (data) {
				gsize size = strlen(data)+1;
				body.data = talloc_memdup(mem_ctx, data, size);
				body.length = size;
				retval = MAPI_E_SUCCESS;
			} else if (exchange_mapi_util_read_generic_stream (obj_message, PR_HTML, stream_list)) {
				retval = MAPI_E_SUCCESS;
			}
			break;
		case olEditorRTF:
			rtf_in_sync = (const bool *) exchange_mapi_util_find_SPropVal_array_propval (lpProps, PR_RTF_IN_SYNC);
//			if (!(rtf_in_sync && *rtf_in_sync))
			{
				mapi_object_t obj_stream;

				mapi_object_init(&obj_stream);

				retval = OpenStream(obj_message, PR_RTF_COMPRESSED, STREAM_ACCESS_READ, &obj_stream);
				if (retval != MAPI_E_SUCCESS) {
					mapi_errstr("OpenStream", GetLastError());
					mapi_object_release(&obj_stream);
					break;
				}

				retval = WrapCompressedRTFStream(&obj_stream, &body);
				if (retval != MAPI_E_SUCCESS) {
					mapi_errstr("WrapCompressedRTFStream", GetLastError());
					mapi_object_release(&obj_stream);
					break;
				}

				proptag = PR_RTF_COMPRESSED;

				mapi_object_release(&obj_stream);
			}
			break;
		default:
			break;
	}

	if (retval == MAPI_E_SUCCESS && proptag) {
		ExchangeMAPIStream	*stream = g_new0 (ExchangeMAPIStream, 1);

		stream->value = g_byte_array_sized_new (body.length);
		stream->value = g_byte_array_append (stream->value, body.data, body.length);

		stream->proptag = proptag;

		*stream_list = g_slist_append (*stream_list, stream);
	}

	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return (retval == MAPI_E_SUCCESS);
}

/* Returns TRUE if all streams were written succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_write_generic_streams (mapi_object_t *obj_message, GSList *stream_list)
{
	GSList		*l;
	enum MAPISTATUS	retval;
	gboolean	status = TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	for (l = stream_list; l; l = l->next) {
		ExchangeMAPIStream	*stream = (ExchangeMAPIStream *) (l->data);
		uint32_t		total_written;
		gboolean		done = FALSE;
		mapi_object_t		obj_stream;

		mapi_object_init(&obj_stream);

		/* OpenStream on required proptag */
		retval = OpenStream(obj_message, stream->proptag, STREAM_ACCESS_READWRITE, &obj_stream);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("OpenStream", GetLastError());
			goto cleanup;
		}

		/* Set the stream size */
		retval = SetStreamSize(&obj_stream, stream->value->len);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("SetStreamSize", GetLastError());
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

			retval = WriteStream(&obj_stream,
					     &blob,
					     &cn_written);

			if (retval != MAPI_E_SUCCESS) {
				mapi_errstr("WriteStream", GetLastError());
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
		retval = CommitStream(&obj_stream);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("CommitStream", GetLastError());
			goto cleanup;
		}

	cleanup:
		if (retval != MAPI_E_SUCCESS)
			status = FALSE;
		mapi_object_release(&obj_stream);
	}

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

static gboolean
exchange_mapi_util_delete_attachments (mapi_object_t *obj_message)
{
	enum MAPISTATUS		retval;
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
	retval = GetAttachmentTable(obj_message, &obj_tb_attach);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetAttachmentTable", GetLastError());
		goto cleanup;
	}

	retval = SetColumns(&obj_tb_attach, proptags);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetColumns", GetLastError());
		goto cleanup;
	}

	retval = QueryPosition(&obj_tb_attach, NULL, &attach_count);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("QueryPosition", GetLastError());
		goto cleanup;
	}

	retval = QueryRows(&obj_tb_attach, attach_count, TBL_ADVANCE, &rows_attach);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("QueryRows", GetLastError());
		goto cleanup;
	}

	/* foreach attachment, delete by PR_ATTACH_NUM */
	for (i_row_attach = 0; i_row_attach < rows_attach.cRows; i_row_attach++) {
		const uint32_t	*num_attach;

		num_attach = (const uint32_t *) get_SPropValue_SRow_data(&rows_attach.aRow[i_row_attach], PR_ATTACH_NUM);

		retval = DeleteAttach(obj_message, *num_attach);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("DeleteAttach", GetLastError());
			status = FALSE;
		}
	}

cleanup:
	if (retval != MAPI_E_SUCCESS)
		status = FALSE;
	mapi_object_release(&obj_tb_attach);
	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

/* Returns TRUE if all attachments were written succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_set_attachments (mapi_object_t *obj_message, GSList *attach_list, gboolean remove_existing)
{
//	TALLOC_CTX	*mem_ctx;
	GSList		*l;
	enum MAPISTATUS	retval;
	gboolean	status = TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	if (remove_existing)
		exchange_mapi_util_delete_attachments (obj_message);

//	mem_ctx = talloc_init ("ExchangeMAPI_SetAttachments");

	for (l = attach_list; l; l = l->next) {
		ExchangeMAPIAttachment *attachment = (ExchangeMAPIAttachment *) (l->data);
		mapi_object_t		obj_attach;

		mapi_object_init(&obj_attach);

		/* CreateAttach */
		retval = CreateAttach(obj_message, &obj_attach);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("CreateAttach", GetLastError());
			goto cleanup;
		}

		/* SetProps */
		retval = SetProps(&obj_attach, attachment->lpProps, attachment->cValues);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("SetProps", GetLastError());
			goto cleanup;
		}

		/* If there are any streams to be set, write them. */
		exchange_mapi_util_write_generic_streams (&obj_attach, attachment->streams);

		/* message->SaveChangesAttachment() */
		retval = SaveChangesAttachment(obj_message, &obj_attach, KeepOpenReadWrite);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("SaveChangesAttachment", GetLastError());
			goto cleanup;
		}

	cleanup:
		if (retval != MAPI_E_SUCCESS)
			status = FALSE;
		mapi_object_release(&obj_attach);
	}

//	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

/* Returns TRUE if all attachments were read succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_get_attachments (mapi_object_t *obj_message, GSList **attach_list)
{
	enum MAPISTATUS		retval;
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
	retval = GetAttachmentTable(obj_message, &obj_tb_attach);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetAttachmentTable", GetLastError());
		goto cleanup;
	}

	retval = SetColumns(&obj_tb_attach, proptags);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetColumns", GetLastError());
		goto cleanup;
	}

	retval = QueryPosition(&obj_tb_attach, NULL, &attach_count);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("QueryPosition", GetLastError());
		goto cleanup;
	}

	retval = QueryRows(&obj_tb_attach, attach_count, TBL_ADVANCE, &rows_attach);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("QueryRows", GetLastError());
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

		retval = OpenAttach(obj_message, *ui32, &obj_attach);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("OpenAttach", GetLastError());
			goto loop_cleanup;
		}

		retval = GetPropsAll (&obj_attach, &properties);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetPropsAll", GetLastError());
			goto loop_cleanup;
		}

		attachment = g_new0 (ExchangeMAPIAttachment, 1);
		attachment->cValues = properties.cValues;
		attachment->lpProps = g_new0 (struct SPropValue, attachment->cValues + 1);
		for (z=0; z < properties.cValues; z++)
			cast_SPropValue (&properties.lpProps[z], &(attachment->lpProps[z]));

		/* just to get all the other streams */
		for (z=0; z < properties.cValues; z++) {
			if ((properties.lpProps[z].ulPropTag & 0xFFFF) == PT_BINARY)
				exchange_mapi_util_read_generic_stream (&obj_attach, properties.lpProps[z].ulPropTag, &(attachment->streams));
		}

		/* HACK */
		ui32 = (const uint32_t *) get_SPropValue_SRow_data(&rows_attach.aRow[i_row_attach], PR_ATTACH_METHOD);
		if (ui32 && *ui32 == ATTACH_BY_VALUE)
			exchange_mapi_util_read_generic_stream (&obj_attach, PR_ATTACH_DATA_BIN, &(attachment->streams));

		*attach_list = g_slist_append (*attach_list, attachment);

	loop_cleanup:
		if (retval != MAPI_E_SUCCESS)
			status = FALSE;
		mapi_object_release(&obj_attach);
	}

cleanup:
	if (retval != MAPI_E_SUCCESS)
		status = FALSE;
	mapi_object_release(&obj_tb_attach);
	talloc_free (mem_ctx);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return status;
}

static ExchangeMAPIGALEntry *
mapidump_PAB_gal_entry (struct SRow *aRow)
{
	const gchar	*addrtype;
	const gchar	*name;
	const gchar	*email;
	const gchar	*account;
	ExchangeMAPIGALEntry *gal_entry;

	addrtype = (const gchar *)exchange_mapi_util_find_row_propval (aRow, PR_ADDRTYPE);
	name = (const gchar *)exchange_mapi_util_find_row_propval (aRow, PR_DISPLAY_NAME_UNICODE);
	email = (const gchar *)exchange_mapi_util_find_row_propval (aRow, PR_SMTP_ADDRESS_UNICODE);
	account = (const gchar *)exchange_mapi_util_find_row_propval (aRow, PR_ACCOUNT_UNICODE);

	printf("[%s] %s:\n\tName: %-25s\n\tEmail: %-25s\n",
	       addrtype, account, name, email);

	gal_entry = g_new0 (ExchangeMAPIGALEntry, 1);
	gal_entry->name = g_strdup (name);
	gal_entry->email = g_strdup (email);

	return gal_entry;
}

gboolean
exchange_mapi_connection_get_gal (ExchangeMapiConnection *conn, GPtrArray *contacts_array)
{
	struct SPropTagArray	*SPropTagArray;
	struct SRowSet		*SRowSet;
	enum MAPISTATUS		retval;
	uint32_t		i;
	uint32_t		count;
	uint8_t			ulFlags;
	TALLOC_CTX *mem_ctx;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);

	mem_ctx = talloc_init ("ExchangeMAPI_GetGAL");

	LOCK ();

	SPropTagArray = set_SPropTagArray(mem_ctx, 0xc,
					  PR_INSTANCE_KEY,
					  PR_ENTRYID,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_SMTP_ADDRESS_UNICODE,
					  PR_DISPLAY_TYPE,
					  PR_OBJECT_TYPE,
					  PR_ADDRTYPE,
					  PR_OFFICE_TELEPHONE_NUMBER_UNICODE,
					  PR_OFFICE_LOCATION_UNICODE,
					  PR_TITLE_UNICODE,
					  PR_COMPANY_NAME_UNICODE,
					  PR_ACCOUNT_UNICODE);

	count = 0x7;
	ulFlags = TABLE_START;
	do {
		count += 0x2;
		SRowSet = NULL;
		retval = GetGALTable (priv->session, SPropTagArray, &SRowSet, count, ulFlags);
		if ((!SRowSet) || (!(SRowSet->aRow)) || retval != MAPI_E_SUCCESS) {
			UNLOCK ();
			MAPIFreeBuffer (SPropTagArray);
			return FALSE;
		}
		if (SRowSet->cRows) {
			for (i = 0; i < SRowSet->cRows; i++) {
				ExchangeMAPIGALEntry *gal_entry = g_new0 (ExchangeMAPIGALEntry, 1);
				gal_entry = mapidump_PAB_gal_entry(&SRowSet->aRow[i]);
				g_ptr_array_add(contacts_array, gal_entry);
			}
		}
		ulFlags = TABLE_CUR;
		MAPIFreeBuffer(SRowSet);
	} while (SRowSet->cRows == count);
	mapi_errstr("GetPABTable", GetLastError());

	MAPIFreeBuffer(SPropTagArray);

	UNLOCK ();

	return TRUE;

}

/* Returns TRUE if all recipients were read succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_get_recipients (mapi_object_t *obj_message, GSList **recip_list)
{
	enum MAPISTATUS		retval;
	struct SPropTagArray	proptags;
	struct SRowSet		rows_recip;
	uint32_t		i_row_recip;
	gboolean		status = TRUE;

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	/* fetch recipient table */
	retval = GetRecipientTable(obj_message, &rows_recip, &proptags);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetRecipientTable", GetLastError());
		goto cleanup;
	}

	for (i_row_recip = 0; i_row_recip < rows_recip.cRows; i_row_recip++) {
		ExchangeMAPIRecipient	*recipient = g_new0 (ExchangeMAPIRecipient, 1);

		recipient->mem_ctx = talloc_init ("ExchangeMAPI_GetRecipients");

		recipient->email_id = talloc_steal (recipient->mem_ctx, (const gchar *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_SMTP_ADDRESS_UNICODE));
		/* fallback */
		if (!recipient->email_id) {
			const gchar *addrtype = talloc_steal (recipient->mem_ctx, (const gchar *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_ADDRTYPE));
			if (addrtype && !g_ascii_strcasecmp(addrtype, "SMTP"))
				recipient->email_id = talloc_steal (recipient->mem_ctx, (const gchar *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_EMAIL_ADDRESS_UNICODE));
		}
		/* fail */
		if (!recipient->email_id) {
			g_debug ("%s: %s() - object has a recipient without a PR_SMTP_ADDRESS ", G_STRLOC, G_STRFUNC);
			mapidump_SRow (&(rows_recip.aRow[i_row_recip]), " ");
		}

		recipient->out_SRow.ulAdrEntryPad = rows_recip.aRow[i_row_recip].ulAdrEntryPad;
		recipient->out_SRow.cValues = rows_recip.aRow[i_row_recip].cValues;
		recipient->out_SRow.lpProps = talloc_steal ((TALLOC_CTX *)recipient->mem_ctx, rows_recip.aRow[i_row_recip].lpProps);

		*recip_list = g_slist_append (*recip_list, recipient);
	}

cleanup:
	if (retval != MAPI_E_SUCCESS)
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
		struct Binary_r *oneoff_eid;
		struct SPropValue sprop;
		const gchar *dn = NULL, *email = NULL;

		dn = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (recipient->in.ext_lpProps, PR_DISPLAY_NAME_UNICODE);
		dn = (dn) ? dn : "";
		email = (const gchar *) exchange_mapi_util_find_SPropVal_array_propval (recipient->in.ext_lpProps, PR_SMTP_ADDRESS_UNICODE);
		email = (email) ? email : "";
		oneoff_eid = exchange_mapi_util_entryid_generate_oneoff (mem_ctx, dn, email, FALSE);
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
exchange_mapi_util_modify_recipients (ExchangeMapiConnection *conn, TALLOC_CTX *mem_ctx, mapi_object_t *obj_message , GSList *recipients, gboolean remove_existing)
{
	enum MAPISTATUS	retval;
	struct SPropTagArray	*SPropTagArray = NULL;
	struct SRowSet		*SRowSet = NULL;
	struct SPropTagArray	*FlagList = NULL;
	GSList			*l;
	const gchar		**users = NULL;
	uint32_t		i, j, count = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	SPropTagArray = set_SPropTagArray(mem_ctx, 0xA,
					  PR_ENTRYID,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_OBJECT_TYPE,
					  PR_DISPLAY_TYPE,
					  PR_TRANSMITTABLE_DISPLAY_NAME_UNICODE,
					  PR_EMAIL_ADDRESS_UNICODE,
					  PR_ADDRTYPE,
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
	retval = ResolveNames (priv->session, users, SPropTagArray, &SRowSet, &FlagList, MAPI_UNICODE);
	UNLOCK ();
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("ResolveNames", GetLastError());
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
		RemoveAllRecipients (obj_message);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("RemoveAllRecipients", GetLastError());
			goto cleanup;
		}
	}

	/* Modify the recipient table */
	retval = ModifyRecipients (obj_message, SRowSet);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("ModifyRecpients", GetLastError());
		goto cleanup;
	}

cleanup:
	g_free (users);

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return TRUE;
}

GSList *
exchange_mapi_connection_check_restriction (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SRestriction *res)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_table;
	struct SPropTagArray *SPropTagArray, *GetPropsTagArray;
	struct SRowSet SRowSet;
	uint32_t count, i;
	GSList *mids = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, NULL);
	g_return_val_if_fail (priv->session != NULL, NULL);

	g_debug("%s: Entering %s: folder-id %016" G_GINT64_MODIFIER "X ", G_STRLOC, G_STRFUNC, fid);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_CheckRestriction");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	/* Attempt to open the folder */
	retval = OpenFolder(&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Get a handle on the container */
	retval = GetContentsTable(&obj_folder, &obj_table, 0, NULL);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetContentsTable", GetLastError());
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
	retval = SetColumns(&obj_table, SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetColumns", GetLastError());
		goto cleanup;
	}

	if (res) {
		/* Applying any restriction that are set. */
		retval = Restrict(&obj_table, res, NULL);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("Restrict", GetLastError());
			goto cleanup;
		}
	}

	/* Number of items in the container */
	retval = QueryPosition(&obj_table, NULL, &count);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetRowCount", GetLastError());
		goto cleanup;
	}

	/* Fill the table columns with data from the rows */
	retval = QueryRows(&obj_table, count, TBL_ADVANCE, &SRowSet);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("QueryRows", GetLastError());
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
					const uint32_t *GetPropsList, const uint16_t cn_props,
					BuildNameID build_name_id, gpointer build_name_data,
					FetchCallback cb, gpointer data,
					guint32 options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_table;
	struct SPropTagArray *SPropTagArray, *GetPropsTagArray = NULL;
	struct SRowSet SRowSet;
	uint32_t count, i, cursor_pos = 0;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s: folder-id %016" G_GINT64_MODIFIER "X ", G_STRLOC, G_STRFUNC, fid);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_FetchItems");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	if ((options & MAPI_OPTIONS_USE_PFSTORE) != 0) {
		if (!ensure_public_store (priv))
			goto cleanup;
	}

	/* Attempt to open the folder */
	retval = OpenFolder (((options & MAPI_OPTIONS_USE_PFSTORE) != 0 ? &priv->public_store : &priv->msg_store), fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Get a handle on the container */
	retval = GetContentsTable(&obj_folder, &obj_table, TableFlags_UseUnicode, NULL);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetContentsTable", GetLastError());
		goto cleanup;
	}

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x4,
					  PR_FID,
					  PR_MID,
					  PR_LAST_MODIFICATION_TIME,
					  PR_HASATTACH);

	/* Set primary columns to be fetched */
	retval = SetColumns(&obj_table, SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetColumns", GetLastError());
		goto cleanup;
	}

	if (res) {
		/* Applying any restriction that are set. */
		retval = Restrict(&obj_table, res, NULL);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("Restrict", GetLastError());
			goto cleanup;
		}
	}

	if (sort_order) {
		retval = SortTable(&obj_table, sort_order);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("SortTable", GetLastError());
			goto cleanup;
		}
	}

	if ((GetPropsList && (cn_props > 0)) || build_name_id) {
		struct SPropTagArray *NamedPropsTagArray;
		uint32_t m;
		struct mapi_nameid *nameid;

		nameid = mapi_nameid_new(mem_ctx);
		NamedPropsTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

		NamedPropsTagArray->cValues = 0;
		/* Add named props using callback */
		if (build_name_id) {
			if (!build_name_id (nameid, build_name_data)) {
				g_debug ("%s: (%s): Could not build named props ",
					 G_STRLOC, G_STRFUNC);
				goto GetProps_cleanup;
			}

			retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, NamedPropsTagArray);
			if (retval != MAPI_E_SUCCESS) {
				mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
				goto GetProps_cleanup;
			}
		}

 GetProps_cleanup:
		for (m = 0; m < NamedPropsTagArray->cValues; m++) {
			if (G_UNLIKELY (!GetPropsTagArray))
				GetPropsTagArray = set_SPropTagArray (mem_ctx, 0x1,
								      NamedPropsTagArray->aulPropTag[m]);
			else
				SPropTagArray_add (mem_ctx, GetPropsTagArray,
						   NamedPropsTagArray->aulPropTag[m]);
		}

		for (m = 0; m < cn_props; m++) {
			if (G_UNLIKELY (!GetPropsTagArray))
				GetPropsTagArray = set_SPropTagArray (mem_ctx, 0x1,
								      GetPropsList[m]);
			else
				SPropTagArray_add (mem_ctx, GetPropsTagArray,
						   GetPropsList[m]);
		}

		MAPIFreeBuffer (NamedPropsTagArray);
		talloc_free (nameid);
	}

	/* Note : We maintain a cursor position. count parameter in QueryRows */
	/* is more of a request and not gauranteed  */
	do {
		/* Number of items in the container */
		retval = QueryPosition(&obj_table, &cursor_pos, &count);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("QueryPosition", GetLastError());
			goto cleanup;
		}

		/* Fill the table columns with data from the rows */
		retval = QueryRows(&obj_table, count, TBL_ADVANCE, &SRowSet);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("QueryRows", GetLastError());
			goto cleanup;
		}

		for (i = 0; i < SRowSet.cRows; i++) {
			mapi_object_t obj_message;
			struct mapi_SPropValue_array properties_array = {0};
			const mapi_id_t *pfid;
			const mapi_id_t	*pmid;
			const bool *has_attach = NULL;
			GSList *attach_list = NULL;
			GSList *recip_list = NULL;
			GSList *stream_list = NULL;
			gboolean cb_retval = false;

			mapi_object_init(&obj_message);

			pfid = (const uint64_t *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_FID);
			pmid = (const uint64_t *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_MID);

			has_attach = (const bool *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_HASATTACH);

			if (options & MAPI_OPTIONS_DONT_OPEN_MESSAGE)
				goto relax;

			retval = OpenMessage(&obj_folder, *pfid, *pmid, &obj_message, 0);
			if (retval != MAPI_E_SUCCESS) {
				mapi_errstr("OpenMessage", GetLastError());
				goto loop_cleanup;
			}

			if (has_attach && *has_attach && (MAPI_OPTIONS_FETCH_ATTACHMENTS & options)) {
				exchange_mapi_util_get_attachments (&obj_message, &attach_list);
			}

			if (options & MAPI_OPTIONS_FETCH_RECIPIENTS)
				exchange_mapi_util_get_recipients (&obj_message, &recip_list);

			/* get the main body stream no matter what */
			if (options & MAPI_OPTIONS_FETCH_BODY_STREAM)
				exchange_mapi_util_read_body_stream (&obj_message, &stream_list,
								     options & MAPI_OPTIONS_GETBESTBODY);

			if (GetPropsTagArray && GetPropsTagArray->cValues) {
				struct SPropValue *lpProps;
				struct SPropTagArray *tags;
				uint32_t prop_count = 0, k;
				/* we need to make a local copy of the tag array
				 * since GetProps will modify the array on any
				 * errors */
				tags = set_SPropTagArray (mem_ctx, 0x1, GetPropsTagArray->aulPropTag[0]);
				for (k = 1; k < GetPropsTagArray->cValues; k++)
					SPropTagArray_add (mem_ctx, tags, GetPropsTagArray->aulPropTag[k]);
				retval = GetProps (&obj_message, tags, &lpProps, &prop_count);
				MAPIFreeBuffer (tags);
				properties_array.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue,
									 prop_count + 1);
				properties_array.cValues = prop_count;
				for (k=0; k < prop_count; k++)
					cast_mapi_SPropValue(&properties_array.lpProps[k], &lpProps[k]);

			} else
				retval = GetPropsAll (&obj_message, &properties_array);
 relax:
			if (retval == MAPI_E_SUCCESS) {
				FetchItemsCallbackData *item_data;
				uint32_t z;

				if ((options & MAPI_OPTIONS_DONT_OPEN_MESSAGE) == 0) {
					/* just to get all the other streams */
					for (z=0; z < properties_array.cValues; z++) {
						if ((properties_array.lpProps[z].ulPropTag & 0xFFFF) == PT_BINARY &&
						    (options & MAPI_OPTIONS_FETCH_GENERIC_STREAMS))
						exchange_mapi_util_read_generic_stream (&obj_message, properties_array.lpProps[z].ulPropTag, &stream_list);
					}

					mapi_SPropValue_array_named(&obj_message, &properties_array);
				}

				/* NOTE: stream_list, recipient_list and attach_list
				   should be freed by the callback */
				item_data = g_new0 (FetchItemsCallbackData, 1);
				item_data->conn = conn;
				item_data->fid = *pfid;
				item_data->mid = *pmid;
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

			if (GetPropsTagArray && GetPropsTagArray->cValues)
				talloc_free (properties_array.lpProps);

		loop_cleanup:
			if ((options & MAPI_OPTIONS_DONT_OPEN_MESSAGE) == 0)
				mapi_object_release (&obj_message);

			if (!cb_retval) break;
		}

	} while (cursor_pos < count);

	result = TRUE;

 cleanup:
	if (GetPropsTagArray)
		MAPIFreeBuffer (GetPropsTagArray);
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_table);
	talloc_free (mem_ctx);
	UNLOCK ();

	g_debug("%s: Leaving %s: folder-id %016" G_GINT64_MODIFIER "X ", G_STRLOC, G_STRFUNC, fid);

	return result;
}

gboolean
exchange_mapi_connection_fetch_item (ExchangeMapiConnection *conn, mapi_id_t fid, mapi_id_t mid,
				     const uint32_t *GetPropsList, const uint16_t cn_props,
				     BuildNameID build_name_id, gpointer build_name_data,
				     FetchCallback cb, gpointer data,
				     guint32 options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct mapi_SPropValue_array properties_array;
	struct SPropTagArray *GetPropsTagArray;
	GSList *attach_list = NULL;
	GSList *recip_list = NULL;
	GSList *stream_list = NULL;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s: folder-id %016" G_GINT64_MODIFIER "X message-id %016" G_GINT64_MODIFIER "X",
				G_STRLOC, G_STRFUNC, fid, mid);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_FetchItem");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	if ((options & MAPI_OPTIONS_USE_PFSTORE) != 0) {
		if (!ensure_public_store (priv))
			goto cleanup;
	}

	/* Attempt to open the folder */
	retval = OpenFolder (((options & MAPI_OPTIONS_USE_PFSTORE) != 0 ? &priv->public_store : &priv->msg_store), fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	GetPropsTagArray = talloc_zero(mem_ctx, struct SPropTagArray);
	GetPropsTagArray->cValues = 0;

	if ((GetPropsList && (cn_props > 0)) || build_name_id) {
		struct SPropTagArray *NamedPropsTagArray;
		uint32_t m, n=0;
		struct mapi_nameid *nameid;

		nameid = mapi_nameid_new(mem_ctx);
		NamedPropsTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

		NamedPropsTagArray->cValues = 0;
		/* Add named props using callback */
		if (build_name_id) {
			if (!build_name_id (nameid, build_name_data)) {
				g_debug ("%s: (%s): Could not build named props ", G_STRLOC, G_STRFUNC);
				goto GetProps_cleanup;
			}

			retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, NamedPropsTagArray);
			if (retval != MAPI_E_SUCCESS) {
				mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
				goto GetProps_cleanup;
			}
		}

		GetPropsTagArray->cValues = (uint32_t) (cn_props + NamedPropsTagArray->cValues);
		GetPropsTagArray->aulPropTag = talloc_zero_array (mem_ctx, uint32_t, GetPropsTagArray->cValues + 1);

		for (m = 0; m < NamedPropsTagArray->cValues; m++, n++)
			GetPropsTagArray->aulPropTag[n] = NamedPropsTagArray->aulPropTag[m];

		for (m = 0; m < cn_props; m++, n++)
			GetPropsTagArray->aulPropTag[n] = GetPropsList[m];

	GetProps_cleanup:
			MAPIFreeBuffer (NamedPropsTagArray);
			talloc_free (nameid);
	}

	/* Open the item */
	retval = OpenMessage(&obj_folder, fid, mid, &obj_message, 0x0);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMessage", GetLastError());
		goto cleanup;
	}

	/* Fetch attachments */
	if (options & MAPI_OPTIONS_FETCH_ATTACHMENTS)
		exchange_mapi_util_get_attachments (&obj_message, &attach_list);

	/* Fetch recipients */
	if (options & MAPI_OPTIONS_FETCH_RECIPIENTS)
		exchange_mapi_util_get_recipients (&obj_message, &recip_list);

	/* get the main body stream no matter what */
	if (options & MAPI_OPTIONS_FETCH_BODY_STREAM)
		exchange_mapi_util_read_body_stream (&obj_message, &stream_list,
			options & MAPI_OPTIONS_GETBESTBODY);

	if (GetPropsTagArray->cValues) {
		struct SPropValue *lpProps;
		uint32_t prop_count = 0, k;

		lpProps = talloc_zero(mem_ctx, struct SPropValue);
		retval = GetProps (&obj_message, GetPropsTagArray, &lpProps, &prop_count);

		/* Conversion from SPropValue to mapi_SPropValue. (no padding here) */
		properties_array.cValues = prop_count;
		properties_array.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, prop_count + 1);
		for (k=0; k < prop_count; k++)
			cast_mapi_SPropValue(&properties_array.lpProps[k], &lpProps[k]);

	} else
		retval = GetPropsAll (&obj_message, &properties_array);

	if (retval == MAPI_E_SUCCESS) {
		uint32_t z;

		/* just to get all the other streams */
		for (z=0; z < properties_array.cValues; z++)
			if ((properties_array.lpProps[z].ulPropTag & 0xFFFF) == PT_BINARY && (options & MAPI_OPTIONS_FETCH_GENERIC_STREAMS))
				exchange_mapi_util_read_generic_stream (&obj_message, properties_array.lpProps[z].ulPropTag, &stream_list);

		mapi_SPropValue_array_named(&obj_message, &properties_array);
	}

	/* Release the objects so that the callback may use the store. */
	mapi_object_release(&obj_message);
	mapi_object_release(&obj_folder);

	if (retval == MAPI_E_SUCCESS) {
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

//	if (GetPropsTagArray->cValues)
//		talloc_free (properties_array.lpProps);

	result = TRUE;

cleanup:
	if (!result) {
		mapi_object_release(&obj_message);
		mapi_object_release(&obj_folder);
	}
	talloc_free (mem_ctx);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

mapi_id_t
exchange_mapi_connection_create_folder (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t pfid, const gchar *name)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_folder;
	mapi_object_t obj_top;
	struct SPropValue vals[1];
	const gchar *type;
	mapi_id_t fid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, 0);
	g_return_val_if_fail (priv->session != NULL, 0);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mapi_object_init(&obj_top);
	mapi_object_init(&obj_folder);

	/* We now open the top/parent folder */
	retval = OpenFolder (&priv->msg_store, pfid, &obj_top);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Attempt to create the folder */
	retval = CreateFolder(&obj_top, FOLDER_GENERIC, name, "Created using Evolution/LibMAPI", OPEN_IF_EXISTS, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("CreateFolder", GetLastError());
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

	retval = SetProps(&obj_folder, vals, 1);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetProps", GetLastError());
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
exchange_mapi_connection_empty_folder (ExchangeMapiConnection *conn, mapi_id_t fid)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_folder;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mapi_object_init (&obj_folder);

	/* Attempt to open the folder to be emptied */
	retval = OpenFolder(&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Empty the contents of the folder */
	retval = EmptyFolder(&obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("EmptyFolder", GetLastError());
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
exchange_mapi_connection_remove_folder (ExchangeMapiConnection *conn, mapi_id_t fid)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_top;
	mapi_object_t obj_folder;
	ExchangeMAPIFolder *folder;
	gboolean result = FALSE;
	GSList *l;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	folder = NULL;
	for (l = exchange_mapi_connection_peek_folders_list (conn); l && !folder; l = l->next) {
		folder = l->data;

		if (!folder || !folder->folder_id)
			folder = NULL;
	}

	g_return_val_if_fail (folder != NULL, FALSE);

	LOCK ();
	mapi_object_init(&obj_top);
	mapi_object_init(&obj_folder);

	/* FIXME: If the folder has sub-folders, open each of them in turn, empty them and delete them.
	 * Note that this has to be done recursively, for the sub-folders as well.
	 */

	/* Attempt to open the folder to be removed */
	retval = OpenFolder(&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Empty the contents of the folder */
	retval = EmptyFolder(&obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("EmptyFolder", GetLastError());
		goto cleanup;
	}

	g_debug("Folder with id %016" G_GINT64_MODIFIER "X was emptied ", fid);

	/* Attempt to open the top/parent folder */
	retval = OpenFolder (&priv->msg_store, folder->parent_folder_id, &obj_top);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Call DeleteFolder on the folder to be removed */
	retval = DeleteFolder(&obj_top, fid, DEL_FOLDERS, NULL);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("DeleteFolder", GetLastError());
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
exchange_mapi_connection_rename_folder (ExchangeMapiConnection *conn, mapi_id_t fid, const gchar *new_name)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_folder;
	struct SPropValue *props = NULL;
	TALLOC_CTX *mem_ctx;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_RenameFolder");
	mapi_object_init(&obj_folder);

	/* Open the folder to be renamed */
	retval = OpenFolder (&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	props = talloc_zero(mem_ctx, struct SPropValue);
	set_SPropValue_proptag (props, PR_DISPLAY_NAME_UNICODE, new_name);

	retval = SetProps(&obj_folder, props, 1);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetProps", GetLastError());
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
exchange_mapi_connection_move_folder (ExchangeMapiConnection *conn, mapi_id_t src_fid, mapi_id_t src_parent_fid, mapi_id_t des_fid, const gchar *new_name)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_src, obj_src_parent, obj_des;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_return_val_if_fail (src_fid != 0, FALSE);
	g_return_val_if_fail (src_parent_fid != 0, FALSE);
	g_return_val_if_fail (des_fid != 0, FALSE);
	g_return_val_if_fail (new_name != NULL, FALSE);
	g_return_val_if_fail (strchr (new_name, '/') == NULL, FALSE);

	LOCK ();

	mapi_object_init (&obj_src);
	mapi_object_init (&obj_src_parent);
	mapi_object_init (&obj_des);

	retval = OpenFolder (&priv->msg_store, src_fid, &obj_src);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr ("OpenFolder src_fid", GetLastError());
		goto cleanup;
	}

	retval = OpenFolder (&priv->msg_store, src_parent_fid, &obj_src_parent);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr ("OpenFolder src_parent_fid", GetLastError());
		goto cleanup;
	}

	retval = OpenFolder (&priv->msg_store, des_fid, &obj_des);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr ("OpenFolder des_fid", GetLastError());
		goto cleanup;
	}

	retval = MoveFolder (&obj_src, &obj_src_parent, &obj_des, (gchar *)new_name, TRUE);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr ("MoveFolder", GetLastError());
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

struct SPropTagArray *
exchange_mapi_connection_resolve_named_props (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid,
					BuildNameID build_name_id, gpointer ni_data)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray, *ret_array = NULL;
	uint32_t i;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, NULL);
	g_return_val_if_fail (priv->session != NULL, NULL);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_ResolveNamedProps");
	mapi_object_init(&obj_folder);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder (&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Add named props using callback */
	if (build_name_id) {
		if (!build_name_id (nameid, ni_data)) {
			g_debug ("%s: (%s): Could not build named props ", G_STRLOC, G_STRFUNC);
			goto cleanup;
		}

		retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, SPropTagArray);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
			goto cleanup;
		}
	}

	ret_array = g_new0 (struct SPropTagArray, 1);
	ret_array->aulPropTag = g_new0 (enum MAPITAGS, SPropTagArray->cValues);
	ret_array->cValues = SPropTagArray->cValues;
	for (i = 0; i < SPropTagArray->cValues; ++i)
		ret_array->aulPropTag[i] = SPropTagArray->aulPropTag[i];

cleanup:
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return ret_array;
}

struct SPropTagArray *
exchange_mapi_connection_resolve_named_prop (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, uint16_t lid, const gchar *OLEGUID)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray, *ret_array = NULL;
	uint32_t i;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, NULL);
	g_return_val_if_fail (priv->session != NULL, NULL);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_ResolveNamedProp");
	mapi_object_init(&obj_folder);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder (&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	mapi_nameid_lid_add (nameid, lid, OLEGUID);

	retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
		goto cleanup;
	}

	ret_array = g_new0 (struct SPropTagArray, 1);
	ret_array->aulPropTag = g_new0 (enum MAPITAGS, SPropTagArray->cValues);
	ret_array->cValues = SPropTagArray->cValues;
	for (i = 0; i < SPropTagArray->cValues; ++i)
		ret_array->aulPropTag[i] = SPropTagArray->aulPropTag[i];

cleanup:
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return ret_array;
}

uint32_t
exchange_mapi_connection_create_named_prop (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid,
				      const gchar *named_prop_name, uint32_t ptype)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	struct GUID guid;
	struct MAPINAMEID *nameid;
	struct SPropTagArray *SPropTagArray;
	uint32_t propID = 0x00000000;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, propID);
	g_return_val_if_fail (priv->session != NULL, propID);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_CreateNamedProp");
	mapi_object_init(&obj_folder);

	GUID_from_string(PS_INTERNET_HEADERS, &guid);
	nameid = talloc_zero(mem_ctx, struct MAPINAMEID);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	nameid[0].lpguid = guid;
	nameid[0].ulKind = MNID_STRING;
	nameid[0].kind.lpwstr.Name = named_prop_name;

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder (&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Fetch an ID from the server */
	retval = GetIDsFromNames(&obj_folder, 1, &nameid[0], MAPI_CREATE, &SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetIDsFromNames", GetLastError());
		goto cleanup;
	}

	propID = SPropTagArray->aulPropTag[0] | ptype;

cleanup:
	mapi_object_release(&obj_folder);
	talloc_free(mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return propID;
}

mapi_id_t
exchange_mapi_connection_get_default_folder_id (ExchangeMapiConnection *conn, uint32_t olFolder)
{
	enum MAPISTATUS retval;
	mapi_id_t fid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, 0);
	g_return_val_if_fail (priv->session != NULL, 0);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	retval = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetDefaultFolder", GetLastError());
		goto cleanup;
	}

cleanup:
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return (retval == MAPI_E_SUCCESS ? fid : 0);
}

mapi_id_t
exchange_mapi_connection_create_item (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid,
			   BuildNameID build_name_id, gpointer ni_data,
			   BuildProps build_props, gpointer p_data,
			   GSList *recipients, GSList *attachments, GSList *generic_streams,
			   uint32_t options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray;
	struct SPropValue *props = NULL;
	gint propslen = 0;
	mapi_id_t mid = 0;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, 0);
	g_return_val_if_fail (priv->session != NULL, 0);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_CreateItem");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder (&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Create the item */
	retval = CreateMessage(&obj_folder, &obj_message);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("CreateMessage", GetLastError());
		goto cleanup;
	}

//	d(mapi_object_debug (&obj_message));

	/* Add named props using callback */
	if (build_name_id) {
		if (!build_name_id (nameid, ni_data)) {
			g_debug ("%s: (%s): Could not build named props ", G_STRLOC, G_STRFUNC);
			goto cleanup;
		}

		retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, SPropTagArray);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
			goto cleanup;
		}
	}

	/* Add regular props using callback */
	if (build_props) {
		propslen = build_props (&props, SPropTagArray, p_data);
		if (propslen < 1) {
			g_debug ("%s: (%s): build_props failed! propslen = %d ", G_STRLOC, G_STRFUNC, propslen);
			goto cleanup;
		}
	}

	/* set properties for the item */
	retval = SetProps(&obj_message, props, propslen);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetProps", GetLastError());
		goto cleanup;
	}

	if (generic_streams) {
		exchange_mapi_util_write_generic_streams (&obj_message, generic_streams);
	}

	/* Set attachments if any */
	if (attachments) {
		exchange_mapi_util_set_attachments (&obj_message, attachments, FALSE);
	}

	/* Set recipients if any */
	if (recipients) {
		exchange_mapi_util_modify_recipients (conn, mem_ctx, &obj_message, recipients, FALSE);
	}

	/* Finally, save all changes */
	retval = SaveChangesMessage(&obj_folder, &obj_message, KeepOpenReadWrite);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SaveChangesMessage", GetLastError());
		goto cleanup;
	}

	if (recipients && !(options & MAPI_OPTIONS_DONT_SUBMIT)) {
		/* Mark message as ready to be sent */
		retval = SubmitMessage(&obj_message);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("SubmitMessage", GetLastError());

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

				retval = DeleteMessage (&obj_folder, &mid, 1);
				if (retval != MAPI_E_SUCCESS) {
					mapi_errstr ("DeleteMessage", GetLastError ());
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
			   BuildNameID build_name_id, gpointer ni_data,
			   BuildProps build_props, gpointer p_data,
			   GSList *recipients, GSList *attachments, GSList *generic_streams,
			   uint32_t options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray;
	struct SPropValue *props = NULL;
	gint propslen = 0;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_ModifyItem");
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder (&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Open the item to be modified */
	retval = OpenMessage(&obj_folder, fid, mid, &obj_message, MAPI_MODIFY);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMessage", GetLastError());
		goto cleanup;
	}

//	d(mapi_object_debug (&obj_message));

	/* Add named props using callback */
	if (build_name_id) {
		if (!build_name_id (nameid, ni_data)) {
			g_debug ("%s: (%s): Could not build named props ", G_STRLOC, G_STRFUNC);
			goto cleanup;
		}

		retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, SPropTagArray);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
			goto cleanup;
		}
	}

	/* Add regular props using callback */
	if (build_props) {
		propslen = build_props (&props, SPropTagArray, p_data);
		if (propslen < 1) {
			g_debug ("%s: (%s): Could not build props ",
					G_STRLOC, G_STRFUNC);
			goto cleanup;
		}
	}

	/* set properties for the item */
	retval = SetProps(&obj_message, props, propslen);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetProps", GetLastError());
		goto cleanup;
	}

	if (generic_streams) {
		exchange_mapi_util_write_generic_streams (&obj_message, generic_streams);
	}

	/* Set attachments if any */
	if (attachments) {
		exchange_mapi_util_set_attachments (&obj_message, attachments, TRUE);
	} else {
		exchange_mapi_util_delete_attachments (&obj_message);
	}

	/* Set recipients if any */
	if (recipients) {
		exchange_mapi_util_modify_recipients (conn, mem_ctx, &obj_message, recipients, TRUE);
	}

	/* Finally, save all changes */
	retval = SaveChangesMessage(&obj_folder, &obj_message, KeepOpenReadWrite);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SaveChangesMessage", GetLastError());
		goto cleanup;
	}

	if (recipients && !(options & MAPI_OPTIONS_DONT_SUBMIT)) {
		/* Mark message as ready to be sent */
		retval = SubmitMessage(&obj_message);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("SubmitMessage", GetLastError());
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
exchange_mapi_connection_set_flags (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, GSList *mids, uint32_t flag, guint32 options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	uint32_t i;
	mapi_id_t *id_messages;
	GSList *tmp = mids;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_SetFlags");
	mapi_object_init(&obj_folder);

	id_messages = talloc_array(mem_ctx, mapi_id_t, g_slist_length (mids));
	for (i=0; tmp; tmp=tmp->next, i++)
		id_messages[i] = *((mapi_id_t *)tmp->data);

	if ((options & MAPI_OPTIONS_USE_PFSTORE) != 0) {
		if (!ensure_public_store (priv))
			goto cleanup;
	}

	/* Attempt to open the folder */
	retval = OpenFolder (((options & MAPI_OPTIONS_USE_PFSTORE) != 0 ? &priv->public_store : &priv->msg_store), fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	retval = SetReadFlags(&obj_folder, flag, i, id_messages);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetReadFlags", GetLastError());
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
mapi_move_items (mapi_object_t *msg_store, mapi_id_t src_fid, mapi_id_t dest_fid, GSList *mid_list, gboolean do_copy)
{
	enum MAPISTATUS	retval;
	mapi_object_t obj_folder_src;
	mapi_object_t obj_folder_dst;
	mapi_id_array_t msg_id_array;
	GSList *l;
	gboolean result = FALSE;

	g_return_val_if_fail (msg_store != NULL, FALSE);

	mapi_object_init(&obj_folder_src);
	mapi_object_init(&obj_folder_dst);
	mapi_id_array_init(&msg_id_array);

	for (l = mid_list; l != NULL; l = g_slist_next (l))
		mapi_id_array_add_id (&msg_id_array, *((mapi_id_t *)l->data));

	retval = OpenFolder (msg_store, src_fid, &obj_folder_src);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder - source folder", GetLastError());
		goto cleanup;
	}

	retval = OpenFolder (msg_store, dest_fid, &obj_folder_dst);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder - destination folder", GetLastError());
		goto cleanup;
	}

	retval = MoveCopyMessages(&obj_folder_src, &obj_folder_dst, &msg_id_array, do_copy);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("MoveCopyMessages", GetLastError());
		goto cleanup;
	}

	result = TRUE;

cleanup:
	mapi_id_array_release(&msg_id_array);
	mapi_object_release(&obj_folder_dst);
	mapi_object_release(&obj_folder_src);

	return result;
}

gboolean
exchange_mapi_connection_copy_items (ExchangeMapiConnection *conn, mapi_id_t src_fid, mapi_id_t dest_fid, GSList *mids)
{
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	result = mapi_move_items (&priv->msg_store, src_fid, dest_fid, mids, TRUE);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_move_items (ExchangeMapiConnection *conn, mapi_id_t src_fid, mapi_id_t dest_fid, GSList *mids)
{
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	result = mapi_move_items (&priv->msg_store, src_fid, dest_fid, mids, FALSE);
	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_remove_items (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, GSList *mids)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_folder;
	uint32_t i;
	mapi_id_t *id_messages;
	GSList *tmp = mids;
	gboolean result = FALSE;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();

	mem_ctx = talloc_init("ExchangeMAPI_RemoveItems");
	mapi_object_init(&obj_folder);

	id_messages = talloc_array(mem_ctx, mapi_id_t, g_slist_length (mids));
	for (i=0; tmp; tmp=tmp->next, i++) {
		struct id_list *data = tmp->data;
		id_messages[i] = data->id;
	}

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder (&priv->msg_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder (&priv->msg_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Delete the messages from the folder */
	retval = DeleteMessage(&obj_folder, id_messages, i);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("DeleteMessage", GetLastError());
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
get_child_folders(TALLOC_CTX *mem_ctx, ExchangeMAPIFolderCategory folder_hier, mapi_object_t *parent,
		  mapi_id_t folder_id, GSList **mapi_folders, gint32 depth)
{
	enum MAPISTATUS		retval;
	mapi_object_t		obj_folder;
	mapi_object_t		obj_table;
	struct SPropTagArray	*SPropTagArray = NULL;
	struct SRowSet		rowset;
	uint32_t		i, row_count = 0;
	gboolean		result = TRUE;

	/* sanity check */
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (parent != NULL, FALSE);

	/*We reached the depth we wanted.*/
	if (!depth ) return true;

	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	/* Attempt to open the folder */
	retval = OpenFolder(parent, folder_id, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Get the hierarchy table */
	retval = GetHierarchyTable(&obj_folder, &obj_table, 0, &row_count);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetHierarchyTable", GetLastError());
		goto cleanup;
	}

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x7,
					  PR_FID,
					  PR_CONTAINER_CLASS,
					  PR_DISPLAY_NAME_UNICODE,
					  PR_CONTENT_UNREAD,
					  PR_CONTENT_COUNT,
					  PR_MESSAGE_SIZE,
					  PR_FOLDER_CHILD_COUNT);

	retval = SetColumns(&obj_table, SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetColumns", GetLastError());
		goto cleanup;
	}

	/* Fill the table columns with data from the rows */
	retval = QueryRows(&obj_table, row_count, TBL_ADVANCE, &rowset);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("QueryRows", GetLastError());
		goto cleanup;
	}

	depth--;

	for (i = 0; i < rowset.cRows; i++) {
		ExchangeMAPIFolder *folder = NULL;
		gchar *newname = NULL;

		const mapi_id_t *fid = (const mapi_id_t *)exchange_mapi_util_find_row_propval (&rowset.aRow[i], PR_FID);
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

		folder = exchange_mapi_folder_new (newname, class, folder_hier, *fid, folder_id,
						   child ? *child : 0, unread ? *unread : 0, total ? *total : 0);

		folder->size = folder_size ? *folder_size : 0;

		*mapi_folders = g_slist_prepend (*mapi_folders, folder);

		if (child && *child && (depth != 0))
			result = (result && get_child_folders(mem_ctx, folder_hier, &obj_folder, *fid,
							      mapi_folders, depth));

		g_free (newname);
	}

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
static void
mapi_get_ren_additional_fids (mapi_object_t *obj_store, GHashTable **folder_list)
{
	mapi_id_t inbox_id, fid;
	mapi_object_t obj_folder_inbox;
	struct SPropTagArray *SPropTagArray;
	struct SPropValue *lpProps;
	struct SRow aRow;
	const struct BinaryArray_r *entryids;
	struct Binary_r entryid;
	enum MAPISTATUS retval;

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
	retval = GetDefaultFolder(obj_store, &inbox_id, olFolderInbox);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetDefaultFolder", GetLastError());
		goto cleanup;
	}

	/* Open InboxFolder. */
	retval = OpenFolder(obj_store, inbox_id, &obj_folder_inbox);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* GetProps on Inbox for PR_ADDITIONAL_REN_ENTRYIDS */
	SPropTagArray = set_SPropTagArray(mem_ctx, 0x1, PR_ADDITIONAL_REN_ENTRYIDS);

	lpProps = talloc_zero(mem_ctx, struct SPropValue);
	retval = GetProps (&obj_folder_inbox, SPropTagArray, &lpProps, &count);

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
			retval = GetFIDFromEntryID(entryid.cb, entryid.lpb, inbox_id, &fid);

			if (retval == MAPI_E_SUCCESS && fid) {
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
}

static void
set_default_folders (mapi_object_t *obj_store, GSList **mapi_folders)
{
	GSList *folder_list = *mapi_folders;

	GHashTable *default_folders = g_hash_table_new_full (g_str_hash, g_str_equal,
							     g_free, g_free);

	mapi_get_ren_additional_fids (obj_store, &default_folders);

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
exchange_mapi_connection_get_folders_list (ExchangeMapiConnection *conn, GSList **mapi_folders)
{
	enum MAPISTATUS	retval;
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
	g_return_val_if_fail (priv->session != NULL, FALSE);

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
	retval = GetProps (&priv->msg_store, SPropTagArray, &lpProps, &count);
	MAPIFreeBuffer(SPropTagArray);

	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetProps", GetLastError());
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
	retval = GetDefaultFolder(&priv->msg_store, &mailbox_id, olFolderTopInformationStore);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetDefaultFolder", GetLastError());
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
	get_child_folders (mem_ctx, MAPI_PERSONAL_FOLDER, &priv->msg_store, mailbox_id, mapi_folders, -1);

	g_free(utf8_mailbox_name);

	*mapi_folders = g_slist_reverse (*mapi_folders);

	set_default_folders (&priv->msg_store, mapi_folders);
	g_slist_foreach (*mapi_folders, (GFunc) set_owner_name, (gpointer) mailbox_owner_name);
	g_slist_foreach (*mapi_folders, (GFunc) set_user_name, (gpointer) mailbox_user_name);

	result = TRUE;

cleanup:
	talloc_free (mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

gboolean
exchange_mapi_connection_get_pf_folders_list (ExchangeMapiConnection *conn, GSList **mapi_folders, mapi_id_t parent_fid)
{
	enum MAPISTATUS		retval;
	TALLOC_CTX		*mem_ctx;
	gboolean		result = FALSE;
	mapi_id_t		mailbox_id;
	ExchangeMAPIFolder	*folder;
	mapi_object_t obj_parent_folder;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	LOCK ();
	mem_ctx = talloc_init("ExchangeMAPI_PF_GetFoldersList");

	if (!ensure_public_store (priv))
		goto cleanup;

	/* Open the folder if parent_fid is given. */
	if (parent_fid) {
		mapi_object_init(&obj_parent_folder);

		retval = OpenFolder (&priv->public_store, parent_fid, &obj_parent_folder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("OpenFolder", GetLastError());
			goto cleanup;
		}
	} else {
		retval = GetDefaultPublicFolder (&priv->public_store, &mailbox_id, olFolderPublicIPMSubtree);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultPublicFolder", GetLastError());
			goto cleanup;
		}
	}
	/*  TODO : Localized string */
	folder = exchange_mapi_folder_new ("All Public Folders", IPF_NOTE, 0,
					   mailbox_id, 0, 0, 0 ,0);
	folder->is_default = true;
	folder->default_type = olPublicFoldersAllPublicFolders;

	*mapi_folders = g_slist_prepend (*mapi_folders, folder);

	/* FIXME: check status of get_child_folders */
	get_child_folders (mem_ctx, MAPI_FAVOURITE_FOLDER, parent_fid ? &obj_parent_folder : &priv->public_store,
			   parent_fid ? parent_fid : mailbox_id, mapi_folders, 1);

	result = TRUE;

cleanup:
	talloc_free (mem_ctx);

	UNLOCK ();

	g_debug("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return result;
}

GSList *
exchange_mapi_connection_peek_folders_list (ExchangeMapiConnection *conn)
{
	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	LOCK ();
	if (!priv->folders)
		exchange_mapi_connection_get_folders_list (conn, &priv->folders);
	UNLOCK ();

	return priv->folders;
}

const gchar *
exchange_mapi_connection_ex_to_smtp (ExchangeMapiConnection *conn, const gchar *ex_address)
{
	enum MAPISTATUS	retval;
	TALLOC_CTX		*mem_ctx;
	struct SPropTagArray	*SPropTagArray;
	struct SRowSet		*SRowSet = NULL;
	struct SPropTagArray	*flaglist = NULL;
	const gchar		*str_array[2];
	const gchar		*smtp_addr = NULL;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	g_return_val_if_fail (ex_address != NULL, NULL);

	str_array[0] = ex_address;
	str_array[1] = NULL;

	mem_ctx = talloc_init("ExchangeMAPI_EXtoSMTP");

	LOCK ();

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x1,
					  PR_SMTP_ADDRESS_UNICODE);

	retval = ResolveNames (priv->session, (const gchar **)str_array, SPropTagArray, &SRowSet, &flaglist, 0);
	if (retval != MAPI_E_SUCCESS)
		retval = ResolveNames (priv->session, (const gchar **)str_array, SPropTagArray, &SRowSet, &flaglist, MAPI_UNICODE);

	if (retval == MAPI_E_SUCCESS && SRowSet && SRowSet->cRows == 1) {
		smtp_addr = (const gchar *) exchange_mapi_util_find_row_propval (SRowSet->aRow, PR_SMTP_ADDRESS_UNICODE);
	}

	talloc_free (mem_ctx);

	UNLOCK ();

	return smtp_addr;
}

gboolean
exchange_mapi_connection_events_init (ExchangeMapiConnection *conn)
{
	gboolean retval;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	LOCK ();
	/* TODO: This requires a context, like session, from OpenChange, thus disabling until added */
	retval = FALSE /*RegisterNotification(0) == MAPI_E_SUCCESS */;
	UNLOCK ();

	return retval;
}

gboolean
exchange_mapi_connection_events_subscribe (ExchangeMapiConnection *conn, guint32 options,
				guint16 event_mask, guint32 *events_conn_id,
				mapi_notify_callback_t callback, gpointer data)
{
	enum MAPISTATUS	retval = MAPI_E_CALL_FAILED;
	gboolean use_store = ((options & MAPI_EVENTS_USE_STORE) ||
			      (options & MAPI_EVENTS_USE_PF_STORE));

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	LOCK ();

	if (options & MAPI_EVENTS_USE_STORE) {
		retval = Subscribe (&priv->msg_store, events_conn_id, event_mask, use_store, (mapi_notify_callback_t) callback, data);
	} else if (options & MAPI_EVENTS_USE_PF_STORE) {
		if (!ensure_public_store (priv)) {
			UNLOCK ();
			return FALSE;
		}

		retval = Subscribe (&priv->public_store, events_conn_id, event_mask, use_store, (mapi_notify_callback_t) callback, data);
	} else if (options & MAPI_EVENTS_FOLDER) {
		/* TODO */
	}

	UNLOCK ();

	return (retval == MAPI_E_SUCCESS);
}

gboolean
exchange_mapi_connection_events_unsubscribe (ExchangeMapiConnection *conn, guint32 events_conn_id)
{
	enum MAPISTATUS	retval;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	LOCK ();
	retval = Unsubscribe (priv->session, events_conn_id);
	UNLOCK ();

	return (retval == MAPI_E_SUCCESS);
}

/* Note : Blocking infinite loop. */
gboolean
exchange_mapi_connection_events_monitor (ExchangeMapiConnection *conn, struct mapi_notify_continue_callback_data *cb_data)
{
	enum MAPISTATUS	retval;

	CHECK_CORRECT_CONN_AND_GET_PRIV (conn, FALSE);
	g_return_val_if_fail (priv->session != NULL, FALSE);

	retval = MonitorNotification (priv->session, NULL, cb_data);

	return retval;
}

/* Shows error message on the console, and, if error_msg is not NULL, then
   sets it to the similar error message as well. */
static void
manage_mapi_error (const gchar *context, uint32_t error_id, gchar **error_msg)
{
	if (!context)
		context = "???";

	mapi_errstr (context, error_id);

	if (error_msg) {
		gchar *e = g_strconcat (context, ":", mapi_get_errstr (error_id), NULL);

		g_free (*error_msg);
		*error_msg = e;
	}
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
ensure_mapi_init_called (void)
{
	static gboolean called = FALSE;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	gchar *profpath;
	enum MAPISTATUS status;

	g_static_mutex_lock (&mutex);
	if (called) {
		g_static_mutex_unlock (&mutex);
		return TRUE;
	}

	profpath = g_build_filename (g_get_home_dir (), DEFAULT_PROF_PATH, NULL);

	if (!g_file_test (profpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		/* Create a ProfileStore */
		status = CreateProfileStore (profpath, LIBMAPI_LDIF_DIR);
		if (status != MAPI_E_SUCCESS && (status != MAPI_E_NO_ACCESS || !g_file_test (profpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
			mapi_errstr ("CreateProfileStore", GetLastError());
			g_free (profpath);

			g_static_mutex_unlock (&mutex);
			return FALSE;
		}
	}

	status = MAPIInitialize (profpath);
	if (status == MAPI_E_SESSION_LIMIT) {
		/* do nothing, the profile store is already initialized */
		/* but this shouldn't happen */
		mapi_errstr ("MAPIInitialize", GetLastError());
	} else if (status != MAPI_E_SUCCESS) {
		mapi_errstr ("MAPIInitialize", GetLastError());
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
mapi_profile_load (const gchar *profname, const gchar *password)
{
	enum MAPISTATUS	retval = MAPI_E_SUCCESS;
	struct mapi_session *session = NULL;
	guint32 debug_log_level = 0;

	g_return_val_if_fail (profname != NULL, NULL);

	g_static_mutex_lock (&profile_mutex);

	/* Initialize libexchangemapi logger*/
	if (g_getenv ("EXCHANGEMAPI_DEBUG")) {
		g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, mapi_debug_logger, NULL);
	} else
		g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, mapi_debug_logger_muted, NULL);

	g_debug("%s: Entering %s ", G_STRLOC, G_STRFUNC);

	if (!ensure_mapi_init_called ())
		goto cleanup;

	/* Initialize libmapi logger*/
	if (g_getenv ("MAPI_DEBUG")) {
		debug_log_level = atoi (g_getenv ("MAPI_DEBUG"));
		SetMAPIDumpData(TRUE);
		SetMAPIDebugLevel(debug_log_level);
	}

	g_debug("Loading profile %s ", profname);

	retval = MapiLogonEx (&session, profname, password);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("MapiLogonEx", GetLastError());
		goto cleanup;
	}

 cleanup:
	g_static_mutex_unlock (&profile_mutex);
	g_debug ("%s: Leaving %s ", G_STRLOC, G_STRFUNC);

	return session;
}

gboolean
exchange_mapi_create_profile (const gchar *username, const gchar *password, const gchar *domain,
			      const gchar *server, gchar **error_msg,
			      mapi_profile_callback_t callback, gpointer data)
{
	enum MAPISTATUS	retval;
	gboolean result = FALSE;
	const gchar *workstation = "localhost";
	gchar *profname = NULL;
	struct mapi_session *session = NULL;

	/*We need all the params before proceeding.*/
	g_return_val_if_fail (username && *username && password && *password &&
			      domain && *domain && server && *server, FALSE);

	g_static_mutex_lock (&profile_mutex);

	g_debug ("Create profile with %s %s %s\n", username, domain, server);

	if (!ensure_mapi_init_called ()) {
		g_static_mutex_unlock (&profile_mutex);
		return FALSE;
	}

	profname = exchange_mapi_util_profile_name (username, domain, server, TRUE);

	/* Delete any existing profiles with the same profilename */
	retval = DeleteProfile (profname);
	/* don't bother to check error - it would be valid if we got an error */

	retval = CreateProfile(profname, username, password, OC_PROFILE_NOPASSWORD);
	if (retval != MAPI_E_SUCCESS) {
		manage_mapi_error ("CreateProfile", GetLastError(), error_msg);
		goto cleanup;
	}

	mapi_profile_add_string_attr(profname, "binding", server);
	mapi_profile_add_string_attr(profname, "workstation", workstation);
	mapi_profile_add_string_attr(profname, "domain", domain);

	/* This is only convenient here and should be replaced at some point */
	mapi_profile_add_string_attr(profname, "codepage", "0x4e4");
	mapi_profile_add_string_attr(profname, "language", "0x409");
	mapi_profile_add_string_attr(profname, "method", "0x409");

	/* Login now */
	g_debug("Logging into the server... ");
	retval = MapiLogonProvider(&session, profname, password, PROVIDER_ID_NSPI);
	if (retval != MAPI_E_SUCCESS) {
		manage_mapi_error ("MapiLogonProvider", GetLastError(), error_msg);
		g_debug ("Deleting profile %s ", profname);
		retval = DeleteProfile(profname);
		if (retval != MAPI_E_SUCCESS)
			manage_mapi_error ("DeleteProfile", GetLastError(), error_msg);
		goto cleanup;
	}
	g_debug("MapiLogonProvider : succeeded \n");

	retval = ProcessNetworkProfile(session, username, callback, data);
	if (retval != MAPI_E_SUCCESS) {
		manage_mapi_error ("ProcessNetworkProfile", GetLastError(), error_msg);
		g_debug ("Deleting profile %s ", profname);
		DeleteProfile(profname);
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

		if (OpenMsgStore (session, &msg_store) == MAPI_E_SUCCESS) {
			Logoff (&msg_store);
		} else {
			/ * how to close and free session without store? * /
			mapi_errstr ("OpenMsgStore", GetLastError());
		}

		mapi_object_release (&msg_store);
	}*/

	g_static_mutex_unlock (&profile_mutex);

	return result;
}

gboolean
exchange_mapi_delete_profile (const gchar *profile)
{
	gboolean result = FALSE;

	g_static_mutex_lock (&profile_mutex);

	if (ensure_mapi_init_called ()) {
		g_debug ("Deleting profile %s ", profile);

		if (DeleteProfile (profile) == MAPI_E_SUCCESS) {
			result = TRUE;
		} else {
			mapi_errstr ("DeleteProfile", GetLastError());
		}
	}

	g_static_mutex_unlock (&profile_mutex);

	return result;
}

/* profile related functions - end */
