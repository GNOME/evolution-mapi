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

#include "exchange-mapi-connection.h"
#include "exchange-mapi-folder.h"
#include "exchange-mapi-utils.h"
#include <param.h>

#define DEFAULT_PROF_PATH ".evolution/mapi-profiles.ldb"
#define d(x) x

static struct mapi_session *global_mapi_session= NULL;
static GStaticRecMutex connect_lock = G_STATIC_REC_MUTEX_INIT;


#define LOCK() 		g_message("%s(%d): %s: lock(connect_lock)", __FILE__, __LINE__, __PRETTY_FUNCTION__);g_static_rec_mutex_lock(&connect_lock);
#define UNLOCK() 	g_message("%s(%d): %s: unlock(connect_lock)", __FILE__, __LINE__, __PRETTY_FUNCTION__);g_static_rec_mutex_unlock(&connect_lock);

#if 0
#define LOGALL() 	lp_set_cmdline(global_mapi_ctx->lp_ctx, "log level", "10"); global_mapi_ctx->dumpdata = TRUE;
#define LOGNONE() 	lp_set_cmdline(global_mapi_ctx->lp_ctx, "log level", "0"); global_mapi_ctx->dumpdata = FALSE;

#define ENABLE_VERBOSE_LOG() 	global_mapi_ctx->dumpdata = TRUE;
#define DISABLE_VERBOSE_LOG() 	global_mapi_ctx->dumpdata = FALSE;
#endif

//#if 0
#define LOGALL()
#define LOGNONE()

#define ENABLE_VERBOSE_LOG()
#define DISABLE_VERBOSE_LOG()
//#endif 

/* Specifies READ/WRITE sizes to be used while handling normal streams */
#define STREAM_MAX_READ_SIZE    0x1000
#define STREAM_MAX_WRITE_SIZE   0x1000
#define STREAM_ACCESS_READ      0x0000
#define STREAM_ACCESS_WRITE     0x0001
#define STREAM_ACCESS_READWRITE 0x0002

static struct mapi_session *
mapi_profile_load (const char *profname, const char *password)
{
	enum MAPISTATUS	retval = MAPI_E_SUCCESS;
	struct mapi_session *session = NULL;
	gchar *profpath = NULL;
	const char *profile = NULL;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	profpath = g_build_filename (g_get_home_dir(), DEFAULT_PROF_PATH, NULL);
	if (!g_file_test (profpath, G_FILE_TEST_EXISTS)) {
		g_warning ("\nMAPI profile database @ %s not found ", profpath);
		goto cleanup;
	}

	MAPIUninitialize ();

	retval = MAPIInitialize(profpath);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("MAPIInitialize", GetLastError());
		if (retval == MAPI_E_SESSION_LIMIT)
			g_print("\n%s(%d): %s: Already connected ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		goto cleanup;
	}

	if (profname)
		profile = profname;
	else {
		retval = GetDefaultProfile(&profile);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultProfile", GetLastError());
			goto cleanup;
		}
	}

	g_print("\nLoading profile %s ", profile);

	retval = MapiLogonEx(&session, profile, password);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("MapiLogonEx", GetLastError());
		goto cleanup;
	}

cleanup:
	if (retval != MAPI_E_SUCCESS && retval != MAPI_E_SESSION_LIMIT)
		MAPIUninitialize ();
	g_free (profpath);

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return session;
}

gboolean
exchange_mapi_connection_exists ()
{
	return global_mapi_session != NULL;
}

gboolean 
exchange_mapi_connection_new (const char *profile, const char *password)
{
	LOCK();
	if (!global_mapi_session)
		global_mapi_session = mapi_profile_load (profile, password);
	UNLOCK();

	if (!global_mapi_session)
		g_warning ("\n%s(%d): %s: Login failed ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
	else
		g_message ("\n%s(%d): %s: Connected ", __FILE__, __LINE__, __PRETTY_FUNCTION__);

	return global_mapi_session != NULL;
}

void
exchange_mapi_connection_close ()
{
	LOCK();
	global_mapi_session = NULL;
	MAPIUninitialize ();	
	UNLOCK();
	/* TODO :  Return status. get last error ? */
}

static gboolean 
exchange_mapi_util_read_generic_stream (mapi_object_t *obj_message, uint32_t proptag, GSList **stream_list)
{
	enum MAPISTATUS	retval;
	TALLOC_CTX 	*mem_ctx;
	mapi_object_t 	obj_stream;
	uint16_t 	cn_read = 0;
	uint32_t 	off_data = 0;
	uint8_t		*buf_data = NULL;
	uint32_t 	buf_size = 0;
	gboolean 	done = FALSE;

	/* sanity */
	g_return_val_if_fail (obj_message, FALSE);
	g_return_val_if_fail (((proptag & 0xFFFF) == PT_BINARY), FALSE);

	/* if compressed RTF stream, then return */
	g_return_val_if_fail (proptag != PR_RTF_COMPRESSED, FALSE);

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));
	d(g_print("\nAttempt to read stream for proptag 0x%08X ", proptag));

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
		ExchangeMAPIStream 		*stream = g_new0 (ExchangeMAPIStream, 1);
		struct mapi_SPropValue_array 	properties_array;

		stream->value = g_byte_array_sized_new (off_data);
		stream->value = g_byte_array_append (stream->value, buf_data, off_data);

		/* Build a mapi_SPropValue_array structure */
		properties_array.cValues = 1; 
		properties_array.lpProps = talloc_array (mem_ctx, struct mapi_SPropValue, properties_array.cValues);
		properties_array.lpProps[0].ulPropTag = proptag; 
		/* This call is needed in case the read stream was a named prop. */
		mapi_SPropValue_array_named (obj_message, &properties_array);

		stream->proptag = properties_array.lpProps[0].ulPropTag;

		d(g_print("\nAttempt succeeded for proptag 0x%08X (after name conversion) ", stream->proptag));

		*stream_list = g_slist_append (*stream_list, stream);
	}

cleanup: 
	mapi_object_release(&obj_stream);
	talloc_free (mem_ctx);

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return (retval == MAPI_E_SUCCESS);
}

static gboolean
exchange_mapi_util_read_body_stream (mapi_object_t *obj_message, GSList **stream_list, gboolean getbestbody)
{
	enum MAPISTATUS			retval;
	TALLOC_CTX 			*mem_ctx;
	struct SPropTagArray		*SPropTagArray;
	struct SPropValue		*lpProps;
	uint32_t			count;
	DATA_BLOB			body;
	uint8_t 			editor;
	const char			*data = NULL;
	const bool 			*rtf_in_sync;
	uint32_t 			proptag = 0;

	/* sanity check */
	g_return_val_if_fail (obj_message, FALSE);

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

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
		const uint32_t *ui32 = (const uint32_t *) get_SPropValue(lpProps, PR_MSG_EDITOR_FORMAT);
		/* if PR_MSG_EDITOR_FORMAT doesn't exist, set it to PLAINTEXT */
		editor = ui32 ? *ui32 : olEditorText;
	}

	/* initialize body DATA_BLOB */
	body.data = NULL;
	body.length = 0;

	retval = -1;
	switch (editor) {
		case olEditorText:
			if ((data = (const char *) get_SPropValue (lpProps, PR_BODY_UNICODE)) != NULL)
				proptag = PR_BODY_UNICODE;
			else if ((data = (const char *) get_SPropValue (lpProps, PR_BODY)) != NULL)
				proptag = PR_BODY;
			if (data) {
				size_t size = strlen(data)+1;
				body.data = talloc_memdup(mem_ctx, data, size);
				body.length = size;
				retval = MAPI_E_SUCCESS;
			} 
			break;
		case olEditorHTML: 
			/* Fixme : */
 			/*if ((data = (const char *) get_SPropValue (lpProps, PR_BODY_HTML_UNICODE)) != NULL) */
 			/*	proptag = PR_BODY_HTML_UNICODE; */
			if ((data = (const char *) get_SPropValue (lpProps, PR_BODY_HTML)) != NULL)
				proptag = PR_BODY_HTML;

			if (data) {
				size_t size = strlen(data)+1;
				body.data = talloc_memdup(mem_ctx, data, size);
				body.length = size;
				retval = MAPI_E_SUCCESS;
			} else if (exchange_mapi_util_read_generic_stream (obj_message, PR_HTML, stream_list)) {
				retval = MAPI_E_SUCCESS;
			}
			break;
		case olEditorRTF: 
			rtf_in_sync = (const bool *) get_SPropValue (lpProps, PR_RTF_IN_SYNC);
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
		ExchangeMAPIStream 	*stream = g_new0 (ExchangeMAPIStream, 1);

		stream->value = g_byte_array_sized_new (body.length);
		stream->value = g_byte_array_append (stream->value, body.data, body.length);

		stream->proptag = proptag;

		*stream_list = g_slist_append (*stream_list, stream);
	}

	talloc_free (mem_ctx);

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return (retval == MAPI_E_SUCCESS);
}

/* Returns TRUE if all streams were written succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_write_generic_streams (mapi_object_t *obj_message, GSList *stream_list) 
{

//	TALLOC_CTX 	*mem_ctx;
	GSList 		*l;
	enum MAPISTATUS	retval;
	gboolean 	status = TRUE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

//	mem_ctx = talloc_init ("ExchangeMAPI_WriteGenericStreams");

	for (l = stream_list; l; l = l->next) {
		ExchangeMAPIStream 	*stream = (ExchangeMAPIStream *) (l->data);
		uint32_t 		total_written;
		gboolean 		done = FALSE;
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
			uint16_t 	cn_written = 0;
			DATA_BLOB 	blob;

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

//	talloc_free (mem_ctx);

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return status;
}

static gboolean
exchange_mapi_util_delete_attachments (mapi_object_t *obj_message)
{
	enum MAPISTATUS		retval;
	TALLOC_CTX 		*mem_ctx;
	mapi_object_t 		obj_tb_attach;
	struct SPropTagArray	*proptags;
	struct SRowSet		rows_attach;
	uint32_t		attach_count;
	uint32_t		i_row_attach;
	gboolean 		status = TRUE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

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

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return status;
}

/* Returns TRUE if all attachments were written succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_set_attachments (mapi_object_t *obj_message, GSList *attach_list, gboolean remove_existing)
{
//	TALLOC_CTX 	*mem_ctx;
	GSList 		*l;
	enum MAPISTATUS	retval;
	gboolean 	status = TRUE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	if (remove_existing)
		exchange_mapi_util_delete_attachments (obj_message);

//	mem_ctx = talloc_init ("ExchangeMAPI_SetAttachments");

	for (l = attach_list; l; l = l->next) {
		ExchangeMAPIAttachment 	*attachment = (ExchangeMAPIAttachment *) (l->data);
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

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return status;
}

/* Returns TRUE if all attachments were read succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_get_attachments (mapi_object_t *obj_message, GSList **attach_list)
{
	enum MAPISTATUS		retval;
	TALLOC_CTX 		*mem_ctx;
	mapi_object_t 		obj_tb_attach;
	struct SPropTagArray	*proptags;
	struct SRowSet		rows_attach;
	uint32_t		attach_count;
	uint32_t		i_row_attach;
	gboolean 		status = TRUE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

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
		ExchangeMAPIAttachment 	*attachment;
		struct mapi_SPropValue_array properties;
		const uint32_t	*ui32;
		mapi_object_t	obj_attach;
		uint32_t 	z;

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
		attachment->lpProps = g_new0 (struct SPropValue, attachment->cValues);
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

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return status;
}

/* Returns TRUE if all recipients were read succcesfully, else returns FALSE */
static gboolean
exchange_mapi_util_get_recipients (mapi_object_t *obj_message, GSList **recip_list)
{
	enum MAPISTATUS		retval;
//	TALLOC_CTX 		*mem_ctx;
	struct SPropTagArray	proptags;
	struct SRowSet		rows_recip;
	uint32_t		i_row_recip;
	gboolean 		status = TRUE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

//	mem_ctx = talloc_init ("ExchangeMAPI_GetRecipients");

	/* fetch recipient table */
	retval = GetRecipientTable(obj_message, &rows_recip, &proptags);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetRecipientTable", GetLastError());
		goto cleanup;
	}

	for (i_row_recip = 0; i_row_recip < rows_recip.cRows; i_row_recip++) {
		ExchangeMAPIRecipient 	*recipient = g_new0 (ExchangeMAPIRecipient, 1);

		recipient->email_id = (const char *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_SMTP_ADDRESS);
		/* fallback */
		if (!recipient->email_id) {
			const char *addrtype = (const char *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_ADDRTYPE);
			if (addrtype && !g_ascii_strcasecmp(addrtype, "SMTP"))
				recipient->email_id = (const char *) exchange_mapi_util_find_row_propval (&(rows_recip.aRow[i_row_recip]), PR_EMAIL_ADDRESS);
		}
		/* fail */
		if (!recipient->email_id) {
			g_warning ("\n%s:%d %s() - object has a recipient without a PR_SMTP_ADDRESS ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
			mapidump_SRow (&(rows_recip.aRow[i_row_recip]), " ");
		}

		recipient->out.all_lpProps = rows_recip.aRow[i_row_recip].lpProps;
		recipient->out.all_cValues = rows_recip.aRow[i_row_recip].cValues;

		*recip_list = g_slist_append (*recip_list, recipient);
	}

cleanup:
	if (retval != MAPI_E_SUCCESS)
		status = FALSE;
//	talloc_free (mem_ctx);

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

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

		dn = (const gchar *) get_SPropValue (recipient->in.ext_lpProps, PR_DISPLAY_NAME);
		dn = (dn) ? dn : "";
		email = (const gchar *) get_SPropValue (recipient->in.ext_lpProps, PR_SMTP_ADDRESS);
		email = (email) ? email : "";
		oneoff_eid = exchange_mapi_util_entryid_generate_oneoff (mem_ctx, dn, email, FALSE);
		set_SPropValue_proptag (&sprop, PR_ENTRYID, (const void *)(oneoff_eid));
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

static void
exchange_mapi_util_modify_recipients (TALLOC_CTX *mem_ctx, mapi_object_t *obj_message , GSList *recipients, gboolean remove_existing)
{
	enum MAPISTATUS 	retval;
	struct SPropTagArray 	*SPropTagArray = NULL;
	struct SRowSet 		*SRowSet = NULL;
	struct SPropTagArray 	*FlagList = NULL;
	GSList 			*l;
	const char 		**users = NULL;
	uint32_t 		i, j, count = 0;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x6,
					  PR_OBJECT_TYPE,
					  PR_DISPLAY_TYPE,
					  PR_7BIT_DISPLAY_NAME,
					  PR_DISPLAY_NAME,
					  PR_SMTP_ADDRESS,
					  PR_GIVEN_NAME);


	count = g_slist_length (recipients);
	users = g_new0 (const char *, count + 1);

	for (i = 0, l = recipients; (i < count && l != NULL); ++i, l = l->next) { 
		ExchangeMAPIRecipient *recipient = (ExchangeMAPIRecipient *)(l->data);
		users[i] = recipient->email_id;
	}

	/* Attempt to resolve names from the server */
	retval = ResolveNames (global_mapi_session, users, SPropTagArray, &SRowSet, &FlagList, 0);
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
			g_warning ("\n%s:%d %s() - '%s' is ambiguous ", __FILE__, __LINE__, __PRETTY_FUNCTION__, recipient->email_id);
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

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));
}

GSList *
exchange_mapi_util_check_restriction (mapi_id_t fid, struct mapi_SRestriction *res)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	mapi_object_t obj_table;
	struct SPropTagArray *SPropTagArray, *GetPropsTagArray;
	struct SRowSet SRowSet;
	uint32_t count, i;
	GSList *mids = NULL;

	d(g_print("\n%s(%d): Entering %s: folder-id %016llX ", __FILE__, __LINE__, __PRETTY_FUNCTION__, fid));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_CheckRestriction");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
					  PR_SUBJECT,
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
	mapi_object_release(&obj_store);
	talloc_free (mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return mids;
}

gboolean
exchange_mapi_connection_fetch_items   (mapi_id_t fid, 
					struct mapi_SRestriction *res,
					const uint32_t *GetPropsList, const uint16_t cn_props, 
					BuildNameID build_name_id, gpointer build_name_data, 
					FetchCallback cb, gpointer data, 
					guint32 options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	mapi_object_t obj_table;
	struct SPropTagArray *SPropTagArray, *GetPropsTagArray;
	struct SRowSet SRowSet;
	uint32_t count, i;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s: folder-id %016llX ", __FILE__, __LINE__, __PRETTY_FUNCTION__, fid));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_FetchItems");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_table);

	/* Open the message store */
	retval = ((options & MAPI_OPTIONS_USE_PFSTORE) ? 
		  OpenPublicFolder(global_mapi_session, &obj_store) : OpenMsgStore(global_mapi_session, &obj_store));
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore / OpenPublicFolder", GetLastError());
		goto cleanup;
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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

	/* Number of items in the container */
	retval = QueryPosition(&obj_table, NULL, &count);
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
				g_warning ("\n%s(%d): (%s): Could not build named props ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
				goto GetProps_cleanup;
			}

			retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, NamedPropsTagArray);
			if (retval != MAPI_E_SUCCESS) {
				mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
				goto GetProps_cleanup;
			}
		}

		GetPropsTagArray->cValues = (cn_props + NamedPropsTagArray->cValues);
		GetPropsTagArray->aulPropTag = talloc_array(mem_ctx, uint32_t, (cn_props + NamedPropsTagArray->cValues));

		for (m = 0; m < NamedPropsTagArray->cValues; m++, n++)
			GetPropsTagArray->aulPropTag[n] = NamedPropsTagArray->aulPropTag[m];

		for (m = 0; m < cn_props; m++, n++)
			GetPropsTagArray->aulPropTag[n] = GetPropsList[m];

	GetProps_cleanup:
			MAPIFreeBuffer (NamedPropsTagArray);
			talloc_free (nameid);
	}

	for (i = 0; i < SRowSet.cRows; i++) {
		mapi_object_t obj_message;
		struct mapi_SPropValue_array properties_array;
		const mapi_id_t *pfid;
		const mapi_id_t	*pmid;
		const bool *has_attach = NULL;
		GSList *attach_list = NULL;
		GSList *recip_list = NULL;
		GSList *stream_list = NULL;

		mapi_object_init(&obj_message);

		pfid = (const uint64_t *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_FID);
		pmid = (const uint64_t *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_MID);

		has_attach = (const bool *) get_SPropValue_SRow_data(&SRowSet.aRow[i], PR_HASATTACH);

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

		if (GetPropsTagArray->cValues) {
			struct SPropValue *lpProps;
			uint32_t prop_count = 0, k;

			lpProps = talloc_zero(mem_ctx, struct SPropValue);
			retval = GetProps (&obj_message, GetPropsTagArray, &lpProps, &prop_count);

			/* Conversion from SPropValue to mapi_SPropValue. (no padding here) */
			properties_array.cValues = prop_count;
			properties_array.lpProps = talloc_array (mem_ctx, struct mapi_SPropValue, prop_count);
			for (k=0; k < prop_count; k++)
				cast_mapi_SPropValue(&properties_array.lpProps[k], &lpProps[k]);

			MAPIFreeBuffer(lpProps);
		} else
			retval = GetPropsAll (&obj_message, &properties_array);

		if (retval == MAPI_E_SUCCESS) {
			uint32_t z;

			/* just to get all the other streams */
			for (z=0; z < properties_array.cValues; z++) {
				if ((properties_array.lpProps[z].ulPropTag & 0xFFFF) == PT_BINARY && (options & MAPI_OPTIONS_FETCH_GENERIC_STREAMS)) 
					exchange_mapi_util_read_generic_stream (&obj_message, properties_array.lpProps[z].ulPropTag, &stream_list);
			}

			mapi_SPropValue_array_named(&obj_message, &properties_array);

			/* NOTE: stream_list, recipient_list and attach_list should be freed by the callback */
			FetchItemsCallbackData *item_data = g_new0 (FetchItemsCallbackData, 1);
			item_data->fid = *pfid;
			item_data->mid = *pmid;
			item_data->properties = &properties_array;
			item_data->streams = stream_list;
			item_data->recipients = recip_list;
			item_data->attachments = attach_list;
			item_data->total = SRowSet.cRows;
			item_data->index = i;

			if (!cb (item_data, data)) {
				g_warning ("\n%s(%d): %s: Callback failed for message-id %016llX ", __FILE__, __LINE__, __PRETTY_FUNCTION__, *pmid);
			}

			g_free (item_data);
		}

		if (GetPropsTagArray->cValues) 
			talloc_free (properties_array.lpProps);

	loop_cleanup:
		mapi_object_release(&obj_message);
	}

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_table);
	mapi_object_release(&obj_store);
	talloc_free (mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s: folder-id %016llX ", __FILE__, __LINE__, __PRETTY_FUNCTION__, fid));

	return result;
}

gboolean
exchange_mapi_connection_fetch_item (mapi_id_t fid, mapi_id_t mid, 
				     const uint32_t *GetPropsList, const uint16_t cn_props, 
				     BuildNameID build_name_id, gpointer build_name_data, 
				     FetchCallback cb, gpointer data, 
				     guint32 options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct mapi_SPropValue_array properties_array;
	struct SPropTagArray *GetPropsTagArray;
	GSList *attach_list = NULL;
	GSList *recip_list = NULL;
	GSList *stream_list = NULL;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s: folder-id %016llX message-id %016llX ", __FILE__, __LINE__, __PRETTY_FUNCTION__, fid, mid));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_FetchItem");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	/* Open the message store */
	retval = ((options & MAPI_OPTIONS_USE_PFSTORE) ? 
		  OpenPublicFolder(global_mapi_session, &obj_store) : OpenMsgStore(global_mapi_session, &obj_store));
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
				g_warning ("\n%s(%d): (%s): Could not build named props ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
				goto GetProps_cleanup;
			}

			retval = mapi_nameid_GetIDsFromNames(nameid, &obj_folder, NamedPropsTagArray);
			if (retval != MAPI_E_SUCCESS) {
				mapi_errstr("mapi_nameid_GetIDsFromNames", GetLastError());
				goto GetProps_cleanup;
			}
		}

		GetPropsTagArray->cValues = (cn_props + NamedPropsTagArray->cValues);
		GetPropsTagArray->aulPropTag = talloc_array(mem_ctx, uint32_t, (cn_props + NamedPropsTagArray->cValues));

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
		properties_array.lpProps = talloc_array (mem_ctx, struct mapi_SPropValue, prop_count);
		for (k=0; k < prop_count; k++)
			cast_mapi_SPropValue(&properties_array.lpProps[k], &lpProps[k]);

		MAPIFreeBuffer(lpProps);
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
	mapi_object_release(&obj_store);

	if (retval == MAPI_E_SUCCESS) {
		FetchItemsCallbackData *item_data = g_new0 (FetchItemsCallbackData, 1);
		item_data->fid = fid;
		item_data->mid = mid;
		item_data->properties = &properties_array;
		item_data->streams = stream_list;
		item_data->recipients = recip_list;
		item_data->attachments = attach_list;

		/* NOTE: stream_list, recipient_list and attach_list should be freed by the callback */
		cb (item_data, data);

		g_free (item_data);
	}

//	if (GetPropsTagArray->cValues) 
//		talloc_free (properties_array.lpProps);

	result = TRUE;

cleanup:
	if (!result) {
		mapi_object_release(&obj_message);
		mapi_object_release(&obj_folder);
		mapi_object_release(&obj_store);
	}
	talloc_free (mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

mapi_id_t 
exchange_mapi_create_folder (uint32_t olFolder, mapi_id_t pfid, const char *name)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	mapi_object_t obj_top;
	struct SPropValue vals[1];
	const char *type;
	mapi_id_t fid = 0;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_top);
	mapi_object_init(&obj_folder);

	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* We now open the top/parent folder */
	retval = OpenFolder(&obj_store, pfid, &obj_top);
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
	g_print("\nFolder %s created with id %016llX ", name, fid);

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_top);
	mapi_object_release(&obj_store);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	/* Shouldn't we return (ExchangeMAPIFolder *) instead of a plain fid ? */
	return fid;
}

gboolean
exchange_mapi_empty_folder (mapi_id_t fid)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);

	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* Attempt to open the folder to be emptied */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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

	g_print("\nFolder with id %016llX was emptied ", fid);

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_store);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

/* FIXME: param olFolder is never used in the routine. Remove it and cleanup at the backends */
gboolean
exchange_mapi_remove_folder (uint32_t olFolder, mapi_id_t fid)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_store;
	mapi_object_t obj_top;
	mapi_object_t obj_folder;
	ExchangeMAPIFolder *folder;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	folder = exchange_mapi_folder_get_folder (fid);
	g_return_val_if_fail (folder != NULL, FALSE);

	LOCK();
	LOGALL();
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_top);
	mapi_object_init(&obj_folder);

	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* FIXME: If the folder has sub-folders, open each of them in turn, empty them and delete them.
	 * Note that this has to be done recursively, for the sub-folders as well. 
	 */

	/* Attempt to open the folder to be removed */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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

	g_print("\nFolder with id %016llX was emptied ", fid);

	/* Attempt to open the top/parent folder */
	retval = OpenFolder(&obj_store, folder->parent_folder_id, &obj_top);
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

	g_print("\nFolder with id %016llX was deleted ", fid);

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_top);
	mapi_object_release(&obj_store);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

gboolean 
exchange_mapi_rename_folder (mapi_id_t fid, const char *new_name)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	struct SPropValue *props = NULL;
	TALLOC_CTX *mem_ctx;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_RenameFolder");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);

	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* Open the folder to be renamed */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	props = talloc_zero(mem_ctx, struct SPropValue);
	set_SPropValue_proptag (props, PR_DISPLAY_NAME, new_name);

	retval = SetProps(&obj_folder, props, 1);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("SetProps", GetLastError());
		goto cleanup;
	}

	result = TRUE;

cleanup:
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

struct SPropTagArray *
exchange_mapi_util_resolve_named_props (uint32_t olFolder, mapi_id_t fid, 
					BuildNameID build_name_id, gpointer ni_data)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray, *ret_array = NULL;
	uint32_t i;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_ResolveNamedProps");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder(&obj_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder", GetLastError());
		goto cleanup;
	}

	/* Add named props using callback */
	if (build_name_id) {
		if (!build_name_id (nameid, ni_data)) {
			g_warning ("\n%s(%d): (%s): Could not build named props ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
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
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return ret_array;
}

struct SPropTagArray *
exchange_mapi_util_resolve_named_prop (uint32_t olFolder, mapi_id_t fid, uint16_t lid, const char *OLEGUID)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray, *ret_array = NULL;
	uint32_t i;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_ResolveNamedProp");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder(&obj_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return ret_array;
}

uint32_t
exchange_mapi_util_create_named_prop (uint32_t olFolder, mapi_id_t fid, 
				      const char *named_prop_name, uint32_t ptype)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	struct GUID guid;
	struct MAPINAMEID *nameid;
	struct SPropTagArray *SPropTagArray;
	uint32_t propID = 0x00000000;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_CreateNamedProp");

	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);

	GUID_from_string(PS_INTERNET_HEADERS, &guid);
	nameid = talloc_zero(mem_ctx, struct MAPINAMEID);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	nameid[0].lpguid = guid;
	nameid[0].ulKind = MNID_STRING;
	nameid[0].kind.lpwstr.Name = named_prop_name;

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder(&obj_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return propID; 
}

mapi_id_t
exchange_mapi_get_default_folder_id (uint32_t olFolder)
{
	enum MAPISTATUS retval;
	mapi_object_t obj_store;
	mapi_id_t fid = 0;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mapi_object_init(&obj_store);

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	retval = GetDefaultFolder(&obj_store, &fid, olFolder);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetDefaultFolder", GetLastError());
		goto cleanup;
	}

cleanup:
	mapi_object_release(&obj_store);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return (retval == MAPI_E_SUCCESS ? fid : 0);
}

mapi_id_t
exchange_mapi_create_item (uint32_t olFolder, mapi_id_t fid, 
			   BuildNameID build_name_id, gpointer ni_data, 
			   BuildProps build_props, gpointer p_data, 
			   GSList *recipients, GSList *attachments, GSList *generic_streams, 
			   uint32_t options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray;
	struct SPropValue *props = NULL;
	gint propslen = 0;
	mapi_id_t mid = 0;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_CreateItem");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder(&obj_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
			g_warning ("\n%s(%d): (%s): Could not build named props ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
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
			g_warning ("\n%s(%d): (%s): build_props failed! propslen = %d ", __FILE__, __LINE__, __PRETTY_FUNCTION__, propslen);
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
		exchange_mapi_util_modify_recipients (mem_ctx, &obj_message, recipients, FALSE);
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

	mid = mapi_object_get_id (&obj_message);

cleanup:
	mapi_object_release(&obj_message);
	mapi_object_release(&obj_folder);
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return mid;
}

gboolean
exchange_mapi_modify_item (uint32_t olFolder, mapi_id_t fid, mapi_id_t mid, 
			   BuildNameID build_name_id, gpointer ni_data, 
			   BuildProps build_props, gpointer p_data, 
			   GSList *recipients, GSList *attachments, GSList *generic_streams, 
			   uint32_t options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	mapi_object_t obj_message;
	struct mapi_nameid *nameid;
	struct SPropTagArray *SPropTagArray;
	struct SPropValue *props = NULL;
	gint propslen = 0;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_ModifyItem");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);
	mapi_object_init(&obj_message);

	nameid = mapi_nameid_new(mem_ctx);
	SPropTagArray = talloc_zero(mem_ctx, struct SPropTagArray);

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder(&obj_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
			g_warning ("\n%s(%d): (%s): Could not build named props ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
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
			g_warning ("\n%s(%d): (%s): Could not build props ", __FILE__, __LINE__, __PRETTY_FUNCTION__);
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
	}

	/* Set recipients if any */
	if (recipients) {
		exchange_mapi_util_modify_recipients (mem_ctx, &obj_message, recipients, TRUE);
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
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

gboolean
exchange_mapi_set_flags (uint32_t olFolder, mapi_id_t fid, GSList *mids, uint32_t flag, guint32 options)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	uint32_t i;
	mapi_id_t *id_messages;
	GSList *tmp = mids;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_SetFlags");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);

	id_messages = talloc_array(mem_ctx, mapi_id_t, g_slist_length (mids));
	for (i=0; tmp; tmp=tmp->next, i++)
		id_messages[i] = *((mapi_id_t *)tmp->data);

	/* Open the message store */
	retval = ((options & MAPI_OPTIONS_USE_PFSTORE) ? 
		  OpenPublicFolder(global_mapi_session, &obj_store) : OpenMsgStore(global_mapi_session, &obj_store)) ;
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore / OpenPublicFolder", GetLastError());
		goto cleanup;
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

static gboolean
mapi_move_items (mapi_id_t src_fid, mapi_id_t dest_fid, GSList *mid_list, gboolean do_copy)
{
	enum MAPISTATUS	retval;
	mapi_object_t obj_store;
	mapi_object_t obj_folder_src;
	mapi_object_t obj_folder_dst;
	mapi_id_array_t msg_id_array;
	GSList *l;
	gboolean result = FALSE;

	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder_src);
	mapi_object_init(&obj_folder_dst);
	mapi_id_array_init(&msg_id_array);

	for (l = mid_list; l != NULL; l = g_slist_next (l))
		mapi_id_array_add_id (&msg_id_array, *((mapi_id_t *)l->data));

	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	retval = OpenFolder(&obj_store, src_fid, &obj_folder_src);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenFolder - source folder", GetLastError());
		goto cleanup;
	}

	retval = OpenFolder(&obj_store, dest_fid, &obj_folder_dst);
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
	mapi_object_release(&obj_store);

	return result;
}

gboolean
exchange_mapi_copy_items (mapi_id_t src_fid, mapi_id_t dest_fid, GSList *mids)
{
	gboolean result = FALSE; 

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	result = mapi_move_items (src_fid, dest_fid, mids, TRUE);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result; 
}

gboolean
exchange_mapi_move_items (mapi_id_t src_fid, mapi_id_t dest_fid, GSList *mids)
{
	gboolean result = FALSE; 

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	result = mapi_move_items (src_fid, dest_fid, mids, FALSE);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result; 
}

gboolean
exchange_mapi_remove_items (uint32_t olFolder, mapi_id_t fid, GSList *mids)
{
	enum MAPISTATUS retval;
	TALLOC_CTX *mem_ctx;
	mapi_object_t obj_store;
	mapi_object_t obj_folder;
	uint32_t i;
	mapi_id_t *id_messages;
	GSList *tmp = mids;
	gboolean result = FALSE;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_RemoveItems");
	mapi_object_init(&obj_store);
	mapi_object_init(&obj_folder);

	id_messages = talloc_array(mem_ctx, mapi_id_t, g_slist_length (mids));
	for (i=0; tmp; tmp=tmp->next, i++) {
		struct id_list *data = tmp->data;
		id_messages[i] = data->id;
	}

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* If fid not present then we'll use olFolder. Document this in API doc. */
	if (fid == 0) {
		retval = GetDefaultFolder(&obj_store, &fid, olFolder);
		if (retval != MAPI_E_SUCCESS) {
			mapi_errstr("GetDefaultFolder", GetLastError());
			goto cleanup;
		}
	}

	/* Attempt to open the folder */
	retval = OpenFolder(&obj_store, fid, &obj_folder);
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
	mapi_object_release(&obj_store);
	talloc_free(mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

static gboolean
get_child_folders(TALLOC_CTX *mem_ctx, ExchangeMAPIFolderCategory folder_hier, mapi_object_t *parent, mapi_id_t folder_id, GSList **mapi_folders)
{
	enum MAPISTATUS		retval;
	mapi_object_t		obj_folder;
	mapi_object_t		obj_table;
	struct SPropTagArray	*SPropTagArray = NULL;
	struct SRowSet		rowset;
	uint32_t		i, row_count = 0;
	gboolean 		result = TRUE;

	/* sanity check */
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (parent != NULL, FALSE);

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

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x6,
					  PR_FID,
					  PR_CONTAINER_CLASS,
					  PR_DISPLAY_NAME,
					  PR_CONTENT_UNREAD,
					  PR_CONTENT_COUNT,
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

	for (i = 0; i < rowset.cRows; i++) {
		ExchangeMAPIFolder *folder = NULL;
		gchar *newname = NULL;

		const mapi_id_t *fid = (const mapi_id_t *)find_SPropValue_data(&rowset.aRow[i], PR_FID);
		const char *class = (const char *)find_SPropValue_data(&rowset.aRow[i], PR_CONTAINER_CLASS);
		const char *name = (const char *)find_SPropValue_data(&rowset.aRow[i], PR_DISPLAY_NAME);
		const uint32_t *unread = (const uint32_t *)find_SPropValue_data(&rowset.aRow[i], PR_CONTENT_UNREAD);
		const uint32_t *total = (const uint32_t *)find_SPropValue_data(&rowset.aRow[i], PR_CONTENT_COUNT);
		const uint32_t *child = (const uint32_t *)find_SPropValue_data(&rowset.aRow[i], PR_FOLDER_CHILD_COUNT);

		if (!class)
			class = IPF_NOTE;

		newname = utf8tolinux (name);
		g_print("\n|---+ %-15s : (Container class: %s %016llX) UnRead : %d Total : %d ", newname, class, *fid, unread ? *unread : 0, total ? *total : 0);

		folder = exchange_mapi_folder_new (newname, class, folder_hier, *fid, folder_id, child ? *child : 0, unread ? *unread : 0, total ? *total : 0);
		*mapi_folders = g_slist_prepend (*mapi_folders, folder);

		if (child && *child)
			result = (result && get_child_folders(mem_ctx, folder_hier, &obj_folder, *fid, mapi_folders));

		g_free (newname);
	}

cleanup:
	MAPIFreeBuffer (SPropTagArray);
	mapi_object_release (&obj_folder);
	mapi_object_release (&obj_table);

	return result;
}

static void 
set_default_folders (mapi_object_t *obj_store, GSList **mapi_folders)
{
	GSList *folder_list = *mapi_folders;
	
	while ((folder_list = g_slist_next (folder_list))) {
		ExchangeMAPIFolder *folder = NULL;
		guint32 default_type = 0;
		folder = folder_list->data;
		if (IsMailboxFolder (obj_store,folder->folder_id, &default_type )) {
			folder->is_default = true; /* TODO : Clean up. Redundant.*/
			folder->default_type = default_type;
		}
	}
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
exchange_mapi_get_folders_list (GSList **mapi_folders)
{
	enum MAPISTATUS 	retval;
	TALLOC_CTX 		*mem_ctx;
	mapi_object_t 		obj_store;
	struct SPropTagArray 	*SPropTagArray;
	struct SPropValue 	*lpProps;
	struct SRow		aRow;
	gboolean 		result = FALSE;
	mapi_id_t		mailbox_id;
	ExchangeMAPIFolder 	*folder;
	uint32_t 		count = 0;
	const char 		*mailbox_name = NULL;
	char 			*utf8_mailbox_name = NULL;
	const char 		*mailbox_owner_name = NULL;
	const char 		*mailbox_user_name = NULL;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_GetFoldersList");
	mapi_object_init(&obj_store);

	/* Open the message store */
	retval = OpenMsgStore(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenMsgStore", GetLastError());
		goto cleanup;
	}

	/* Build the array of Mailbox properties we want to fetch */
	SPropTagArray = set_SPropTagArray(mem_ctx, 0x3,
					  PR_DISPLAY_NAME,
					  PR_MAILBOX_OWNER_NAME,
					  PR_USER_NAME);

	lpProps = talloc_zero(mem_ctx, struct SPropValue);
	retval = GetProps (&obj_store, SPropTagArray, &lpProps, &count);
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
	mailbox_name = (const char *) find_SPropValue_data(&aRow, PR_DISPLAY_NAME);
	mailbox_owner_name = (const char *) find_SPropValue_data(&aRow, PR_MAILBOX_OWNER_NAME);
	mailbox_user_name = (const char *) find_SPropValue_data(&aRow, PR_USER_NAME);

	/* Prepare the directory listing */
	retval = GetDefaultFolder(&obj_store, &mailbox_id, olFolderTopInformationStore);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetDefaultFolder", GetLastError());
		goto cleanup;
	}

	utf8_mailbox_name = utf8tolinux (mailbox_name);

	/* FIXME: May have to get the child folders count? Do we need/use it? */
	folder = exchange_mapi_folder_new (utf8_mailbox_name, IPF_NOTE, MAPI_PERSONAL_FOLDER, mailbox_id, 0, 0, 0 ,0); 
	*mapi_folders = g_slist_prepend (*mapi_folders, folder);

	/* FIXME: check status of get_child_folders */
	get_child_folders (mem_ctx, MAPI_PERSONAL_FOLDER, &obj_store, mailbox_id, mapi_folders);

	g_free(utf8_mailbox_name);

	*mapi_folders = g_slist_reverse (*mapi_folders);

	set_default_folders (&obj_store, mapi_folders);
	g_slist_foreach (*mapi_folders, (GFunc) set_owner_name, (gpointer) mailbox_owner_name);
	g_slist_foreach (*mapi_folders, (GFunc) set_user_name, (gpointer) mailbox_user_name);

	result = TRUE;

cleanup:
	mapi_object_release(&obj_store);
	talloc_free (mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}

gboolean 
exchange_mapi_get_pf_folders_list (GSList **mapi_folders)
{
	enum MAPISTATUS 	retval;
	TALLOC_CTX 		*mem_ctx;
	mapi_object_t 		obj_store;
	gboolean 		result = FALSE;
	mapi_id_t		mailbox_id;
	ExchangeMAPIFolder 	*folder;

	d(g_print("\n%s(%d): Entering %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	LOCK();
	LOGALL();
	mem_ctx = talloc_init("ExchangeMAPI_PF_GetFoldersList");
	mapi_object_init(&obj_store);

	/* Open the PF message store */
	retval = OpenPublicFolder(global_mapi_session, &obj_store);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("OpenPublicFolder", GetLastError());
		goto cleanup;
	}

	/* Prepare the directory listing */
	retval = GetDefaultPublicFolder(&obj_store, &mailbox_id, olFolderPublicIPMSubtree);
	if (retval != MAPI_E_SUCCESS) {
		mapi_errstr("GetDefaultPublicFolder", GetLastError());
		goto cleanup;
	}

	/*  TODO : Localized string */
	folder = exchange_mapi_folder_new ("All Public Folders", IPF_NOTE, 0, mailbox_id, 0, 0, 0 ,0);

	*mapi_folders = g_slist_prepend (*mapi_folders, folder);

	/* FIXME: check status of get_child_folders */
	get_child_folders (mem_ctx, MAPI_FAVOURITE_FOLDER, &obj_store, mailbox_id, mapi_folders);

	result = TRUE;

cleanup:
	mapi_object_release(&obj_store);
	talloc_free (mem_ctx);
	LOGNONE();
	UNLOCK();

	d(g_print("\n%s(%d): Leaving %s ", __FILE__, __LINE__, __PRETTY_FUNCTION__));

	return result;
}


/**
   This function has temporarily been moved here for convenient
   purposes. This is the only routine outside exchange-mapi-connection
   using libmapi calls whih require to have a pointer on MAPI session.

   The function will be moved back to its original location when the
   session context is fixed.
 */
const gchar *
exchange_mapi_util_ex_to_smtp (const gchar *ex_address)
{
	enum MAPISTATUS 	retval;
	TALLOC_CTX 		*mem_ctx;
	struct SPropTagArray	*SPropTagArray;
	struct SRowSet 		*SRowSet = NULL;
	struct SPropTagArray   	*flaglist = NULL;
	const gchar 		*str_array[2];
	const gchar 		*smtp_addr = NULL;

	g_return_val_if_fail (ex_address != NULL, NULL);

	str_array[0] = ex_address;
	str_array[1] = NULL;

	mem_ctx = talloc_init("ExchangeMAPI_EXtoSMTP");

	SPropTagArray = set_SPropTagArray(mem_ctx, 0x2,
					  PR_SMTP_ADDRESS,
					  PR_SMTP_ADDRESS_UNICODE);

	retval = ResolveNames(global_mapi_session, (const char **)str_array, SPropTagArray, &SRowSet, &flaglist, 0);
	if (retval != MAPI_E_SUCCESS)
		retval = ResolveNames(global_mapi_session, (const char **)str_array, SPropTagArray, &SRowSet, &flaglist, MAPI_UNICODE);

	if (retval == MAPI_E_SUCCESS && SRowSet && SRowSet->cRows == 1) {
		smtp_addr = (const char *) find_SPropValue_data(SRowSet->aRow, PR_SMTP_ADDRESS);
		if (!smtp_addr)
			smtp_addr = (const char *) find_SPropValue_data(SRowSet->aRow, PR_SMTP_ADDRESS_UNICODE);
	}

	talloc_free (mem_ctx);

	return smtp_addr;
}
