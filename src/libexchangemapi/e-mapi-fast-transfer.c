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
 *    Milan Crha <mcrha@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc. (www.redhat.com)
 *
 */

#include "evolution-mapi-config.h"

#include "e-mapi-connection.h"
#include "e-mapi-debug.h"

#include "e-mapi-fast-transfer.h"

#ifndef HAVE_FAST_TRANSFER_TAGS_2_1
#define StartMessage PidTagStartMessage
#define EndMessage PidTagEndMessage
#define StartRecip PidTagStartRecip
#define EndToRecip PidTagEndToRecip
#define NewAttach PidTagNewAttach
#define EndAttach PidTagEndAttach
#define StartEmbed PidTagStartEmbed
#define EndEmbed PidTagEndEmbed
#endif

struct _EMapiFXParserClosure;
typedef struct _EMapiFXParserClosure EMapiFXParserClosure;

struct _EMapiFXParserClosure {
	EMapiConnection *conn;
	TALLOC_CTX *mem_ctx;
	TransferObjectCB cb;
	gpointer cb_user_data;
	GCancellable *cancellable;
	GError **perror;

	uint32_t next_proptag_is_nameid;
	uint32_t next_nameid_proptag;
	guint32 object_index;
	guint32 objects_total;

	/* in what section it is now */
	uint32_t marker;
	/* where to store read properties */
	struct mapi_SPropValue_array *current_properties;
	TALLOC_CTX *current_streamed_mem_ctx;
	EMapiStreamedProp **current_streamed_properties;
	guint32 *current_streamed_properties_count;
	
	/* what object is currently read (can be embeded object or the below object */
	EMapiObject *current_object;

	/* main object properties */
	EMapiObject *object;
};

static void
e_mapi_object_finish_read (EMapiObject *object)
{
	EMapiRecipient *rprev, *rtail, *rnext;
	EMapiAttachment *aprev, *atail, *anext;

	if (!object)
		return;

	/* reverse order of recipients and attachments */
	rprev = NULL;
	for (rtail = object->recipients; rtail; rtail = rnext) {
		rnext = rtail->next;
		rtail->next = rprev;
		rprev = rtail;
	}
	object->recipients = rprev;

	aprev = NULL;
	for (atail = object->attachments; atail; atail = anext) {
		anext = atail->next;
		atail->next = aprev;
		aprev = atail;
	}
	object->attachments = aprev;
}

static gboolean
process_parsed_object (EMapiFXParserClosure *data)
{
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->conn != NULL, FALSE);
	g_return_val_if_fail (data->cb != NULL, FALSE);
	g_return_val_if_fail (data->object != NULL, FALSE);

	return data->cb (data->conn, data->mem_ctx, data->object, data->object_index, data->objects_total, data->cb_user_data, data->cancellable, data->perror);
}

static enum MAPISTATUS
parse_marker_cb (uint32_t marker, void *closure)
{
	EMapiFXParserClosure *data = closure;
	gboolean stop = FALSE;

	/* g_print ("\tMarker: %s (0x%08x)\n", get_proptag_name (marker), marker); */
	switch (marker) {
		case StartMessage:
			if (data->object) {
				g_debug ("%s: StartMessage: out of order, previous object not finished yet", G_STRFUNC);
				e_mapi_object_finish_read (data->object);
				stop = !process_parsed_object (data);
				e_mapi_object_free (data->object);
				data->object = NULL;
				data->current_object = NULL;
				data->current_properties = NULL;
				data->current_streamed_mem_ctx = NULL;
				data->current_streamed_properties = NULL;
				data->current_streamed_properties_count = NULL;
			}

			if (stop)
				return MAPI_E_USER_CANCEL;

			/* new object parsing */
			data->object_index++;
			data->object = e_mapi_object_new (data->mem_ctx);
			data->current_object = data->object;
			data->current_properties = &data->object->properties;
			data->current_streamed_mem_ctx = data->object;
			data->current_streamed_properties = &data->object->streamed_properties;
			data->current_streamed_properties_count = &data->object->streamed_properties_count;
			data->marker = marker;
			break;
		case EndMessage:
			if (!data->object) {
				g_debug ("%s: EndMessage no object started", G_STRFUNC);
			} else {
				e_mapi_object_finish_read (data->object);
				stop = !process_parsed_object (data);

				e_mapi_object_free (data->object);
				data->object = NULL;
				data->current_object = NULL;
				data->current_properties = NULL;
				data->current_streamed_mem_ctx = NULL;
				data->current_streamed_properties = NULL;
				data->current_streamed_properties_count = NULL;

				if (stop)
					return MAPI_E_USER_CANCEL;
			}
			data->marker = 0;
			break;
		case StartRecip:
			if (!data->current_object) {
				g_debug ("%s: StartRecip no object started", G_STRFUNC);
			} else {
				EMapiRecipient *recipient;

				recipient = e_mapi_recipient_new (data->mem_ctx);

				/* they are stored in reverse order, but reverted before passing to a caller */
				recipient->next = data->current_object->recipients;
				data->current_object->recipients = recipient;

				data->current_properties = &recipient->properties;
				data->current_streamed_mem_ctx = NULL;
				data->current_streamed_properties = NULL;
				data->current_streamed_properties_count = NULL;
			}
			data->marker = marker;
			break;
		case EndToRecip:
			data->current_properties = NULL;
			data->current_streamed_mem_ctx = NULL;
			data->current_streamed_properties = NULL;
			data->current_streamed_properties_count = NULL;
			data->marker = 0;
			break;
		case NewAttach:
			if (!data->current_object) {
				g_debug ("%s: NewAttach no object started", G_STRFUNC);
			} else {
				EMapiAttachment *attachment;

				attachment = e_mapi_attachment_new (data->mem_ctx);

				/* they are stored in reverse order, but reverted before passing to a caller */
				attachment->next = data->current_object->attachments;
				data->current_object->attachments = attachment;

				data->current_properties = &attachment->properties;
				data->current_streamed_mem_ctx = attachment;
				data->current_streamed_properties = &attachment->streamed_properties;
				data->current_streamed_properties_count = &attachment->streamed_properties_count;
			}
			data->marker = marker;
			break;
		case EndAttach:
			data->current_properties = NULL;
			data->current_streamed_mem_ctx = NULL;
			data->current_streamed_properties = NULL;
			data->current_streamed_properties_count = NULL;
			data->marker = 0;
			break;
		case StartEmbed:
			if (!data->current_object) {
				g_debug ("%s: StartEmbed no object started", G_STRFUNC);
			} else if (!data->current_object->attachments) {
				g_debug ("%s: StartEmbed no attachment started", G_STRFUNC);
			} else if (data->current_object->attachments->embedded_object) {
				g_debug ("%s: StartEmbed attachment has embedded object already", G_STRFUNC);
			} else {
				EMapiObject *object;

				object = e_mapi_object_new (data->mem_ctx);

				object->parent = data->current_object;
				data->current_object->attachments->embedded_object = object;
				data->current_object = object;
				data->current_properties = &object->properties;
				data->current_streamed_mem_ctx = object;
				data->current_streamed_properties = &object->streamed_properties;
				data->current_streamed_properties_count = &object->streamed_properties_count;
			}
			data->marker = marker;
			break;
		case EndEmbed:
			if (!data->current_object) {
				g_debug ("%s: EndEmbed no object started", G_STRFUNC);
			} else if (!data->current_object->parent) {
				g_debug ("%s: EndEmbed no parent object", G_STRFUNC);
			} else {
				e_mapi_object_finish_read (data->current_object);
				data->current_object = data->current_object->parent;
				data->current_properties = NULL;
				data->current_streamed_mem_ctx = NULL;
				data->current_streamed_properties = NULL;
				data->current_streamed_properties_count = NULL;
			}
			data->marker = 0;
			break;
		default:
			data->marker = marker;
			break;
	}

	return MAPI_E_SUCCESS;
}

static enum MAPISTATUS
parse_delprop_cb (uint32_t proptag, void *closure)
{
	return MAPI_E_SUCCESS;
}

static enum MAPISTATUS
parse_namedprop_cb (uint32_t proptag, struct MAPINAMEID nameid, void *closure)
{
	/* the next property is a named property, but cannot make it proptag, thus left it for later */
	EMapiFXParserClosure *data = closure;
	uint32_t lid = MAPI_E_RESERVED;
	char *guid;

	guid = GUID_string (data->mem_ctx, &(nameid.lpguid));

	if (nameid.ulKind == MNID_ID) {
		if (mapi_nameid_lid_lookup_canonical (nameid.kind.lid, guid, &lid) != MAPI_E_SUCCESS)
			lid = MAPI_E_RESERVED;
	} else if (nameid.ulKind == MNID_STRING) {
		if (mapi_nameid_string_lookup_canonical (nameid.kind.lpwstr.Name, guid, &lid) != MAPI_E_SUCCESS)
			lid = MAPI_E_RESERVED;
	}

	talloc_free (guid);

	if (lid != MAPI_E_RESERVED && (lid & 0xFFFF) == (proptag & 0xFFFF)) {
		data->next_proptag_is_nameid = proptag;
		data->next_nameid_proptag = lid;
	}

	return MAPI_E_SUCCESS;
}

static enum MAPISTATUS
parse_property_cb (struct SPropValue prop, void *closure)
{
	EMapiFXParserClosure *data = closure;

	if (data->next_proptag_is_nameid == prop.ulPropTag) {
		prop.ulPropTag = data->next_nameid_proptag;
	}

	data->next_proptag_is_nameid = MAPI_E_RESERVED;
	data->next_nameid_proptag = MAPI_E_RESERVED;

	if (!data->current_properties) {
		if (data->marker)
			g_debug ("%s: Property received out of order under marker %s", G_STRFUNC, get_proptag_name (data->marker));
		return MAPI_E_SUCCESS;
	}

	switch (prop.ulPropTag & 0xFFFF) {
		case PT_BINARY:
			if (data->current_streamed_properties && data->current_streamed_properties_count &&
			    prop.value.bin.cb > 65535) {
				guint32 index;

				(*data->current_streamed_properties) = talloc_realloc (data->current_streamed_mem_ctx,
					(*data->current_streamed_properties),
					EMapiStreamedProp,
					(*data->current_streamed_properties_count) + 1);
				index = (*data->current_streamed_properties_count);
				(*data->current_streamed_properties_count)++;
				(*data->current_streamed_properties)[index].proptag = prop.ulPropTag;
				(*data->current_streamed_properties)[index].cb = prop.value.bin.cb;
				(*data->current_streamed_properties)[index].lpb = prop.value.bin.lpb;
				break;
			} else if (prop.value.bin.cb > 65535) {
				g_debug ("%s: PT_BINARY property 0x%X larger than 64KB (%d), will be truncated", G_STRFUNC, prop.ulPropTag, prop.value.bin.cb);
			}
			/* falls through */
		case PT_BOOLEAN:
		case PT_I2:
		case PT_LONG:
		case PT_DOUBLE:
		case PT_I8:
		case PT_STRING8:
		case PT_UNICODE:
		case PT_SYSTIME:
		case PT_ERROR:
		case PT_CLSID:
		case PT_SVREID:
		case PT_MV_STRING8:
		case PT_MV_UNICODE:
		case PT_MV_BINARY:
		case PT_MV_LONG:
			data->current_properties->cValues++;
			data->current_properties->lpProps = talloc_realloc (data->mem_ctx,
									    data->current_properties->lpProps,
									    struct mapi_SPropValue,
									    data->current_properties->cValues + 1);
			cast_mapi_SPropValue (data->mem_ctx, &data->current_properties->lpProps[data->current_properties->cValues - 1], &prop);
			data->current_properties->lpProps[data->current_properties->cValues].ulPropTag = 0;
			break;
		default:
			/* skip all of other type */
			break;
	}

	return MAPI_E_SUCCESS;
}

static enum MAPISTATUS
e_mapi_fast_transfer_internal (EMapiConnection *conn,
			       TALLOC_CTX *mem_ctx,
			       TransferObjectCB cb,
			       gpointer cb_user_data,
			       gint objects_total,
			       gboolean expect_start_message,
			       mapi_object_t *fasttransfer_ctx,
			       GCancellable *cancellable,
			       GError **perror)
{
	enum MAPISTATUS ms;
	enum TransferStatus transferStatus;
	uint16_t stepCount = -1, totalCount = -1;
	struct fx_parser_context *parser;
	EMapiFXParserClosure data = { 0 };

	data.conn = conn;
	data.mem_ctx = talloc_new (mem_ctx);
	data.cb = cb;
	data.cb_user_data = cb_user_data;
	data.cancellable = cancellable;
	data.perror = perror;

	data.next_proptag_is_nameid = MAPI_E_RESERVED;
	data.next_nameid_proptag = MAPI_E_RESERVED;
	data.object_index = 0;
	data.objects_total = objects_total;
	data.marker = 0;
	data.current_properties = NULL;
	data.current_streamed_mem_ctx = NULL;
	data.current_streamed_properties = NULL;
	data.current_streamed_properties_count = NULL;
	data.current_object = NULL;
	data.object = NULL;

	if (!expect_start_message) {
		data.object_index++;
		data.object = e_mapi_object_new (data.mem_ctx);
		data.current_object = data.object;
		data.current_properties = &data.object->properties;
		data.current_streamed_mem_ctx = data.object;
		data.current_streamed_properties = &data.object->streamed_properties;
		data.current_streamed_properties_count = &data.object->streamed_properties_count;
		data.marker = StartMessage;
	}
		
	parser = fxparser_init (data.mem_ctx, &data);
	fxparser_set_marker_callback (parser, parse_marker_cb);
	fxparser_set_delprop_callback (parser, parse_delprop_cb);
	fxparser_set_namedprop_callback (parser, parse_namedprop_cb);
	fxparser_set_property_callback (parser, parse_property_cb);

	do {
		DATA_BLOB transferdata;

		transferdata.data = NULL;

		ms = FXGetBuffer (fasttransfer_ctx, 0, &transferStatus, &stepCount, &totalCount, &transferdata);
		if (ms != MAPI_E_SUCCESS)
			break;

		ms = fxparser_parse (parser, &transferdata);
		talloc_free (transferdata.data);
		if (ms != MAPI_E_SUCCESS)
			break;

		if (g_cancellable_is_cancelled (cancellable)) {
			ms = MAPI_E_USER_CANCEL;
			break;
		}
	} while ((transferStatus == TransferStatus_Partial) || (transferStatus == TransferStatus_NoRoom));

	if (data.object) {
		e_mapi_object_finish_read (data.object);
		if (ms == MAPI_E_SUCCESS && !process_parsed_object (&data))
			ms = MAPI_E_USER_CANCEL;

		e_mapi_object_free (data.object);
	}

	talloc_free (parser);
	talloc_free (data.mem_ctx);

	return ms;
}

enum MAPISTATUS
e_mapi_fast_transfer_objects (EMapiConnection *conn,
			      TALLOC_CTX *mem_ctx,
			      mapi_object_t *obj_folder,
			      mapi_id_array_t *ids,
			      TransferObjectCB cb,
			      gpointer cb_user_data,
			      GCancellable *cancellable,
			      GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t fasttransfer_ctx;

	mapi_object_init (&fasttransfer_ctx);

	ms = FXCopyMessages (obj_folder, ids, FastTransferCopyMessage_BestBody, FastTransfer_Unicode, &fasttransfer_ctx);
	if (ms == MAPI_E_SUCCESS)
		ms = e_mapi_fast_transfer_internal (conn, mem_ctx, cb, cb_user_data, ids->count, TRUE, &fasttransfer_ctx, cancellable, perror);

	mapi_object_release (&fasttransfer_ctx);

	if (perror && !*perror && ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, G_STRFUNC, ms);

	return ms;
}

enum MAPISTATUS
e_mapi_fast_transfer_object (EMapiConnection *conn,
			     TALLOC_CTX *mem_ctx,
			     mapi_object_t *object,
			     guint32 transfer_flags, /* bit or of EMapiFastTransferFlags */
			     TransferObjectCB cb,
			     gpointer cb_user_data,
			     GCancellable *cancellable,
			     GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t fasttransfer_ctx;
	struct SPropTagArray *excludes = NULL;

	mapi_object_init (&fasttransfer_ctx);

	#define add(x)	{						\
		if (!excludes)						\
			excludes = set_SPropTagArray (mem_ctx, 0x1, x);	\
		else							\
			SPropTagArray_add (mem_ctx, excludes, x);	\
	}

	if (!(transfer_flags & E_MAPI_FAST_TRANSFER_FLAG_ATTACHMENTS))
		add (PidTagMessageAttachments);
	if (!(transfer_flags & E_MAPI_FAST_TRANSFER_FLAG_RECIPIENTS))
		add (PidTagMessageRecipients);

	#undef add

	if (!excludes)
		excludes = talloc_zero (mem_ctx, struct SPropTagArray);

	ms = FXCopyTo (object, 0, FastTransferCopyTo_BestBody, FastTransfer_Unicode, excludes, &fasttransfer_ctx);
	if (ms == MAPI_E_SUCCESS)
		ms = e_mapi_fast_transfer_internal (conn, mem_ctx, cb, cb_user_data, 1, FALSE, &fasttransfer_ctx, cancellable, perror);

	mapi_object_release (&fasttransfer_ctx);
	talloc_free (excludes);

	if (perror && !*perror && ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, G_STRFUNC, ms);

	return ms;
}

enum MAPISTATUS
e_mapi_fast_transfer_properties	(EMapiConnection *conn,
				 TALLOC_CTX *mem_ctx,
				 mapi_object_t *object,
				 struct SPropTagArray *tags,
				 TransferObjectCB cb,
				 gpointer cb_user_data,
				 GCancellable *cancellable,
				 GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t fasttransfer_ctx;

	g_return_val_if_fail (tags != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (tags->cValues > 0, MAPI_E_INVALID_PARAMETER);

	mapi_object_init (&fasttransfer_ctx);

	ms = FXCopyProperties (object, 0, 0, FastTransfer_Unicode, tags, &fasttransfer_ctx);
	if (ms == MAPI_E_SUCCESS)
		ms = e_mapi_fast_transfer_internal (conn, mem_ctx, cb, cb_user_data, 1, FALSE, &fasttransfer_ctx, cancellable, perror);

	mapi_object_release (&fasttransfer_ctx);

	if (perror && !*perror && ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, G_STRFUNC, ms);

	return ms;
}
