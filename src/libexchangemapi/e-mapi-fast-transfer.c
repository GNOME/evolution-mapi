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
 *    Milan Crha <mcrha@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc. (www.redhat.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "e-mapi-connection.h"
#include "e-mapi-debug.h"

#include "e-mapi-fast-transfer.h"
#include "e-mapi-openchange.h"

struct _EMapiFXParserClosure;
typedef struct _EMapiFXParserClosure EMapiFXParserClosure;

struct _EMapiFXParserClosure {
	EMapiConnection *conn;
	mapi_id_t fid;
	TALLOC_CTX *mem_ctx;
	EMapiFastTransferCB cb;
	gpointer cb_user_data;
	GError **perror;

	uint32_t next_proptag_is_nameid;
	uint32_t next_nameid_proptag;
	guint32 message_index;
	guint32 messages_total;

	/* in what section it is now */
	uint32_t marker;
	/* where to store read properties */
	struct mapi_SPropValue_array *current_properties;
	/* what message is currently read (can be embeded message or the below message */
	EMapiMessage *current_message;

	/* main message properties */
	EMapiMessage *message;
};

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
	attachment->embeded_message = NULL;
	attachment->next = NULL;

	g_assert (attachment->properties.lpProps != NULL);

	return attachment;
}

void
e_mapi_attachment_free (EMapiAttachment *attachment)
{
	if (!attachment)
		return;

	e_mapi_message_free (attachment->embeded_message);
	talloc_free (attachment->properties.lpProps);
	talloc_free (attachment);
}

EMapiMessage *
e_mapi_message_new (TALLOC_CTX *mem_ctx)
{
	EMapiMessage *message;

	message = talloc_zero (mem_ctx, EMapiMessage);
	g_assert (message != NULL);

	message->properties.cValues = 0;
	message->properties.lpProps = talloc_zero_array (mem_ctx, struct mapi_SPropValue, 1);
	message->recipients = NULL;
	message->attachments = NULL;
	message->parent = NULL;

	g_assert (message->properties.lpProps != NULL);

	return message;
}

void
e_mapi_message_free (EMapiMessage *message)
{
	EMapiRecipient *recipient;
	EMapiAttachment *attachment;

	if (!message)
		return;

	recipient = message->recipients;
	while (recipient) {
		EMapiRecipient *r = recipient;

		recipient = recipient->next;
		e_mapi_recipient_free (r);
	}

	attachment = message->attachments;
	while (attachment) {
		EMapiAttachment *a = attachment;

		attachment = attachment->next;
		e_mapi_attachment_free (a);
	}

	talloc_free (message->properties.lpProps);
	talloc_free (message);
}

static void
e_mapi_message_finish_read (EMapiMessage *message)
{
	EMapiRecipient *rprev, *rtail, *rnext;
	EMapiAttachment *aprev, *atail, *anext;

	if (!message)
		return;

	/* reverse order of recipients and attachments */
	rprev = NULL;
	for (rtail = message->recipients; rtail; rtail = rnext) {
		rnext = rtail->next;
		rtail->next = rprev;
		rprev = rtail;
	}
	message->recipients = rprev;

	aprev = NULL;
	for (atail = message->attachments; atail; atail = anext) {
		anext = atail->next;
		atail->next = aprev;
		aprev = atail;
	}
	message->attachments = aprev;
}

void
e_mapi_message_dump (EMapiMessage *message, gint indent, gboolean with_properties)
{
	EMapiRecipient *recipient;
	EMapiAttachment *attachment;
	gint index;

	g_print ("%*sEMapiMessage: %p (parent:%p)\n", indent, "", message, message->parent);

	if (!message)
		return;

	if (with_properties)
		e_mapi_debug_dump_properties (NULL, 0, &message->properties, indent + 3);

	for (index = 0, recipient = message->recipients; recipient; index++, recipient = recipient->next) {
		g_print ("%*sRecipient[%d]:\n", indent + 2, "", index);
		if (with_properties)
			e_mapi_debug_dump_properties (NULL, 0, &recipient->properties, indent + 3);
	}

	for (index = 0, attachment = message->attachments; attachment; index++, attachment = attachment->next) {
		g_print ("%*sAttachment[%d]:\n", indent + 2, "", index);
		if (with_properties)
			e_mapi_debug_dump_properties (NULL, 0, &attachment->properties, indent + 3);
		if (attachment->embeded_message) {
			g_print ("%*sEmbeded message:\n", indent + 3, "");
			e_mapi_message_dump (attachment->embeded_message, indent + 5, with_properties);
		}
	}
}

static gboolean
process_parsed_message (EMapiFXParserClosure *data)
{
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->conn != NULL, FALSE);
	g_return_val_if_fail (data->cb != NULL, FALSE);
	g_return_val_if_fail (data->message != NULL, FALSE);

	return data->cb (data->conn, data->fid, data->mem_ctx, data->message, data->message_index, data->messages_total, data->cb_user_data, data->perror);
}

static enum MAPISTATUS
parse_marker_cb (uint32_t marker, void *closure)
{
	EMapiFXParserClosure *data = closure;
	gboolean stop = FALSE;

	/* g_print ("\tMarker: %s (0x%08x)\n", get_proptag_name (marker), marker); */
	switch (marker) {
		case PidTagStartMessage:
			if (data->message) {
				g_debug ("%s: PidTagStartMessage: out of order, previous message not finished yet", G_STRFUNC);
				e_mapi_message_finish_read (data->message);
				stop = !process_parsed_message (data);
				e_mapi_message_free (data->message);
				data->message = NULL;
				data->current_message = NULL;
				data->current_properties = NULL;
			}

			if (stop)
				return MAPI_E_USER_CANCEL;

			/* new message parsing */
			data->message_index++;
			data->message = e_mapi_message_new (data->mem_ctx);
			data->current_message = data->message;
			data->current_properties = &data->message->properties;
			data->marker = marker;
			break;
		case PidTagEndMessage:
			if (!data->message) {
				g_debug ("%s: PidTagEndMessage no message started", G_STRFUNC);
			} else {
				e_mapi_message_finish_read (data->message);
				stop = !process_parsed_message (data);

				e_mapi_message_free (data->message);
				data->message = NULL;
				data->current_message = NULL;
				data->current_properties = NULL;

				if (stop)
					return MAPI_E_USER_CANCEL;
			}
			data->marker = 0;
			break;
		case PidTagStartRecip:
			if (!data->current_message) {
				g_debug ("%s: PidTagStartRecip no message started", G_STRFUNC);
			} else {
				EMapiRecipient *recipient;

				recipient = e_mapi_recipient_new (data->mem_ctx);

				/* they are stored in reverse order, but reverted before passing to a caller */
				recipient->next = data->current_message->recipients;
				data->current_message->recipients = recipient;

				data->current_properties = &recipient->properties;
			}
			data->marker = marker;
			break;
		case PidTagEndToRecip:
			data->current_properties = NULL;
			data->marker = 0;
			break;
		case PidTagNewAttach:
			if (!data->current_message) {
				g_debug ("%s: PidTagNewAttach no message started", G_STRFUNC);
			} else {
				EMapiAttachment *attachment;

				attachment = e_mapi_attachment_new (data->mem_ctx);

				/* they are stored in reverse order, but reverted before passing to a caller */
				attachment->next = data->current_message->attachments;
				data->current_message->attachments = attachment;

				data->current_properties = &attachment->properties;
			}
			data->marker = marker;
			break;
		case PidTagEndAttach:
			data->current_properties = NULL;
			data->marker = 0;
			break;
		case PidTagStartEmbed:
			if (!data->current_message) {
				g_debug ("%s: PidTagStartEmbed no message started", G_STRFUNC);
			} else if (!data->current_message->attachments) {
				g_debug ("%s: PidTagStartEmbed no attachment started", G_STRFUNC);
			} else if (data->current_message->attachments->embeded_message) {
				g_debug ("%s: PidTagStartEmbed attachment has embeded message already", G_STRFUNC);
			} else {
				EMapiMessage *message;

				message = e_mapi_message_new (data->mem_ctx);

				message->parent = data->current_message;
				data->current_message->attachments->embeded_message = message;
				data->current_message = message;
				data->current_properties = &message->properties;
			}
			data->marker = marker;
			break;
		case PidTagEndEmbed:
			if (!data->current_message) {
				g_debug ("%s: PidTagEndEmbed no message started", G_STRFUNC);
			} else if (!data->current_message->parent) {
				g_debug ("%s: PidTagEndEmbed no parent message", G_STRFUNC);
			} else {
				e_mapi_message_finish_read (data->current_message);
				data->current_message = data->current_message->parent;
				data->current_properties = NULL;
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
		if (e_mapi_nameid_lid_lookup_canonical (nameid.kind.lid, guid, &lid) != MAPI_E_SUCCESS)
			lid = MAPI_E_RESERVED;
	} else if (nameid.ulKind == MNID_STRING) {
		if (e_mapi_nameid_string_lookup_canonical (nameid.kind.lpwstr.Name, guid, &lid) != MAPI_E_SUCCESS)
			lid = MAPI_E_RESERVED;
	}

	talloc_free (guid);

	if (lid != MAPI_E_RESERVED) {
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
			       mapi_id_t fid,
			       TALLOC_CTX *mem_ctx,
			       EMapiFastTransferCB cb,
			       gpointer cb_user_data,
			       gint messages_total,
			       gboolean expect_start_message,
			       mapi_object_t *fasttransfer_ctx,
			       GError **perror)
{
	enum MAPISTATUS ms;
	enum TransferStatus transferStatus;
	uint16_t stepCount = -1, totalCount = -1;
	struct fx_parser_context *parser;
	EMapiFXParserClosure data = { 0 };

	data.conn = conn;
	data.fid = fid;
	data.mem_ctx = talloc_new (mem_ctx);
	data.cb = cb;
	data.cb_user_data = cb_user_data;
	data.perror = perror;

	data.next_proptag_is_nameid = MAPI_E_RESERVED;
	data.next_nameid_proptag = MAPI_E_RESERVED;
	data.message_index = 0;
	data.messages_total = messages_total;
	data.marker = 0;
	data.current_properties = NULL;
	data.current_message = NULL;
	data.message = NULL;

	if (!expect_start_message) {
		data.message_index++;
		data.message = e_mapi_message_new (data.mem_ctx);
		data.current_message = data.message;
		data.current_properties = &data.message->properties;
		data.marker = PidTagStartMessage;
	}
		
	parser = fxparser_init (data.mem_ctx, &data);
	fxparser_set_marker_callback (parser, parse_marker_cb);
	fxparser_set_delprop_callback (parser, parse_delprop_cb);
	fxparser_set_namedprop_callback (parser, parse_namedprop_cb);
	fxparser_set_property_callback (parser, parse_property_cb);

	do {
		DATA_BLOB transferdata;

		ms = FXGetBuffer (fasttransfer_ctx, 0, &transferStatus, &stepCount, &totalCount, &transferdata);
		if (ms != MAPI_E_SUCCESS)
			break;

		fxparser_parse (parser, &transferdata);
	} while ((transferStatus == TransferStatus_Partial) || (transferStatus == TransferStatus_NoRoom));

	if (data.message) {
		e_mapi_message_finish_read (data.message);
		if (ms == MAPI_E_SUCCESS && !process_parsed_message (&data))
			ms = MAPI_E_USER_CANCEL;

		e_mapi_message_free (data.message);
	}

	talloc_free (parser);
	talloc_free (data.mem_ctx);

	return ms;
}

enum MAPISTATUS
e_mapi_fast_transfer_objects (EMapiConnection *conn,
			      mapi_id_t fid,
			      TALLOC_CTX *mem_ctx,
			      mapi_object_t *obj_folder,
			      mapi_id_array_t *ids,
			      EMapiFastTransferCB cb,
			      gpointer cb_user_data,
			      GError **perror)
{
	enum MAPISTATUS ms;
	mapi_object_t fasttransfer_ctx;

	mapi_object_init (&fasttransfer_ctx);

	ms = FXCopyMessages (obj_folder, ids, FastTransferCopyMessage_BestBody, FastTransfer_Unicode, &fasttransfer_ctx);
	if (ms != MAPI_E_SUCCESS) {
		return ms;
	}

	ms = e_mapi_fast_transfer_internal (conn, fid, mem_ctx, cb, cb_user_data, ids->count, TRUE, &fasttransfer_ctx, perror);

	mapi_object_release (&fasttransfer_ctx);

	if (perror && !*perror && ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, G_STRFUNC, ms);

	return ms;
}

enum MAPISTATUS
e_mapi_fast_transfer_object (EMapiConnection *conn,
			     mapi_id_t fid,
			     TALLOC_CTX *mem_ctx,
			     mapi_object_t *obj_message,
			     guint32 transfer_flags, /* bit or of EMapiFastTransferFlags */
			     EMapiFastTransferCB cb,
			     gpointer cb_user_data,
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

	ms = FXCopyTo (obj_message, 0, FastTransferCopyTo_BestBody, FastTransfer_Unicode, excludes, &fasttransfer_ctx);
	if (ms != MAPI_E_SUCCESS) {
		return ms;
	}

	ms = e_mapi_fast_transfer_internal (conn, fid, mem_ctx, cb, cb_user_data, 1, FALSE, &fasttransfer_ctx, perror);

	mapi_object_release (&fasttransfer_ctx);
	talloc_free (excludes);

	if (perror && !*perror && ms != MAPI_E_SUCCESS)
		make_mapi_error (perror, G_STRFUNC, ms);

	return ms;
}
