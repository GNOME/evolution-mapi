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

#ifndef EXCHANGE_MAPI_CONNECTION_H
#define EXCHANGE_MAPI_CONNECTION_H 

#include <glib.h>
#include <glib-object.h>

#include <libmapi/libmapi.h>

/* Standard GObject macros */
#define EXCHANGE_TYPE_MAPI_CONNECTION (exchange_mapi_connection_get_type ())
#define EXCHANGE_MAPI_CONNECTION(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), EXCHANGE_TYPE_MAPI_CONNECTION, ExchangeMapiConnection))
#define EXCHANGE_MAPI_CONNECTION_CLASS(cls) (G_TYPE_CHECK_CLASS_CAST ((cls), EXCHANGE_TYPE_MAPI_CONNECTION, ExchangeMapiConnectionClass))
#define EXCHANGE_IS_MAPI_CONNECTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), EXCHANGE_TYPE_MAPI_CONNECTION))
#define EXCHANGE_IS_MAPI_CONNECTION_CLASS(cls) (G_TYPE_CHECK_CLASS_TYPE ((cls), EXCHANGE_TYPE_MAPI_CONNECTION))
#define EXCHANGE_MAPI_CONNECTION_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), EXCHANGE_TYPE_MAPI_CONNECTION, ExchangeMapiConnectionClass))

G_BEGIN_DECLS

GQuark e_mapi_error_quark (void);
#define E_MAPI_ERROR e_mapi_error_quark ()

typedef struct _ExchangeMapiConnection ExchangeMapiConnection;
typedef struct _ExchangeMapiConnectionClass ExchangeMapiConnectionClass;
typedef struct _ExchangeMapiConnectionPrivate ExchangeMapiConnectionPrivate;

typedef enum {
	MAPI_OPTIONS_FETCH_ATTACHMENTS = 1<<0,
	MAPI_OPTIONS_FETCH_RECIPIENTS = 1<<1,
	MAPI_OPTIONS_FETCH_BODY_STREAM = 1<<2,
	MAPI_OPTIONS_FETCH_GENERIC_STREAMS = 1<<3,
	MAPI_OPTIONS_FETCH_GAL = 1 <<4,
	MAPI_OPTIONS_DONT_SUBMIT = 1<<5,
	MAPI_OPTIONS_GETBESTBODY = 1<<6,
	MAPI_OPTIONS_USE_PFSTORE = 1<<7,
	MAPI_OPTIONS_DONT_OPEN_MESSAGE = 1<<8,
	MAPI_OPTIONS_DELETE_ON_SUBMIT_FAILURE = 1<<9
} ExchangeMAPIOptions;

/* Flags for push notification APIs*/
typedef enum {
	MAPI_EVENTS_USE_STORE = 1<<0,
	MAPI_EVENTS_USE_PF_STORE = 1<<1,
	MAPI_EVENTS_FOLDER = 1<<2,
} ExchangeMAPIEventsOptions;

#define MAPI_OPTIONS_FETCH_ALL MAPI_OPTIONS_FETCH_ATTACHMENTS | \
			       MAPI_OPTIONS_FETCH_RECIPIENTS | \
			       MAPI_OPTIONS_FETCH_BODY_STREAM | \
			       MAPI_OPTIONS_FETCH_GENERIC_STREAMS

typedef struct {
	GByteArray *value;
	uint32_t proptag;
} ExchangeMAPIStream;

typedef struct {
	GByteArray *value;
	uint32_t proptag;
	uint32_t editor_format;
} ExchangeMAPIBodyStream;

typedef struct {
	/* MANDATORY */
	const gchar *email_id;
	TALLOC_CTX *mem_ctx;

	/* It is ideal to set all these properties on all recipients
	 * as we never know if a recipient would be resolved or not. */
	struct {
		/* These are properties which would be set on the
		 * recipients regardless if the recipient is resolved or not */
		uint32_t req_cValues;
		struct SPropValue *req_lpProps;

		/* These are properties which would be set on the
		 * recipients only if the recipient is MAPI_UNRESOLVED */
		uint32_t ext_cValues;
		struct SPropValue *ext_lpProps;
	} in;

	/* These are properties which would be set on the
	 * recipients after GetRecipientTable() */
	struct SRow out_SRow;
} ExchangeMAPIRecipient;

struct _MailItem;

typedef struct {
	uint32_t cValues;
	struct SPropValue *lpProps;
	GSList *streams;
	GSList *objects;
	struct _MailItem *mail; /* not NULL when writing mail attachment; in this case are other members ignored */
} ExchangeMAPIAttachment;

typedef struct {
	ExchangeMapiConnection *conn;
	struct mapi_SPropValue_array *properties;
	mapi_id_t fid;
	mapi_id_t mid;
	uint32_t msg_flags; /* used only with fetch_items */
	GSList *attachments;
	GSList *recipients;
	GSList *gallist;
	GSList *streams;
	guint total; /*Total number of results*/
	guint index; /*Index of this Item*/
} FetchItemsCallbackData;

struct id_list {
	mapi_id_t id;
};

typedef struct {
	uint32_t pidlid_propid; /* PidLid or PidName legacy property named ID to resolve */
	uint32_t propid;	/* resolved prop ID; equals to MAPI_E_RESERVED when not found or other error */
} ResolveNamedIDsData;

typedef gboolean (*FetchCallback)	(FetchItemsCallbackData *item_data, gpointer data);
typedef gboolean (*FetchGALCallback)	(ExchangeMapiConnection *conn, uint32_t row_index, uint32_t n_rows, struct SRow *aRow, gpointer data);
typedef gboolean (*BuildWritePropsCB)	(ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropValue **values, uint32_t *n_values, gpointer data);
typedef gboolean (*BuildReadPropsCB)	(ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data);

struct _ExchangeMapiConnection {
	GObject parent;

	ExchangeMapiConnectionPrivate *priv;
};

struct _ExchangeMapiConnectionClass {
	GObjectClass parent_class;

	/* signals */
};

GType			exchange_mapi_connection_get_type (void);
ExchangeMapiConnection *exchange_mapi_connection_new (const gchar *profile, const gchar *password, GError **perror);
ExchangeMapiConnection *exchange_mapi_connection_find (const gchar *profile);
gboolean		exchange_mapi_connection_reconnect (ExchangeMapiConnection *conn, const gchar *password, GError **perror);
gboolean		exchange_mapi_connection_close (ExchangeMapiConnection *conn);
gboolean		exchange_mapi_connection_connected (ExchangeMapiConnection *conn);

gboolean		exchange_mapi_connection_fetch_object_props (
					ExchangeMapiConnection *conn, mapi_object_t *obj_folder, mapi_id_t fid, mapi_id_t mid, mapi_object_t *obj_message,
					BuildReadPropsCB build_props, gpointer brp_data,
					FetchCallback cb, gpointer data,
					guint32 options, GError **perror);

gboolean		exchange_mapi_connection_fetch_item (ExchangeMapiConnection *conn, mapi_id_t fid, mapi_id_t mid,
					BuildReadPropsCB build_props, gpointer brp_data,
					FetchCallback cb, gpointer data,
					guint32 options, GError **perror);

gboolean		exchange_mapi_connection_fetch_items (ExchangeMapiConnection *conn, mapi_id_t fid,
					struct mapi_SRestriction *res, struct SSortOrderSet *sort_order,
					BuildReadPropsCB build_props, gpointer brp_data,
					FetchCallback cb, gpointer data,
					guint32 options, GError **perror);

gboolean		exchange_mapi_connection_fetch_gal (ExchangeMapiConnection *conn, struct mapi_SRestriction *restrictions,
					BuildReadPropsCB build_props, gpointer brp_data,
					FetchGALCallback cb, gpointer data, GError **perror);

gboolean		exchange_mapi_connection_get_public_folder (ExchangeMapiConnection *conn, mapi_object_t *obj_object, GError **perror);

mapi_id_t		exchange_mapi_connection_create_folder (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t pfid, guint32 fid_options, const gchar *name, GError **perror);
gboolean		exchange_mapi_connection_remove_folder (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, GError **perror);
gboolean		exchange_mapi_connection_empty_folder (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, GError **perror);
gboolean		exchange_mapi_connection_rename_folder (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, const gchar *new_name, GError **perror);
gboolean		exchange_mapi_connection_move_folder (ExchangeMapiConnection *conn, mapi_id_t src_fid, mapi_id_t src_parent_fid, guint32 src_fid_options, mapi_id_t des_fid, guint32 des_fid_options, const gchar *new_name, GError **perror);
GSList *		exchange_mapi_connection_check_restriction (ExchangeMapiConnection *conn, mapi_id_t fid, guint32 fid_options, struct mapi_SRestriction *res, GError **perror);
mapi_id_t		exchange_mapi_connection_get_default_folder_id (ExchangeMapiConnection *conn, uint32_t olFolder, GError **perror);
mapi_id_t		exchange_mapi_connection_create_item (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid,
					BuildWritePropsCB build_props, gpointer bwp_data,
					GSList *recipients, GSList *attachments, GSList *generic_streams,
					uint32_t options, GError **perror);

gboolean		exchange_mapi_connection_modify_item (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, mapi_id_t mid,
					BuildWritePropsCB build_props, gpointer bwp_data,
					GSList *recipients, GSList *attachments, GSList *generic_streams,
					uint32_t options, GError **perror);

gboolean		exchange_mapi_connection_set_flags (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, guint32 fid_options, GSList *mid_list, uint32_t flag, GError **perror);
gboolean		exchange_mapi_connection_remove_items (ExchangeMapiConnection *conn, uint32_t olFolder, mapi_id_t fid, guint32 fid_options, GSList *mids, GError **perror);
gboolean		exchange_mapi_connection_copy_items (ExchangeMapiConnection *conn, mapi_id_t src_fid, guint32 src_fid_options, mapi_id_t dest_fid, guint32 dest_fid_options, GSList *mids, GError **perror);
gboolean		exchange_mapi_connection_move_items (ExchangeMapiConnection *conn, mapi_id_t src_fid, guint32 src_fid_options, mapi_id_t dest_fid, guint32 dest_fid_options, GSList *mids, GError **perror);
gboolean		exchange_mapi_connection_get_folders_list (ExchangeMapiConnection *conn, GSList **mapi_folders, GError **perror);
gboolean		exchange_mapi_connection_get_pf_folders_list (ExchangeMapiConnection *conn, GSList **mapi_folders, GError **perror);
GSList *		exchange_mapi_connection_peek_folders_list (ExchangeMapiConnection *conn);

gboolean		exchange_mapi_connection_resolve_named_props (ExchangeMapiConnection *conn, mapi_id_t fid, ResolveNamedIDsData *named_ids_list, guint named_ids_n_elems, GError **perror);
uint32_t		exchange_mapi_connection_resolve_named_prop (ExchangeMapiConnection *conn, mapi_id_t fid, uint32_t pidlid_propid, GError **perror);

gchar *			exchange_mapi_connection_ex_to_smtp (ExchangeMapiConnection *conn, const gchar *ex_address, GError **perror);

/* Push notifications APIs */
typedef gboolean (*exchange_check_continue) (void);

gboolean		exchange_mapi_connection_events_init (ExchangeMapiConnection *conn, GError **perror);
gboolean		exchange_mapi_connection_events_monitor (ExchangeMapiConnection *conn, struct mapi_notify_continue_callback_data *cb_data);

gboolean		exchange_mapi_connection_events_subscribe (ExchangeMapiConnection *conn, guint32 options,
					guint16 event_mask, guint32 *events_conn_id,
					mapi_notify_callback_t callback, gpointer data, GError **perror);

gboolean		exchange_mapi_connection_events_subscribe_and_monitor (ExchangeMapiConnection *conn, mapi_id_t *obj_id, guint32 options,
					guint16 event_mask, guint32 *events_conn_id,
					gboolean use_store, mapi_notify_callback_t callback,
					gpointer data);

gboolean		exchange_mapi_connection_events_unsubscribe (ExchangeMapiConnection *conn, guint32 events_conn_id, GError **perror);

/* profile functions */

enum {
	CREATE_PROFILE_FLAG_NONE = 0,
	CREATE_PROFILE_FLAG_USE_SSL = (1 << 0)
};

gboolean		exchange_mapi_create_profile (const gchar *username, const gchar *password,
				       const gchar *domain, const gchar *server, guint32 flags,
				       mapi_profile_callback_t cb, gpointer data, GError **perror);

gboolean		exchange_mapi_delete_profile (const gchar *profile, GError **perror);
void			exchange_mapi_rename_profile (const gchar *old_name, const gchar *new_name);

/* utility functions */

void make_mapi_error (GError **perror, const gchar *context, enum MAPISTATUS mapi_status);

G_END_DECLS

#endif
