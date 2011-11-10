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

#ifndef E_MAPI_CONNECTION_H
#define E_MAPI_CONNECTION_H 

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include <libmapi/libmapi.h>

/* Standard GObject macros */
#define E_MAPI_TYPE_CONNECTION (e_mapi_connection_get_type ())
#define E_MAPI_CONNECTION(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), E_MAPI_TYPE_CONNECTION, EMapiConnection))
#define E_MAPI_CONNECTION_CLASS(cls) (G_TYPE_CHECK_CLASS_CAST ((cls), E_MAPI_TYPE_CONNECTION, EMapiConnectionClass))
#define E_MAPI_IS_CONNECTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), E_MAPI_TYPE_CONNECTION))
#define E_MAPI_IS_CONNECTION_CLASS(cls) (G_TYPE_CHECK_CLASS_TYPE ((cls), E_MAPI_TYPE_CONNECTION))
#define E_MAPI_CONNECTION_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), E_MAPI_TYPE_CONNECTION, EMapiConnectionClass))

G_BEGIN_DECLS

GQuark e_mapi_error_quark (void);
#define E_MAPI_ERROR e_mapi_error_quark ()

typedef struct _EMapiConnection EMapiConnection;
typedef struct _EMapiConnectionClass EMapiConnectionClass;
typedef struct _EMapiConnectionPrivate EMapiConnectionPrivate;

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
	TALLOC_CTX *mem_ctx;
	const gchar *email_id;
	const gchar *display_name;

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
	EMapiConnection *conn;
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

typedef struct {
	mapi_id_t mid; /* message ID, from PR_MID */
	uint32_t msg_flags; /* MAPI MSGFLAG_* bit OR, from PR_MESSAGE_FLAGS */
	time_t last_modified; /* PR_LAST_MODIFICATION_TIME as UTC */
} ListObjectsData;

struct _EMapiObject;
struct _EMapiRecipient;
struct _EMapiAttachment;

typedef struct _EMapiObject EMapiObject;
typedef struct _EMapiRecipient EMapiRecipient;
typedef struct _EMapiAttachment EMapiAttachment;

struct _EMapiRecipient
{
	struct mapi_SPropValue_array properties;

	EMapiRecipient *next;
};

struct _EMapiAttachment
{
	struct mapi_SPropValue_array properties;
	EMapiObject *embedded_object;

	EMapiAttachment *next;
};

struct _EMapiObject {
	struct mapi_SPropValue_array properties;
	EMapiRecipient *recipients; /* NULL when none */
	EMapiAttachment *attachments; /* NULL when none */

	EMapiObject *parent; /* chain up to parent's object, if this is embeded attachment */
};

EMapiRecipient *	e_mapi_recipient_new	(TALLOC_CTX *mem_ctx);
void			e_mapi_recipient_free	(EMapiRecipient *recipient);

EMapiAttachment *	e_mapi_attachment_new	(TALLOC_CTX *mem_ctx);
void			e_mapi_attachment_free	(EMapiAttachment *attachment);

EMapiObject *		e_mapi_object_new	(TALLOC_CTX *mem_ctx);
void			e_mapi_object_free	(EMapiObject *object);

/* callbacks return whether to continue in transfer of the next object */
typedef gboolean (*FetchCallback)		(FetchItemsCallbackData *item_data,
						 gpointer data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*FetchGALCallback)		(EMapiConnection *conn,
						 uint32_t row_index,
						 uint32_t n_rows,
						 struct SRow *aRow,
						 gpointer data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*BuildWritePropsCB)		(EMapiConnection *conn,
						 mapi_id_t fid,
						 TALLOC_CTX *mem_ctx,
						 struct SPropValue **values,
						 uint32_t *n_values,
						 gpointer data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*BuildReadPropsCB)		(EMapiConnection *conn,
						 mapi_id_t fid,
						 TALLOC_CTX *mem_ctx,
						 struct SPropTagArray *props,
						 gpointer data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*BuildRestrictionsCB)		(EMapiConnection *conn,
						 mapi_id_t fid,
						 TALLOC_CTX *mem_ctx,
						 struct mapi_SRestriction **restrictions,
						 gpointer user_data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*ListObjectsCB)		(EMapiConnection *conn,
						 mapi_id_t fid,
						 TALLOC_CTX *mem_ctx,
						 const ListObjectsData *item_data,
						 guint32 item_index,
						 guint32 items_total,
						 gpointer user_data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*TransferObjectCB)		(EMapiConnection *conn,
						 TALLOC_CTX *mem_ctx,
						 /* const */ EMapiObject *object,
						 guint32 obj_index,
						 guint32 obj_total,
						 gpointer user_data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*GetFolderPropertiesCB)	(EMapiConnection *conn,
						 mapi_id_t fid,
						 TALLOC_CTX *mem_ctx,
						 /* const */ struct mapi_SPropValue_array *properties,
						 gpointer user_data,
						 GCancellable *cancellable,
						 GError **perror);

typedef gboolean (*ProgressNotifyCB)		(EMapiConnection *conn,
						 guint32 item_index,
						 guint32 items_total,
						 gpointer user_data,
						 GCancellable *cancellable,
						 GError **perror);

struct _EMapiConnection {
	GObject parent;

	EMapiConnectionPrivate *priv;
};

struct _EMapiConnectionClass {
	GObjectClass parent_class;

	/* signals */
};

GType			e_mapi_connection_get_type		(void);
EMapiConnection *	e_mapi_connection_new			(const gchar *profile,
								 const gchar *password,
								 GCancellable *cancellable,
								 GError **perror);
EMapiConnection *	e_mapi_connection_find			(const gchar *profile);
gboolean		e_mapi_connection_reconnect		(EMapiConnection *conn,
								 const gchar *password,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_close			(EMapiConnection *conn);
gboolean		e_mapi_connection_connected		(EMapiConnection *conn);

gboolean		e_mapi_connection_open_default_folder	(EMapiConnection *conn,
								 uint32_t olFolderIdentifier,
								 mapi_object_t *obj_folder, /* out */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_open_personal_folder	(EMapiConnection *conn,
								 mapi_id_t fid,
								 mapi_object_t *obj_folder, /* out */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_open_public_folder	(EMapiConnection *conn,
								 mapi_id_t fid,
								 mapi_object_t *obj_folder, /* out */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_close_folder		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_get_folder_properties	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 BuildReadPropsCB brp_cb,
								 gpointer brp_cb_user_data,
								 GetFolderPropertiesCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_list_objects		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 BuildRestrictionsCB build_rs_cb,
								 gpointer build_rs_cb_data,
								 ListObjectsCB cb,
								 gpointer user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_transfer_objects	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 const GSList *mids,
								 TransferObjectCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_transfer_object	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 mapi_id_t message_id,
								 TransferObjectCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_transfer_summary	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 const GSList *mids,
								 TransferObjectCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_fetch_object_props	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 mapi_id_t fid,
								 mapi_id_t mid,
								 mapi_object_t *obj_message,
								 BuildReadPropsCB build_props,
								 gpointer brp_data,
								 FetchCallback cb,
								 gpointer data,
								 guint32 options,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_fetch_item		(EMapiConnection *conn,
								 mapi_id_t fid,
								 mapi_id_t mid,
								 BuildReadPropsCB build_props,
								 gpointer brp_data,
								 FetchCallback cb,
								 gpointer data,
								 guint32 options,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_fetch_items		(EMapiConnection *conn,
								 mapi_id_t fid,
								 BuildRestrictionsCB build_rs_cb,
								 gpointer build_rs_cb_data,
								 struct SSortOrderSet *sort_order,
								 BuildReadPropsCB build_props,
								 gpointer brp_data,
								 FetchCallback cb,
								 gpointer data,
								 guint32 options,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_fetch_gal		(EMapiConnection *conn,
								 BuildRestrictionsCB build_rs_cb,
								 gpointer build_rs_cb_data,
								 BuildReadPropsCB build_props,
								 gpointer brp_data,
								 FetchGALCallback cb,
								 gpointer data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_get_public_folder	(EMapiConnection *conn,
								 mapi_object_t *obj_object,
								 GCancellable *cancellable,
								 GError **perror);

mapi_id_t		e_mapi_connection_create_folder		(EMapiConnection *conn,
								 uint32_t olFolder,
								 mapi_id_t pfid,
								 guint32 fid_options,
								 const gchar *name,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_remove_folder		(EMapiConnection *conn,
								 mapi_id_t fid,
								 guint32 fid_options,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_empty_folder		(EMapiConnection *conn,
								 mapi_id_t fid,
								 guint32 fid_options,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_rename_folder		(EMapiConnection *conn,
								 mapi_id_t fid,
								 guint32 fid_options,
								 const gchar *new_name,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_move_folder		(EMapiConnection *conn,
								 mapi_id_t src_fid,
								 mapi_id_t src_parent_fid,
								 guint32 src_fid_options,
								 mapi_id_t des_fid,
								 guint32 des_fid_options,
								 const gchar *new_name,
								 GCancellable *cancellable,
								 GError **perror);
mapi_id_t		e_mapi_connection_get_default_folder_id	(EMapiConnection *conn,
								 uint32_t olFolder,
								 GCancellable *cancellable,
								 GError **perror);
mapi_id_t		e_mapi_connection_create_item		(EMapiConnection *conn,
								 uint32_t olFolder,
								 mapi_id_t fid,
								 BuildWritePropsCB build_props,
								 gpointer bwp_data,
								 GSList *recipients,
								 GSList *attachments,
								 GSList *generic_streams,
								 uint32_t options,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_modify_item		(EMapiConnection *conn,
								 uint32_t olFolder,
								 mapi_id_t fid,
								 mapi_id_t mid,
								 BuildWritePropsCB build_props,
								 gpointer bwp_data,
								 GSList *recipients,
								 GSList *attachments,
								 GSList *generic_streams,
								 uint32_t options,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_set_flags		(EMapiConnection *conn,
								 uint32_t olFolder,
								 mapi_id_t fid,
								 guint32 fid_options,
								 GSList *mid_list,
								 uint32_t flag,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_remove_items		(EMapiConnection *conn,
								 uint32_t olFolder,
								 mapi_id_t fid,
								 guint32 fid_options,
								 GSList *mids,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_copy_items		(EMapiConnection *conn,
								 mapi_id_t src_fid,
								 guint32 src_fid_options,
								 mapi_id_t dest_fid,
								 guint32 dest_fid_options,
								 GSList *mids,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_move_items		(EMapiConnection *conn,
								 mapi_id_t src_fid,
								 guint32 src_fid_options,
								 mapi_id_t dest_fid,
								 guint32 dest_fid_options,
								 GSList *mids,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_get_folders_list	(EMapiConnection *conn,
								 GSList **mapi_folders,
								 ProgressNotifyCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_get_pf_folders_list	(EMapiConnection *conn,
								 GSList **mapi_folders,
								 ProgressNotifyCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);
GSList *		e_mapi_connection_peek_folders_list	(EMapiConnection *conn);

gboolean		e_mapi_connection_resolve_named_props	(EMapiConnection *conn,
								 mapi_id_t fid,
								 ResolveNamedIDsData *named_ids_list,
								 guint named_ids_n_elems,
								 GCancellable *cancellable,
								 GError **perror);
uint32_t		e_mapi_connection_resolve_named_prop	(EMapiConnection *conn,
								 mapi_id_t fid,
								 uint32_t pidlid_propid,
								 GCancellable *cancellable,
								 GError **perror);
uint32_t		e_mapi_connection_unresolve_proptag_to_nameid
								(EMapiConnection *conn,
								 mapi_id_t fid,
								 uint32_t proptag);

gchar *			e_mapi_connection_ex_to_smtp		(EMapiConnection *conn,
								 const gchar *ex_address,
								 gchar **display_name,
								 GCancellable *cancellable,
								 GError **perror);

/* Push notifications APIs */
typedef gboolean (*exchange_check_continue) (void);

gboolean		e_mapi_connection_events_init		(EMapiConnection *conn,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_events_monitor	(EMapiConnection *conn,
								 struct mapi_notify_continue_callback_data *cb_data);

gboolean		e_mapi_connection_events_subscribe	(EMapiConnection *conn,
								 guint32 options,
								 guint16 event_mask,
								 guint32 *events_conn_id,
								 mapi_notify_callback_t callback,
								 gpointer data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_events_unsubscribe	(EMapiConnection *conn,
								 guint32 events_conn_id,
								 GCancellable *cancellable,
								 GError **perror);

/* profile functions */

typedef struct {
	const gchar *username;
	gchar *password;
	const gchar *domain;
	const gchar *server;
	gboolean use_ssl;
	gboolean krb_sso;
	const gchar *krb_realm;
} EMapiProfileData;

#define COMPLETE_PROFILEDATA(x) \
	((x)->username && *(x)->username && (x)->server && *(x)->server \
	 && (((x)->domain && *(x)->domain && (x)->password && *(x)->password) \
	     || ((x)->krb_sso && (x)->krb_realm && *(x)->krb_realm)))

gboolean		e_mapi_create_profile			(struct mapi_context *mapi_ctx,
								 EMapiProfileData *profile,
								 mapi_profile_callback_t cb,
								 gconstpointer data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_delete_profile			(struct mapi_context *mapi_ctx,
								 const gchar *profile,
								 GError **perror);
void			e_mapi_rename_profile			(struct mapi_context *mapi_ctx,
								 const gchar *old_name,
								 const gchar *new_name,
								 GError **perror);

/* utility functions */

void			make_mapi_error				(GError **perror,
								 const gchar *context,
								 enum MAPISTATUS mapi_status);

G_END_DECLS

#endif
