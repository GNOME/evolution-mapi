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
#include <libmapi/mapi_nameid.h>

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

typedef struct {
	uint32_t pidlid_propid; /* PidLid or PidName legacy property named ID to resolve */
	uint32_t propid;	/* resolved prop ID; equals to MAPI_E_RESERVED when not found or other error */
} EResolveNamedIDsData;

typedef struct {
	mapi_id_t mid;		/* message ID, from PidTagMid */
	const gchar *msg_class;	/* PidTagMessageClass */
	uint32_t msg_flags;	/* MAPI MSGFLAG_* bit OR, from PidTagMessageFlags */
	time_t last_modified;	/* PidTagLastModificationTime as UTC */
} ListObjectsData;

typedef struct _EMapiStreamedProp {
	uint32_t proptag;
	uint64_t cb;
	const uint8_t *lpb; /* taken from the original mapi prop, no need to copy the memory */
	gconstpointer orig_value; /* exact original value, as stored inside mapi prop; the lpb can be converted to utf16 */
} EMapiStreamedProp;

typedef struct _EMapiRecipient EMapiRecipient;
typedef struct _EMapiAttachment EMapiAttachment;
typedef struct _EMapiObject EMapiObject;

struct _EMapiRecipient {
	struct mapi_SPropValue_array properties;

	EMapiRecipient *next;
};

struct _EMapiAttachment {
	struct mapi_SPropValue_array properties;
	EMapiStreamedProp *streamed_properties; /* use get/add functions for these */
	guint32 streamed_properties_count;

	EMapiObject *embedded_object;

	EMapiAttachment *next;
};

struct _EMapiObject {
	struct mapi_SPropValue_array properties;
	EMapiStreamedProp *streamed_properties; /* use get/add functions for these */
	guint32 streamed_properties_count;

	EMapiRecipient *recipients; /* NULL when none */
	EMapiAttachment *attachments; /* NULL when none */

	EMapiObject *parent; /* chain up to parent's object, if this is embeded attachment */
};

EMapiRecipient *	e_mapi_recipient_new		(TALLOC_CTX *mem_ctx);
void			e_mapi_recipient_free		(EMapiRecipient *recipient);

EMapiAttachment *	e_mapi_attachment_new		(TALLOC_CTX *mem_ctx);
void			e_mapi_attachment_free		(EMapiAttachment *attachment);
void			e_mapi_attachment_add_streamed	(EMapiAttachment *attachment,
							 uint32_t proptag,
							 uint64_t cb,
							 const uint8_t *lpb); /* this might be created inside the attachment TALLOC_CTX */
EMapiStreamedProp *	e_mapi_attachment_get_streamed	(EMapiAttachment *attachment,
							 uint32_t proptag);
gboolean		e_mapi_attachment_get_bin_prop	(EMapiAttachment *attachment,
							 uint32_t proptag,
							 uint64_t *cb,
							 const uint8_t **lpb);

EMapiObject *		e_mapi_object_new		(TALLOC_CTX *mem_ctx);
void			e_mapi_object_free		(EMapiObject *object);
void			e_mapi_object_add_recipient	(EMapiObject *object,
							 EMapiRecipient *recipient);
void			e_mapi_object_add_attachment	(EMapiObject *object,
							 EMapiAttachment *attachment);
void			e_mapi_object_add_streamed	(EMapiObject *object,
							 uint32_t proptag,
							 uint64_t cb,
							 const uint8_t *lpb); /* this might be created inside the attachment TALLOC_CTX */
EMapiStreamedProp *	e_mapi_object_get_streamed	(EMapiObject *object,
							 uint32_t proptag);
gboolean		e_mapi_object_get_bin_prop	(EMapiObject *object,
							 uint32_t proptag,
							 uint64_t *cb,
							 const uint8_t **lpb);

#define E_MAPI_PERMISSION_MEMBER_ID_ANONYMOUS_CLIENT	(~((uint64_t) 0))
#define E_MAPI_PERMISSION_MEMBER_ID_DEFAULT_USER	((uint64_t) 0)

typedef enum {
	E_MAPI_PERMISSION_BIT_FREE_BUSY_DETAILED	= 0x00001000,
	E_MAPI_PERMISSION_BIT_FREE_BUSY_SIMPLE		= 0x00000800,
	E_MAPI_PERMISSION_BIT_FOLDER_VISIBLE		= 0x00000400,
	E_MAPI_PERMISSION_BIT_FOLDER_CONTACT		= 0x00000200,
	E_MAPI_PERMISSION_BIT_FOLDER_OWNER		= 0x00000100,
	E_MAPI_PERMISSION_BIT_CREATE_SUBFOLDER		= 0x00000080,
	E_MAPI_PERMISSION_BIT_DELETE_ANY		= 0x00000040,
	E_MAPI_PERMISSION_BIT_EDIT_ANY			= 0x00000020,
	E_MAPI_PERMISSION_BIT_DELETE_OWNED		= 0x00000010,
	E_MAPI_PERMISSION_BIT_EDIT_OWNED		= 0x00000008,
	E_MAPI_PERMISSION_BIT_CREATE			= 0x00000002,
	E_MAPI_PERMISSION_BIT_READ_ANY			= 0x00000001
} EMapiPermissionBits;

typedef struct {
	gchar *username;		/* PidTagMemberName - display name for a user */

	struct SBinary_short entry_id;	/* PidTagEntryId of the user */
	uint64_t member_id;		/* PidTagMemberId of the user */
	uint32_t member_rights;		/* PidTagMemberRights of the user */
} EMapiPermissionEntry;

EMapiPermissionEntry *	e_mapi_permission_entry_new	(const gchar *username,
							 const struct SBinary_short *entry_id,
							 uint64_t member_id,
							 uint32_t member_rights);
void			e_mapi_permission_entry_free	(EMapiPermissionEntry *entry);

typedef enum {
	E_MAPI_CREATE_FLAG_NONE		= 0,
	E_MAPI_CREATE_FLAG_SUBMIT	= 1 << 0
} EMapiCreateFlags;

/* callbacks return whether to continue in transfer of the next object */
typedef gboolean (*BuildReadPropsCB)		(EMapiConnection *conn,
						 TALLOC_CTX *mem_ctx,
						 struct SPropTagArray *props,
						 gpointer data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*BuildRestrictionsCB)		(EMapiConnection *conn,
						 TALLOC_CTX *mem_ctx,
						 struct mapi_SRestriction **restrictions,
						 gpointer user_data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*ListObjectsCB)		(EMapiConnection *conn,
						 TALLOC_CTX *mem_ctx,
						 const ListObjectsData *object_data,
						 guint32 obj_index,
						 guint32 obj_total,
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
typedef gboolean (*WriteObjectCB)		(EMapiConnection *conn,
						 TALLOC_CTX *mem_ctx,
						 EMapiObject **pobject, /* out */
						 gpointer user_data,
						 GCancellable *cancellable,
						 GError **perror);
typedef gboolean (*GetPropertiesCB)		(EMapiConnection *conn,
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

gboolean		e_mapi_connection_test_foreign_folder	(EMapiConnection *conn,
								 const gchar *username,
								 const gchar *folder_name,
								 mapi_id_t *fid, /* out */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_peek_store		(EMapiConnection *conn,
								 gboolean public_store,
								 const gchar *foreign_username,
								 mapi_object_t **obj_store, /* out */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_get_store_quotas	(EMapiConnection *conn,
								 mapi_object_t *obj_store, /* can be NULL */
								 uint64_t *current_size, /* out */
								 uint64_t *receive_quota, /* out */
								 uint64_t *send_quota, /* out */
								 GCancellable *cancellable,
								 GError **perror);

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

gboolean		e_mapi_connection_open_foreign_folder	(EMapiConnection *conn,
								 const gchar *username,
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
								 GetPropertiesCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_get_permissions	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 gboolean with_freebusy,
								 GSList **entries, /* out, EMapiPermissionEntry */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_set_permissions	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 gboolean with_freebusy,
								 const GSList *entries, /* EMapiPermissionEntry */
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

gboolean		e_mapi_connection_create_object		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 uint32_t flags, /* bit-or of EMapiCreateFlags */
								 WriteObjectCB write_object_cb,
								 gpointer woc_data,
								 mapi_id_t *out_mid,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_modify_object		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 mapi_id_t mid,
								 WriteObjectCB write_object_cb,
								 gpointer woc_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_count_gal_objects	(EMapiConnection *conn,
								 guint32 *obj_total,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_list_gal_objects	(EMapiConnection *conn,
								 BuildRestrictionsCB build_rs_cb,
								 gpointer build_rs_cb_data,
								 ListObjectsCB cb,
								 gpointer user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_transfer_gal_objects	(EMapiConnection *conn,
								 const GSList *mids,
								 BuildReadPropsCB brp_cb, /* NULL for all supported */
								 gpointer brp_cb_user_data,
								 TransferObjectCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_transfer_gal_object	(EMapiConnection *conn,
								 mapi_id_t message_id,
								 TransferObjectCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_get_public_folder	(EMapiConnection *conn,
								 mapi_object_t *obj_folder, /* out */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_create_folder		(EMapiConnection *conn,
								 mapi_object_t *obj_parent_folder, /* in */
								 const gchar *name,
								 const gchar *new_folder_type, /* usually IPF_NOTE and similar */
								 mapi_id_t *new_fid, /* out */
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_remove_folder		(EMapiConnection *conn,
								 mapi_object_t *obj_store, /* in, store, to which folder belongs */
								 mapi_id_t fid_to_remove,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_empty_folder		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_rename_folder		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 const gchar *new_name,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_move_folder		(EMapiConnection *conn,
								 mapi_object_t *src_obj_folder,
								 mapi_object_t *src_parent_obj_folder,
								 mapi_object_t *des_obj_folder,
								 const gchar *new_name,
								 GCancellable *cancellable,
								 GError **perror);
mapi_id_t		e_mapi_connection_get_default_folder_id	(EMapiConnection *conn,
								 uint32_t olFolder,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_set_flags		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 GSList *mid_list,
								 uint32_t flag,
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_remove_items		(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 const GSList *mids, /* data is (mapi_id_t *) */
								 GCancellable *cancellable,
								 GError **perror);
gboolean		e_mapi_connection_copymove_items	(EMapiConnection *conn,
								 mapi_object_t *src_obj_folder,
								 mapi_object_t *des_obj_folder,
								 gboolean do_copy,
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
								 mapi_object_t *obj_folder,
								 EResolveNamedIDsData *named_ids_list,
								 guint named_ids_n_elems,
								 GCancellable *cancellable,
								 GError **perror);
uint32_t		e_mapi_connection_resolve_named_prop	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
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

gboolean		e_mapi_connection_resolve_username	(EMapiConnection *conn,
								 const gchar *to_resolve,
								 BuildReadPropsCB brp_cb,
								 gpointer brp_cb_user_data,
								 GetPropertiesCB cb,
								 gpointer cb_user_data,
								 GCancellable *cancellable,
								 GError **perror);

/* Push notifications APIs */

gboolean		e_mapi_connection_enable_notifications	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
								 uint32_t event_mask,
								 GCancellable *cancellable,
								 GError **perror);

gboolean		e_mapi_connection_disable_notifications	(EMapiConnection *conn,
								 mapi_object_t *obj_folder,
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
