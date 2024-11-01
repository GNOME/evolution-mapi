/*
 * Copyright (C) 2016 Red Hat, Inc. (www.redhat.com)
 *
 * This library is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "camel/camel.h"
#include "camel-mapi-folder-summary.h"

#include "camel-mapi-message-info.h"

struct _CamelMapiMessageInfoPrivate {
	guint32 server_flags;
	gint64 last_modified; /* like time_t */
};

enum {
	PROP_0,
	PROP_SERVER_FLAGS,
	PROP_LAST_MODIFIED
};

G_DEFINE_TYPE_WITH_PRIVATE (CamelMapiMessageInfo, camel_mapi_message_info, CAMEL_TYPE_MESSAGE_INFO_BASE)

static CamelMessageInfo *
mapi_message_info_clone (const CamelMessageInfo *mi,
			 CamelFolderSummary *assign_summary)
{
	CamelMessageInfo *result;

	g_return_val_if_fail (CAMEL_IS_MAPI_MESSAGE_INFO (mi), NULL);

	result = CAMEL_MESSAGE_INFO_CLASS (camel_mapi_message_info_parent_class)->clone (mi, assign_summary);
	if (!result)
		return NULL;

	if (CAMEL_IS_MAPI_MESSAGE_INFO (result)) {
		CamelMapiMessageInfo *mmi, *mmi_result;

		mmi = CAMEL_MAPI_MESSAGE_INFO (mi);
		mmi_result = CAMEL_MAPI_MESSAGE_INFO (result);

		/* safe-guard that the mmi's filename doesn't change before it's copied to mmi_result */
		camel_message_info_property_lock (mi);

		camel_mapi_message_info_set_server_flags (mmi_result, camel_mapi_message_info_get_server_flags (mmi));
		camel_mapi_message_info_set_last_modified (mmi_result, camel_mapi_message_info_get_last_modified (mmi));

		camel_message_info_property_unlock (mi);
	}

	return result;
}

static gboolean
mapi_message_info_load (CamelMessageInfo *mi,
			const CamelMIRecord *record,
			/* const */ gchar **bdata_ptr)
{
	CamelMapiMessageInfo *mmi;

	g_return_val_if_fail (CAMEL_IS_MAPI_MESSAGE_INFO (mi), FALSE);
	g_return_val_if_fail (record != NULL, FALSE);
	g_return_val_if_fail (bdata_ptr != NULL, FALSE);

	if (!CAMEL_MESSAGE_INFO_CLASS (camel_mapi_message_info_parent_class)->load ||
	    !CAMEL_MESSAGE_INFO_CLASS (camel_mapi_message_info_parent_class)->load (mi, record, bdata_ptr))
		return FALSE;

	mmi = CAMEL_MAPI_MESSAGE_INFO (mi);

	camel_mapi_message_info_set_server_flags (mmi, camel_util_bdata_get_number (bdata_ptr, 0));
	camel_mapi_message_info_set_last_modified (mmi, camel_util_bdata_get_number (bdata_ptr, 0));

	return TRUE;
}

static gboolean
mapi_message_info_save (const CamelMessageInfo *mi,
			CamelMIRecord *record,
			GString *bdata_str)
{
	CamelMapiMessageInfo *mmi;

	g_return_val_if_fail (CAMEL_IS_MAPI_MESSAGE_INFO (mi), FALSE);
	g_return_val_if_fail (record != NULL, FALSE);
	g_return_val_if_fail (bdata_str != NULL, FALSE);

	if (!CAMEL_MESSAGE_INFO_CLASS (camel_mapi_message_info_parent_class)->save ||
	    !CAMEL_MESSAGE_INFO_CLASS (camel_mapi_message_info_parent_class)->save (mi, record, bdata_str))
		return FALSE;

	mmi = CAMEL_MAPI_MESSAGE_INFO (mi);

	camel_util_bdata_put_number (bdata_str, camel_mapi_message_info_get_server_flags (mmi));
	camel_util_bdata_put_number (bdata_str, camel_mapi_message_info_get_last_modified (mmi));

	return TRUE;
}

static void
mapi_message_info_set_property (GObject *object,
				guint property_id,
				const GValue *value,
				GParamSpec *pspec)
{
	CamelMapiMessageInfo *mmi = CAMEL_MAPI_MESSAGE_INFO (object);

	switch (property_id) {
	case PROP_SERVER_FLAGS:
		camel_mapi_message_info_set_server_flags (mmi, g_value_get_uint (value));
		return;

	case PROP_LAST_MODIFIED:
		camel_mapi_message_info_set_last_modified (mmi, g_value_get_int64 (value));
		return;
	}

	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
}

static void
mapi_message_info_get_property (GObject *object,
				   guint property_id,
				   GValue *value,
				   GParamSpec *pspec)
{
	CamelMapiMessageInfo *mmi = CAMEL_MAPI_MESSAGE_INFO (object);

	switch (property_id) {
	case PROP_SERVER_FLAGS:
		g_value_set_uint (value, camel_mapi_message_info_get_server_flags (mmi));
		return;

	case PROP_LAST_MODIFIED:
		g_value_set_int64 (value, camel_mapi_message_info_get_last_modified (mmi));
		return;
	}

	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
}

static void
camel_mapi_message_info_class_init (CamelMapiMessageInfoClass *class)
{
	CamelMessageInfoClass *mi_class;
	GObjectClass *object_class;

	mi_class = CAMEL_MESSAGE_INFO_CLASS (class);
	mi_class->clone = mapi_message_info_clone;
	mi_class->load = mapi_message_info_load;
	mi_class->save = mapi_message_info_save;

	object_class = G_OBJECT_CLASS (class);
	object_class->set_property = mapi_message_info_set_property;
	object_class->get_property = mapi_message_info_get_property;

	/**
	 * CamelMapiMessageInfo:server-flags
	 *
	 * Flags of the message on the server.
	 *
	 * Since: 3.24
	 **/
	g_object_class_install_property (
		object_class,
		PROP_SERVER_FLAGS,
		g_param_spec_uint (
			"server-flags",
			"Server Flags",
			NULL,
			0, G_MAXUINT32, 0,
			G_PARAM_READWRITE));

	/**
	 * CamelMapiMessageInfo:last-modified
	 *
	 * PidTagLastModificationTime of this message.
	 *
	 * Since: 3.24
	 **/
	g_object_class_install_property (
		object_class,
		PROP_LAST_MODIFIED,
		g_param_spec_int64 (
			"last-modified",
			"Last Modified",
			NULL,
			G_MININT64, G_MAXINT64, 0,
			G_PARAM_READWRITE));
}

static void
camel_mapi_message_info_init (CamelMapiMessageInfo *mmi)
{
	mmi->priv = camel_mapi_message_info_get_instance_private (mmi);
}

guint32
camel_mapi_message_info_get_server_flags (const CamelMapiMessageInfo *mmi)
{
	CamelMessageInfo *mi;
	guint32 result;

	g_return_val_if_fail (CAMEL_IS_MAPI_MESSAGE_INFO (mmi), 0);

	mi = CAMEL_MESSAGE_INFO (mmi);

	camel_message_info_property_lock (mi);
	result = mmi->priv->server_flags;
	camel_message_info_property_unlock (mi);

	return result;
}

gboolean
camel_mapi_message_info_set_server_flags (CamelMapiMessageInfo *mmi,
					  guint32 server_flags)
{
	CamelMessageInfo *mi;
	gboolean changed;

	g_return_val_if_fail (CAMEL_IS_MAPI_MESSAGE_INFO (mmi), FALSE);

	mi = CAMEL_MESSAGE_INFO (mmi);

	camel_message_info_property_lock (mi);

	changed = mmi->priv->server_flags != server_flags;

	if (changed)
		mmi->priv->server_flags = server_flags;

	camel_message_info_property_unlock (mi);

	if (changed && !camel_message_info_get_abort_notifications (mi)) {
		g_object_notify (G_OBJECT (mmi), "server-flags");
		camel_message_info_set_dirty (mi, TRUE);
	}

	return changed;
}

gint64
camel_mapi_message_info_get_last_modified (const CamelMapiMessageInfo *mmi)
{
	CamelMessageInfo *mi;
	gint64 result;

	g_return_val_if_fail (CAMEL_IS_MAPI_MESSAGE_INFO (mmi), 0);

	mi = CAMEL_MESSAGE_INFO (mmi);

	camel_message_info_property_lock (mi);
	result = mmi->priv->last_modified;
	camel_message_info_property_unlock (mi);

	return result;
}

gboolean
camel_mapi_message_info_set_last_modified (CamelMapiMessageInfo *mmi,
					   gint64 last_modified)
{
	CamelMessageInfo *mi;
	gboolean changed;

	g_return_val_if_fail (CAMEL_IS_MAPI_MESSAGE_INFO (mmi), FALSE);

	mi = CAMEL_MESSAGE_INFO (mmi);

	camel_message_info_property_lock (mi);

	changed = mmi->priv->last_modified != last_modified;

	if (changed)
		mmi->priv->last_modified = last_modified;

	camel_message_info_property_unlock (mi);

	if (changed && !camel_message_info_get_abort_notifications (mi)) {
		g_object_notify (G_OBJECT (mmi), "last-modified");
		camel_message_info_set_dirty (mi, TRUE);
	}

	return changed;
}
