/*
 * e-source-mapi-folder.c
 *
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
 */

#include "e-source-mapi-folder.h"

#define E_SOURCE_MAPI_FOLDER_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE \
	((obj), E_TYPE_SOURCE_MAPI_FOLDER, ESourceMapiFolderPrivate))

struct _ESourceMapiFolderPrivate {
	GMutex property_lock;
	guint64 fid;
	guint64 parent_fid;
	gboolean is_public;
	gboolean server_notification;
	gchar *foreign_username;
	gboolean allow_partial;
	gint partial_count;
};

enum {
	PROP_0,
	PROP_ID,
	PROP_PARENT_ID,
	PROP_IS_PUBLIC,
	PROP_SERVER_NOTIFICATION,
	PROP_FOREIGN_USERNAME,
	PROP_ALLOW_PARTIAL,
	PROP_PARTIAL_COUNT
};

G_DEFINE_DYNAMIC_TYPE (
	ESourceMapiFolder,
	e_source_mapi_folder,
	E_TYPE_SOURCE_EXTENSION)

static void
source_mapi_folder_set_property (GObject *object,
				 guint property_id,
                                 const GValue *value,
                                 GParamSpec *pspec)
{
	switch (property_id) {
		case PROP_ID:
			e_source_mapi_folder_set_id (
				E_SOURCE_MAPI_FOLDER (object),
				g_value_get_uint64 (value));
			return;

		case PROP_PARENT_ID:
			e_source_mapi_folder_set_parent_id (
				E_SOURCE_MAPI_FOLDER (object),
				g_value_get_uint64 (value));
			return;

		case PROP_IS_PUBLIC:
			e_source_mapi_folder_set_is_public (
				E_SOURCE_MAPI_FOLDER (object),
				g_value_get_boolean (value));
			return;

		case PROP_SERVER_NOTIFICATION:
			e_source_mapi_folder_set_server_notification (
				E_SOURCE_MAPI_FOLDER (object),
				g_value_get_boolean (value));
			return;

		case PROP_FOREIGN_USERNAME:
			e_source_mapi_folder_set_foreign_username (
				E_SOURCE_MAPI_FOLDER (object),
				g_value_get_string (value));
			return;

		case PROP_ALLOW_PARTIAL:
			e_source_mapi_folder_set_allow_partial (
				E_SOURCE_MAPI_FOLDER (object),
				g_value_get_boolean (value));
			return;

		case PROP_PARTIAL_COUNT:
			e_source_mapi_folder_set_partial_count (
				E_SOURCE_MAPI_FOLDER (object),
				g_value_get_int (value));
			return;
	}

	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
}

static void
source_mapi_folder_get_property (GObject *object,
				 guint property_id,
                                 GValue *value,
                                 GParamSpec *pspec)
{
	switch (property_id) {
		case PROP_ID:
			g_value_set_uint64 (
				value,
				e_source_mapi_folder_get_id (
				E_SOURCE_MAPI_FOLDER (object)));
			return;

		case PROP_PARENT_ID:
			g_value_set_uint64 (
				value,
				e_source_mapi_folder_get_parent_id (
				E_SOURCE_MAPI_FOLDER (object)));
			return;

		case PROP_IS_PUBLIC:
			g_value_set_boolean (
				value,
				e_source_mapi_folder_is_public (
				E_SOURCE_MAPI_FOLDER (object)));
			return;

		case PROP_SERVER_NOTIFICATION:
			g_value_set_boolean (
				value,
				e_source_mapi_folder_get_server_notification (
				E_SOURCE_MAPI_FOLDER (object)));
			return;

		case PROP_FOREIGN_USERNAME:
			g_value_take_string (
				value,
				e_source_mapi_folder_dup_foreign_username (
				E_SOURCE_MAPI_FOLDER (object)));
			return;

		case PROP_ALLOW_PARTIAL:
			g_value_set_boolean (
				value,
				e_source_mapi_folder_get_allow_partial (
				E_SOURCE_MAPI_FOLDER (object)));
			return;

		case PROP_PARTIAL_COUNT:
			g_value_set_int (
				value,
				e_source_mapi_folder_get_partial_count (
				E_SOURCE_MAPI_FOLDER (object)));
			return;
	}

	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
}

static void
source_mapi_folder_finalize (GObject *object)
{
	ESourceMapiFolderPrivate *priv;

	priv = E_SOURCE_MAPI_FOLDER_GET_PRIVATE (object);

	g_mutex_clear (&priv->property_lock);

	g_free (priv->foreign_username);

	/* Chain up to parent's finalize() method. */
	G_OBJECT_CLASS (e_source_mapi_folder_parent_class)->finalize (object);
}

static void
e_source_mapi_folder_class_init (ESourceMapiFolderClass *class)
{
	GObjectClass *object_class;
	ESourceExtensionClass *extension_class;

	g_type_class_add_private (class, sizeof (ESourceMapiFolderPrivate));

	object_class = G_OBJECT_CLASS (class);
	object_class->set_property = source_mapi_folder_set_property;
	object_class->get_property = source_mapi_folder_get_property;
	object_class->finalize = source_mapi_folder_finalize;

	extension_class = E_SOURCE_EXTENSION_CLASS (class);
	extension_class->name = E_SOURCE_EXTENSION_MAPI_FOLDER;

	g_object_class_install_property (
		object_class,
		PROP_ID,
		g_param_spec_uint64 (
			"id",
			"ID",
			"The server-assigned folder ID",
			0, G_MAXUINT64, 0,
			G_PARAM_READWRITE |
			G_PARAM_STATIC_STRINGS |
			E_SOURCE_PARAM_SETTING));

	g_object_class_install_property (
		object_class,
		PROP_PARENT_ID,
		g_param_spec_uint64 (
			"parent-id",
			"Parent ID",
			"The server-assigned folder's parent ID",
			0, G_MAXUINT64, 0,
			G_PARAM_READWRITE |
			G_PARAM_STATIC_STRINGS |
			E_SOURCE_PARAM_SETTING));

	g_object_class_install_property (
		object_class,
		PROP_IS_PUBLIC,
		g_param_spec_boolean (
			"is-public",
			"Is Public",
			"Folder is a public folder",
			FALSE,
			G_PARAM_READWRITE |
			G_PARAM_STATIC_STRINGS |
			E_SOURCE_PARAM_SETTING));

	g_object_class_install_property (
		object_class,
		PROP_SERVER_NOTIFICATION,
		g_param_spec_boolean (
			"server-notification",
			"Server Notification",
			"Whether to listen for server notifications on this folder",
			FALSE,
			G_PARAM_READWRITE |
			G_PARAM_STATIC_STRINGS |
			E_SOURCE_PARAM_SETTING));

	g_object_class_install_property (
		object_class,
		PROP_FOREIGN_USERNAME,
		g_param_spec_string (
			"foreign-username",
			"Foreign Username",
			"Set for folders belonging to other (foreign) users",
			NULL,
			G_PARAM_READWRITE |
			G_PARAM_STATIC_STRINGS |
			E_SOURCE_PARAM_SETTING));

	g_object_class_install_property (
		object_class,
		PROP_ALLOW_PARTIAL,
		g_param_spec_boolean (
			"allow-partial",
			"Allow Partial",
			"Allow Partial fetching for GAL",
			TRUE,
			G_PARAM_READWRITE |
			G_PARAM_STATIC_STRINGS |
			E_SOURCE_PARAM_SETTING));

	g_object_class_install_property (
		object_class,
		PROP_PARTIAL_COUNT,
		g_param_spec_int (
			"partial-count",
			"Partial Count",
			"Count of contacts for Partial fetching of GAL",
			G_MININT, G_MAXINT, 50,
			G_PARAM_READWRITE |
			G_PARAM_STATIC_STRINGS |
			E_SOURCE_PARAM_SETTING));
}

static void
e_source_mapi_folder_class_finalize (ESourceMapiFolderClass *class)
{
}

static void
e_source_mapi_folder_init (ESourceMapiFolder *extension)
{
	extension->priv = E_SOURCE_MAPI_FOLDER_GET_PRIVATE (extension);
	g_mutex_init (&extension->priv->property_lock);

	extension->priv->fid = 0;
	extension->priv->parent_fid = 0;
	extension->priv->is_public = FALSE;
	extension->priv->server_notification = FALSE;
	extension->priv->foreign_username = NULL;
	extension->priv->allow_partial = TRUE;
	extension->priv->partial_count = 50;
}

void
e_source_mapi_folder_type_register (GTypeModule *type_module)
{
	/* XXX G_DEFINE_DYNAMIC_TYPE declares a static type registration
	 *     function, so we have to wrap it with a public function in
	 *     order to register types from a separate compilation unit. */
	e_source_mapi_folder_register_type (type_module);
}

guint64
e_source_mapi_folder_get_id (ESourceMapiFolder *extension)
{
	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), 0);

	return extension->priv->fid;
}

void
e_source_mapi_folder_set_id (ESourceMapiFolder *extension,
			     guint64 id)
{
	g_return_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension));

	if (extension->priv->fid == id)
		return;

	extension->priv->fid = id;

	g_object_notify (G_OBJECT (extension), "id");
}

guint64
e_source_mapi_folder_get_parent_id (ESourceMapiFolder *extension)
{
	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), 0);

	return extension->priv->parent_fid;
}

void
e_source_mapi_folder_set_parent_id (ESourceMapiFolder *extension,
				    guint64 id)
{
	g_return_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension));

	if (extension->priv->parent_fid == id)
		return;

	extension->priv->parent_fid = id;

	g_object_notify (G_OBJECT (extension), "parent-id");
}

gboolean
e_source_mapi_folder_is_public (ESourceMapiFolder *extension)
{
	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), FALSE);

	return extension->priv->is_public;
}

void
e_source_mapi_folder_set_is_public (ESourceMapiFolder *extension,
				    gboolean is_public)
{
	g_return_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension));

	if ((extension->priv->is_public ? 1 : 0) == (is_public ? 1 : 0))
		return;

	extension->priv->is_public = is_public;

	g_object_notify (G_OBJECT (extension), "is-public");
}

gboolean
e_source_mapi_folder_get_allow_partial (ESourceMapiFolder *extension)
{
	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), FALSE);

	return extension->priv->allow_partial;
}

void
e_source_mapi_folder_set_allow_partial (ESourceMapiFolder *extension,
					gboolean allow_partial)
{
	g_return_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension));

	if ((extension->priv->allow_partial ? 1 : 0) == (allow_partial ? 1 : 0))
		return;

	extension->priv->allow_partial = allow_partial;

	g_object_notify (G_OBJECT (extension), "allow-partial");
}

gint
e_source_mapi_folder_get_partial_count (ESourceMapiFolder *extension)
{
	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), FALSE);

	return extension->priv->partial_count;
}

void
e_source_mapi_folder_set_partial_count (ESourceMapiFolder *extension,
					gint partial_count)
{
	g_return_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension));

	if (extension->priv->partial_count == partial_count)
		return;

	extension->priv->partial_count = partial_count;

	g_object_notify (G_OBJECT (extension), "partial-count");
}

gboolean
e_source_mapi_folder_get_server_notification (ESourceMapiFolder *extension)
{
	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), FALSE);

	return extension->priv->server_notification;
}

void
e_source_mapi_folder_set_server_notification (ESourceMapiFolder *extension,
					      gboolean server_notification)
{
	g_return_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension));

	if ((extension->priv->server_notification ? 1 : 0) == (server_notification ? 1 : 0))
		return;

	extension->priv->server_notification = server_notification;

	g_object_notify (G_OBJECT (extension), "server-notification");
}

const gchar *
e_source_mapi_folder_get_foreign_username (ESourceMapiFolder *extension)
{
	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), NULL);

	return extension->priv->foreign_username;
}

gchar *
e_source_mapi_folder_dup_foreign_username (ESourceMapiFolder *extension)
{
	gchar *duplicate;

	g_return_val_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension), NULL);

	g_mutex_lock (&extension->priv->property_lock);

	duplicate = g_strdup (e_source_mapi_folder_get_foreign_username (extension));

	g_mutex_unlock (&extension->priv->property_lock);

	return duplicate;
}

void
e_source_mapi_folder_set_foreign_username (ESourceMapiFolder *extension,
					  const gchar *foreign_username)
{
	g_return_if_fail (E_IS_SOURCE_MAPI_FOLDER (extension));

	g_mutex_lock (&extension->priv->property_lock);

	if (foreign_username && !*foreign_username)
		foreign_username = NULL;

	if (g_strcmp0 (extension->priv->foreign_username, foreign_username) == 0) {
		g_mutex_unlock (&extension->priv->property_lock);
		return;
	}

	g_free (extension->priv->foreign_username);
	extension->priv->foreign_username = g_strdup (foreign_username);

	g_mutex_unlock (&extension->priv->property_lock);

	g_object_notify (G_OBJECT (extension), "foreign-username");
}
