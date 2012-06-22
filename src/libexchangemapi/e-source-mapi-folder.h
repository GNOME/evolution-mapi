/*
 * e-source-mapi-folder.h
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

#ifndef E_SOURCE_MAPI_FOLDER_H
#define E_SOURCE_MAPI_FOLDER_H

#include <libedataserver/libedataserver.h>

/* Standard GObject macros */
#define E_TYPE_SOURCE_MAPI_FOLDER \
	(e_source_mapi_folder_get_type ())
#define E_SOURCE_MAPI_FOLDER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), E_TYPE_SOURCE_MAPI_FOLDER, ESourceMapiFolder))
#define E_SOURCE_MAPI_FOLDER_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), E_TYPE_SOURCE_MAPI_FOLDER, ESourceMapiFolderClass))
#define E_IS_SOURCE_MAPI_FOLDER(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), E_TYPE_SOURCE_MAPI_FOLDER))
#define E_IS_SOURCE_MAPI_FOLDER_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), E_TYPE_SOURCE_MAPI_FOLDER))
#define E_SOURCE_MAPI_FOLDER_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), E_TYPE_SOURCE_MAPI_FOLDER, ESourceMapiFolderClass))

#define E_SOURCE_EXTENSION_MAPI_FOLDER "Exchange MAPI Folder"

G_BEGIN_DECLS

typedef struct _ESourceMapiFolder ESourceMapiFolder;
typedef struct _ESourceMapiFolderClass ESourceMapiFolderClass;
typedef struct _ESourceMapiFolderPrivate ESourceMapiFolderPrivate;

struct _ESourceMapiFolder {
	ESourceExtension parent;
	ESourceMapiFolderPrivate *priv;
};

struct _ESourceMapiFolderClass {
	ESourceExtensionClass parent_class;
};

GType		e_source_mapi_folder_get_type		(void) G_GNUC_CONST;
void		e_source_mapi_folder_type_register	(GTypeModule *type_module);

guint64		e_source_mapi_folder_get_id		(ESourceMapiFolder *extension);
void		e_source_mapi_folder_set_id		(ESourceMapiFolder *extension,
							 guint64 id);

guint64		e_source_mapi_folder_get_parent_id	(ESourceMapiFolder *extension);
void		e_source_mapi_folder_set_parent_id	(ESourceMapiFolder *extension,
							 guint64 id);

gboolean	e_source_mapi_folder_is_public		(ESourceMapiFolder *extension);
void		e_source_mapi_folder_set_is_public	(ESourceMapiFolder *extension,
							 gboolean is_public);

gboolean	e_source_mapi_folder_get_allow_partial	(ESourceMapiFolder *extension);
void		e_source_mapi_folder_set_allow_partial	(ESourceMapiFolder *extension,
							 gboolean allow_partial);

gint		e_source_mapi_folder_get_partial_count	(ESourceMapiFolder *extension);
void		e_source_mapi_folder_set_partial_count	(ESourceMapiFolder *extension,
							 gint partial_count);

gboolean	e_source_mapi_folder_get_server_notification
							(ESourceMapiFolder *extension);
void		e_source_mapi_folder_set_server_notification
							(ESourceMapiFolder *extension,
							 gboolean server_notification);

const gchar *	e_source_mapi_folder_get_foreign_username
							(ESourceMapiFolder *extension);
gchar *		e_source_mapi_folder_dup_foreign_username
							(ESourceMapiFolder *extension);
void		e_source_mapi_folder_set_foreign_username
							(ESourceMapiFolder *extension,
							 const gchar *foreign_username);

G_END_DECLS

#endif /* E_SOURCE_MAPI_FOLDER_H */
