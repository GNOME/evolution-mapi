/*
 * e-book-config-mapi.h
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

#ifndef E_BOOK_CONFIG_MAPI_H
#define E_BOOK_CONFIG_MAPI_H

#include <misc/e-source-config-backend.h>

/* Standard GObject macros */
#define E_TYPE_BOOK_CONFIG_MAPI \
	(e_book_config_mapi_get_type ())
#define E_BOOK_CONFIG_MAPI(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), E_TYPE_BOOK_CONFIG_MAPI, EBookConfigMapi))
#define E_BOOK_CONFIG_MAPI_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), E_TYPE_BOOK_CONFIG_MAPI, EBookConfigMapiClass))
#define E_IS_BOOK_CONFIG_MAPI(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), E_TYPE_BOOK_CONFIG_MAPI))
#define E_IS_BOOK_CONFIG_MAPI_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), E_TYPE_BOOK_CONFIG_MAPI))
#define E_BOOK_CONFIG_MAPI_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), E_TYPE_BOOK_CONFIG_MAPI, EBookConfigMapiClass))

G_BEGIN_DECLS

typedef struct _EBookConfigMapi EBookConfigMapi;
typedef struct _EBookConfigMapiClass EBookConfigMapiClass;
typedef struct _EBookConfigMapiPrivate EBookConfigMapiPrivate;

struct _EBookConfigMapi {
	ESourceConfigBackend parent;
	EBookConfigMapiPrivate *priv;
};

struct _EBookConfigMapiClass {
	ESourceConfigBackendClass parent_class;
};

GType	e_book_config_mapi_get_type		(void) G_GNUC_CONST;
void	e_book_config_mapi_type_register	(GTypeModule *type_module);

G_END_DECLS

#endif /* E_BOOK_CONFIG_MAPI_H */
