/*
 * e-mapi-backend.h
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

#ifndef E_MAPI_BACKEND_H
#define E_MAPI_BACKEND_H

#include <libebackend/libebackend.h>

/* Standard GObject macros */
#define E_TYPE_MAPI_BACKEND \
	(e_mapi_backend_get_type ())
#define E_MAPI_BACKEND(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), E_TYPE_MAPI_BACKEND, EMapiBackend))
#define E_MAPI_BACKEND_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), E_TYPE_MAPI_BACKEND, EMapiBackendClass))
#define E_IS_MAPI_BACKEND(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), E_TYPE_MAPI_BACKEND))
#define E_IS_MAPI_BACKEND_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), E_TYPE_MAPI_BACKEND))
#define E_MAPI_BACKEND_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), E_TYPE_MAPI_BACKEND, EMapiBackendClass))

G_BEGIN_DECLS

typedef struct _EMapiBackend EMapiBackend;
typedef struct _EMapiBackendClass EMapiBackendClass;
typedef struct _EMapiBackendPrivate EMapiBackendPrivate;

struct _EMapiBackend {
	ECollectionBackend parent;
	EMapiBackendPrivate *priv;
};

struct _EMapiBackendClass {
	ECollectionBackendClass parent_class;
};

GType		e_mapi_backend_get_type		(void) G_GNUC_CONST;
void		e_mapi_backend_type_register	(GTypeModule *type_module);

G_END_DECLS

#endif /* E_MAPI_BACKEND_H */
