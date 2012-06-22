/*
 * e-mapi-backend-factory.h
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

#ifndef E_MAPI_BACKEND_FACTORY_H
#define E_MAPI_BACKEND_FACTORY_H

#include <libebackend/libebackend.h>

/* Standard GObject macros */
#define E_TYPE_MAPI_BACKEND_FACTORY \
	(e_mapi_backend_factory_get_type ())
#define E_MAPI_BACKEND_FACTORY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), E_TYPE_MAPI_BACKEND_FACTORY, EMapiBackendFactory))
#define E_MAPI_BACKEND_FACTORY_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), E_TYPE_MAPI_BACKEND_FACTORY, EMapiBackendFactoryClass))
#define E_IS_MAPI_BACKEND_FACTORY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), E_TYPE_MAPI_BACKEND_FACTORY))
#define E_IS_MAPI_BACKEND_FACTORY_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), E_TYPE_MAPI_BACKEND_FACTORY))
#define E_MAPI_BACKEND_FACTORY_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), E_TYPE_MAPI_BACKEND_FACTORY, EMapiBackendFactoryClass))

G_BEGIN_DECLS

typedef struct _EMapiBackendFactory EMapiBackendFactory;
typedef struct _EMapiBackendFactoryClass EMapiBackendFactoryClass;
typedef struct _EMapiBackendFactoryPrivate EMapiBackendFactoryPrivate;

struct _EMapiBackendFactory {
	ECollectionBackendFactory parent;
	EMapiBackendFactoryPrivate *priv;
};

struct _EMapiBackendFactoryClass {
	ECollectionBackendFactoryClass parent_class;
};

GType		e_mapi_backend_factory_get_type	(void) G_GNUC_CONST;
void		e_mapi_backend_factory_type_register
						(GTypeModule *type_module);

G_END_DECLS

#endif /* E_MAPI_BACKEND_FACTORY_H */
