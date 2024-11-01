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
 *     Johnny Jacob <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef CAMEL_MAPI_TRANSPORT_H
#define CAMEL_MAPI_TRANSPORT_H

#include <camel/camel.h>
#include <libmapi/libmapi.h>
#include <e-mapi-connection.h>

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_TRANSPORT \
	(camel_mapi_transport_get_type ())
#define CAMEL_MAPI_TRANSPORT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_TRANSPORT, CamelMapiTransport))
#define CAMEL_MAPI_TRANSPORT_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_TRANSPORT, CamelMapiTransportClass))
#define CAMEL_IS_MAPI_TRANSPORT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_TRANSPORT))
#define CAMEL_IS_MAPI_TRANSPORT_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_TRANSPORT))
#define CAMEL_MAPI_TRANSPORT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_TRANSPORT, CamelMapiTransportClass))

G_BEGIN_DECLS

typedef struct _CamelMapiTransport CamelMapiTransport;
typedef struct _CamelMapiTransportClass CamelMapiTransportClass;

struct _CamelMapiTransport {
	CamelTransport parent;
	gboolean connected;
};

struct _CamelMapiTransportClass {
	CamelTransportClass parent_class;
};

GType camel_mapi_transport_get_type (void);

G_END_DECLS

#endif /* CAMEL_MAPI_TRANSPORT_H */
