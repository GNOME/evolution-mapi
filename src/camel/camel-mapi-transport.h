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
 *     Johnny Jacob <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef CAMEL_MAPI_TRANSPORT_H
#define CAMEL_MAPI_TRANSPORT_H 1

#include <libmapi/libmapi.h>
#include <camel/camel-transport.h>
#include <exchange-mapi-connection.h>

#define CAMEL_MAPI_TRANSPORT_TYPE     (camel_mapi_transport_get_type ())
#define CAMEL_MAPI_TRANSPORT(obj)     (CAMEL_CHECK_CAST((obj), CAMEL_MAPI_TRANSPORT_TYPE, CamelMapiTransport))
#define CAMEL_MAPI_TRANSPORT_CLASS(k) (CAMEL_CHECK_CLASS_CAST ((k), CAMEL_MAPI_TRANSPORT_TYPE, CamelMapiTransportClass))
#define CAMEL_IS_MAPI_TRANSPORT(o)    (CAMEL_CHECK_TYPE((o), CAMEL_MAPI_TRANSPORT_TYPE))

G_BEGIN_DECLS

typedef struct {
	CamelTransport parent_object;
	gboolean connected ;

} CamelMapiTransport;


typedef struct {
	CamelTransportClass parent_class;

} CamelMapiTransportClass;


/* Standard Camel function */
CamelType camel_mapi_transport_get_type (void);

G_END_DECLS

#endif /* CAMEL_MAPI_TRANSPORT_H */
