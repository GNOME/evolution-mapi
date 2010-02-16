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
 * Copyright (C) 1999-2009 Novell, Inc. (www.novell.com)
 *
 */

#ifndef __CAMEL_MAPI_UTILS_H__
#define __CAMEL_MAPI_UTILS_H__

G_BEGIN_DECLS

MapiItem *
camel_mapi_utils_mime_to_item (CamelMimeMessage *message, CamelAddress *from, CamelException *ex);

gint
camel_mapi_utils_create_item_build_props (struct SPropValue **value, 
					  struct SPropTagArray *SPropTagArray,
					  gpointer data);

G_END_DECLS

#endif /* CAMEL_MAPI_UTILS_H */
