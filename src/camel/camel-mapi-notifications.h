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

/* For push notification listener*/

#ifndef CAMEL_MAPI_NOTIFICATIONS_H
#define CAMEL_MAPI_NOTIFICATIONS_H

G_BEGIN_DECLS

gpointer camel_mapi_notification_listener_start (CamelMapiStore *store, guint16 mask, guint32 options);
void camel_mapi_notification_listener_stop (CamelMapiStore *store, gpointer start_value);

G_END_DECLS

#endif /* CAMEL_MAPI_NOTIFICATIONS_H */
