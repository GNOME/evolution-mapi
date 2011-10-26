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
 *		Srinivasa Ragavan <sragavan@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifndef E_MAPI_ACCOUNT_LISTENER_H
#define E_MAPI_ACCOUNT_LISTENER_H

#include <glib.h>
#include <glib-object.h>
#include <camel/camel.h>
G_BEGIN_DECLS

#define E_MAPI_ACCOUNT_LISTENER_TYPE		(e_mapi_account_listener_get_type ())
#define E_MAPI_ACCOUNT_LISTENER(obj)		(G_TYPE_CHECK_INSTANCE_CAST ((obj), E_MAPI_ACCOUNT_LISTENER_TYPE, EMapiAccountListener))
#define E_MAPI_ACCOUNT_LISTENER_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass), E_MAPI_ACCOUNT_LISTENER_TYPE,  EMapiAccountListenerClass))
#define E_MAPI_IS_ACCOUNT_LISTENER(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), E_MAPI_ACCOUNT_LISTENER_TYPE))
#define E_MAPI_IS_ACCOUNT_LISTENER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((obj), E_MAPI_ACCOUNT_LISTENER_TYPE))

typedef struct _EMapiAccountListener		EMapiAccountListener;
typedef struct _EMapiAccountListenerClass	EMapiAccountListenerClass;
typedef struct _EMapiAccountListenerPrivate	EMapiAccountListenerPrivate;

struct _EMapiAccountListener {
	GObject parent;
	EMapiAccountListenerPrivate *priv;
};

struct _EMapiAccountListenerClass {
	GObjectClass parent_class;
};

void			e_mapi_add_esource			(CamelService *service, const gchar *folder_name, const gchar *fid, gint folder_type);
void			e_mapi_remove_esource			(CamelService *service, const gchar *folder_name, const gchar *fid, gint folder_type);
GType			e_mapi_account_listener_get_type	(void);
EMapiAccountListener *	e_mapi_account_listener_new		(void);

G_END_DECLS

#endif /* E_MAPI_ACCOUNT_LISTENER_H */
