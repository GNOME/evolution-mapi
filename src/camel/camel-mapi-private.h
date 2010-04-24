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

#ifndef CAMEL_MAPI_PRIVATE_H
#define CAMEL_MAPI_PRIVATE_H

/* need a way to configure and save this data, if this header is to
   be installed.  For now, dont install it */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

//#ifdef ENABLE_THREADS
#define CAMEL_MAPI_FOLDER_LOCK(f, l) \
	(g_static_mutex_lock(&((CamelMapiFolder *)f)->priv->l))
#define CAMEL_MAPI_FOLDER_UNLOCK(f, l) \
	(g_static_mutex_unlock(&((CamelMapiFolder *)f)->priv->l))
#define CAMEL_MAPI_FOLDER_REC_LOCK(f, l) \
	(g_static_rec_mutex_lock(&((CamelMapiFolder *)f)->priv->l))
#define CAMEL_MAPI_FOLDER_REC_UNLOCK(f, l) \
	(g_static_rec_mutex_unlock(&((CamelMapiFolder *)f)->priv->l))
//#else
#define MAPI_FOLDER_LOCK(f, l)
#define MAPI_FOLDER_UNLOCK(f, l)
#define MAPI_FOLDER_REC_LOCK(f, l)
#define MAPI_FOLDER_REC_UNLOCK(f, l)
//#endif

#endif /* CAMEL_IMAP_PRIVATE_H */
