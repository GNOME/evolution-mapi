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
 * Copyright (C) 1999-2010 Novell, Inc. (www.novell.com)
 *
 */

#ifndef E_MAPI_OPERATION_QUEUE_H
#define E_MAPI_OPERATION_QUEUE_H

#include <glib.h>
#include <glib-object.h>

/* Standard GObject macros */
#define E_MAPI_TYPE_OPERATION_QUEUE (e_mapi_operation_queue_get_type ())
#define E_MAPI_OPERATION_QUEUE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), E_MAPI_TYPE_OPERATION_QUEUE, EMapiOperationQueue))
#define E_MAPI_OPERATION_QUEUE_CLASS(cls) (G_TYPE_CHECK_CLASS_CAST ((cls), E_MAPI_TYPE_OPERATION_QUEUE, EMapiOperationQueueClass))
#define E_MAPI_IS_OPERATION_QUEUE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), E_MAPI_TYPE_OPERATION_QUEUE))
#define E_MAPI_IS_OPERATION_QUEUE_CLASS(cls) (G_TYPE_CHECK_CLASS_TYPE ((cls), E_MAPI_TYPE_OPERATION_QUEUE))
#define E_MAPI_OPERATION_QUEUE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), E_MAPI_TYPE_OPERATION_QUEUE, EMapiOperationQueueClass))

G_BEGIN_DECLS

typedef struct _EMapiOperationQueue        EMapiOperationQueue;
typedef struct _EMapiOperationQueueClass   EMapiOperationQueueClass;
typedef struct _EMapiOperationQueuePrivate EMapiOperationQueuePrivate;

struct _EMapiOperationQueue {
	GObject parent;

	EMapiOperationQueuePrivate *priv;
};

struct _EMapiOperationQueueClass {
	GObjectClass parent_class;

	/* signals */
};

GType			e_mapi_operation_queue_get_type (void);

/* 'user_data' corresponds to 'user_data' from e_mapi_operation_queue_new(),
   'worker_data' corresponds to 'worker_data' from e_mapi_operation_queue_push() */
typedef void (*EMapiOperationQueueFunc)(gpointer worker_data, gboolean cancelled, gpointer user_data);

EMapiOperationQueue *	e_mapi_operation_queue_new		(EMapiOperationQueueFunc worker_cb, gpointer user_data);
void			e_mapi_operation_queue_push		(EMapiOperationQueue *queue, gpointer worker_data);
gboolean		e_mapi_operation_queue_cancel		(EMapiOperationQueue *queue, gpointer worker_data);
gboolean		e_mapi_operation_queue_cancel_all	(EMapiOperationQueue *queue);
gint			e_mapi_operation_queue_length		(EMapiOperationQueue *queue);

EMapiOperationQueue *	e_mapi_async_queue_new		(void);
void			e_mapi_async_queue_push		(EMapiOperationQueue *queue,
							 gpointer worker_data,
							 gpointer user_data,
							 EMapiOperationQueueFunc worker_cb, /* run in a new thread */
							 EMapiOperationQueueFunc done_cb);  /* run in a main thread */

#endif /* E_MAPI_OPERATION_QUEUE */
