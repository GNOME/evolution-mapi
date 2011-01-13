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

#ifndef EM_OPERATION_QUEUE_H
#define EM_OPERATION_QUEUE_H

#include <glib.h>
#include <glib-object.h>

/* Standard GObject macros */
#define EM_TYPE_OPERATION_QUEUE (em_operation_queue_get_type ())
#define EM_OPERATION_QUEUE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), EM_TYPE_OPERATION_QUEUE, EMOperationQueue))
#define EM_OPERATION_QUEUE_CLASS(cls) (G_TYPE_CHECK_CLASS_CAST ((cls), EM_TYPE_OPERATION_QUEUE, EMOperationQueueClass))
#define EM_IS_OPERATION_QUEUE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), EM_TYPE_OPERATION_QUEUE))
#define EM_IS_OPERATION_QUEUE_CLASS(cls) (G_TYPE_CHECK_CLASS_TYPE ((cls), EM_TYPE_OPERATION_QUEUE))
#define EM_OPERATION_QUEUE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), EM_TYPE_OPERATION_QUEUE, EMOperationQueueClass))

G_BEGIN_DECLS

typedef struct _EMOperationQueue        EMOperationQueue;
typedef struct _EMOperationQueueClass   EMOperationQueueClass;
typedef struct _EMOperationQueuePrivate EMOperationQueuePrivate;

struct _EMOperationQueue {
	GObject parent;

	EMOperationQueuePrivate *priv;
};

struct _EMOperationQueueClass {
	GObjectClass parent_class;

	/* signals */
};

GType			em_operation_queue_get_type (void);

/* 'user_data' corresponds to 'user_data' from em_operation_queue_new(),
   'worker_data' corresponds to 'worker_data' from em_operation_queue_push() */
typedef void (*EMOperationQueueFunc)(gpointer worker_data, gboolean cancelled, gpointer user_data);

EMOperationQueue *	em_operation_queue_new		(EMOperationQueueFunc worker_cb, gpointer user_data);
void			em_operation_queue_push		(EMOperationQueue *queue, gpointer worker_data);
gboolean		em_operation_queue_cancel	(EMOperationQueue *queue, gpointer worker_data);
gboolean		em_operation_queue_cancel_all	(EMOperationQueue *queue);
gint			em_operation_queue_length	(EMOperationQueue *queue);

EMOperationQueue *	em_async_queue_new		(void);
void			em_async_queue_push		(EMOperationQueue *queue,
							 gpointer worker_data,
							 gpointer user_data,
							 EMOperationQueueFunc worker_cb, /* run in a new thread */
							 EMOperationQueueFunc done_cb);  /* run in a main thread */

#endif /* EM_OPERATION_QUEUE */
