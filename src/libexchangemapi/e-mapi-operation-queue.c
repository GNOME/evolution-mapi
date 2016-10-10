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

#include "evolution-mapi-config.h"

#include <stdio.h>
#include "e-mapi-operation-queue.h"

static void thread_func_cb (gpointer data, gpointer pqueue);

#define LOCK()   g_mutex_lock   (&priv->lock)
#define UNLOCK() g_mutex_unlock (&priv->lock)

/* GObject foo - begin */

G_DEFINE_TYPE (EMapiOperationQueue, e_mapi_operation_queue, G_TYPE_OBJECT)

struct _EMapiOperationQueuePrivate
{
	GMutex lock;
	GThreadPool *pool;
	EMapiOperationQueueFunc worker_cb;
	gpointer user_data;
	GSList *ops;
};

static void
e_mapi_operation_queue_dispose (GObject *object)
{
	EMapiOperationQueue *queue = E_MAPI_OPERATION_QUEUE (object);
	EMapiOperationQueuePrivate *priv;

	g_return_if_fail (queue != NULL);

	priv = queue->priv;

	if (priv) {
		e_mapi_operation_queue_cancel_all (queue);

		LOCK ();
		if (priv->ops) {
			g_warn_if_reached ();
		}

		g_thread_pool_free (priv->pool, FALSE, TRUE);

		queue->priv = NULL;

		UNLOCK ();

		g_mutex_clear (&priv->lock);
	}

	if (G_OBJECT_CLASS (e_mapi_operation_queue_parent_class)->dispose)
		G_OBJECT_CLASS (e_mapi_operation_queue_parent_class)->dispose (object);
}

static void
e_mapi_operation_queue_class_init (EMapiOperationQueueClass *klass)
{
	GObjectClass *object_class;

	g_type_class_add_private (klass, sizeof (EMapiOperationQueuePrivate));

	object_class = G_OBJECT_CLASS (klass);
	object_class->dispose = e_mapi_operation_queue_dispose;
}

static void
e_mapi_operation_queue_init (EMapiOperationQueue *queue)
{
	EMapiOperationQueuePrivate *priv;

	g_return_if_fail (queue != NULL);
	g_return_if_fail (E_MAPI_IS_OPERATION_QUEUE (queue));

	queue->priv = G_TYPE_INSTANCE_GET_PRIVATE (queue, E_MAPI_TYPE_OPERATION_QUEUE, EMapiOperationQueuePrivate);
	priv = queue->priv;
	g_return_if_fail (priv != NULL);

	g_mutex_init (&priv->lock);
	priv->pool = g_thread_pool_new (thread_func_cb, queue, 1, FALSE, NULL);
	priv->worker_cb = NULL;
	priv->user_data = NULL;
	priv->ops = NULL;
}

/* GObject foo - end */

struct OPData
{
	gpointer worker_data;
	gboolean cancelled;
};

static void
thread_func_cb (gpointer data, gpointer pqueue)
{
	EMapiOperationQueue *queue = pqueue;
	EMapiOperationQueuePrivate *priv;
	struct OPData *op = data;
	gpointer worker_data = NULL;
	gboolean cancelled = TRUE;

	g_return_if_fail (E_MAPI_IS_OPERATION_QUEUE (queue));
	g_return_if_fail (op != NULL);

	priv = queue->priv;
	g_return_if_fail (priv != NULL);

	LOCK ();

	g_object_ref (queue);

	worker_data = op->worker_data;

	if (g_slist_find (priv->ops, op) && !op->cancelled)
		cancelled = FALSE;

	priv->ops = g_slist_remove (priv->ops, op);

	UNLOCK ();

	if (priv->worker_cb)
		priv->worker_cb (worker_data, cancelled, priv->user_data);

	g_object_unref (queue);
	g_free (op);
}

EMapiOperationQueue *
e_mapi_operation_queue_new (EMapiOperationQueueFunc worker_cb, gpointer user_data)
{
	EMapiOperationQueue *queue;
	EMapiOperationQueuePrivate *priv;

	g_return_val_if_fail (worker_cb != NULL, NULL);

	queue = g_object_new (E_MAPI_TYPE_OPERATION_QUEUE, NULL);

	priv = queue->priv;
	g_return_val_if_fail (priv != NULL, NULL);

	priv->worker_cb = worker_cb;
	priv->user_data = user_data;

	return queue;
}

void
e_mapi_operation_queue_push (EMapiOperationQueue *queue, gpointer worker_data)
{
	EMapiOperationQueuePrivate *priv;
	struct OPData *op;

	g_return_if_fail (queue != NULL);
	g_return_if_fail (E_MAPI_IS_OPERATION_QUEUE (queue));

	priv = queue->priv;
	g_return_if_fail (priv != NULL);

	LOCK ();
	op = g_new0 (struct OPData, 1);
	op->cancelled = FALSE;
	op->worker_data = worker_data;

	priv->ops = g_slist_prepend (priv->ops, op);

	g_thread_pool_push (priv->pool, op, NULL);

	UNLOCK ();
}

gboolean
e_mapi_operation_queue_cancel (EMapiOperationQueue *queue, gpointer worker_data)
{
	EMapiOperationQueuePrivate *priv;
	gboolean found = FALSE;
	GSList *l;

	g_return_val_if_fail (queue != NULL, FALSE);
	g_return_val_if_fail (E_MAPI_IS_OPERATION_QUEUE (queue), FALSE);

	priv = queue->priv;
	g_return_val_if_fail (priv != NULL, FALSE);

	LOCK ();

	for (l = priv->ops; l; l = l->next) {
		struct OPData *op = l->data;

		if (op && op->worker_data == worker_data) {
			found = TRUE;
			op->cancelled = TRUE;
			priv->ops = g_slist_remove (priv->ops, op);
			break;
		}
	}

	UNLOCK ();

	return found;
}

gboolean
e_mapi_operation_queue_cancel_all (EMapiOperationQueue *queue)
{
	EMapiOperationQueuePrivate *priv;
	gboolean found_any = FALSE;
	GSList *l;

	g_return_val_if_fail (queue != NULL, FALSE);
	g_return_val_if_fail (E_MAPI_IS_OPERATION_QUEUE (queue), FALSE);

	priv = queue->priv;
	g_return_val_if_fail (priv != NULL, FALSE);

	LOCK ();

	for (l = priv->ops; l; l = l->next) {
		struct OPData *op = l->data;

		if (op) {
			found_any = TRUE;
			op->cancelled = TRUE;
		}
	}

	g_slist_free (priv->ops);
	priv->ops = NULL;

	UNLOCK ();

	return found_any;
}

gint
e_mapi_operation_queue_length (EMapiOperationQueue *queue)
{
	EMapiOperationQueuePrivate *priv;
	gint len;

	g_return_val_if_fail (queue != NULL, -1);
	g_return_val_if_fail (E_MAPI_IS_OPERATION_QUEUE (queue), -1);

	priv = queue->priv;
	g_return_val_if_fail (priv != NULL, -1);

	LOCK ();
	len = g_slist_length (priv->ops);
	UNLOCK ();

	return len;
}

struct async_queue_data
{
	gpointer worker_data;
	gpointer user_data;
	EMapiOperationQueueFunc worker_cb;
	EMapiOperationQueueFunc done_cb;

	gboolean cancelled;
};

static gboolean
async_queue_idle_cb (gpointer user_data)
{
	struct async_queue_data *data = user_data;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->done_cb != NULL, FALSE);

	if (data->done_cb)
		data->done_cb (data->worker_data, data->cancelled, data->user_data);

	g_free (data);

	return FALSE;
}

static void
async_queue_worker_cb (gpointer worker_data, gboolean cancelled, gpointer user_data)
{
	struct async_queue_data *data = worker_data;

	g_return_if_fail (data != NULL);

	data->cancelled = cancelled;

	if (data->worker_cb)
		data->worker_cb (data->worker_data, data->cancelled, data->user_data);

	if (data->done_cb)
		g_idle_add (async_queue_idle_cb, data);
	else
		g_free (data);
}

EMapiOperationQueue *
e_mapi_async_queue_new (void)
{
	return e_mapi_operation_queue_new (async_queue_worker_cb, NULL);
}

void
e_mapi_async_queue_push (EMapiOperationQueue *queue, gpointer worker_data, gpointer user_data, EMapiOperationQueueFunc worker_cb, EMapiOperationQueueFunc done_cb)
{
	struct async_queue_data *data;

	g_return_if_fail (queue != NULL);

	data = g_new0 (struct async_queue_data, 1);
	data->worker_data = worker_data;
	data->user_data = user_data;
	data->worker_cb = worker_cb;
	data->done_cb = done_cb;

	e_mapi_operation_queue_push (queue, data);
}
