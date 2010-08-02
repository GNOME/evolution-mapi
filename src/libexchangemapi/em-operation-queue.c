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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include "em-operation-queue.h"

static void thread_func_cb (gpointer data, gpointer pqueue);

#define LOCK()   g_mutex_lock   (priv->lock)
#define UNLOCK() g_mutex_unlock (priv->lock)

/* GObject foo - begin */

G_DEFINE_TYPE (EMOperationQueue, em_operation_queue, G_TYPE_OBJECT)

#define EM_OPERATION_QUEUE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), EM_TYPE_OPERATION_QUEUE, EMOperationQueuePrivate))

struct _EMOperationQueuePrivate
{
	GMutex *lock;
	GThreadPool *pool;
	EMOperationQueueFunc worker_cb;
	gpointer user_data;
	GSList *ops;
};

static void
em_operation_queue_dispose (GObject *object)
{
	EMOperationQueue *queue = EM_OPERATION_QUEUE (object);
	EMOperationQueuePrivate *priv;

	g_return_if_fail (queue != NULL);

	priv = queue->priv;

	if (priv) {
		em_operation_queue_cancel_all (queue);

		LOCK ();
		if (priv->ops) {
			g_warn_if_reached ();
		}

		g_thread_pool_free (priv->pool, FALSE, TRUE);

		queue->priv = NULL;

		UNLOCK ();

		g_mutex_free (priv->lock);
	}

	if (G_OBJECT_CLASS (em_operation_queue_parent_class)->dispose)
		G_OBJECT_CLASS (em_operation_queue_parent_class)->dispose (object);
}

static void
em_operation_queue_class_init (EMOperationQueueClass *klass)
{
	GObjectClass *object_class;

	g_type_class_add_private (klass, sizeof (EMOperationQueuePrivate));

	object_class = G_OBJECT_CLASS (klass);
	object_class->dispose = em_operation_queue_dispose;
}

static void
em_operation_queue_init (EMOperationQueue *queue)
{
	EMOperationQueuePrivate *priv;

	g_return_if_fail (queue != NULL);
	g_return_if_fail (EM_IS_OPERATION_QUEUE (queue));

	queue->priv = EM_OPERATION_QUEUE_GET_PRIVATE (queue);
	priv = queue->priv;
	g_return_if_fail (priv != NULL);

	priv->lock = g_mutex_new ();
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
	EMOperationQueue *queue = pqueue;
	EMOperationQueuePrivate *priv;
	struct OPData *op = data;
	gpointer worker_data = NULL;
	gboolean cancelled = TRUE;

	g_return_if_fail (EM_IS_OPERATION_QUEUE (queue));
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
		priv->worker_cb (op->worker_data, cancelled, priv->user_data);

	g_object_unref (queue);
	g_free (op);
}

EMOperationQueue *
em_operation_queue_new (EMOperationQueueFunc worker_cb, gpointer user_data)
{
	EMOperationQueue *queue;
	EMOperationQueuePrivate *priv;

	g_return_val_if_fail (worker_cb != NULL, NULL);

	queue = g_object_new (EM_TYPE_OPERATION_QUEUE, NULL);

	priv = queue->priv;
	g_return_val_if_fail (priv != NULL, NULL);

	priv->worker_cb = worker_cb;
	priv->user_data = user_data;

	return queue;
}

void
em_operation_queue_push (EMOperationQueue *queue, gpointer worker_data)
{
	EMOperationQueuePrivate *priv;
	struct OPData *op;

	g_return_if_fail (queue != NULL);
	g_return_if_fail (EM_IS_OPERATION_QUEUE (queue));

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
em_operation_queue_cancel (EMOperationQueue *queue, gpointer worker_data)
{
	EMOperationQueuePrivate *priv;
	gboolean found = FALSE;
	GSList *l;

	g_return_val_if_fail (queue != NULL, FALSE);
	g_return_val_if_fail (EM_IS_OPERATION_QUEUE (queue), FALSE);

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
em_operation_queue_cancel_all (EMOperationQueue *queue)
{
	EMOperationQueuePrivate *priv;
	gboolean found_any = FALSE;
	GSList *l;

	g_return_val_if_fail (queue != NULL, FALSE);
	g_return_val_if_fail (EM_IS_OPERATION_QUEUE (queue), FALSE);

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
em_operation_queue_length (EMOperationQueue *queue)
{
	EMOperationQueuePrivate *priv;
	gint len;

	g_return_val_if_fail (queue != NULL, -1);
	g_return_val_if_fail (EM_IS_OPERATION_QUEUE (queue), -1);

	priv = queue->priv;
	g_return_val_if_fail (priv != NULL, -1);

	LOCK ();
	len = g_slist_length (priv->ops);
	UNLOCK ();

	return len;
}
