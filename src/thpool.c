/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <glib.h>
#include <stdlib.h>
#include <stdbool.h>
#include "thpool.h"

struct ArchipelagoThreadPool *thread_pool_init(GFunc func, int max_threads)
{
    GError *error = NULL;
    struct ArchipelagoThreadPool *thp = malloc(sizeof(struct ArchipelagoThreadPool));

    if (thp == NULL) {
        return NULL;
    }

    /*
     * An error can only occure when 'exclusive' is set to TRUE and not all
     * peer->nr_ops threads could be created.
     */
    thp->gpool = g_thread_pool_new(func, NULL, max_threads, TRUE, &error);
    if (error) {
        free(thp);
        return NULL;
    }
    thp->work_queue = g_async_queue_new();
    return thp;
}

void thread_pool_free(struct ArchipelagoThreadPool *pool)
{
    if (pool == NULL) {
        return;
    }
    g_thread_pool_free(pool->gpool, TRUE, TRUE);
    g_async_queue_unref(pool->work_queue);
}

bool thread_pool_submit_work(struct ArchipelagoThreadPool *pool, void *arg)
{
    GError *error = NULL;
    bool rv = g_thread_pool_push(pool->gpool, arg, &error);
    return rv;
}

void thread_pool_workqueue_put(struct ArchipelagoThreadPool *pool, void *arg)
{
    if (!arg) {
        return;
    }
    g_async_queue_push(pool->work_queue, arg);
}

void *thread_pool_workqueue_get(struct ArchipelagoThreadPool *pool)
{
    return g_async_queue_try_pop(pool->work_queue);
}


void thread_pool_workqueue_lock(struct ArchipelagoThreadPool *pool)
{
    g_async_queue_lock(pool->work_queue);
}

void thread_pool_workqueue_unlock(struct ArchipelagoThreadPool *pool)
{
    g_async_queue_unlock(pool->work_queue);
}

void *thread_pool_workqueue_get_unlocked(struct ArchipelagoThreadPool *pool)
{
    return g_async_queue_try_pop_unlocked(pool->work_queue);
}
