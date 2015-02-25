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
#ifndef __THPOOL_H
#define __THPOOL_H

#include <pthread.h>
#include <glib.h>

struct ArchipelagoThreadPool {
	GAsyncQueue *work_queue;
	GThreadPool *gpool;
};

struct ArchipelagoThreadPool *thread_pool_init(GFunc func, int max_threads);
void thread_pool_free(struct ArchipelagoThreadPool *pool);
bool thread_pool_submit_work(struct ArchipelagoThreadPool *pool, void *arg);
void thread_pool_workqueue_put(struct ArchipelagoThreadPool *pool, void *arg);
void *thread_pool_workqueue_get(struct ArchipelagoThreadPool *pool);
void thread_pool_workqueue_lock(struct ArchipelagoThreadPool *pool);
void thread_pool_workqueue_unlock(struct ArchipelagoThreadPool *pool);
void *thread_pool_workqueue_get_unlocked(struct ArchipelagoThreadPool *pool);


#endif
