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

#ifndef __UTIL_H
#define __UTIL_H

#include <pthread.h>
#include <sys/syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <glib.h>

#if __GNUC__ >= 3
# define unlikely(cond) __builtin_expect ((cond), 0)
# define likely(cond)   __builtin_expect ((cond), 1)
#else
# define unlikely(cond) (cond)
# define likely(cond)   (cond)
#endif

#define panic(fmt, args...) \
({                  \
        syslog(LOG_EMERG, "PANIC: " fmt, ##args); \
        abort();                                \
})

static inline void *zalloc(size_t size)
{
    return calloc(1, size);
}

static inline void archipelago_init_mutex(pthread_mutex_t *mutex)
{
    int rv;

    do {
        rv = pthread_mutex_init(mutex, NULL);
    } while (rv == EAGAIN);

    if (unlikely(rv != 0)) {
        panic("failed to initialize mutex, %s", strerror(rv));
    }
}

static inline void archipelago_destroy_mutex(pthread_mutex_t *mutex)
{
    int rv;

    do {
        rv = pthread_mutex_destroy(mutex);
    } while (rv == EAGAIN);

    if (unlikely(rv != 0)) {
        panic("failed to destroy mutex, %s", strerror(rv));
    }
}

static inline void archipelago_mutex_lock(pthread_mutex_t *mutex)
{
    int rv;

    do {
        rv = pthread_mutex_lock(mutex);
    } while (rv == EAGAIN);

    if (unlikely(rv != 0)) {
        panic("failed to lock mutex, %s", strerror(rv));
    }
}

static inline void archipelago_mutex_unlock(pthread_mutex_t *mutex)
{
    int rv;

    do {
        rv = pthread_mutex_unlock(mutex);
    } while (rv == EAGAIN);

    if (unlikely(rv != 0)) {
        panic("failed to unlock mutex, %s", strerror(rv));
    }
}
#endif
