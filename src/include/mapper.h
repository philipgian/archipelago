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

#ifndef MAPPER_H

#define MAPPER_H

#include <unistd.h>
#include <xseg/xseg.h>
#include <hash.h>
#include <peer.h>
#include <xseg/protocol.h>
#include <mapper-version0.h>
#include <mapper-version1.h>
#include <mapper-version2.h>
#include <mapper-version3.h>
#include <glib.h>

/* Alternative, each header file could define an appropriate MAP_V# */
enum { MAP_V0, MAP_V1, MAP_V2, MAP_V3};
#define MAP_LATEST_VERSION MAP_V3
#define MAP_LATEST_MOPS &v3_ops

#define MAX_EPOCH (UINT32_MAX -2)
#define MAX_NAME_IDX ((1<<30) -1)

struct header_struct {
    uint32_t signature;
    uint32_t version;
    unsigned char pad[504];
} __attribute__ ((packed));

#define MAX_MAPHEADER_SIZE (sizeof(struct header_struct))

/* should always be the minimum blocksize required by all versions */
#define MIN_BLOCKSIZE (v3_objectsize_in_map)
/* should always be the maximum objectlen of all versions */
#define MAX_OBJECT_LEN 123

/* since object names are cacluclated from the volume names, the limit of the
 * maximum volume len is calculated from the maximum object len, statically for
 * all map versions.
 *
 * How the object name is calculated is reflected in this formula:
 *
 * volume-index-epoch
 */
#define MAX_VOLUME_LEN (MAX_OBJECT_LEN - HEXLIFIED_INDEX_LEN - HEXLIFIED_EPOCH_LEN - 2)


/* Some compile time checks */
#if MAX_OBJECT_LEN > XSEG_MAX_TARGETLEN
#error 	"XSEG_MAX_TARGETLEN should be at least MAX_OBJECT_LEN"
#endif

#if MAX_OBJECT_LEN < v3_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v3_max_objectlen"
#endif

#if MAX_OBJECT_LEN < v2_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v2_max_objectlen"
#endif

#if MAX_OBJECT_LEN < v1_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v1_max_objectlen"
#endif

#if MAX_OBJECT_LEN < v0_max_objectlen
#error "MAX_OBJECT_LEN is smaller than v0_max_objectlen"
#endif

/* TODO Use some form of static assert for the following. Comment out for now.

#if MAX_MAPHEADER_SIZE < v3_mapheader_size
#error "MAX_MAPHEADER_SIZE is smaller than v3_mapheader_size"
#endif

#if MAX_MAPHEADER_SIZE < v2_mapheader_size
#error "MAX_MAPHEADER_SIZE is smaller than v2_mapheader_size"
#endif

#if MAX_MAPHEADER_SIZE < v1_mapheader_size
#error "MAX_MAPHEADER_SIZE is smaller than v1_mapheader_size"
#endif

#if MAX_MAPHEADER_SIZE < v0_mapheader_size
#error "MAX_MAPHEADER_SIZE is smaller than v0_mapheader_size"
#endif

*/

/*
#if MAX_VOLUME_LEN > XSEG_MAX_TARGETLEN
#error 	"XSEG_MAX_TARGETLEN should be at least MAX_VOLUME_LEN"
#endif
*/

struct map;
struct mapping;
/* Map I/O ops */
struct map_ops {
    struct xseg_request *(*prepare_write_object) (struct peer_req * pr,
                                                  struct map * map,
                                                  uint64_t obj_idx,
                                                  struct mapping *m);
    int (*load_map_data) (struct peer_req * pr, struct map * map);
    int (*write_map_data) (struct peer_req * pr, struct map * map);
    int (*delete_map_data) (struct peer_req * pr, struct map * map);
};

/* general mapper flags */
#define MF_LOAD         (1 << 0)
#define MF_EXCLUSIVE    (1 << 1)
#define MF_FORCE        (1 << 2)
#define MF_ARCHIP       (1 << 3)
#define MF_SERIALIZE    (1 << 4)
#define MF_CREATE       (1 << 5)

#define MAPPER_DEFAULT_BLOCKSIZE (1<<22)
#define MAPPER_DEFAULT_HEXCASSIZE (HEXLIFIED_SHA256_DIGEST_SIZE)

#define MAPPER_PREFIX "archip_"
#define MAPPER_PREFIX_LEN 7

/* These values come straight from the size of mapping->objectidx and
 * map->epoch.
 */
#define HEXLIFIED_EPOCH_LEN (sizeof(uint64_t) << 1)
#define HEXLIFIED_INDEX_LEN (sizeof(uint64_t) << 1)



extern char *zero_block;
#define ZERO_BLOCK_LEN (64)     /* strlen(zero_block) */

/* callback function type */
typedef void (*cb_t) (struct peer_req * pr, struct xseg_request * req);


/* map object flags */
#define MF_OBJECT_WRITABLE  (1 << 0)
#define MF_OBJECT_ARCHIP    (1 << 1)
#define MF_OBJECT_ZERO      (1 << 2)
#define MF_OBJECT_DELETED   (1 << 3)
#define MF_OBJECT_V1        (1 << 4)

/* run time map object state flags */
#define MF_OBJECT_COPYING   (1 << 0)
#define MF_OBJECT_WRITING   (1 << 1)
#define MF_OBJECT_DELETING  (1 << 2)
//#define MF_OBJECT_DESTROYED   (1 << 3)
#define MF_OBJECT_SNAPSHOTTING  (1 << 4)

#define MF_OBJECT_NOT_READY (                       \
                             MF_OBJECT_COPYING      \
                            |MF_OBJECT_WRITING      \
                            |MF_OBJECT_DELETING     \
                            |MF_OBJECT_SNAPSHOTTING \
                            )

struct mapping {
    uint32_t flags;
    volatile uint32_t state;
    uint32_t vol_epoch;
    uint32_t name_idx;

    volatile uint32_t ref;
    volatile uint32_t waiters;
    st_cond_t cond;
};

/* map flags */
#define MF_MAP_READONLY     (1 << 0)
#define MF_MAP_DELETED      (1 << 1)
#define MF_MAP_GCSCANED     (1 << 2)

/* run time map state flags */
#define MF_MAP_LOADING          (1 << 0)
#define MF_MAP_DESTROYED        (1 << 1)
#define MF_MAP_WRITING          (1 << 2)
#define MF_MAP_DELETING         (1 << 3)
#define MF_MAP_DROPPING_CACHE   (1 << 4)
#define MF_MAP_EXCLUSIVE        (1 << 5)
#define MF_MAP_OPENING          (1 << 6)
#define MF_MAP_CLOSING          (1 << 7)
//#define MF_MAP_DELETED        (1 << 8)
#define MF_MAP_SNAPSHOTTING     (1 << 9)
#define MF_MAP_SERIALIZING      (1 << 10)
#define MF_MAP_HASHING          (1 << 11)
#define MF_MAP_RENAMING         (1 << 12)
#define MF_MAP_CANCACHE         (1 << 13)
#define MF_MAP_PURGING          (1 << 14)
#define MF_MAP_DELETING_DATA    (1 << 15)
#define MF_MAP_DESTROYING       (1 << 16)
#define MF_MAP_TRUNCATING       (1 << 17)
#define MF_MAP_CREATING         (1 << 18)
#define MF_MAP_LOADED           (1 << 19)
#define MF_MAP_COPYING          (1 << 20)

#define MF_MAP_NOT_READY    (                       \
                             MF_MAP_LOADING         \
                            |MF_MAP_WRITING         \
                            |MF_MAP_DELETING        \
                            |MF_MAP_DROPPING_CACHE  \
                            |MF_MAP_OPENING         \
                            |MF_MAP_SNAPSHOTTING    \
                            |MF_MAP_SERIALIZING     \
                            |MF_MAP_HASHING         \
                            |MF_MAP_RENAMING        \
                            |MF_MAP_PURGING         \
                            |MF_MAP_DELETING_DATA   \
                            |MF_MAP_DESTROYING      \
                            |MF_MAP_TRUNCATING      \
                            |MF_MAP_CLOSING         \
                            |MF_MAP_CREATING        \
                            |MF_MAP_COPYING         \
                            )

/* hex value of "AMF."
 * Stands for Archipelago Map Format */
#define MAP_SIGNATURE (uint32_t)(0x414d462e)

struct vol_idx {
    uint16_t len;
    char *name;
};

struct map {
    uint32_t version;
    uint32_t signature;
    uint64_t epoch;
    uint32_t flags;
    uint64_t size;
    uint32_t blocksize;

    uint64_t nr_objs;
    uint32_t volumelen;
    char volume[MAX_VOLUME_LEN + 1];    /* NULL terminated string */
    char key[MAX_VOLUME_LEN + 1];       /* NULL terminated string, for cache */
    struct mapping *objects;
    volatile uint32_t ref;

    volatile uint32_t state;
    volatile uint32_t waiters;
    st_cond_t cond;
    uint64_t opened_count;
    struct map_ops *mops;

    volatile uint32_t pending_io;
    volatile uint32_t waiters_pending_io;
    st_cond_t pending_io_cond;

    /* Length of hexlified CA name */
    uint32_t hex_cas_size;
    /* Length in bytes of the cas_array (hexlified) */
    uint64_t hex_cas_array_len;
    /* Length in bytes of the vol_array in the form of
     *  length | STRING
     * 2 bytes | ...
     */
    uint64_t vol_array_len;
    /* Index of the currrent volume name */
    uint32_t cur_vol_idx;

    /* Number of CA names */
    uint32_t cas_nr;
    /* Number of volume entries */
    uint32_t vol_nr;
    /* Index of the CA names (Not NULL terminated) */
    char **cas_names;
    /* Index of the volume names (Not NULL terminated) */
    struct vol_idx *vol_names;
    /* Buffer that holds the (hexlified) CA name data */
    char *cas_array;
    /* Buffer that holds the volume name data */
    char *vol_array;
};

struct mapperd {
    xport bportno;              /* blocker that accesses data */
    xport mbportno;             /* blocker that accesses maps */
    GHashTable *cached_maps;
};

struct mapper_io {
    GHashTable *req_ctxs;       /* Hash table to associate issued requests with their contextes */
    volatile int err;           /* error flag */
    cb_t cb;
    volatile int active;
    void *priv;
    volatile uint64_t pending_reqs;
    uint64_t count;
    struct map *first_map;
};

struct req_ctx {
    struct mapping *orig_mapping;
    struct mapping copyup_mapping;
    uint64_t obj_idx;
    struct map *map;
    char *buf;
};

/* usefull abstraction macros for context switching */

#define wait_on_pr(__pr, __condition__) 	\
	do {					\
		ta--;				\
		__get_mapper_io(pr)->active = 0;\
		flogger_debug(logger, "Waiting on pr %lx, ta: %u",  pr, ta); \
		st_cond_wait(__pr->cond);	\
	} while (__condition__)

#define wait_on_mapping(__mn, __condition__)	\
	do {					\
		ta--;				\
		__mn->waiters++;		\
		flogger_debug(logger, "Waiting on map node %lx, waiters: %u, \
		              ta: %u",  __mn, __mn->waiters, ta);  \
		st_cond_wait(__mn->cond);	\
	} while (__condition__)

#define wait_on_map(__map, __condition__)	\
	do {					\
		ta--;				\
		__map->waiters++;		\
		flogger_debug(logger, "Waiting on map %lx %s, waiters: %u, ta: %u",\
				      __map, __map->volume, __map->waiters, ta); \
		st_cond_wait(__map->cond);	\
	} while (__condition__)

#define wait_all_objects_ready(__map)	\
	do {					\
		ta--;				\
		__map->waiters_users++;		\
		flogger_debug(logger, "Waiting for objects ready on map %lx %s, waiters: %u, ta: %u",\
				      __map, __map->volume, __map->waiters_users, ta); \
		st_cond_wait(__map->users_cond);	\
	} while (__map->users)

#define wait_all_pending_io(__map)	\
	do {					\
		ta--;				\
		__map->waiters_pending_io++;		\
		flogger_debug(logger, "Waiting for objects ready on map %lx %s, waiters: %u, ta: %u",\
				      __map, __map->volume, __map->waiters_pending_io, ta); \
		st_cond_wait(__map->pending_io_cond);	\
	} while (__map->pending_io)

#define signal_pr(__pr)				\
	do { 					\
		if (!__get_mapper_io(pr)->active){\
			ta++;			\
			flogger_debug(logger, "Signaling  pr %lx, ta: %u",  pr, ta);\
			__get_mapper_io(pr)->active = 1;\
			st_cond_signal(__pr->cond);	\
		}				\
	}while(0)

#define signal_map(__map)			\
	do { 					\
		flogger_debug(logger, "Checking map %lx %s. Waiters %u, ta: %u", \
				      __map, __map->volume, __map->waiters, ta);  \
		if (__map->waiters) {		\
			ta += __map->waiters;		\
			flogger_debug(logger, "Signaling map %lx %s, waiters: %u, \
			              ta: %u",  __map, __map->volume, __map->waiters, ta); \
			__map->waiters = 0;	\
			st_cond_broadcast(__map->cond);	\
		}				\
	}while(0)

#define signal_all_objects_ready(__map)			\
	do { 					\
		/* assert __map->users == 0 */ \
		if (__map->waiters_users) {		\
			ta += __map->waiters_users;		\
			flogger_debug(logger, "Signaling objects ready for map %lx %s, waiters: %u, \
			              ta: %u",  __map, __map->volume, __map->waiters_users, ta); \
			__map->waiters_users = 0;	\
			st_cond_broadcast(__map->users_cond);	\
		}				\
	}while(0)

#define signal_all_pending_io_ready(__map)			\
	do { 					\
		/* assert __map->users == 0 */ \
		if (__map->waiters_pending_io) {		\
			ta += __map->waiters_pending_io;		\
			flogger_debug(logger, "Signaling pending io ready for map %lx %s, waiters: %u, \
			              ta: %u",  __map, __map->volume, __map->waiters_pending_io, ta); \
			__map->waiters_pending_io = 0;	\
			st_cond_broadcast(__map->pending_io_cond);\
		}				\
	}while(0)


#define signal_mapping(__mn)			\
	do { 					\
		if (__mn->waiters) {		\
			ta += __mn->waiters;	\
			flogger_debug(logger, "Signaling map node %lx, waiters: \
			              %u, ta: %u",  __mn, __mn->waiters, ta); \
			__mn->waiters = 0;	\
			st_cond_broadcast(__mn->cond);	\
		}				\
	}while(0)


/* Helper functions */
static inline struct mapperd *__get_mapperd(struct peerd *peer)
{
    return (struct mapperd *) peer->priv;
}

static inline struct mapper_io *__get_mapper_io(struct peer_req *pr)
{
    return (struct mapper_io *) pr->priv;
}

static inline uint64_t __calc_map_obj(uint64_t size, uint32_t blocksize)
{
    uint64_t nr_objs;

    nr_objs = size / blocksize;
    if (size % blocksize) {
        nr_objs++;
    }

    return nr_objs;
}

static inline uint64_t calc_map_obj(struct map *map)
{
    return __calc_map_obj(map->size, map->blocksize);
}

static inline int is_valid_blocksize(uint64_t x)
{
    return (x && !(x & (x - 1)) && x > MIN_BLOCKSIZE);
}

/* map handling functions */
int open_map(struct peer_req *pr, struct map *map, uint32_t flags);
struct xseg_request *__close_map(struct peer_req *pr, struct map *map);
int close_map(struct peer_req *pr, struct map *map);
int write_map(struct peer_req *pr, struct map *map);
int write_map_metadata(struct peer_req *pr, struct map *map);
int load_map(struct peer_req *pr, struct map *map);
struct xseg_request *copyup_object(struct peer_req *pr, struct map *map, uint64_t idx);
void copyup_cb(struct peer_req *pr, struct xseg_request *req);
int load_map_metadata(struct peer_req *pr, struct map *map);
int delete_map(struct peer_req *pr, struct map *map, int delete_data);
int delete_map_data(struct peer_req *pr, struct map *map);
int purge_map(struct peer_req *pr, struct map *map);
int initialize_map_objects(struct map *map);
struct mapping *get_mapping(struct map *map, uint64_t objindex);
void put_mapping(struct mapping *mn);
struct xseg_request *object_delete(struct peer_req *pr, struct map *map,
                                   uint64_t obj_idx);
void object_delete_cb(struct peer_req *pr, struct xseg_request *req);

int set_req_ctx(struct mapper_io *mio, struct xseg_request *req,
                struct req_ctx *rctx);
int remove_req_ctx(struct mapper_io *mio, struct xseg_request *req);
struct req_ctx * get_req_ctx(struct mapper_io *mio, struct xseg_request *req);

void restore_map_objects(struct map *map);
void restore_map(struct map *map);
#endif                          /* end MAPPER_H */
