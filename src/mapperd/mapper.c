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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <xseg/xseg.h>
#include <xseg/xhash.h>
#include <xseg/protocol.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>

#include "peer.h"
#include "hash.h"
#include "mapper.h"
#include "mapper-versions.h"

uint64_t accepted_req_count = 0;

extern st_cond_t req_cond;
/* pithos considers this a block full of zeros, so should we.
 * it is actually the sha256 hash of nothing.
 */
char *zero_block =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

void custom_peer_usage()
{
    fprintf(stderr, "Custom peer options: \n"
            "-bp  : port for block blocker(!)\n"
            "-mbp : port for map blocker\n" "\n");
}

static int map_action(int (action) (struct peer_req * pr, struct map * map),
                      struct peer_req *pr, char *name, uint32_t namelen,
                      uint32_t flags);

/*
 * Helper functions
 */

static uint64_t calc_nr_obj(struct map *map, struct xseg_request *req)
{
    uint64_t nr_objs = 1;
    uint64_t rem_size, obj_offset, obj_size;

    rem_size = req->size;
    obj_offset = req->offset & (map->blocksize - 1);   //modulo
    if (rem_size + obj_offset > map->blocksize) {
        obj_size = map->blocksize - obj_offset;
    } else {
        obj_size = rem_size;
    }
    rem_size -= obj_size;

    nr_objs += rem_size / map->blocksize;
    if (rem_size & (map->blocksize - 1)) {
        nr_objs++;
    }

    return nr_objs;
}

static void copy_object_properties(struct mapping *from, struct mapping *to)
{
    if (from->flags & MF_OBJECT_ZERO) {
        to->flags = MF_OBJECT_ZERO;
        to->vol_epoch = 0;
        to->name_idx = 0;
    } else {
        to->flags = 0;
        to->flags |= from->flags & MF_OBJECT_ARCHIP;
        to->flags |= from->flags & MF_OBJECT_WRITABLE;
        to->vol_epoch = from->vol_epoch;
        to->name_idx = from->name_idx;
    }
}

/*
 * Map cache handling functions
 */

static struct map *cache_lookup(struct mapperd *mapper, char *volume)
{
    struct map *m = NULL;
    int r = xhash_lookup(mapper->hashmaps, (xhashidx) volume,
                         (xhashidx *) & m);
    if (r < 0) {
        return NULL;
    }
    return m;
}

static struct map *cache_lookup_len(struct mapperd *mapper, char *target,
                                uint32_t targetlen, uint32_t flags)
{
    char buf[XSEG_MAX_TARGETLEN + 1];

    if (targetlen > MAX_VOLUME_LEN) {
        XSEGLOG2(&lc, E, "Namelen %u too long. Max: %d",
                 targetlen, MAX_VOLUME_LEN);
        return NULL;
    }
//      if (flags & MF_ARCHIP){
//              strncpy(buf, MAPPER_PREFIX, MAPPER_PREFIX_LEN);
//              strncpy(buf + MAPPER_PREFIX_LEN, target, targetlen);
//              buf[MAPPER_PREFIX_LEN + targetlen] = 0;
//              targetlen += MAPPER_PREFIX_LEN;
//      }
//      else {
    strncpy(buf, target, targetlen);
    buf[targetlen] = '\0';
//      }

    XSEGLOG2(&lc, D, "looking up map %s, len %u", buf, targetlen);
    return cache_lookup(mapper, buf);
}


static int insert_cache(struct mapperd *mapper, struct map *map)
{
    int r = -1;

    if (cache_lookup(mapper, map->key)) {
        XSEGLOG2(&lc, W, "Map %s found in hash maps", map->key);
        goto out;
    }

    XSEGLOG2(&lc, D, "Inserting map %s, len: %d (map: %lx)",
             map->key, strlen(map->key), (unsigned long) map);
    r = xhash_insert(mapper->hashmaps, (xhashidx) map->key, (xhashidx) map);
    while (r == -XHASH_ERESIZE) {
        xhashidx shift = xhash_grow_size_shift(mapper->hashmaps);
        xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, 0, NULL);
        if (!new_hashmap) {
            XSEGLOG2(&lc, E, "Cannot grow mapper->hashmaps to sizeshift %llu",
                     (unsigned long long) shift);
            goto out;
        }
        mapper->hashmaps = new_hashmap;
        r = xhash_insert(mapper->hashmaps, (xhashidx) map->key,
                         (xhashidx) map);
    }
  out:
    return r;
}

static int remove_cache(struct mapperd *mapper, struct map *map)
{
    int r = -1;

    //assert no pending pr on map

    r = xhash_delete(mapper->hashmaps, (xhashidx) map->key);
    while (r == -XHASH_ERESIZE) {
        xhashidx shift = xhash_shrink_size_shift(mapper->hashmaps);
        xhash_t *new_hashmap = xhash_resize(mapper->hashmaps, shift, 0, NULL);
        if (!new_hashmap) {
            XSEGLOG2(&lc, E,
                     "Cannot shrink mapper->hashmaps to sizeshift %llu",
                     (unsigned long long) shift);
            goto out;
        }
        mapper->hashmaps = new_hashmap;
        r = xhash_delete(mapper->hashmaps, (xhashidx) map->volume);
    }
  out:
    return r;
}

inline struct mapping *get_mapping(struct map *map, uint64_t index)
{
    // assert(index < map->nr_objs);
    // assert(map->objects);
    if (index >= map->nr_objs) {
        XSEGLOG2(&lc, E, "Index out of range: %llu > %llu",
                 index, map->nr_objs);
        return NULL;
    }

    if (!map->objects) {
        XSEGLOG2(&lc, E, "Map %s has no objects", map->volume);
        return NULL;
    }

    return &map->objects[index];
}

inline void put_mapping(struct mapping *m)
{
    return;
}

int initialize_map_objects(struct map *map)
{
    uint64_t i;
    struct mapping *mapping = map->objects;

    if (!mapping) {
        return -1;
    }

    for (i = 0; i < map->nr_objs; i++) {
        mapping[i].flags = 0;
        mapping[i].vol_epoch = 0;
        mapping[i].name_idx = 0;
        mapping[i].waiters = 0;
        mapping[i].state = 0;
        mapping[i].ref = 1;
        mapping[i].cond = st_cond_new();       //FIXME err check;
    }
    return 0;
}



static inline void __get_map(struct map *map)
{
    map->ref++;
}

static inline void put_map(struct map *map)
{
    uint64_t i;
    struct mapping *m;

    XSEGLOG2(&lc, D, "Putting map %lx %s. ref %u", map, map->volume, map->ref);

    map->ref--;
    if (!map->ref) {
        XSEGLOG2(&lc, I, "Freeing map %s", map->volume);
        for (i = 0; i < map->nr_objs; i++) {
            // cleanup mapping resources;
            m = get_mapping(map, i);
            /*
             * Check that every object is not used by another state thread.
             * This should always check out, otherwise there is a bug. Since
             * before a thread can manipulate an object, it must first get
             * the map, the map ref will never hit zero, while another
             * thread is using an object.
             */
            // assert(!(m->state & MF_OBJECT_NOT_READY));
            st_cond_destroy(m->cond);
        }

        // clean up map resources

        if (map->objects) {
            free(map->objects);
        }
        if (map->cas_names) {
            free(map->cas_names);
        }
        if (map->vol_names) {
            free(map->vol_names);
        }
        if (map->cas_array) {
            free(map->cas_array);
        }
        if (map->vol_array) {
            free(map->vol_array);
        }

        st_cond_destroy(map->pending_io_cond);
        st_cond_destroy(map->users_cond);

        XSEGLOG2(&lc, I, "Freed map %s", map->volume);

        free(map);
    }
}

static void change_map_volume(struct map *map, char *name, uint32_t namelen)
{
    strncpy(map->volume, name, namelen);
    map->volume[namelen] = '\0';
    map->volumelen = namelen;
}

static void initialize_map_fields(struct map *map)
{
    map->flags = 0;
    map->epoch = 0;
    map->nr_objs = 0;
    map->size = 0;
    map->blocksize = 0;
    map->objects = NULL;
    map->hex_cas_size = 0;
    map->hex_cas_array_len = 0;
    map->vol_array_len = 0;
    map->cur_vol_idx = 0;
    map->cas_nr = 0;
    map->vol_nr = 0;
    map->cas_names = NULL;
    map->vol_names = NULL;
    map->cas_array = NULL;
    map->vol_array = NULL;
}

static struct map *create_map(char *name, uint32_t namelen, uint32_t flags)
{
    struct map *map;

    if (namelen + MAPPER_PREFIX_LEN > MAX_VOLUME_LEN) {
        XSEGLOG2(&lc, E, "Namelen %u too long. Max: %d",
                 namelen, MAX_VOLUME_LEN - MAPPER_PREFIX_LEN);
        return NULL;
    }

    map = calloc(1, sizeof(struct map));
    if (!map) {
        XSEGLOG2(&lc, E, "Cannot allocate map ");
        return NULL;
    }
    strncpy(map->volume, name, namelen);
    map->volume[namelen] = '\0';
    map->volumelen = namelen;
    //initialize key to volume name
    strncpy(map->key, name, namelen);
    map->key[namelen] = '\0';
    /* Use the latest map version here, when creating a new map. If
     * the map is read from storage, this version will be rewritten
     * with the right value.
     */
    map->version = MAP_LATEST_VERSION;
    map->mops = MAP_LATEST_MOPS;

    initialize_map_fields(map);

    map->signature = MAP_SIGNATURE;
    map->state = 0;

    map->ref = 1;
    map->waiters = 0;
    map->cond = st_cond_new();    //FIXME err check;

    map->users = 0;
    map->waiters_users = 0;
    map->users_cond = st_cond_new();

    map->pending_io= 0;
    map->waiters_pending_io= 0;
    map->pending_io_cond = st_cond_new();

    return map;
}

static void wait_all_map_objects_ready(struct map *map)
{
    uint64_t i;
    struct mapping *mn;

    //TODO: maybe add counter on the map on how many objects are used, to
    //speed up the common case, where there are no used objects.
    map->state |= MF_MAP_SERIALIZING;
    if (map->users) {
        wait_all_objects_ready(map);
    }

    for (i = 0; i < map->nr_objs; i++) {
        mn = get_mapping(map, i);
        if (mn) {
            //make sure all pending operations on all objects are completed
            if (mn->state & MF_OBJECT_NOT_READY) {
                XSEGLOG2(&lc, E, "BUG: Map node %x of map %s, "
                         "idx: %llu is not ready", mn, map->volume, i);
//                              wait_on_mapping(mn, mn->state & MF_OBJECT_NOT_READY);
            }
            put_mapping(mn);
        }
    }

    map->state &= ~MF_MAP_SERIALIZING;
}

// TODO move this to mapper_handling
static int do_copyups(struct peer_req *pr, struct map *map, uint64_t start, int n)
{
    struct mapper_io *mio = __get_mapper_io(pr);
    struct mapping *m;
    uint64_t i;

    mio->pending_reqs = 0;
    mio->cb = copyup_cb;
    mio->err = 0;

    /* do a first scan and issue as many copyups as we can.
     * then retry and wait when an object is not ready.
     * this could be done better, since now we wait also on the
     * pending copyups
     */
    for (i = start; i < (start + n) && !mio->err; i++) {
        m = get_mapping(map, i);
        // assert(m);

        //do copyups
        if (m->state & MF_OBJECT_NOT_READY) {
            continue;
        }

        if (!(m->flags & MF_OBJECT_WRITABLE)) {
            //calc new_target, copy up object
            if (copyup_object(pr, map, i) == NULL) {
                XSEGLOG2(&lc, E, "Error in copy up object");
                mio->err = 1;
                goto out;
            } else {
                mio->pending_reqs++;
            }
        }
    }

    for (i = start; i < (start + n) && !mio->err; i++) {
        m = get_mapping(map, i);
        // assert(m);

        if (m->state & MF_OBJECT_NOT_READY) {
            /* here m->flags should be
             * MF_OBJECT_COPYING or MF_OBJECT_WRITING or
             * later MF_OBJECT_HASHING.
             * Otherwise it's a bug.
             */
            if (m->state != MF_OBJECT_COPYING
                    && m->state != MF_OBJECT_WRITING) {
                XSEGLOG2(&lc, E, "BUG: Map node has wrong state");
            }
            wait_on_mapping(m, m->state & MF_OBJECT_NOT_READY);
            /* This should never happen as delete is serialized */
            if (m->state & MF_OBJECT_DELETED) {
                mio->err = 1;
                continue;
            }
        }

        if (!(m->flags & MF_OBJECT_WRITABLE)) {
            if (copyup_object(pr, map, i) == NULL) {
                XSEGLOG2(&lc, E, "Error in copy up object");
                mio->err = 1;
                goto out;
            } else {
                mio->pending_reqs++;
            }
        }
    }

out:
    if (mio->err) {
        XSEGLOG2(&lc, E, "Mio->err, pending_copyups: %d", mio->pending_reqs);
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    mio->cb = NULL;

    return mio->err ? -1 : 0;
}

static int req2objs(struct peer_req *pr, struct map *map, int write)
{
    int r = 0;
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    char *target = xseg_get_target(peer->xseg, pr->req);
    uint64_t reply_size, i, start, nr_objs;
    uint64_t rem_size, obj_index, obj_offset, obj_size;
    struct mapping *m;
    char buf[XSEG_MAX_TARGETLEN];
    struct xseg_reply_map *reply;


    if (pr->req->offset + pr->req->size > map->size) {
        XSEGLOG2(&lc, E, "Invalid offset/size: offset: %llu, "
                         "size: %llu, map size: %llu",
                 pr->req->offset, pr->req->size, map->size);
        return -EINVAL;
    }

    nr_objs = calc_nr_obj(map, pr->req);
    XSEGLOG2(&lc, D, "Calculated %u nr_objs", nr_objs);

    start = pr->req->offset/map->blocksize;
    if (write) {
        r = do_copyups(pr, map, start, nr_objs);
        if (r < 0) {
            XSEGLOG2(&lc, E, "do_copyups failed");
            return r;
        }
    } else {
        // wait all objects ready
    }

    /* resize request to fit reply */
    reply_size = sizeof(struct xseg_reply_map) +
                 sizeof(struct xseg_reply_map_scatterlist) * nr_objs;
    strncpy(buf, target, pr->req->targetlen);
    r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen, reply_size);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot resize request");
        return -ENOMEM;
    }
    target = xseg_get_target(peer->xseg, pr->req);
    strncpy(target, buf, pr->req->targetlen);

    /* structure reply */
    reply = (struct xseg_reply_map *)xseg_get_data(peer->xseg, pr->req);
    reply->cnt = nr_objs;

    // calculate values for the first object
    rem_size = pr->req->size;
    obj_index = pr->req->offset / map->blocksize;
    obj_offset = pr->req->offset & (map->blocksize - 1);        //modulo
    if (obj_offset + rem_size > map->blocksize) {
        obj_size = map->blocksize - obj_offset;
    } else {
        obj_size = rem_size;
    }

    for (i = 0; i < nr_objs; i++) {
        m = get_mapping(map, start + i);
        if (m->flags & MF_OBJECT_ZERO) {
            reply->segs[i].flags = XF_MAPFLAG_ZERO;
            reply->segs[i].targetlen = 0;
        } else {
            reply->segs[i].targetlen = XSEG_MAX_TARGETLEN;
            r = calculate_object_name(reply->segs[i].target,
                    &reply->segs[i].targetlen, map, m, start + i);
            if (r < 0) {
                return r;
            }
            reply->segs[i].flags = 0;
        }

        reply->segs[i].offset = obj_offset;
        reply->segs[i].size = obj_size;

        // calculate values for the next object
        obj_offset = 0;
        rem_size -= obj_size;
        if (rem_size > map->blocksize) {
            obj_size = map->blocksize;
        } else {
            obj_size = rem_size;
        }
    }

    return 0;
}


static int do_info(struct peer_req *pr, struct map *map)
{
    struct peerd *peer = pr->peer;
    struct xseg_reply_info *xinfo;
    struct xseg_request *req = pr->req;
    char buf[XSEG_MAX_TARGETLEN + 1];
    char *target;
    int r;

    if (req->datalen < sizeof(struct xseg_reply_info)) {
        target = xseg_get_target(peer->xseg, req);
        strncpy(buf, target, req->targetlen);
        r = xseg_resize_request(peer->xseg, req, req->targetlen,
                                sizeof(struct xseg_reply_info));
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot resize request");
            return -1;
        }
        target = xseg_get_target(peer->xseg, req);
        strncpy(target, buf, req->targetlen);
    }

    xinfo = (struct xseg_reply_info *) xseg_get_data(peer->xseg, req);
    xinfo->size = map->size;
    return 0;
}


static int do_open(struct peer_req *pr, struct map *map)
{
    if (map->state & MF_MAP_EXCLUSIVE) {
        return 0;
    } else {
        return -1;
    }
}

static int do_update(struct peer_req *pr, struct map *map)
{
    if (map->version != MAP_LATEST_VERSION) {
        return -1;
    } else {
        return 0;
    }
}


static int dropcache(struct peer_req *pr, struct map *map)
{
    int r;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    XSEGLOG2(&lc, I, "Dropping cache for map %s", map->volume);
    /*
     * We can lazily drop the cache from here, by just removing from the maps
     * hashmap making it inaccessible from future requests. This is because:
     *
     * a) Dropping cache for a map is serialized on a map level. So there
     * should not be any other threds modifying the struct map.
     *
     * b) Any other thread manipulating the map nodes should not have
     * any pending requests on the map node, if the map is not opened
     * exclusively. If that's the case, then we should not close the map,
     * a.k.a. releasing the map lock without checking for any pending
     * requests. Furthermore, since each operation on a map gets a map
     * reference, the memory will not be freed, unless every request has
     * finished processing the map.
     */

    /* Set map as destroyed to notify any waiters that hold a reference to
     * the struct map.
     */
    //FIXME err check
    r = remove_cache(mapper, map);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Remove map %s from hashmap failed", map->volume);
        XSEGLOG2(&lc, E, "Dropping cache for map %s failed", map->volume);
        return -1;
    }
    map->state |= MF_MAP_DESTROYED;
    XSEGLOG2(&lc, I, "Dropping cache for map %s completed", map->volume);
    put_map(map);               // put map here to destroy it (matches m->ref = 1 on map create)
    return 0;
}

static int do_close(struct peer_req *pr, struct map *map)
{
    if (!(map->state & MF_MAP_EXCLUSIVE)) {
        XSEGLOG2(&lc, E, "Attempted to close a not opened map");
        return -1;
    }
    /* Do not close the map while there are pending requests on the
     * map nodes.
     */
    wait_all_map_objects_ready(map);
    if (close_map(pr, map) < 0) {
        return -1;
    }

    return 0;
}

static int do_hash(struct peer_req *pr, struct map *map)
{
    return -1;
}

static int write_snapshot(struct peer_req *pr, struct map *snap_map)
{
    int r;
    uint64_t i;
    char *was_writable = NULL;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct map *map = mio->first_map;
    struct map old_map;

    old_map = *map;

    if (snap_map->state & MF_MAP_LOADED) {
        // assert(map->opened_count != mio->count);
        return -EEXIST;
    }
    if (!(snap_map->state & MF_MAP_EXCLUSIVE)) {
        XSEGLOG2(&lc, E, "Could not open snap map");
        XSEGLOG2(&lc, E, "Snapshot exists");
        return -EEXIST;
    }

    snap_map->state |= MF_MAP_CREATING;

    r = load_map_metadata(pr, snap_map);
    if (r >= 0 & !(snap_map->flags & MF_MAP_DELETED)) {
        XSEGLOG2(&lc, E, "Snapshot exists");
        r = -EEXIST;
        goto out;
    }

    // TODO convert to bitmap
    was_writable = calloc(map->nr_objs, sizeof(char));
    if (!was_writable) {
        r = -ENOMEM;
        goto out;
    }

    for (i = 0; i < map->nr_objs; i++) {
        // store old writable status
        if (map->objects[i].flags & MF_OBJECT_WRITABLE) {
            was_writable[i] = 1;
            map->objects[i].flags &= ~MF_OBJECT_WRITABLE;
        }
    }

    map->epoch++;
    r = write_map(pr, map);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
        map->epoch--;
        for (i = 0; i < map->nr_objs; i++) {
            if (was_writable[i]) {
                map->objects[i].flags |= MF_OBJECT_WRITABLE;
            }
        }
        goto out;
    }

    r = delete_map_data(pr, &old_map);
    if (r < 0) {
        XSEGLOG2(&lc, W, "Could not delete map data for map %s (epoch: %llu)",
                 old_map.volume, old_map.epoch);
    }


    snap_map->epoch++;

    /* "Steal" attributes from map, to write snapshot */
    snap_map->flags = MF_MAP_READONLY;
    snap_map->size = map->size;
    snap_map->blocksize = map->blocksize;
    snap_map->nr_objs = map->nr_objs;
    snap_map->objects = map->objects;

    snap_map->hex_cas_size = map->hex_cas_size;
    snap_map->hex_cas_array_len = map->hex_cas_array_len;
    snap_map->vol_array_len = map->vol_array_len;
    snap_map->cur_vol_idx = map->cur_vol_idx;
    snap_map->cas_array = map->cas_array;
    snap_map->vol_array = map->vol_array;
    snap_map->cas_names = map->cas_names;
    snap_map->vol_names = map->vol_names;
    snap_map->cas_nr = map->cas_nr;
    snap_map->vol_nr = map->vol_nr;

    snap_map->state |= MF_MAP_LOADED;

    r = write_map(pr, snap_map);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not write snap map");
        r = -EIO;
        goto out;
    }

    r = 0;

out:
    // restore snap_map here, dropping all references to map resources.
    free(was_writable);

    // assert(snap_map->opened_count == mio->count);
    if (snap_map->opened_count == mio->count) {
        initialize_map_fields(snap_map);
        snap_map->state &= ~MF_MAP_LOADED;
        close_map(pr, snap_map);
    }
    snap_map->state &= ~MF_MAP_CREATING;

    return r;
}

static int do_snapshot(struct peer_req *pr, struct map *map)
{
    int r;
    uint64_t i, nr_objs;
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request_snapshot *xsnapshot;
    char *snapname;
    uint32_t snapnamelen;

    xsnapshot = (struct xseg_request_snapshot *)xseg_get_data(peer->xseg, pr->req);
    if (!xsnapshot) {
        return -EINVAL;
    }
    snapname = xsnapshot->target;
    snapnamelen = xsnapshot->targetlen;

    if (!snapnamelen) {
        XSEGLOG2(&lc, E, "Snapshot name must be provided");
        return -EINVAL;
    }

    if (!(map->state & MF_MAP_EXCLUSIVE)) {
        XSEGLOG2(&lc, E, "Map was not opened exclusively");
        return -EACCES;
    }

    if (map->epoch == MAX_EPOCH) {
        XSEGLOG2(&lc, E, "Max epoch reached for %s", map->volume);
        return -1;
    }

    XSEGLOG2(&lc, I, "Starting snapshot for map %s", map->volume);

    map->state |= MF_MAP_SNAPSHOTTING;

    mio->first_map = map;
    r = map_action(write_snapshot, pr, snapname, snapnamelen,
                   MF_CREATE | MF_EXCLUSIVE | MF_SERIALIZE);
    if (r < 0) {
        XSEGLOG2(&lc, W, "Could not create snapshot map %s",
                 null_terminate(snapname, snapnamelen));
    }

out:
    map->state &= ~MF_MAP_SNAPSHOTTING;

    if (map->opened_count == mio->count) {
        close_map(pr, map);
    }

    if (r < 0) {
        XSEGLOG2(&lc, E, "Snapshot for map %s failed", map->volume);
    } else {
        XSEGLOG2(&lc, I, "Snapshot for map %s completed", map->volume);
    }

    return r;
}

/* This should probably me a map function */
static int do_destroy(struct peer_req *pr, struct map *map)
{
    uint64_t i, nr_objs;
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct mapping *mn;
    struct xseg_request *req;
    int r;

    if (!(map->state & MF_MAP_EXCLUSIVE)) {
        return -1;
    }

    if (map->flags & MF_MAP_DELETED) {
        XSEGLOG2(&lc, E, "Map %s already deleted", map->volume);
        do_close(pr, map);
        return -1;
    }

    XSEGLOG2(&lc, I, "Destroying map %s", map->volume);
    map->state |= MF_MAP_DESTROYING;

    mio->cb = object_delete_cb;
    nr_objs = map->nr_objs;
    mio->pending_reqs = 0;
    for (i = 0; i < nr_objs; i++) {
        //throttle generated requests
        if (mio->pending_reqs >= peer->nr_ops) {
            wait_on_pr(pr, mio->pending_reqs >= peer->nr_ops);
        }

        mn = get_mapping(map, i);
        if (!mn) {
            XSEGLOG2(&lc, E, "Could not get map node %llu for map %s",
                     i, map->volume);
            mio->err = 1;
            break;
        }

        if (mn->state & MF_OBJECT_NOT_READY) {
            XSEGLOG2(&lc, E, "BUG: object not ready");
            wait_on_mapping(mn, mn->state & MF_OBJECT_NOT_READY);
        }

        if (mn->flags & MF_OBJECT_ZERO
            || mn->flags & MF_OBJECT_DELETED
            || !(mn->flags & MF_OBJECT_ARCHIP
                 && mn->flags & MF_OBJECT_WRITABLE)) {
            //only remove writable archipelago objects.
            //skip already deleted
            XSEGLOG2(&lc, D, "Skipping object %llu", i);
            continue;
        }
        XSEGLOG2(&lc, D, "%llu flags:\n  Writable: %s\n  Zero: %s\n"
                 "  Deleted: %s\n  Archip: %s", i,
                 (mn->flags & MF_OBJECT_WRITABLE ? "yes" : "no"),
                 (mn->flags & MF_OBJECT_ZERO ? "yes" : "no"),
                 (mn->flags & MF_OBJECT_DELETED ? "yes" : "no"),
                 (mn->flags & MF_OBJECT_ARCHIP ? "yes" : "no"));

        req = object_delete(pr, map, i);
        if (!req) {
            XSEGLOG2(&lc, E, "Error removing object %llu", i);
            mio->err = 1;
        }
        //mapping will be put by delete_object on completion
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    if (mio->err) {
        XSEGLOG2(&lc, E, "Error while removing objects of %s", map->volume);
        map->state &= ~MF_MAP_DESTROYING;
        return -1;
    }

    r = delete_map(pr, map, 1);
    if (r < 0) {
        map->state &= ~MF_MAP_DESTROYING;
        XSEGLOG2(&lc, E, "Failed to destroy map %s", map->volume);
        return -1;
    }
    map->state &= ~MF_MAP_DESTROYING;
    XSEGLOG2(&lc, I, "Destroyed map %s", map->volume);
    /* do close will drop the map from cache  */

    do_close(pr, map);
    /* if do_close fails, an error message will be logged, but the deletion
     * was successfull, and there isn't much to do about the error.
     */
    return 0;
}

//Returns a new opened map
static int rename_map(struct peer_req *pr, struct map *map,
                      char *newname, uint32_t newnamelen, int purge)
{
    uint64_t i;
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct mapping *mn;
    uint64_t nr_objs;
    struct map *new_map;
    struct xseg_request_rename *xrename;
    int r;

    if (!newnamelen) {
        XSEGLOG2(&lc, E, "A new name must be provided");
        return -1;
    }

    if (!(map->state & MF_MAP_EXCLUSIVE)) {
        XSEGLOG2(&lc, E, "Map was not opened exclusively");
        return -1;
    }
    XSEGLOG2(&lc, I, "Starting rename for map %s", map->volume);
    map->state |= MF_MAP_RENAMING;

    //create new map struct with name newname.
    new_map = create_map(newname, newnamelen, MF_ARCHIP);
    if (!new_map) {
        goto out_err;
    }
    //open/load map to check if snap exists
    r = open_map(pr, new_map, 0);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Could not open new map");
        XSEGLOG2(&lc, E, "Rename destination exists");
        goto out_put;
    }
    r = load_map_metadata(pr, new_map);
    if (r >= 0 && !(map->flags & MF_MAP_DELETED)) {
        XSEGLOG2(&lc, E, "Rename destination exists");
        goto out_close;
    }
    if (new_map->epoch == UINT64_MAX) {
        XSEGLOG2(&lc, E, "Max epoch reached for %s", new_map->volume);
        goto out_close;
    }

    /* Populate new map fields */
    new_map->epoch++;
    new_map->objects = map->objects;
    new_map->size = map->size;
    new_map->blocksize = map->blocksize;
    new_map->nr_objs = map->nr_objs;
    new_map->flags = map->flags;

    nr_objs = map->nr_objs;

    //TODO, maybe skip that check and add an epoch number on each object.
    //Then we can check if object is writable iff object epoch == map epoch
    wait_all_map_objects_ready(map);

    //write new map
    r = write_map(pr, new_map);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot write map %s", new_map->volume);
        goto out_unset;
    }
    XSEGLOG2(&lc, I, "New map %s created", new_map->volume);
    new_map->objects = NULL;

    XSEGLOG2(&lc, I, "Will now proceed to remove old map %s", map->volume);

    if (purge) {
        r = purge_map(pr, map);
    } else {
        r = delete_map(pr, map, 1);
    }

    if (r < 0) {
        XSEGLOG2(&lc, W, "Could not remove old prefixed volume %s. "
                 "Continuing anyway.", map->volume);
    }
    //close old map here to leave the lock
    close_map(pr, map);

    change_map_volume(map, newname, newnamelen);
    //set state to exclusive here, since we hold the lock for the new map
    map->state |= MF_MAP_EXCLUSIVE;
    //adjust state of the map to the one of the new_map
    map->state = new_map->state | MF_MAP_RENAMING;
    //Adjust the deleted flag set by delete map
    //map->flags &= ~MF_MAP_DELETED;
    map->flags = new_map->flags;
    //adjust cached epoch
    map->epoch = new_map->epoch;
    //these do not need updating
    //map->objects = new_map->objects;
    //map->size = new_map->size;
    //map->blocksize = new_map->blocksize;
    //map->nr_objs = new_map->nr_objs;
    //This should be the same, on implicit rename, since it must be opened
    //by the same pr.
    //On explicit rename, this might need adjustment
    //map->opened_count = new_map->opened_count;

    put_map(new_map);
    map->state &= ~MF_MAP_RENAMING;
    XSEGLOG2(&lc, I, "Renamed %s completed ", map->volume);
    return 0;

  out_unset:
    new_map->objects = NULL;
  out_close:
    close_map(pr, new_map);
  out_put:
    put_map(new_map);
  out_err:
    map->state &= ~MF_MAP_RENAMING;
    XSEGLOG2(&lc, E, "Rename for map %s failed", map->volume);
    return -1;
}

static int do_rename(struct peer_req *pr, struct map *map)
{
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request_rename *xrename;
    char *newname;
    uint32_t newnamelen;
    int r;

    xrename =
        (struct xseg_request_rename *) xseg_get_data(peer->xseg, pr->req);
    if (!xrename) {
        return -1;
    }
    newname = xrename->target;
    newnamelen = xrename->targetlen;

    if (!newnamelen) {
        XSEGLOG2(&lc, E, "A new name must be provided");
        return -1;
    }

    r = rename_map(pr, map, newname, newnamelen, 0);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Rename for map %s failed", map->volume);
        return -1;
    }

    /* do close will drop the map from cache  */

    /* if do_close fails, an error message will be logged, but the deletion
     * was successfull, and there isn't much to do about the error.
     */
    do_close(pr, map);
    XSEGLOG2(&lc, I, "Renamed %s completed ", map->volume);
    return 0;
}

static void log_map_io(struct peer_req *pr, struct xseg_request *reply)
{
    int i;
    char buf[XSEG_MAX_TARGETLEN + 1];
    struct peerd *peer = pr->peer;
    struct xseg_reply_map *map_reply =
        (struct xseg_reply_map *)xseg_get_data(peer->xseg, reply);

    XSEGLOG2(&lc, D, "Total objects: %u", map_reply->cnt);
    for (i = 0; i < map_reply->cnt; i++) {
        if (map_reply->segs[i].flags & XF_MAPFLAG_ZERO) {
            XSEGLOG2(&lc, D, "%d: Object: (ZERO_OBJECT), offset: %llu, size: %llu",
                     i,
                     (unsigned long long)map_reply->segs[i].offset,
                     (unsigned long long)map_reply->segs[i].size);

        } else {
            strncpy(buf, map_reply->segs[i].target, map_reply->segs[i].targetlen);
            buf[map_reply->segs[i].targetlen] = 0;
            XSEGLOG2(&lc, D, "%d: Object: %s, offset: %llu, size: %llu",
                     i, buf,
                     (unsigned long long)map_reply->segs[i].offset,
                     (unsigned long long)map_reply->segs[i].size);
        }
    }
}

static int do_mapr(struct peer_req *pr, struct map *map)
{
    int r = req2objs(pr, map, 0);
    if (r < 0) {
        XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu failed",
                 map->volume,
                 (unsigned long long)pr->req->offset,
                 (unsigned long long)(pr->req->offset + pr->req->size));
        return r;
    }

    XSEGLOG2(&lc, I, "Map r of map %s, range: %llu-%llu completed",
             map->volume,
             (unsigned long long)pr->req->offset,
             (unsigned long long)(pr->req->offset + pr->req->size));

    if (verbose >= D) {
        log_map_io(pr, pr->req);
    }

    return 0;
}

static int do_mapw(struct peer_req *pr, struct map *map)
{
    int r;

    if (map->flags & MF_MAP_READONLY) {
        XSEGLOG2(&lc, E, "Cannot write to a read only map");
        return -EROFS;
    }

    r = req2objs(pr, map, 1);
    if (r < 0) {
        XSEGLOG2(&lc, I, "Map w of map %s, range: %llu-%llu failed",
                 map->volume,
                 (unsigned long long) pr->req->offset,
                 (unsigned long long) (pr->req->offset + pr->req->size));
        return r;
    }

    XSEGLOG2(&lc, I, "Map w of map %s, range: %llu-%llu completed",
             map->volume,
             (unsigned long long) pr->req->offset,
             (unsigned long long) (pr->req->offset + pr->req->size));

    if (verbose >= D) {
        log_map_io(pr, pr->req);
    }

    return 0;
}

//here map is the parent map
static int do_clone(struct peer_req *pr, struct map *map)
{
    long i, c;
    int r;
    struct peerd *peer = pr->peer;
    //struct mapperd *mapper = __get_mapperd(peer);
    char *target = xseg_get_target(peer->xseg, pr->req);
    struct map *clonemap;
    struct mapping *mappings, *mn;
    struct xseg_request_clone *xclone =
        (struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);

    if (!(map->flags & MF_MAP_READONLY)) {
        XSEGLOG2(&lc, E, "Cloning is supported only from a snapshot");
        return -1;
    }

    XSEGLOG2(&lc, I, "Cloning map %s", map->volume);
    clonemap = create_map(target, pr->req->targetlen, MF_ARCHIP);
    if (!clonemap) {
        XSEGLOG2(&lc, E, "Create map %s failed");
        return -1;
    }

    /* open map to get exclusive access to map */
    r = open_map(pr, clonemap, 0);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot open map %s", clonemap->volume);
        XSEGLOG2(&lc, E, "Target volume %s exists", clonemap->volume);
        goto out_put;
    }
    r = load_map_metadata(pr, clonemap);
    if (r >= 0 && !(clonemap->flags & MF_MAP_DELETED)) {
        XSEGLOG2(&lc, E, "Target volume %s exists", clonemap->volume);
        goto out_close;
    }

    /* Make sure, we can take at least one snapshot of the new volume */
    if (map->epoch >= UINT64_MAX - 2) {
        XSEGLOG2(&lc, E, "Max epoch reached for %s", clonemap->volume);
        goto out_close;
    }
    clonemap->flags = 0;
    clonemap->epoch++;

    if (!(xclone->size)) {
        clonemap->size = map->size;
    } else {
        clonemap->size = xclone->size;
    }
    if (clonemap->size < map->size) {
        XSEGLOG2(&lc, W, "Requested clone size (%llu) < map size (%llu)"
                 "\n\t for requested clone %s",
                 (unsigned long long) clonemap->size,
                 (unsigned long long) map->size, clonemap->volume);
        goto out_close;
    }

    clonemap->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
    //alloc and init mappings
    c = calc_map_obj(clonemap);
    mappings = calloc(c, sizeof(struct mapping));
    if (!mappings) {
        goto out_close;
    }
    clonemap->objects = mappings;
    clonemap->nr_objs = c;
    for (i = 0; i < c; i++) {
        mn = get_mapping(map, i);
        if (mn) {
            strncpy(mappings[i].object, mn->object, mn->objectlen);
            mappings[i].objectlen = mn->objectlen;
            mappings[i].flags = 0;
            if (mn->flags & MF_OBJECT_ARCHIP) {
                mappings[i].flags |= MF_OBJECT_ARCHIP;
            }
            if (mn->flags & MF_OBJECT_ZERO) {
                mappings[i].flags |= MF_OBJECT_ZERO;
            }
            put_mapping(mn);
        } else {
            strncpy(mappings[i].object, zero_block, ZERO_BLOCK_LEN);
            mappings[i].objectlen = ZERO_BLOCK_LEN;
            mappings[i].flags = MF_OBJECT_ZERO;
        }
        mappings[i].object[mappings[i].objectlen] = '\0';     //NULL terminate
        mappings[i].state = 0;
        mappings[i].objectidx = i;
        mappings[i].map = clonemap;
        mappings[i].ref = 1;
        mappings[i].waiters = 0;
        mappings[i].cond = st_cond_new();      //FIXME errcheck;
    }

    r = write_map(pr, clonemap);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot write map %s", clonemap->volume);
        goto out_close;
    }

    XSEGLOG2(&lc, I, "Cloning map %s to %s completed",
             map->volume, clonemap->volume);
    close_map(pr, clonemap);
    put_map(clonemap);
    return 0;

  out_close:
    close_map(pr, clonemap);
  out_put:
    put_map(clonemap);
    return -1;
}

static int truncate_map(struct peer_req *pr, struct map *map, uint64_t offset)
{
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct mapping *mn;
    uint64_t nr_objs, old_nr_objs;
    int r;

    if (!(map->state & MF_MAP_EXCLUSIVE)) {
        XSEGLOG2(&lc, E, "Map was not opened exclusively");
        return -1;
    }
    XSEGLOG2(&lc, I, "Starting truncation for map %s", map->volume);
    map->state |= MF_MAP_TRUNCATING;

    wait_all_map_objects_ready(map);

    old_nr_objs = map->nr_objs;
    nr_objs = __calc_map_obj(offset, map->blocksize);

    /* If new volume size is larger than the old one
     * extend mapfile with zero blocks.
     */
    if (nr_objs > old_nr_objs) {
        struct mapping *mappings = calloc(nr_objs, sizeof(struct mapping));
        if (!mappings) {
            XSEGLOG2(&lc, E, "Cannot allocate %llu nr_objs", nr_objs);
            goto out_unset;
        }
        uint64_t i;
        for (i = 0; i < old_nr_objs; i++) {
            mn = get_mapping(map, i);
            if (mn) {
                strncpy(mappings[i].object, mn->object, mn->objectlen);
                mappings[i].objectlen = mn->objectlen;
                mappings[i].flags = 0;
                if (mn->flags & MF_OBJECT_ARCHIP) {
                    mappings[i].flags |= MF_OBJECT_ARCHIP;
                }
                if (mn->flags & MF_OBJECT_ZERO) {
                    mappings[i].flags |= MF_OBJECT_ZERO;
                }
                put_mapping(mn);
            } else {
                strncpy(mappings[i].object, zero_block, ZERO_BLOCK_LEN);
                mappings[i].objectlen = ZERO_BLOCK_LEN;
                mappings[i].flags = MF_OBJECT_ZERO;
            }
            mappings[i].object[mappings[i].objectlen] = 0;
            mappings[i].state = 0;
            mappings[i].objectidx = i;
            mappings[i].map = map;
            mappings[i].ref = 1;
            mappings[i].waiters = 0;
            mappings[i].cond = st_cond_new();
        }

        for (i = old_nr_objs; i < nr_objs; i++) {
            strncpy(mappings[i].object, zero_block, ZERO_BLOCK_LEN);
            mappings[i].objectlen = ZERO_BLOCK_LEN;
            mappings[i].flags = MF_OBJECT_ZERO;
            mappings[i].object[mappings[i].objectlen] = 0;
            mappings[i].state = 0;
            mappings[i].objectidx = i;
            mappings[i].map = map;
            mappings[i].ref = 1;
            mappings[i].waiters = 0;
            mappings[i].cond = st_cond_new();
        }
        free(map->objects);
        map->objects = mappings;
    }
    map->size = offset;
    map->nr_objs = nr_objs;

    r = write_map(pr, map);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
        goto out_unset;
    }
    XSEGLOG2(&lc, I, "Map %s truncated", map->volume);

    map->state &= ~MF_MAP_TRUNCATING;
    XSEGLOG2(&lc, I, "Truncation of %s completed ", map->volume);
    return 0;

  out_unset:
    map->state &= ~MF_MAP_TRUNCATING;
    XSEGLOG2(&lc, E, "Truncation for map %s failed ", map->volume);
    return -1;
}


static int do_truncate(struct peer_req *pr, struct map *map)
{
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req = pr->req;
    uint64_t offset = req->offset;
    int r;

    r = truncate_map(pr, map, offset);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Truncation for map %s failed", map->volume);
        return -1;
    }
    do_close(pr, map);
    XSEGLOG2(&lc, I, "Truncation for map %s completed ", map->volume);
    return 0;
}


static int open_load_map(struct peer_req *pr, struct map *map, uint32_t flags)
{
    int r, opened = 0;
    if (flags & MF_EXCLUSIVE) {
        r = open_map(pr, map, flags);
        if (r < 0) {
            if (flags & MF_FORCE) {
                return -1;
            }
        } else {
            opened = 1;
        }
    }
    r = load_map(pr, map);
    if (r < 0 && opened) {
        close_map(pr, map);
    }
    return r;
}

struct map *get_map(struct peer_req *pr, char *name, uint32_t namelen,
                    uint32_t flags)
{
    int r, archip_map = 0;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct map *map = cache_lookup_len(mapper, name, namelen, flags);
    if (!map) {
        if (flags & MF_LOAD) {
            map = create_map(name, namelen, flags);
            if (!map) {
                return NULL;
            }
            r = insert_cache(mapper, map);
            if (r < 0) {
                XSEGLOG2(&lc, E, "Cannot insert map %s", map->volume);
                put_map(map);
                return NULL;
            }
            __get_map(map);
          retry:
            r = open_load_map(pr, map, flags);
            if (r < 0) {
                dropcache(pr, map);
                /* signal map here, so any other threads that
                 * tried to get the map, but couldn't because
                 * of the opening or loading operation that
                 * failed, can continue.
                 */
                signal_map(map);
                put_map(map);
                return NULL;
            }

            /* If the map is deleted, drop everything and return
             * NULL.
             */
            if (map->flags & MF_MAP_DELETED) {
                XSEGLOG2(&lc, E, "Loaded deleted map %s. Failing...",
                         map->volume);
                do_close(pr, map);
                dropcache(pr, map);
                signal_map(map);
                put_map(map);
                return NULL;
            }

            return map;
        } else if (flags & MF_CREATE) {
            map = create_map(name, namelen, flags);
            if (!map) {
                return NULL;
            }
            r = insert_cache(mapper, map);
            if (r < 0) {
                XSEGLOG2(&lc, E, "Cannot insert map %s", map->volume);
                put_map(map);
                return NULL;
            }
            __get_map(map);

            if (!(flags & MF_EXCLUSIVE)) {
                return map;
            }

            r = open_map(pr, map, flags);
            if (r < 0) {
                if (flags & MF_FORCE) {
                    dropcache(pr, map);
                    signal_map(map);
                    put_map(map);
                    return NULL;
                }
            }

            return map;
        } else {
            return NULL;
        }
    } else {
        __get_map(map);
    }
    return map;

}

static struct map *get_ready_map(struct peer_req *pr, char *name,
                                 uint32_t namelen, uint32_t flags)
{
    struct map *map;

    map = get_map(pr, name, namelen, flags);
    while (map && map->state & MF_MAP_NOT_READY) {
        wait_on_map(map, (map->state & MF_MAP_NOT_READY));
        put_map(map);
        map = get_map(pr, name, namelen, flags);
    }

    if (map == NULL) {
        return map;
    }

    if (flags & MF_SERIALIZE) {
        map->state |= MF_MAP_SERIALIZING;
        if (map->pending_io) {
            wait_all_pending_io(map);
        }
        map->state &= ~MF_MAP_SERIALIZING;
    }

    return map;
}

static int map_action(int (action) (struct peer_req * pr, struct map * map),
                      struct peer_req *pr, char *name, uint32_t namelen,
                      uint32_t flags)
{
    int r;
    struct map *map;

    map = get_ready_map(pr, name, namelen, flags);
    if (!map) {
        return -ENOENT;
    }
    map->pending_io++;
    r = action(pr, map);
    //always drop cache if map not read exclusively
    if (!(map->state & MF_MAP_EXCLUSIVE)) {
        dropcache(pr, map);
    }
    map->pending_io--;
    if (!map->pending_io) {
        signal_all_pending_io_ready(map);
    }
    signal_map(map);
    put_map(map);
    return r;
}

void *handle_info(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    int r = map_action(do_info, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_clone(struct peer_req *pr)
{
    int r;
    struct peerd *peer = pr->peer;
    //struct mapperd *mapper = __get_mapperd(peer);
    struct xseg_request_clone *xclone;
    xclone = (struct xseg_request_clone *) xseg_get_data(peer->xseg, pr->req);
    if (!xclone) {
        r = -1;
        goto out;
    }

    if (xclone->targetlen) {
        r = map_action(do_clone, pr, xclone->target,
                       xclone->targetlen, MF_LOAD | MF_ARCHIP);
    } else {
        /* else try to create a new volume */
        XSEGLOG2(&lc, I, "Creating volume");
        if (!xclone->size) {
            XSEGLOG2(&lc, E, "Cannot create volume. Size not specified");
            r = -1;
            goto out;
        }
        struct map *map;
        char *target = xseg_get_target(peer->xseg, pr->req);

        //create a new empty map of size
        map = create_map(target, pr->req->targetlen, MF_ARCHIP);
        if (!map) {
            r = -1;
            goto out;
        }
        /* open map to get exclusive access to map */
        r = open_map(pr, map, 0);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot open map %s", map->volume);
            XSEGLOG2(&lc, E, "Target volume %s exists", map->volume);
            put_map(map);
            r = -1;
            goto out;
        }
        r = load_map_metadata(pr, map);
        if (r >= 0 && !(map->flags & MF_MAP_DELETED)) {
            XSEGLOG2(&lc, E, "Map exists %s", map->volume);
            close_map(pr, map);
            put_map(map);
            r = -1;
            goto out;
        }
        if (map->epoch >= UINT64_MAX - 2) {
            XSEGLOG2(&lc, E, "Max epoch reached for %s", map->volume);
            close_map(pr, map);
            put_map(map);
            r = -1;
            goto out;
        }
        map->epoch++;
        map->flags = 0;
        map->size = xclone->size;
        map->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
        map->nr_objs = 0;
        map->objects = NULL;

        //populate_map with zero objects;
        uint64_t nr_objs = calc_map_obj(map);
        struct mapping *mappings = calloc(nr_objs, sizeof(struct mapping));
        if (!mappings) {
            XSEGLOG2(&lc, E, "Cannot allocate %llu nr_objs", nr_objs);
            close_map(pr, map);
            put_map(map);
            r = -1;
            goto out;
        }
        map->objects = mappings;
        map->nr_objs = nr_objs;

        uint64_t i;
        for (i = 0; i < nr_objs; i++) {
            strncpy(mappings[i].object, zero_block, ZERO_BLOCK_LEN);
            mappings[i].objectlen = ZERO_BLOCK_LEN;
            mappings[i].object[mappings[i].objectlen] = 0;    //NULL terminate
            mappings[i].flags = MF_OBJECT_ZERO;        //MF_OBJECT_ARCHIP;
            mappings[i].state = 0;
            mappings[i].objectidx = i;
            mappings[i].map = map;
            mappings[i].ref = 1;
            mappings[i].waiters = 0;
            mappings[i].cond = st_cond_new();  //FIXME errcheck;
        }
        r = write_map(pr, map);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
            close_map(pr, map);
            put_map(map);
            goto out;
        }
        XSEGLOG2(&lc, I, "Volume %s created", map->volume);
        r = 0;
        close_map(pr, map);
        put_map(map);
    }
  out:
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_create(struct peer_req *pr)
{
    int r;
    struct peerd *peer = pr->peer;
    struct xseg_request *req = pr->req;
    //struct mapperd *mapper = __get_mapperd(peer);
    XSEGLOG2(&lc, I, "Creating volume");
    if (!req->size) {
        XSEGLOG2(&lc, E, "Cannot create volume. Size not specified");
        r = -1;
        goto out;
    }
    struct map *map;
    char *target = xseg_get_target(peer->xseg, pr->req);

    //create a new empty map of size
    //ARCHIP or PITHOS
    map = create_map(target, pr->req->targetlen, MF_ARCHIP);
    if (!map) {
        r = -1;
        goto out;
    }
    /* open map to get exclusive access to map */
    r = open_map(pr, map, 0);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot open map %s", map->volume);
        XSEGLOG2(&lc, E, "Target volume %s exists", map->volume);
        put_map(map);
        r = -1;
        goto out;
    }
    r = load_map_metadata(pr, map);
    if (r >= 0 && !(map->flags & MF_MAP_DELETED)) {
        XSEGLOG2(&lc, E, "Map exists %s", map->volume);
        close_map(pr, map);
        put_map(map);
        r = -1;
        goto out;
    }
    if (map->epoch >= UINT64_MAX - 2) {
        XSEGLOG2(&lc, E, "Max epoch reached for %s", map->volume);
        close_map(pr, map);
        put_map(map);
        r = -1;
        goto out;
    }


    uint64_t nr_objs;
    struct xseg_request_create *mapdata;
    mapdata =
        (struct xseg_request_create *) xseg_get_data(peer->xseg, pr->req);

    map->epoch++;
    map->flags = 0;
    if (mapdata->create_flags & XF_MAPFLAG_READONLY) {
        map->flags |= MF_MAP_READONLY;
    } else {
        map->flags &= ~MF_MAP_READONLY;
    }
    map->size = req->size;
    if (!mapdata->blocksize) {
        map->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
    } else if (!is_valid_blocksize(mapdata->blocksize)) {
        close_map(pr, map);
        put_map(map);
        r = -1;
        goto out;
    } else {
        map->blocksize = mapdata->blocksize;
    }
    map->nr_objs = 0;
    map->objects = NULL;


    nr_objs = calc_map_obj(map);
    if (nr_objs != mapdata->cnt) {
        XSEGLOG2(&lc, E, "Map size does not match supplied objects");
        close_map(pr, map);
        put_map(map);
        r = -1;
        goto out;
    }

    struct mapping *mappings = calloc(nr_objs, sizeof(struct mapping));
    if (!mappings) {
        XSEGLOG2(&lc, E, "Cannot allocate %llu nr_objs", nr_objs);
        close_map(pr, map);
        put_map(map);
        r = -1;
        goto out;
    }
    map->objects = mappings;
    map->nr_objs = nr_objs;

    uint64_t i;
    for (i = 0; i < nr_objs; i++) {
        mappings[i].objectlen = mapdata->segs[i].targetlen;
        strncpy(mappings[i].object, mapdata->segs[i].target,
                mapdata->segs[i].targetlen);
        mappings[i].object[mapdata->segs[i].targetlen] = 0;
        XSEGLOG2(&lc, D, "%d: %s (%u)", i, mappings[i].object,
                 mapdata->segs[i].targetlen);
        mappings[i].state = 0;
        mappings[i].flags = 0;
        if (!(mapdata->segs[i].flags & XF_MAPFLAG_READONLY)) {
            mappings[i].flags |= MF_OBJECT_WRITABLE;
        }
        if (!strncmp(mappings[i].object, zero_block, ZERO_BLOCK_LEN)) {
            mappings[i].flags |= MF_OBJECT_ZERO;
            //assert READONLY
            if (mappings[i].flags & MF_OBJECT_WRITABLE) {
                XSEGLOG2(&lc, W, "Zero objects must always be READONLY");
                mappings[i].flags &= ~MF_OBJECT_WRITABLE;
            }
        }
        mappings[i].objectidx = i;
        mappings[i].map = map;
        mappings[i].ref = 1;
        mappings[i].waiters = 0;
        mappings[i].cond = st_cond_new();      //FIXME errcheck;
    }


    r = write_map(pr, map);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot write map %s", map->volume);
        close_map(pr, map);
        put_map(map);
        goto out;
    }
    XSEGLOG2(&lc, I, "Volume %s created", map->volume);
    r = 0;
    close_map(pr, map);
    put_map(map);
  out:
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_mapr(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    int r = map_action(do_mapr, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_mapw(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    int r = map_action(do_mapw, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE | MF_FORCE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    XSEGLOG2(&lc, D, "Ta: %d", ta);
    ta--;
    return NULL;
}

void *handle_destroy(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    /* request EXCLUSIVE access, but do not force it.
     * check if succeeded on do_destroy
     */
    int r = map_action(do_destroy, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_open(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    int r = map_action(do_open, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_close(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    //here we do not want to load
    int r = map_action(do_close, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_EXCLUSIVE | MF_FORCE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_snapshot(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    /* request EXCLUSIVE access, but do not force it.
     * check if succeeded on do_snapshot
     */
    int r = map_action(do_snapshot, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_rename(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    /* request EXCLUSIVE access, but do not force it.
     * check if succeeded on do_snapshot
     */
    int r = map_action(do_rename, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_hash(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    /* Do not request exclusive access. Since we are hashing only shapshots
     * which are read only, there is no need for locking
     */
    int r = map_action(do_hash, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_truncate(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    int r = map_action(do_truncate, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}

void *handle_update(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    char *target = xseg_get_target(peer->xseg, pr->req);
    int r = map_action(do_update, pr, target, pr->req->targetlen,
                       MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE);
    if (r < 0) {
        fail(peer, pr);
    } else {
        complete(peer, pr);
    }
    ta--;
    return NULL;
}


int dispatch_accepted(struct peerd *peer, struct peer_req *pr,
                      struct xseg_request *req)
{
    //struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    void *(*action) (struct peer_req *) = NULL;

    //mio->state = ACCEPTED;
    mio->err = 0;
    mio->cb = NULL;
    accepted_req_count++;
    mio->count = accepted_req_count;
    switch (pr->req->op) {
        /* primary xseg operations of mapper */
    case X_CLONE:
        action = handle_clone;
        break;
    case X_MAPR:
        action = handle_mapr;
        break;
    case X_MAPW:
        action = handle_mapw;
        break;
    case X_SNAPSHOT:
        action = handle_snapshot;
        break;
    case X_INFO:
        action = handle_info;
        break;
    case X_DELETE:
        action = handle_destroy;
        break;
    case X_OPEN:
        action = handle_open;
        break;
    case X_CLOSE:
        action = handle_close;
        break;
    case X_HASH:
        action = handle_hash;
        break;
    case X_CREATE:
        action = handle_create;
        break;
    case X_RENAME:
        action = handle_rename;
        break;
    case X_TRUNCATE:
        action = handle_truncate;
        break;
    case X_UPDATE:
        action = handle_update;
        break;
    default:
        fprintf(stderr, "mydispatch: unknown op\n");
        break;
    }
    if (action) {
        ta++;
        mio->active = 1;
        st_thread_create(action, pr, 0, 0);
    }
    return 0;

}

struct cb_arg {
    struct peer_req *pr;
    struct xseg_request *req;
};

void *callback_caller(struct cb_arg *arg)
{
    struct peer_req *pr = arg->pr;
    struct xseg_request *req = arg->req;
    struct mapper_io *mio = __get_mapper_io(pr);

    mio->cb(pr, req);
    free(arg);
    ta--;
    return NULL;
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
             enum dispatch_reason reason)
{
    struct mapper_io *mio = __get_mapper_io(pr);
    struct cb_arg *arg;

    if (reason == dispatch_accept)
        dispatch_accepted(peer, pr, req);
    else {
        if (mio->cb) {
//                      mio->cb(pr, req);
            arg = calloc(1, sizeof(struct cb_arg));
            if (!arg) {
                XSEGLOG2(&lc, E, "Cannot allocate cb_arg");
                return -1;
            }
            arg->pr = pr;
            arg->req = req;
            ta++;
            //      mio->active = 1;
            st_thread_create(callback_caller, arg, 0, 0);
        } else {
            signal_pr(pr);
        }
    }
    return 0;
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
    int i;

    //FIXME error checks
    struct mapperd *mapper = calloc(1, sizeof(struct mapperd));
    peer->priv = mapper;
    //mapper = mapperd;
    mapper->hashmaps = xhash_new(3, 0, XHASH_STRING);

    for (i = 0; i < peer->nr_ops; i++) {
        struct mapper_io *mio = calloc(1, sizeof(struct mapper_io));
        mio->req_ctxs = g_hash_table_new(g_direct_hash, g_direct_equal);
        mio->pending_reqs = 0;
        mio->err = 0;
        mio->active = 0;
        peer->peer_reqs[i].priv = mio;
    }

    mapper->bportno = -1;
    mapper->mbportno = -1;
    BEGIN_READ_ARGS(argc, argv);
    READ_ARG_ULONG("-bp", mapper->bportno);
    READ_ARG_ULONG("-mbp", mapper->mbportno);
    END_READ_ARGS();
    if (mapper->bportno == -1) {
        XSEGLOG2(&lc, E, "Portno for blocker must be provided");
        usage(argv[0]);
        return -1;
    }
    if (mapper->mbportno == -1) {
        XSEGLOG2(&lc, E, "Portno for mblocker must be provided");
        usage(argv[0]);
        return -1;
    }

    const struct sched_param param = {.sched_priority = 99 };
    sched_setscheduler(syscall(SYS_gettid), SCHED_FIFO, &param);
    /* FIXME maybe place it in peer
     * should be done for each port (sportno to eportno)
     */
    xseg_set_max_requests(peer->xseg, peer->portno_start, 5000);
    xseg_set_freequeue_size(peer->xseg, peer->portno_start, 3000, 0);

    req_cond = st_cond_new();

//      test_map(peer);

    return 0;
}

/* FIXME this should not be here */
int wait_reply(struct peerd *peer, struct xseg_request *expected_req)
{
    struct xseg *xseg = peer->xseg;
    xport portno_start = peer->portno_start;
    xport portno_end = peer->portno_end;
    struct peer_req *pr;
    xport i;
    int r, c = 0;
    struct xseg_request *received;
    xseg_prepare_wait(xseg, portno_start);
    while (1) {
        XSEGLOG2(&lc, D, "Attempting to check for reply");
        c = 1;
        while (c) {
            c = 0;
            for (i = portno_start; i <= portno_end; i++) {
                received = xseg_receive(xseg, i, 0);
                if (received) {
                    c = 1;
                    r = xseg_get_req_data(xseg, received, (void **) &pr);
                    if (r < 0 || !pr || received != expected_req) {
                        XSEGLOG2(&lc, W, "Received request with no pr data\n");
                        xport p =
                            xseg_respond(peer->xseg, received,
                                         peer->portno_start, X_ALLOC);
                        if (p == NoPort) {
                            XSEGLOG2(&lc, W,
                                     "Could not respond stale request");
                            xseg_put_request(xseg, received, portno_start);
                            continue;
                        } else {
                            xseg_signal(xseg, p);
                        }
                    } else {
                        xseg_cancel_wait(xseg, portno_start);
                        return 0;
                    }
                }
            }
        }
        xseg_wait_signal(xseg, peer->sd, 1000000UL);
    }
}


void custom_peer_finalize(struct peerd *peer)
{
    struct mapperd *mapper = __get_mapperd(peer);
    struct peer_req *pr = alloc_peer_req(peer);
    if (!pr) {
        XSEGLOG2(&lc, E, "Cannot get peer request");
        return;
    }
    struct map *map;
    struct xseg_request *req;
    xhash_iter_t it;
    xhashidx key, val;
    xhash_iter_init(mapper->hashmaps, &it);
    while (xhash_iterate(mapper->hashmaps, &it, &key, &val)) {
        map = (struct map *) val;
        if (!(map->state & MF_MAP_EXCLUSIVE)) {
            continue;
        }
        req = __close_map(pr, map);
        if (!req) {
            continue;
        }
        wait_reply(peer, req);
        if (!(req->state & XS_SERVED)) {
            XSEGLOG2(&lc, E, "Couldn't close map %s", map->volume);
        }
        map->state &= ~MF_MAP_CLOSING;
        put_request(pr, req);
    }
    return;


}

/*
void print_obj(struct mapping *mn)
{
	fprintf(stderr, "[%llu]object name: %s[%u] exists: %c\n",
			(unsigned long long) mn->objectidx, mn->object,
			(unsigned int) mn->objectlen,
			(mn->flags & MF_OBJECT_WRITABLE) ? 'y' : 'n');
}

void print_map(struct map *m)
{
	uint64_t nr_objs = m->size/MAPPER_DEFAULT_BLOCKSIZE;
	if (m->size % MAPPER_DEFAULT_BLOCKSIZE)
		nr_objs++;
	fprintf(stderr, "Volume name: %s[%u], size: %llu, nr_objs: %llu, version: %u\n",
			m->volume, m->volumelen,
			(unsigned long long) m->size,
			(unsigned long long) nr_objs,
			m->version);
	uint64_t i;
	struct mapping *mn;
	if (nr_objs > 1000000) //FIXME to protect against invalid volume size
		return;
	for (i = 0; i < nr_objs; i++) {
		mn = find_object(m, i);
		if (!mn){
			printf("object idx [%llu] not found!\n", (unsigned long long) i);
			continue;
		}
		print_obj(mn);
	}
}
*/
