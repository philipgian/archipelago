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

#include <stdlib.h>
#include <asm/byteorder.h>
#include <xseg/xseg.h>
#include <glib.h>

#include "mapper.h"
#include "mapper-helpers.h"
#include "mapper-version2.h"


/* Must be a power of 2, as the blocksize */
#define v2_chunksize (512*1024)

enum name_type {
    NAME_TYPE_ZERO, NAME_TYPE_CAS, NAME_TYPE_ARCHIP
};

/* v2 functions */

static uint32_t get_map_block_name(char *target, struct map *map,
                                   uint64_t block_id)
{
    uint32_t targetlen;
    uint64_t be_block_id = __cpu_to_be64(block_id);
    char buf[sizeof(be_block_id) * 2 + 1];

    hexlify((unsigned char *) &be_block_id, sizeof(be_block_id), buf);
    buf[2 * sizeof(block_id)] = 0;
    sprintf(target, "%s_%s", map->volume, buf);
    targetlen = map->volumelen + 1 + (sizeof(be_block_id) * 2);

    return targetlen;
}

static uint32_t get_chunk_size(struct map *map)
{
    return (map->blocksize < v2_chunksize) ? map->blocksize : v2_chunksize;
}

static int get_block_id(struct map *map, uint64_t idx)
{
    return (idx * v2_objectsize_in_map) / map->blocksize;
}

static uint64_t get_offset_in_block(struct map *map, uint64_t idx)
{
    uint64_t objects_in_block = map->blocksize / v2_objectsize_in_map;
    return ((idx % objects_in_block) * v2_objectsize_in_map) % map->blocksize;
}

static uint32_t get_offset_in_chunk(struct map *map, uint64_t offset)
{
    uint32_t chunksize = get_chunk_size(map);
    /* since blocksize and chunksize are both power of two, the following is
     * equivalent to:
     * offset_in_block = offset % map->blocksize;
     * offset_in_chunk = offset % chunksize;
     */
    return offset % chunksize;
}

struct chunk {
    char target[XSEG_MAX_TARGETLEN + 1];
    uint32_t targetlen;
    uint64_t start;
    uint64_t nr;
};


static int split_to_chunks(struct map *map, uint64_t start, uint64_t nr,
                           struct chunk **chunks)
{
    uint32_t i;
    int nr_chunks;
    uint64_t processed;
    struct chunk *chunk;
    int blockid;
    uint64_t offset_in_block, objects_in_block, objects_in_chunk, obj;
    uint32_t chunksize = get_chunk_size(map);

    if (!nr) {
        *chunks = 0;
        return 0;
    }


    objects_in_block = map->blocksize / v2_objectsize_in_map;
    objects_in_chunk = chunksize / v2_objectsize_in_map;

    nr_chunks = 0;
    obj = start;
    do {
        nr_chunks++;
        offset_in_block = obj % objects_in_block;
        if (offset_in_block + objects_in_chunk < objects_in_block) {
            obj += objects_in_chunk;
        } else {
            obj += objects_in_block - offset_in_block;
        }
    } while (obj < nr);

    chunk = calloc(nr_chunks, sizeof(struct chunk));
    *chunks = chunk;
    if (!chunk) {
        return -ENOMEM;
    }


    i = 0;
    obj = start;
    do {
        blockid = get_block_id(map, obj);
        chunk[i].targetlen = get_map_block_name(chunk[i].target, map, blockid);
        chunk[i].start = obj;
        offset_in_block = obj % objects_in_block;
        if (nr > objects_in_chunk) {
            if (offset_in_block + objects_in_chunk > objects_in_block) {
                chunk[i].nr = objects_in_block - offset_in_block;
            } else {
                chunk[i].nr = objects_in_chunk;
            }
        } else {
            if (offset_in_block + nr > objects_in_block) {
                chunk[i].nr = objects_in_block - offset_in_block;
            } else {
                chunk[i].nr = nr;
            }
        }
        obj += chunk[i].nr;
        nr -= chunk[i].nr;
        i++;
    } while (nr > 0);


    return nr_chunks;
}

static int read_archip_object_v2(struct map *map, struct mapping *m,
                                 struct v2_object_on_disk *o)
{
    int underscores, i;
    uint32_t vol_name_len;
    uint64_t be_epoch, epoch;
    char * hexlified_epoch, *cas_name, *vol_name;
    char object_name[v2_max_objectlen + 1];

    memcpy(object_name, o->object, o->objectlen);
    object_name[o->objectlen] = '\0';

    m->flags = 0;

    m->flags |= MF_OBJECT_ARCHIP;
    m->flags |= o->flags & MF_OBJECT_WRITABLE;

    // extract volume name from object name
    // object name is in the form of: volname_hexepoch_hexidx
    underscores = 0;
    for (i = o->objectlen - 1; i >= 0; i--) {
        if (object_name[i] != '_') {
            continue;
        }
        underscores++;
        if (underscores == 2) {
            break;
        }
    }

    if (underscores != 2) {
        if (strncmp(object_name, MAPPER_PREFIX, MAPPER_PREFIX_LEN) ||
             o->objectlen != MAPPER_PREFIX_LEN + HEXLIFIED_SHA256_DIGEST_SIZE) {
            flogger_error(logger, "Could not extract volume name from object %s",
                          object_name);
            return -EINVAL;
        }

        // old v1 name
        cas_name = object_name + MAPPER_PREFIX_LEN;

        for (i = 0; i < map->cas_nr; i++) {
            if (!memcmp(map->cas_array + i * HEXLIFIED_SHA256_DIGEST_SIZE,
                        cas_name, HEXLIFIED_SHA256_DIGEST_SIZE)) {
                break;
            }
        }

        // assert(i<map->cas_nr);
        if (i >= map->cas_nr) {
            return -EINVAL;
        }

        m->flags |= MF_OBJECT_V1;
        m->vol_epoch = 0;
        // m->vol_epoch = V3_OBJECT_V1_EPOCH;
        m->name_idx = i;
    } else {
        object_name[i] = '\0';
        vol_name = object_name;
        vol_name_len = i;
        hexlified_epoch = object_name + vol_name_len + 1;
        hexlified_epoch[HEXLIFIED_EPOCH_LEN] = '\0';
        epoch = strtoull(hexlified_epoch, NULL, 16);

        // assert(epoch < MAX_EPOCH);
        if (epoch >= MAX_EPOCH) {
            flogger_error(logger, "Detected invalid object epoch %llu", epoch);
            return -EINVAL;
        }

        for (i = 0; i < map->vol_nr; i++) {
            if (map->vol_names[i].len == vol_name_len &&
                    !memcmp(map->vol_names[i].name, vol_name, vol_name_len)) {
                break;
            }
        }

        // assert(i<map->vol_nr);
        if (i >= map->vol_nr) {
            return -EINVAL;
        }

        m->vol_epoch = epoch;
        m->name_idx = i;
    }

    return 0;
}

static int read_cas_object_v2(struct map *map, struct mapping *m,
                              struct v2_object_on_disk *o)
{
    int exists;
    uint32_t i;
    char *cas_name;

    m->flags = 0;

    if (o->objectlen != HEXLIFIED_SHA256_DIGEST_SIZE) {
        flogger_error(logger, "Invalid object len %u for CA object",
                      o->objectlen);
        return -EINVAL;
    }

    cas_name = o->object;

    for (i = 0; i < map->cas_nr; i++) {
        if (!memcmp(map->cas_array + i * HEXLIFIED_SHA256_DIGEST_SIZE,
                    cas_name, HEXLIFIED_SHA256_DIGEST_SIZE)) {
            break;
        }
    }
    // assert(i<map->cas_nr);
    if (i >= map->cas_nr) {
        return -EINVAL;
    }

    m->name_idx = i;
    m->vol_epoch = 0;

    return 0;
}

static int read_object_v2(struct map *map, struct mapping *m, unsigned char *buf)
{
    int r;
    struct v2_object_on_disk *object;

    object = (struct v2_object_on_disk *)buf;

    if (object->objectlen > v2_max_objectlen) {
        flogger_error(logger, "Invalid object len %u", object->objectlen);
        return -EINVAL;
    }

    m->flags = 0;
    if (object->flags & MF_OBJECT_ZERO) {
        m->flags = MF_OBJECT_ZERO;
        return;
    }


    if (object->flags & MF_OBJECT_ARCHIP) {
        r = read_archip_object_v2(map, m, object);
    } else {
        r = read_cas_object_v2(map, m, object);
    }

    return 0;
}

static int extract_archip_name_v2(struct v2_object_on_disk *o,
                                  enum name_type *type, char **name)
{
    int underscores, i;
    char object_name[v2_max_objectlen + 1];

    memcpy(object_name, o->object, o->objectlen);
    object_name[o->objectlen] = '\0';

    // extract volume name from object name
    // object name is in the form of: volname_hexepoch_hexidx
    underscores = 0;
    for (i = o->objectlen - 1; i >= 0; i--) {
        if (object_name[i] != '_') {
            continue;
        }
        underscores++;
        if (underscores == 2) {
            break;
        }
    }

    if (underscores != 2) {
        if (strncmp(object_name, MAPPER_PREFIX, MAPPER_PREFIX_LEN) ||
             o->objectlen != MAPPER_PREFIX_LEN + HEXLIFIED_SHA256_DIGEST_SIZE) {
            flogger_error(logger, "Could not extract volume name from object %s",
                          object_name);
            return -EINVAL;
        }
        // old v1 name
        *type = NAME_TYPE_CAS;
        *name = strndup(object_name + MAPPER_PREFIX_LEN, HEXLIFIED_SHA256_DIGEST_SIZE);
    } else {
        *type = NAME_TYPE_ARCHIP;
        *name = strndup(object_name, i);
    }

    if (!*name) {
        return -ENOMEM;
    }

    return 0;
}

static int extract_cas_name_v2(struct v2_object_on_disk *o,
                               enum name_type *type, char **name)
{
    uint32_t i;
    char *cas_name;

    if (o->objectlen != HEXLIFIED_SHA256_DIGEST_SIZE) {
        flogger_error(logger, "Invalid object len %u for CA object",
                      o->objectlen);
        return -EINVAL;
    }

    *name = strndup(o->object, HEXLIFIED_SHA256_DIGEST_SIZE);
    if (!*name) {
        return -ENOMEM;
    }
    *type = NAME_TYPE_CAS;

    return 0;
}

static int extract_name_from_object(struct v2_object_on_disk *o,
                                    enum name_type *type, char **name)
{
    int r;

    *name = NULL;

    if (o->objectlen > v2_max_objectlen) {
        flogger_error(logger, "Invalid object len %u", o->objectlen);
        return -EINVAL;
    }

    if (o->flags & MF_OBJECT_ZERO) {
        *type = NAME_TYPE_ZERO;
        return 0;
    }

    if (o->flags & MF_OBJECT_ARCHIP) {
        r = extract_archip_name_v2(o, type, name);
    } else {
        r = extract_cas_name_v2(o, type, name);
    }

    return r;
}

static int extract_names(struct map *map, unsigned char *buf,
                         GHashTable *cas_names, GHashTable *vol_names)
{
    int r;
    uint64_t i, pos = 0;
    char *name;
    enum name_type type;
    GHashTable *ht;

    for (i = 0; i < map->nr_objs; i++) {
        r = extract_name_from_object((struct v2_object_on_disk *)(buf + pos),
                                     &type, &name);
        if (r < 0) {
            return r;
        }

        pos += v2_objectsize_in_map;

        if (type == NAME_TYPE_ZERO) {
            continue;
        }

        if (!name) {
            return -EINVAL;
        }

        if (type == NAME_TYPE_CAS) {
            g_hash_table_add(cas_names, name);
        } else if (type == NAME_TYPE_ARCHIP) {
            g_hash_table_add(vol_names, name);
        } else {
            // asssert(0);
            return -EINVAL;
        }
    }

    return 0;
}

/* Fill a buffer representing an object on disk from a given map node */
static void object_to_map_v2(unsigned char *buf, struct mapping *mn)
{
}

static struct xseg_request *prepare_write_chunk(struct peer_req *pr,
                                                struct map *map,
                                                struct chunk *chunk)
{
    struct xseg_request *req;
    uint64_t limit, obj, pos, datalen;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    char *data;
    struct mapping *mn;

    datalen = v2_chunksize;

    flogger_debug(logger, "Starting for map %s, start: %llu, nr: %llu "
                  "offset:%llu, size: %llu",
                 map->volume, chunk->start, chunk->nr,
                 get_offset_in_block(map, chunk->start),
                 v2_objectsize_in_map * chunk->nr);

    req = get_request(pr, mapper->mbportno, chunk->target, chunk->targetlen,
                      datalen);
    if (!req) {
        flogger_error(logger, "Cannot get request");
        return NULL;
    }

    req->op = X_WRITE;
    req->offset = get_offset_in_block(map, chunk->start);
    req->size = v2_objectsize_in_map * chunk->nr;

    data = xseg_get_data(peer->xseg, req);
    //assert chunk->size > v2_objectsize_in_map

    flogger_debug(logger, "Start: %llu, nr: %llu", chunk->start, chunk->nr);
    pos = 0;
    for (obj = chunk->start; obj < chunk->start + chunk->nr; obj++) {
        mn = &map->objects[obj];
        object_to_map_v2((unsigned char *) (data + pos), mn);
        pos += v2_objectsize_in_map;
    }

    return req;

}

static struct xseg_request *prepare_load_chunk(struct peer_req *pr,
                                               struct map *map,
                                               struct chunk *chunk)
{
    struct xseg_request *req;
    uint64_t limit, obj, pos, datalen;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    char *data;
    struct mapping *mn;
    uint64_t size, offset;
    uint64_t offset_in_first_object;

    size = v2_objectsize_in_map * chunk->nr;
    offset = get_offset_in_block(map, chunk->start);
    //chunksize will be at most v2_chunksize
    datalen = v2_chunksize;

    flogger_debug(logger, "Starting for map %s, start: %llu, nr: %llu, "
                  "offset:%llu, size: %llu",
                  map->volume, chunk->start, chunk->nr, offset, size);

    req = get_request(pr, mapper->mbportno, chunk->target, chunk->targetlen,
                      datalen);
    if (!req) {
        flogger_error(logger, "Cannot get request");
        return NULL;
    }

    req->op = X_READ;
    req->offset = offset;
    req->size = size;

    return req;

}

struct xseg_request *prepare_write_objects_v2(struct peer_req *pr,
                                              struct map *map, uint64_t start,
                                              uint64_t nr)
{
    struct chunk *chunks;
    int nr_chunks;

    nr_chunks = split_to_chunks(map, start, nr, &chunks);
    if (nr_chunks != 1) {
        flogger_error(logger, "Map %s, start: %llu, nr: %llu return %d chunks",
                      map->volume, start, nr, nr_chunks);
        return NULL;
    }

    return prepare_write_chunk(pr, map, chunks);
}

static struct xseg_request *prepare_write_object_v2(struct peer_req *pr,
                                                    struct map *map,
                                                    uint64_t obj_idx,
                                                    struct mapping *mn)
{
    return NULL;
}


int read_map_objects_v2(struct map *map, unsigned char *data)
{
    int r;
    struct mapping *mapping;
    char *vol_name, *cas_name;
    uint32_t vol_name_len;
    uint64_t i, vol_name_sum, pos = 0;
    GHashTable *cas_names = NULL, *vol_names = NULL;
    GHashTableIter iter;
    gpointer key, value;

    flogger_debug(logger, "Allocating %llu nr_objs for size %llu",
                  map->nr_objs, map->size);

    mapping = calloc(map->nr_objs, sizeof(struct mapping));
    if (!mapping) {
        flogger_error(logger, "Cannot allocate mem for %llu objects",
                      map->nr_objs);
        return -ENOMEM;
    }

    map->objects = mapping;
    r = initialize_map_objects(map);
    if (r < 0) {
        flogger_error(logger, "Cannot initialize map objects for map %s",
                      map->volume);
        goto out_err;
    }


    // find cas and vol names;
    cas_names = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    vol_names = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    if (!cas_names || !vol_names) {
        r = -ENOMEM;
        goto out_err;
    }

    r = extract_names(map, data, cas_names, vol_names);
    if (r < 0) {
        goto out_err;
    }

    if (!g_hash_table_contains(vol_names, map->volume)) {
        vol_name = strndup(map->volume, map->volumelen);
        if (!vol_name) {
            r = -ENOMEM;
            goto out_err;
        }
        g_hash_table_add(vol_names, vol_name);
        vol_name = NULL;
    }

    vol_name_sum = 0;

    g_hash_table_iter_init (&iter, vol_names);
    while (g_hash_table_iter_next (&iter, &key, &value))
    {
        vol_name = (char *)key;
        vol_name_sum += strlen(key);
    }

    map->cas_nr = g_hash_table_size(cas_names);
    map->vol_nr = g_hash_table_size(vol_names);

    map->hex_cas_size = HEXLIFIED_SHA256_DIGEST_SIZE;
    map->hex_cas_array_len = map->cas_nr * HEXLIFIED_SHA256_DIGEST_SIZE;

    map->vol_array_len = map->vol_nr * sizeof(uint16_t) + vol_name_sum;

    if (map->cas_nr > 0) {
        map->cas_array = calloc(1, map->cas_nr * HEXLIFIED_SHA256_DIGEST_SIZE);
        map->cas_names = calloc(map->cas_nr, sizeof(char *));
        if (!map->cas_array || !map->cas_names) {
            r = -ENOMEM;
            goto out_err;
        }

        i = 0;
        g_hash_table_iter_init(&iter, cas_names);
        while (g_hash_table_iter_next(&iter, &key, &value))
        {
            cas_name = (char *)key;

            memcpy(map->cas_array + i * map->hex_cas_size, cas_name,
                   map->hex_cas_size);
            map->cas_names[i] = map->cas_array + i * map->hex_cas_size;
            i++;
        }
        // assert(i == map->cas_nr);
    }

    map->vol_array = calloc(1, vol_name_sum);
    map->vol_names = calloc(map->vol_nr, sizeof(struct vol_idx));
    if (!map->vol_names || !map->vol_array) {
        r = -ENOMEM;
        goto out_err;
    }

    i = 0;
    vol_name_sum = 0;
    g_hash_table_iter_init(&iter, vol_names);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        vol_name = (char *)key;
        vol_name_len = strlen(key);

        memcpy(map->vol_array+vol_name_sum, vol_name, vol_name_len);

        map->vol_names[i].len = vol_name_len;
        map->vol_names[i].name = map->vol_array + vol_name_sum;

        if (!strncmp(vol_name, map->volume, vol_name_len)) {
            map->cur_vol_idx = i;
        }

        vol_name_sum += vol_name_len;
        i++;
    }

    mapping = map->objects;

    for (i = 0; i < map->nr_objs; i++) {
        r = read_object_v2(map, &mapping[i], data + pos);
        if (r < 0) {
            flogger_error(logger, "Map %s: could not read object %llu",
                          map->volume, i);
            goto out_err;
        }
        pos += v2_objectsize_in_map;
    }

    r = 0;

out:
    if (vol_names) {
        g_hash_table_destroy(vol_names);
    }

    if (cas_names) {
        g_hash_table_destroy(cas_names);
    }

    return r;

out_err:
    restore_map_objects(map);
    goto out;
}

static void delete_map_data_v2_cb(struct peer_req *pr,
                                  struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);

    if (req->state & XS_FAILED) {
        mio->err = 1;
        flogger_error(logger, "Request failed");
    }

    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}


static int __delete_map_data_v2(struct peer_req *pr, struct map *map)
{
    int r, i;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    char target[v2_max_objectlen];
    uint32_t targetlen, blockid;
    uint64_t objects_in_block, obj;

    objects_in_block = map->blocksize / v2_objectsize_in_map;
    for (obj = 0; obj < map->nr_objs; obj += objects_in_block) {
        blockid = get_block_id(map, obj);
        targetlen = get_map_block_name(target, map, blockid);
        req = get_request(pr, mapper->mbportno, target, targetlen, 0);
        if (!req) {
            flogger_error(logger, "Cannot get request");
            goto out_err;
        }
        req->op = X_DELETE;
        req->offset = 0;
        req->size = 0;
        flogger_debug(logger, "Deleting %s(%u)", target, targetlen);
        r = send_request(pr, req);
        if (r < 0) {
            flogger_error(logger, "Cannot send request");
            goto out_put;
        }
        mio->pending_reqs++;
    }
    return 0;

  out_put:
    put_request(pr, req);
  out_err:
    mio->err = 1;
    return -1;
}

static int delete_map_data_v2(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = delete_map_data_v2_cb;

    r = __delete_map_data_v2(pr, map);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    mio->priv = NULL;
    mio->cb = NULL;
    return (mio->err ? -1 : 0);
}

static void write_objects_v2_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);

    if (req->state & XS_FAILED) {
        mio->err = 1;
        flogger_error(logger, "Request failed");
        goto out;
    }

    if (req->serviced != req->size) {
        mio->err = 1;
        flogger_error(logger, "Serviced != size");
        goto out;
    }

  out:
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}

static int __write_objects_v2(struct peer_req *pr, struct map *map,
                              uint64_t start, uint64_t nr)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    struct chunk *chunks;
    int nr_chunks, i;

    flogger_debug(logger, "Writing objects for %s: start: %llu, nr: %llu",
                  map->volume, start, nr);
    if (start + nr > map->nr_objs) {
        flogger_error(logger, "Attempting to write beyond nr_objs");
        return -1;
    }

    nr_chunks = split_to_chunks(map, start, nr, &chunks);

    if (nr_chunks < 0) {
        goto out_err;
    }

    for (i = 0; i < nr_chunks; i++) {
        req = prepare_write_chunk(pr, map, &chunks[i]);
        if (!req) {
            goto out_free;

        }
        flogger_debug(logger, "Writing chunk %s(%u) , start: %llu, nr :%llu",
                      chunks[i].target, chunks[i].targetlen, chunks[i].start,
                      chunks[i].nr);
        r = send_request(pr, req);
        if (r < 0) {
            flogger_error(logger, "Cannot send request");
            goto out_put;
        }
        mio->pending_reqs++;
    }

    free(chunks);
    return 0;

  out_put:
    put_request(pr, req);
  out_free:
    free(chunks);
  out_err:
    mio->err = 1;
    return -1;
}

static int write_objects_v2(struct peer_req *pr, struct map *map,
                            uint64_t start, uint64_t nr)
{
    int r;
    //unsigned char *buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = write_objects_v2_cb;

    r = __write_objects_v2(pr, map, start, nr);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    mio->priv = NULL;
    mio->cb = NULL;
    return (mio->err ? -1 : 0);
}

static int write_map_data_v2(struct peer_req *pr, struct map *map)
{
    return write_objects_v2(pr, map, 0, map->nr_objs);
}

static void load_map_data_v2_cb(struct peer_req *pr, struct xseg_request *req)
{
    char *data;
    unsigned char *buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct peerd *peer = pr->peer;
    struct req_ctx *req_ctx = NULL;

    req_ctx = get_req_ctx(mio, req);
    if (!req_ctx) {
        flogger_error(logger, "Cannot get request context");
        mio->err = 1;
        goto out;
    }

    remove_req_ctx(mio, req);

    buf = req_ctx->buf;

    flogger_info(logger, "Callback of req %p, buf: %p", req, buf);

    //buf = (unsigned char *)mio->priv;
    if (!buf) {
        flogger_error(logger, "Cannot get load buffer");
        mio->err = 1;
        goto out;
    }

    if (req->state & XS_FAILED) {
        mio->err = 1;
        flogger_error(logger, "Request failed");
        goto out;
    }

    if (req->serviced != req->size) {
        mio->err = 1;
        flogger_error(logger, "Serviced != size");
        goto out;
    }

    data = xseg_get_data(peer->xseg, req);
    flogger_debug(logger, "Memcpy %llu to %p from (%p)", req->serviced, buf,
                  data);
    memcpy(buf, data, req->serviced);

out:
    free(req_ctx);
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}

static int __load_map_objects_v2(struct peer_req *pr, struct map *map,
                                 uint64_t start, uint64_t nr,
                                 unsigned char *buf)
{
    int r;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    struct chunk *chunk;
    int nr_chunks, i;
    struct req_ctx *req_ctx;

    unsigned char *obuf = buf;

    if (start + nr > map->nr_objs) {
        flogger_error(logger, "Attempting to load beyond nr_objs");
        goto out_err;
    }

    nr_chunks = split_to_chunks(map, start, nr, &chunk);
    if (nr_chunks < 0) {
        return -1;
    }

    for (i = 0; i < nr_chunks; i++) {
        req = prepare_load_chunk(pr, map, &chunk[i]);
        if (!req) {
            flogger_error(logger, "Cannot get request");
            goto out_free;
        }
        flogger_debug(logger, "Reading chunk %s(%u) , start %llu, nr :%llu",
                      chunk[i].target, chunk[i].targetlen,
                      chunk[i].start, chunk[i].nr);

        req_ctx = calloc(1, sizeof(struct req_ctx));
        if (!req_ctx) {
            r = -ENOMEM;
            goto out_put;
        }

        req_ctx->buf = buf;

        r = set_req_ctx(mio, req, req_ctx);
        if (r < 0) {
            flogger_error(logger, "Cannot set request ctx");
            goto out_put;
        }

        flogger_debug(logger, "Send buf: %p, offset from start: %d, "
                      "nr_objs: %d", buf, buf - obuf,
                      (buf - obuf) / v2_objectsize_in_map);

        buf += chunk[i].nr * v2_objectsize_in_map;

        flogger_debug(logger, "Next buf: %p, offset from start: %d, "
                      "nr_objs: %d", buf, buf - obuf,
                      (buf - obuf) / v2_objectsize_in_map);

        r = send_request(pr, req);
        if (r < 0) {
            flogger_error(logger, "Cannot send request");
            goto out_unset_ctx;
        }
        mio->pending_reqs++;
    }

    free(chunk);
    return 0;

out_unset_ctx:
    remove_req_ctx(mio, req);
    free(req_ctx);
out_put:
    put_request(pr, req);
out_free:
    free(chunk);
out_err:
    mio->err = 1;
    return r;
}

static int load_map_objects_v2(struct peer_req *pr, struct map *map,
                               uint64_t start, uint64_t nr)
{
    int r;
    unsigned char *buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    uint32_t rem;

    if (map->flags & MF_MAP_DELETED) {
        flogger_info(logger, "Map deleted. Ignoring loading objects");
        return 0;
    }

    buf = calloc(nr, sizeof(unsigned char) * v2_objectsize_in_map);
    if (!buf) {
        flogger_error(logger, "Cannot allocate memory");
        return -ENOMEM;
    }

    mio->priv = buf;
    mio->cb = load_map_data_v2_cb;
    flogger_debug(logger, "Allocated buf: %p for %llu objs", buf, nr);

    r = __load_map_objects_v2(pr, map, start, nr, buf);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    if (mio->err) {
        flogger_error(logger, "Error issuing load request");
        goto out;
    }

    flogger_debug(logger, "Loaded mapdata. Proceed to reading");
    r = read_map_objects_v2(map, buf);
    if (r < 0) {
        mio->err = 1;
    }

  out:
    free(buf);
    mio->priv = NULL;
    mio->cb = NULL;
    return (mio->err ? -1 : 0);
}

static int load_map_data_v2(struct peer_req *pr, struct map *map)
{
    return load_map_objects_v2(pr, map, 0, map->nr_objs);
}

struct map_ops v2_ops = {
    .prepare_write_object = prepare_write_object_v2,
    .load_map_data = load_map_data_v2,
    .write_map_data = write_map_data_v2,
    .delete_map_data = delete_map_data_v2
};

void write_map_header_v2(struct map *map, struct v2_header_struct *v2_hdr)
{
    v2_hdr->signature = __cpu_to_be32(MAP_SIGNATURE);
    v2_hdr->version = __cpu_to_be32(MAP_V2);
    v2_hdr->size = __cpu_to_be64(map->size);
    v2_hdr->blocksize = __cpu_to_be32(map->blocksize);
    v2_hdr->flags = __cpu_to_be32(map->flags);
    v2_hdr->epoch = __cpu_to_be64(map->epoch);
}

int read_map_header_v2(struct map *map, struct v2_header_struct *v2_hdr)
{
    int r;
    uint32_t version = __be32_to_cpu(v2_hdr->version);
    if (version != MAP_V2) {
        return -1;
    }
    map->version = version;
    map->signature = __be32_to_cpu(v2_hdr->signature);
    map->size = __be64_to_cpu(v2_hdr->size);
    map->blocksize = __be32_to_cpu(v2_hdr->blocksize);
    //FIXME check each flag seperately
    map->flags = __be32_to_cpu(v2_hdr->flags);
    map->epoch = __be64_to_cpu(v2_hdr->epoch);
    /* sanitize flags */
    //map->flags &= MF_MAP_SANITIZE;
    map->nr_objs = calc_map_obj(map);
    map->mops = &v2_ops;

    return 0;
}
