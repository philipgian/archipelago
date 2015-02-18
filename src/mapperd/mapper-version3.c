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

#include "mapper.h"
#include "mapper-helpers.h"
#include "mapper-version3.h"


/* Must be a power of 2, as the blocksize */
#define v3_chunksize (512*1024)

#define V3_OBJECT_TYPE_ARCHIP 1
#define V3_OBJECT_TYPE_CAS 0
#define V3_OBJECT_READONLY 1
#define V3_OBJECT_WRITABLE 0

#define V3_OBJECT_ZERO_EPOCH (UINT32_MAX)
#define V3_OBJECT_V1_EPOCH (UINT32_MAX - 1)

#define V3_META_HEADER_SIZE 512

struct v3_meta_hdr {
    /* size of each cas name (unhexlified) */
    uint32_t cas_size;
    /* total length in bytes of the cas_array */
    uint64_t cas_array_len;
    /* total length in bytes of the vol_array */
    uint64_t vol_array_len;
    /* Volume name index of the current volume */
    uint32_t cur_vol_idx;
} __attribute__ ((packed));

static read_meta_header_v3(struct map * map, struct v3_meta_hdr *meta_hdr)
{
    map->hex_cas_size = __be32_to_cpu(meta_hdr->cas_size) * 2;
    map->hex_cas_array_len = __be64_to_cpu(meta_hdr->cas_array_len) * 2;
    map->vol_array_len = __be64_to_cpu(meta_hdr->vol_array_len);
    map->cur_vol_idx= __be32_to_cpu(meta_hdr->cur_vol_idx);
}

static write_meta_header_v3(struct map *map, struct v3_meta_hdr *meta_hdr)
{
    meta_hdr->cas_size = __cpu_to_be32(map->hex_cas_size/2);
    meta_hdr->cas_array_len = __cpu_to_be64(map->hex_cas_array_len/2);
    meta_hdr->vol_array_len = __cpu_to_be64(map->vol_array_len);
    meta_hdr->cur_vol_idx = __cpu_to_be32(map->cur_vol_idx);
}

struct v3_object {
    uint32_t epoch;
    unsigned name_idx:30;
    unsigned type:1;
    unsigned ro:1;
};

static struct v3_object v3_zero_object = {
    V3_OBJECT_ZERO_EPOCH,
    0,
    V3_OBJECT_TYPE_CAS,
    V3_OBJECT_READONLY
};

static int v3_mappings_equal(struct v3_object *o1, struct v3_object *o2)
{
    return o1->epoch == o2->epoch && o1->name_idx == o2->name_idx
            && o1->type == o2->type && o1->ro == o2->ro;
}

static int is_zero_object(struct v3_object *o)
{
    return v3_mappings_equal(o, &v3_zero_object);
}

static int is_v1_object(struct v3_object *o)
{
    return o->epoch == V3_OBJECT_V1_EPOCH && o->type == V3_OBJECT_TYPE_ARCHIP;
}


/* Convert fucntions from on disk big-endian representation, to the on memory
 * bit-field based representation
 */
static void v3_object_to_disk(struct v3_object *o, struct v3_object_on_disk *od)
{
    uint64_t tmp;

    tmp = o->name_idx;
    tmp <<= 1;
    if (o->type == V3_OBJECT_TYPE_ARCHIP) {
        tmp |= V3_OBJECT_TYPE_ARCHIP;
    }
    tmp <<= 1;

    if (o->ro == V3_OBJECT_READONLY) {
        tmp |= V3_OBJECT_READONLY;
    }

    od->epoch = __cpu_to_be32(o->epoch);
    od->nameidx_type_ro = __cpu_to_be32(tmp);
}

static void v3_object_from_disk(struct v3_object_on_disk *od, struct v3_object *o)
{
    uint64_t tmp;

    o->epoch = __be32_to_cpu(od->epoch);
    tmp = __be32_to_cpu(od->nameidx_type_ro);

    if (tmp & V3_OBJECT_READONLY) {
        o->ro = V3_OBJECT_READONLY;
    } else {
        o->ro = V3_OBJECT_WRITABLE;
    }
    tmp >>= 1;

    if (tmp & V3_OBJECT_TYPE_ARCHIP) {
        o->type = V3_OBJECT_TYPE_ARCHIP;
    } else {
        o->type = V3_OBJECT_TYPE_CAS;
    }
    tmp >>= 1;

    o->name_idx = tmp;
}


static volname_from_disk(void *buf, struct vol_idx *vi, void *name)
{
    uint16_t *be_len;

    be_len = buf;
    vi->len = __be16_to_cpu(*be_len);
    memcpy(name, buf + sizeof(uint16_t), vi->len);
    vi->name = name;
}

static volname_to_disk(struct vol_idx *vi, void *buf)
{
    uint16_t *be_len;

    be_len = buf;
    *be_len = __cpu_to_be16(vi->len);
    memcpy(buf + sizeof(uint16_t), vi->name, vi->len);
}


/* v3 functions */

static uint32_t get_map_block_name(char *target, struct map *map,
                                   uint64_t block_id)
{
    uint32_t targetlen;
    uint64_t be_block_id = __cpu_to_be64(block_id);
    uint64_t be_epoch = __cpu_to_be64(map->epoch);
    char buf_blockid[sizeof(be_block_id) * 2 + 1];
    char buf_epoch[HEXLIFIED_EPOCH_LEN + 1];

    hexlify((unsigned char *)&be_block_id, sizeof(be_block_id), buf_blockid);
    buf_blockid[2 * sizeof(block_id)] = 0;

    hexlify((unsigned char *)&be_epoch, sizeof(map->epoch), buf_epoch);
    buf_epoch[HEXLIFIED_EPOCH_LEN] = 0;

    sprintf(target, "%s_%s_%s", map->volume, buf_epoch, buf_blockid);
    // Calculate length of the above string
    targetlen = map->volumelen + 1 + HEXLIFIED_EPOCH_LEN + 1 + (sizeof(be_block_id) * 2);

    return targetlen;
}

// TODO add support for max meta object size
static uint32_t get_map_meta_name(char *target, struct map *map)
{
    uint32_t targetlen;
    uint64_t be_epoch = __cpu_to_be64(map->epoch);
    char buf_epoch[HEXLIFIED_EPOCH_LEN + 1];

    hexlify((unsigned char *)&be_epoch, sizeof(map->epoch), buf_epoch);
    buf_epoch[HEXLIFIED_EPOCH_LEN] = 0;

    sprintf(target, "%s_%s.meta", map->volume, buf_epoch);
    // Calculate length of the above string
    targetlen = map->volumelen + 1 + HEXLIFIED_EPOCH_LEN + 1 + 4;

    return targetlen;
}

static uint32_t get_chunk_size(struct map *map)
{
    return (map->blocksize < v3_chunksize) ? map->blocksize : v3_chunksize;
}

static int get_block_id(struct map *map, uint64_t idx)
{
    return (idx * v3_objectsize_in_map) / map->blocksize;
}

static uint64_t get_offset_in_block(struct map *map, uint64_t idx)
{
    uint64_t objects_in_block = map->blocksize / v3_objectsize_in_map;
    return ((idx % objects_in_block) * v3_objectsize_in_map) % map->blocksize;
}

static uint32_t get_offset_in_chunk(struct map *map, uint64_t offset)
{
    uint32_t chunksize = get_chunk_size(map);
    /* since blocksize and chunksize are both power of two, the following is
     * equivalent to:
     *   offset_in_block = offset % map->blocksize;
     *   offset_in_chunk = offset % chunksize;
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


    objects_in_block = map->blocksize / v3_objectsize_in_map;
    objects_in_chunk = chunksize / v3_objectsize_in_map;

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


static int read_object_v3(struct mapping *m, unsigned char *buf)
{
    char c = buf[0];
    int len = 0;
    uint32_t objectlen;

    struct v3_object_on_disk *be_mapping;
    struct v3_object mapping;

    be_mapping = (struct v3_object_on_disk *)buf;
    v3_object_from_disk(be_mapping, &mapping);

    m->flags = 0;

    if (is_zero_object(&mapping)) {
        m->flags |= MF_OBJECT_ZERO;
    } else if (is_v1_object(&mapping)) {
        m->flags |= MF_OBJECT_V1;
        m->flags |= MF_OBJECT_ARCHIP;
        if (mapping.type == V3_OBJECT_TYPE_ARCHIP) {
            m->flags |= MF_OBJECT_ARCHIP;
        }
        m->vol_epoch = mapping.epoch;
        m->name_idx = mapping.name_idx;
    } else {
        if (mapping.ro != V3_OBJECT_READONLY) {
            m->flags |= MF_OBJECT_WRITABLE;
        }
        if (mapping.type == V3_OBJECT_TYPE_ARCHIP) {
            m->flags |= MF_OBJECT_ARCHIP;
        }
        m->vol_epoch = mapping.epoch;
        m->name_idx = mapping.name_idx;
    }

    return 0;
}

/* Fill a buffer representing an object on disk from a given map node */
static void object_to_map_v3(unsigned char *buf, struct mapping *m)
{
    struct v3_object mapping;
    struct v3_object_on_disk *be_mapping;

    if (m->flags & MF_OBJECT_ZERO) {
        mapping = v3_zero_object;
    } else if (m->flags & MF_OBJECT_V1) {
        // assert(m->flags & MF_OBJECT_ARCHIP);
        mapping.type = V3_OBJECT_TYPE_ARCHIP;
        if (m->flags & MF_OBJECT_WRITABLE) {
            mapping.ro = V3_OBJECT_WRITABLE;
        } else {
            mapping.ro = V3_OBJECT_READONLY;
        }
        mapping.epoch = V3_OBJECT_V1_EPOCH;
        mapping.name_idx = m->name_idx;
    } else {
        if (m->flags & MF_OBJECT_WRITABLE) {
            mapping.ro = V3_OBJECT_WRITABLE;
        } else {
            mapping.ro = V3_OBJECT_READONLY;
        }

        if (m->flags & MF_OBJECT_ARCHIP) {
            mapping.type = V3_OBJECT_TYPE_ARCHIP;
        } else {
            mapping.type = V3_OBJECT_TYPE_CAS;
        }

        mapping.name_idx = m->name_idx;
        mapping.epoch = m->vol_epoch;
    }

    be_mapping = (struct v3_object_on_disk *)buf;
    v3_object_to_disk(&mapping, be_mapping);
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

    datalen = v3_chunksize;

    flogger_debug(logger, "Starting for map %s, start: %llu, nr: %llu "
                  "offset:%llu, size: %llu",
                  map->volume, chunk->start, chunk->nr,
                  get_offset_in_block(map, chunk->start),
                  v3_objectsize_in_map * chunk->nr);

    req = get_request(pr, mapper->mbportno, chunk->target, chunk->targetlen,
                      datalen);
    if (!req) {
        flogger_error(logger, "Cannot get request");
        return NULL;
    }

    req->op = X_WRITE;
    req->offset = get_offset_in_block(map, chunk->start);
    req->size = v3_objectsize_in_map * chunk->nr;

    data = xseg_get_data(peer->xseg, req);
    //assert chunk->size > v3_objectsize_in_map

    flogger_debug(logger, "Start: %llu, nr: %llu", chunk->start, chunk->nr);
    pos = 0;
    for (obj = chunk->start; obj < chunk->start + chunk->nr; obj++) {
        mn = &map->objects[obj];
        object_to_map_v3((unsigned char *) (data + pos), mn);
        pos += v3_objectsize_in_map;
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

    size = v3_objectsize_in_map * chunk->nr;
    offset = get_offset_in_block(map, chunk->start);
    //chunksize will be at most v3_chunksize
    datalen = v3_chunksize;

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

struct xseg_request *prepare_write_objects_v3(struct peer_req *pr,
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

static struct xseg_request *prepare_write_object_v3(struct peer_req *pr,
                                                    struct map *map,
                                                    uint64_t obj_idx,
                                                    struct mapping *m)
{
    struct peerd *peer = pr->peer;
    char *data;
    struct xseg_request *req;

    req = prepare_write_objects_v3(pr, map, obj_idx, 1);
    if (!req) {
        return NULL;
    }
    data = xseg_get_data(peer->xseg, req);
    object_to_map_v3((unsigned char *)data, m);
    return req;
}


int read_map_objects_v3(struct map *map, unsigned char *data, uint64_t start,
                        uint64_t nr)
{
    int r;
    struct mapping *mapping;
    uint64_t i;
    uint64_t pos = 0;

    if (start + nr > map->nr_objs) {
        return -1;
    }

    if (!map->objects) {
        flogger_debug(logger, "Allocating %llu nr_objs for size %llu",
                 map->nr_objs, map->size);
        mapping = calloc(map->nr_objs, sizeof(struct mapping));
        if (!mapping) {
            flogger_error(logger, "Cannot allocate mem for %llu objects",
                          map->nr_objs);
            return -1;
        }
        map->objects = mapping;
        r = initialize_map_objects(map);
        if (r < 0) {
            flogger_error(logger, "Cannot initialize map objects for map %s",
                          map->volume);
            goto out_free;
        }
    }

    mapping = map->objects;

    for (i = start; i < nr; i++) {
        r = read_object_v3(&mapping[i], data + pos);
        if (r < 0) {
            flogger_error(logger, "Map %s: Could not read object %llu",
                          map->volume, i);
            goto out_free;
        }
        pos += v3_objectsize_in_map;
    }
    return 0;

  out_free:
    free(map->objects);
    map->objects = NULL;
    return -1;
}

static int read_map_v3(struct map *m, unsigned char *data)
{
    /* totally unsafe */
    return read_map_objects_v3(m, data, 0, m->nr_objs);
}

static void delete_map_data_v3_cb(struct peer_req *pr,
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


static int __delete_map_data_v3(struct peer_req *pr, struct map *map)
{
    int r, i;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    char target[XSEG_MAX_TARGETLEN + 1];
    uint32_t targetlen, blockid;
    uint64_t objects_in_block, obj;

    objects_in_block = map->blocksize / v3_objectsize_in_map;
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

static void delete_meta_v3_cb(struct peer_req *pr,
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

static int __delete_meta_v3(struct peer_req *pr, struct map *map)
{
    int r;
    char meta_object[XSEG_MAX_TARGETLEN];
    uint32_t meta_object_len;
    uint64_t size;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);

    size = map->hex_cas_array_len/2 + map->vol_array_len;
    meta_object_len = get_map_meta_name(meta_object, map);

    req = get_request(pr, mapper->mbportno, meta_object, meta_object_len, 0);
    if (!req) {
        flogger_error(logger, "Cannot get request");
        return -ENOSPC;
    }

    req->op = X_DELETE;
    req->offset = 0;
    req->size = size;

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request");
        put_request(pr, req);
        return -1;
    }

    mio->pending_reqs++;

    return 0;
}

static int delete_meta_v3(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = delete_meta_v3_cb;

    r = __delete_meta_v3(pr, map);
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

static int delete_map_data_v3(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);

    r = delete_meta_v3(pr, map);
    if (r < 0) {
        return r;
    }

    mio->cb = delete_map_data_v3_cb;
    r = __delete_map_data_v3(pr, map);
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

static void write_objects_v3_cb(struct peer_req *pr, struct xseg_request *req)
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

static int __write_objects_v3(struct peer_req *pr, struct map *map,
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

static int write_objects_v3(struct peer_req *pr, struct map *map,
                            uint64_t start, uint64_t nr)
{
    int r;
    //unsigned char *buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = write_objects_v3_cb;

    r = __write_objects_v3(pr, map, start, nr);
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

static void write_meta_v3_cb(struct peer_req *pr, struct xseg_request *req)
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

static int __write_meta_v3(struct peer_req *pr, struct map *map)
{
    int r;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    uint32_t i;
    struct v3_meta_hdr *meta_hdr;
    char meta_object[XSEG_MAX_TARGETLEN];
    uint32_t meta_object_len;
    void *meta_buf, *vol_buf, *cas_buf;
    struct xseg_request *req;

    uint32_t meta_size = V3_META_HEADER_SIZE + map->hex_cas_array_len/2 +
                                map->vol_array_len;

    if (map->vol_array == NULL) {
        return -EINVAL;
    }

    meta_object_len = get_map_meta_name(meta_object, map);
    req = get_request(pr, mapper->mbportno, meta_object, meta_object_len,
                      meta_size);
    if (!req) {
        flogger_error(logger, "Cannot get request");
        return -ENOSPC;
    }

    req->op = X_WRITE;
    req->offset = 0;
    req->size = meta_size;

    meta_buf = xseg_get_data(peer->xseg, req);

    meta_hdr = meta_buf;
    cas_buf = meta_buf + V3_META_HEADER_SIZE;
    vol_buf = meta_buf + V3_META_HEADER_SIZE;

    write_meta_header_v3(map, meta_hdr);

    if (map->cas_array != NULL) {
        for (i = 0; i < map->cas_nr; i++) {
            unhexlify(map->cas_names[i], cas_buf + i * map->hex_cas_size/2);
        }
        vol_buf += i * map->hex_cas_size/2;
    }

    for (i = 0; i < map->vol_nr; i++) {
        volname_to_disk(&map->vol_names[i], vol_buf);
        vol_buf += sizeof(uint16_t) + map->vol_names[i].len;
    }

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request");
        put_request(pr, req);
        return -1;
    }

    mio->pending_reqs++;

    return 0;
}

static int write_meta_v3(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = write_meta_v3_cb;

    r = __write_meta_v3(pr, map);
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


static int write_map_data_v3(struct peer_req *pr, struct map *map)
{
    int r;
    r = write_meta_v3(pr, map);
    if (r < 0) {
        return r;
    }
    return write_objects_v3(pr, map, 0, map->nr_objs);
}

static void load_map_data_v3_cb(struct peer_req *pr, struct xseg_request *req)
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

static int __load_map_objects_v3(struct peer_req *pr, struct map *map,
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
                      (buf - obuf) / v3_objectsize_in_map);

        buf += chunk[i].nr * v3_objectsize_in_map;
        flogger_debug(logger, "Next buf: %p, offset from start: %d, "
                      "nr_objs: %d", buf, buf - obuf,
                      (buf - obuf) / v3_objectsize_in_map);

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
    return -1;
}

static int load_map_objects_v3(struct peer_req *pr, struct map *map,
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

    buf = calloc(nr, sizeof(unsigned char) * v3_objectsize_in_map);
    if (!buf) {
        flogger_error(logger, "Cannot allocate memory");
        return -1;
    }

    mio->priv = buf;
    mio->cb = load_map_data_v3_cb;
    flogger_debug(logger, "Allocated buf: %p for %llu objs", buf, nr);

    r = __load_map_objects_v3(pr, map, start, nr, buf);
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
    r = read_map_objects_v3(map, buf, start, nr);
    if (r < 0) {
        mio->err = 1;
    }
  out:
    free(buf);
    mio->priv = NULL;
    mio->cb = NULL;
    return (mio->err ? -1 : 0);
}

static void load_meta_v3_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct peerd *peer = pr->peer;
    uint32_t i;
    char *vol_buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct map *map = mio->priv;
    char *data;

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

    // assert req->serviced == map->array_size;

    data = xseg_get_data(peer->xseg, req);

    map->cas_names = NULL;
    map->cas_array = NULL;
    map->vol_names = NULL;
    map->vol_array = NULL;

    if (map->hex_cas_array_len > 0) {
        map->cas_names = calloc(map->hex_cas_array_len/map->hex_cas_size, sizeof(char *));
        map->cas_array = calloc(1, map->hex_cas_array_len);
        if (!map->cas_names || !map->cas_array) {
            goto out_err;
        }

        for (i = 0; i < map->hex_cas_array_len/map->hex_cas_size; i++) {
            hexlify((unsigned char *)data + i *  map->hex_cas_size/2,
                     map->hex_cas_size/2,
                     (unsigned char *)map->cas_array + i * map->hex_cas_size);
            // build index
            map->cas_names[i] = map->cas_array + i * map->hex_cas_size;
        }
        map->cas_nr = i;
    }

    if (!(map->vol_array_len > 0)) {
        goto out_err;
    }

    uint16_t len;
    uint64_t processed = 0, c = 0, sum = 0;
    char *vol_names = data + map->hex_cas_array_len/2;

    while (processed < map->vol_array_len) {
        len = __be16_to_cpu(*(uint16_t *)(vol_names + processed));
        c++;
        sum += len;
        processed += sizeof(uint16_t) + len;
    }

    map->vol_array = calloc(1, sum);
    if (!map->vol_array) {
        goto out_err;
    }

    map->vol_nr = c;
    map->vol_names = calloc(c, sizeof(struct vol_idx));
    if (!map->vol_names) {
        goto out_err;
    }

    i = 0;
    processed = 0;
    sum = 0;
    while (processed < map->vol_array_len) {
        volname_from_disk(vol_names + processed, &map->vol_names[i], map->vol_array + sum);
        // processed = i * sizeof(uint16_t) + sum;
        processed += sizeof(uint16_t) + map->vol_names[i].len;
        sum += map->vol_names[i].len;
        i++;
    }

out:
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;

out_err:
    free(map->cas_names);
    free(map->cas_array);
    free(map->vol_names);
    free(map->vol_array);
    map->cas_names = NULL;
    map->cas_array = NULL;
    map->vol_names = NULL;
    map->vol_array = NULL;
    mio->err = 1;
    goto out;
}

static int __load_meta_v3(struct peer_req *pr, struct map *map)
{
    int r;
    char meta_object[XSEG_MAX_TARGETLEN];
    uint32_t meta_object_len;
    uint64_t size;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);

    size = map->hex_cas_array_len/2 + map->vol_array_len;
    meta_object_len = get_map_meta_name(meta_object, map);

    req = get_request(pr, mapper->mbportno, meta_object, meta_object_len, size);
    if (!req) {
        flogger_error(logger, "Cannot get request");
        return -ENOSPC;
    }

    req->op = X_READ;
    req->offset = V3_META_HEADER_SIZE;
    req->size = size;

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request");
        put_request(pr, req);
        return -1;
    }
    mio->pending_reqs++;

    return 0;
}

static void load_meta_header_v3_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);
    struct v3_meta_hdr *meta_hdr;
    struct peerd *peer = pr->peer;
    struct map *map = mio->priv;

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

    meta_hdr = (struct v3_meta_hdr *)xseg_get_data(peer->xseg, req);
    read_meta_header_v3(map, meta_hdr);

out:
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}

static int __load_meta_header_v3(struct peer_req *pr, struct map *map)
{
    int r;
    uint32_t i;
    char meta_object[XSEG_MAX_TARGETLEN];
    uint32_t meta_object_len;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;

    meta_object_len = get_map_meta_name(meta_object, map);

    req = get_request(pr, mapper->mbportno, meta_object, meta_object_len,
                      V3_META_HEADER_SIZE);
    if (!req) {
        flogger_error(logger, "Cannot get request");
        return -ENOSPC;
    }

    req->op = X_READ;
    req->offset = 0;
    req->size = V3_META_HEADER_SIZE;

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request");
        put_request(pr, req);
        return -1;
    }
    mio->pending_reqs++;

    return 0;
}

static int load_meta_v3(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = load_meta_header_v3_cb;
    mio->priv = map;

    r = __load_meta_header_v3(pr, map);
    if (r < 0) {
        goto out_err;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    if (mio->err) {
        goto out;
    }

    mio->cb = load_meta_v3_cb;
    r = __load_meta_v3(pr, map);
    if (r < 0) {
        goto out_err;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

out:
    mio->priv = NULL;
    mio->cb = NULL;

    return (mio->err ? -1 : 0);

out_err:
    mio->err = 1;
    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }
    goto out;
}

static int load_map_data_v3(struct peer_req *pr, struct map *map)
{
    int r;
    r = load_meta_v3(pr, map);
    if (r < 0) {
        return r;
    }
    return load_map_objects_v3(pr, map, 0, map->nr_objs);
}

struct map_ops v3_ops = {
    .prepare_write_object = prepare_write_object_v3,
    .load_map_data = load_map_data_v3,
    .write_map_data = write_map_data_v3,
    .delete_map_data = delete_map_data_v3
};

void write_map_header_v3(struct map *map, struct v3_header_struct *v3_hdr)
{
    v3_hdr->signature = __cpu_to_be32(MAP_SIGNATURE);
    v3_hdr->version = __cpu_to_be32(MAP_V3);
    v3_hdr->size = __cpu_to_be64(map->size);
    v3_hdr->blocksize = __cpu_to_be32(map->blocksize);
    v3_hdr->flags = __cpu_to_be32(map->flags);
    v3_hdr->epoch = __cpu_to_be64(map->epoch);
}

int read_map_header_v3(struct map *map, struct v3_header_struct *v3_hdr)
{
    int r;
    uint32_t version = __be32_to_cpu(v3_hdr->version);
    if (version != MAP_V3) {
        return -1;
    }
    map->version = version;
    map->signature = __be32_to_cpu(v3_hdr->signature);
    map->size = __be64_to_cpu(v3_hdr->size);
    map->blocksize = __be32_to_cpu(v3_hdr->blocksize);
    //FIXME check each flag seperately
    map->flags = __be32_to_cpu(v3_hdr->flags);
    map->epoch = __be64_to_cpu(v3_hdr->epoch);

    /* sanitize flags */
    //map->flags &= MF_MAP_SANITIZE;
    map->nr_objs = calc_map_obj(map);
    map->mops = &v3_ops;

    return 0;
}
