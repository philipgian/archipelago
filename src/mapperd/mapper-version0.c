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

#include <xseg/xseg.h>
#include <stdlib.h>

#include "mapper.h"
#include "mapper-helpers.h"
#include "mapper-version0.h"

/* version 0 functions */
#define v0_chunked_read_size (512*1024)

int read_object_v0(struct map *map, struct mapping *m, unsigned char *buf)
{
    int exists;
    uint32_t i, cas_name_idx;
    char cas_name[HEXLIFIED_SHA256_DIGEST_SIZE + 1];
    hexlify(buf, SHA256_DIGEST_SIZE, cas_name);
    cas_name[HEXLIFIED_SHA256_DIGEST_SIZE] = '\0';

    //not MF_OBJECT_WRITABLE;
    m->flags = 0;

    if (!strncmp(cas_name, zero_block, ZERO_BLOCK_LEN)) {
        m->flags = MF_OBJECT_ZERO;
        return 0;
    }

    exists = 0;
    for (i = 0; i < map->cas_nr; i++) {
        if (!memcmp(map->cas_array + i * HEXLIFIED_SHA256_DIGEST_SIZE,
                    buf, HEXLIFIED_SHA256_DIGEST_SIZE)) {
            exists = 1;
            break;
        }
    }

    if (exists) {
        cas_name_idx = i;
    } else {
        // append cas_name_idx to cas_names;
        memcpy(map->cas_array + map->cas_nr * HEXLIFIED_SHA256_DIGEST_SIZE,
               buf, HEXLIFIED_SHA256_DIGEST_SIZE);
        cas_name_idx = map->cas_nr;
        map->cas_nr++;
    }

    m->name_idx = cas_name_idx;
    m->vol_epoch = 0;

    return 0;
}

int read_map_v0(struct map *map, unsigned char *data)
{
    int r;
    struct mapping *mapping = NULL;
    uint64_t i, limit, pos = 0;
    uint64_t max_read_obj = v0_chunked_read_size / v0_objectsize_in_map;
    char nulls[SHA256_DIGEST_SIZE];
    char *cas_array = NULL;
    memset(nulls, 0, SHA256_DIGEST_SIZE);

    limit = map->nr_objs + max_read_obj;

    // create enough space to hold CA objects names
    cas_array = realloc(map->cas_array,
                        limit * HEXLIFIED_SHA256_DIGEST_SIZE * sizeof(char));
    if (!cas_array) {
        return -ENOMEM;
    }
    map->cas_array = cas_array;

    mapping = realloc(map->objects, limit * sizeof(struct mapping));
    if (!mapping) {
        // caller will clean up map->cas_array
        return -ENOMEM;
    }
    map->objects = mapping;

    for (i = map->nr_objs; i < limit; i++) {
        if (!memcmp(data + pos, nulls, v0_objectsize_in_map)) {
            break;
        }
        // Initialize mappings here incrementally, as we do not know the exact
        // number of objects from the start.
        mapping[i].waiters = 0;
        mapping[i].state = 0;
        mapping[i].ref = 1;
        mapping[i].cond = st_cond_new();       //FIXME err check;
        read_object_v0(map, &mapping[i], data + pos);
        pos += v0_objectsize_in_map;
    }

    flogger_debug(logger, "Found %llu objects", i);
    map->size = i * MAPPER_DEFAULT_BLOCKSIZE;
    map->nr_objs = i;

    return (limit - map->nr_objs);
}

struct xseg_request *prepare_write_object_v0(struct peer_req *pr,
                                             struct map *map,
                                             uint64_t obj_idx,
                                             struct mapping *mn)
{
    return NULL;
}

int delete_map_data_v0(struct peer_req *pr, struct map *map)
{
    return -ENOTSUP;
}


int write_map_data_v0(struct peer_req *pr, struct map *map)
{
    return -ENOTSUP;
}


struct xseg_request *__load_map_data_v0(struct peer_req *pr, struct map *map)
{
    int r;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    uint64_t datalen;

    if (v0_chunked_read_size % v0_objectsize_in_map) {
        flogger_error(logger, "v0_chunked_read_size should be a multiple of",
                      "v0_objectsize_in_map");
        return NULL;
    }

    datalen = v0_chunked_read_size;

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
                      datalen);
    if (!req) {
        flogger_error(logger, "Cannot get request for map %s", map->volume);
        goto out_fail;
    }

    req->op = X_READ;
    req->size = datalen;
    req->offset = v0_mapheader_size + map->nr_objs * v0_objectsize_in_map;

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      req, pr, map->volume);
        goto out_put;
    }
    return req;

  out_put:
    put_request(pr, req);
  out_fail:
    return NULL;
}

int load_map_data_v0(struct peer_req *pr, struct map *map)
{
    int r = 0;
    uint32_t i;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    char *data;

    // set defaults here
    map->hex_cas_size = HEXLIFIED_SHA256_DIGEST_SIZE;
    map->cur_vol_idx = 0;

    map->vol_nr = 1;
    map->vol_names = calloc(1, sizeof(struct vol_idx));
    map->vol_array = calloc(map->volumelen, sizeof(char));
    if (!map->vol_array || !map->vol_names) {
        r = -ENOMEM;
        goto out_restore;
    }
    memcpy(map->vol_array, map->volume, map->volumelen);
    map->vol_names[0].len = map->volumelen;
    map->vol_names[0].name = map->vol_array;


  retry:
    req = __load_map_data_v0(pr, map);
    if (!req) {
        return -1;
    }
    wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));

    if (req->state & XS_FAILED) {
        flogger_error(logger, "Map load failed for map %s", map->volume);
        r = -EIO;
        put_request(pr, req);
        goto out_restore;
    }

    //assert req->service == req->size
    data = xseg_get_data(peer->xseg, req);
    r = read_map_v0(map, (unsigned char *) data);
    put_request(pr, req);
    if (!r) {
        goto retry;
    }

    if (r < 0) {
        goto out_restore;
    }

    map->hex_cas_array_len = map->cas_nr * HEXLIFIED_SHA256_DIGEST_SIZE;
    map->cas_names = calloc(map->cas_nr, sizeof(char *));
    if (!map->cas_names) {
        r = -ENOMEM;
        goto out_restore;
    }

    for (i = 0; i < map->cas_nr; i++) {
        map->cas_names[i] = map->cas_array + i * HEXLIFIED_SHA256_DIGEST_SIZE;
    }

    return 0;

out_restore:
    restore_map_objects(map);
    return r;
}

struct map_ops v0_ops = {
    .prepare_write_object = prepare_write_object_v0,
    .load_map_data = load_map_data_v0,
    .write_map_data = write_map_data_v0,
    .delete_map_data = delete_map_data_v0
};

int read_map_header_v0(struct map *map, struct v0_header_struct *v0_hdr)
{
    /* No header. Just set defaults */
    map->version = MAP_V0;
    map->size = 0;
    map->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
    map->nr_objs = 0;
    map->flags = MF_MAP_READONLY;
    map->epoch = 0;
    map->objects = NULL;
    map->mops = &v0_ops;

    return 0;
}

void write_map_header_v0(struct map *map, struct v0_header_struct *v0_hdr)
{
    return;
}
