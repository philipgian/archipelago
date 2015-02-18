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
#include <time.h>
#include <xseg/xseg.h>
#include <xseg/protocol.h>
#include <xseg/xhash.h>
#include <asm/byteorder.h>

#include "peer.h"
#include "hash.h"
#include "mapper.h"
#include "mapper-versions.h"
#include "mapper-helpers.h"


#define NO_V0SIZE ((uint64_t)-1)

int set_req_ctx(struct mapper_io *mio, struct xseg_request *req,
                struct req_ctx *rctx)
{
    flogger_debug(logger, "Inserting ctx %lx of request %lx on mio %lx",
                  rctx, req, mio);

    g_hash_table_insert(mio->req_ctxs, req, rctx);

    flogger_debug(logger, "Inserted ctx %lx of request %lx on mio %lx",
                  rctx, req, mio);
    return 0;
}

int remove_req_ctx(struct mapper_io *mio, struct xseg_request *req)
{
    gboolean ret;

    flogger_debug(logger, "Removing ctx of request %lx from mio %lx", req, mio);

    ret = g_hash_table_remove(mio->req_ctxs, req);
    if (!ret) {
        flogger_error(logger, "Deleting ctx of request %lx on mio %lx failed",
                      req, mio);
        return -ENOENT;
    }

    flogger_debug(logger, "Removed ctx of request %lx from mio %lx", req, mio);

    return 0;
}

struct req_ctx * get_req_ctx(struct mapper_io *mio, struct xseg_request *req)
{
    struct req_ctx *ret;

    ret = g_hash_table_lookup(mio->req_ctxs, req);
    if (ret == NULL) {
        flogger_warn(logger, "Cannot find ctx of req %lx on mio %lx", req, mio);
        return NULL;
    }

    flogger_debug(logger, "Found ctx %lx of req %lx on mio %lx", ret, req, mio);

    return ret;
}

struct xseg_request *__close_map(struct peer_req *pr, struct map *map)
{
    int r;
    struct peerd *peer = pr->peer;
    struct xseg_request *req;
    struct mapperd *mapper = __get_mapperd(peer);

    flogger_info(logger, "Closing map %s", map->volume);

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
    if (!req) {
        flogger_error(logger, "Cannot get request for map %s", map->volume);
        goto out_err;
    }

    req->op = X_RELEASE;
    req->size = 0;
    req->offset = 0;
    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      req, pr, map->volume);
        goto out_put;
    }


    flogger_info(logger, "Map %s closing", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int close_map(struct peer_req *pr, struct map *map)
{
    int err;
    struct xseg_request *req;

    map->state |= MF_MAP_CLOSING;
    req = __close_map(pr, map);
    if (!req) {
        map->state &= ~MF_MAP_CLOSING;
        return -1;
    }

    wait_on_pr(pr, (!((req->state & XS_FAILED) || (req->state & XS_SERVED))));
    map->state &= ~MF_MAP_CLOSING;
    err = req->state & XS_FAILED;
    put_request(pr, req);
    if (err) {
        return -1;
    } else {
        map->state &= ~MF_MAP_EXCLUSIVE;
    }
    return 0;
}

struct xseg_request *__open_map(struct peer_req *pr, struct map *map,
                                uint32_t flags)
{
    int r;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);

    flogger_info(logger, "Opening map %s", map->volume);

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
    if (!req) {
        flogger_error(logger, "Cannot get request for map %s", map->volume);
        goto out_err;
    }

    req->op = X_ACQUIRE;
    req->size = MAPPER_DEFAULT_BLOCKSIZE;
    req->offset = 0;
    if (!(flags & MF_FORCE)) {
        req->flags = XF_NOSYNC;
    }

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      req, pr, map->volume);
        goto out_put;
    }

    flogger_info(logger, "Map %s opening", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int open_map(struct peer_req *pr, struct map *map, uint32_t flags)
{
    int err;
    struct xseg_request *req;
    struct mapper_io *mio = __get_mapper_io(pr);

    map->state |= MF_MAP_OPENING;
    req = __open_map(pr, map, flags);
    if (!req) {
        map->state &= ~MF_MAP_OPENING;
        return -1;
    }
    wait_on_pr(pr, (!((req->state & XS_FAILED) || (req->state & XS_SERVED))));
    map->state &= ~MF_MAP_OPENING;
    err = req->state & XS_FAILED;
    put_request(pr, req);
    if (err) {
        return -1;
    } else {
        map->state |= MF_MAP_EXCLUSIVE;
        map->opened_count = mio->count;
    }
    return 0;
}

struct xseg_request *__write_map_metadata(struct peer_req *pr, struct map *map)
{
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct xseg_request *req;
    char *data;
    uint64_t pos;
    int r;
    struct header_struct hdr;
    uint32_t header_size = 0;


    switch (map->version) {
    case MAP_V0:
        write_map_header_v0(map, (struct v0_header_struct *) &hdr);
        header_size = v0_mapheader_size;
        break;
    case MAP_V1:
        flogger_error(logger, "Mapfile version 1 is deprecated and no longer supported");
        goto out_err;
    case MAP_V2:
        write_map_header_v2(map, (struct v2_header_struct *) &hdr);
        header_size = v2_mapheader_size;
        break;
    case MAP_V3:
        write_map_header_v3(map, (struct v3_header_struct *) &hdr);
        header_size = v3_mapheader_size;
        break;
    default:
        flogger_error(logger, "Invalid version %u found", map->version);
        goto out_err;
    }
    if (!header_size) {
        goto out;
    }

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
                      header_size);
    if (!req) {
        flogger_error(logger, "Cannot get request for map %s", map->volume);
        goto out_err;
    }


    req->op = X_WRITE;
    req->size = header_size;
    req->offset = 0;
    data = xseg_get_data(peer->xseg, req);
    memcpy(data, &hdr, header_size);

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      req, pr, map->volume);
        goto out_put;
    }
  out:
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int write_map_metadata(struct peer_req *pr, struct map *map)
{
    int err;
    struct xseg_request *req;

    map->state |= MF_MAP_WRITING;
    req = __write_map_metadata(pr, map);
    if (!req) {
        map->state &= ~MF_MAP_WRITING;
        return -1;
    }
    wait_on_pr(pr, (!((req->state & XS_FAILED) || (req->state & XS_SERVED))));
    map->state &= ~MF_MAP_WRITING;
    err = req->state & XS_FAILED;
    put_request(pr, req);
    if (err) {
        return -1;
    }
    return 0;
}

/*
int write_map_data(struct peer_req *pr, struct map *map)
{
}
*/

int write_map(struct peer_req *pr, struct map *map)
{
    int r;
    map->state |= MF_MAP_WRITING;
    struct mapper_io *mio = __get_mapper_io(pr);

    mio->cb = NULL;
    mio->err = 0;

    r = map->mops->write_map_data(pr, map);
    if (r < 0) {
        map->state &= ~MF_MAP_WRITING;
        return r;
    }
    map->state &= ~MF_MAP_WRITING;

    return write_map_metadata(pr, map);
}


int delete_map_data(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    map->state |= MF_MAP_DELETING_DATA;

    flogger_info(logger, "Deleting map data for %s (epoch %llu)",
                 map->volume, map->epoch);
    mio->cb = NULL;
    mio->err = 0;

    r = map->mops->delete_map_data(pr, map);

    map->state &= ~MF_MAP_DELETING_DATA;
    flogger_info(logger, "Deleted map data for %s (epoch %llu)",
                 map->volume, map->epoch);
    return r;
}

struct xseg_request *__purge_map(struct peer_req *pr, struct map *map)
{
    int r;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    uint64_t datalen;

    flogger_info(logger, "Purging map %s", map->volume);

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
    if (!req) {
        flogger_error(logger, "Cannot get request for map %s", map->volume);
        goto out_err;
    }


    req->op = X_DELETE;
    req->size = 0;
    req->offset = 0;

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      req, pr, map->volume);
        goto out_put;
    }

    flogger_info(logger, "Map %s purging ", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int purge_map(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;

    map->state |= MF_MAP_PURGING;

    r = delete_map(pr, map, 1);
    if (r < 0) {
        flogger_error(logger, "Failed to purge map %s", map->volume);
        map->state &= ~MF_MAP_PURGING;
        return -1;
    }

    req = __purge_map(pr, map);
    if (!req) {
        goto out_err;
    }
    wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
    if (req->state & XS_FAILED) {
        goto out_put;
    }

    map->state &= ~MF_MAP_PURGING;
    put_request(pr, req);
    flogger_info(logger, "Purged map %s", map->volume);
    return 0;

  out_put:
    put_request(pr, req);
  out_err:
    flogger_error(logger, "Failed to purge map %s", map->volume);
    map->state &= ~MF_MAP_PURGING;
    return -1;
}

int delete_map(struct peer_req *pr, struct map *map, int delete_data)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);

    map->state |= MF_MAP_DELETING;

    mio->cb = NULL;
    mio->pending_reqs = 0;

    map->flags |= MF_MAP_DELETED;
    r = write_map_metadata(pr, map);
    if (r < 0) {
        map->flags &= ~MF_MAP_DELETED;
        map->state &= ~MF_MAP_DELETING;
        flogger_error(logger, "Failed to delete map %s", map->volume);
        return -1;
    }
    flogger_info(logger, "Deleted map %s", map->volume);

    if (delete_data) {
        r = delete_map_data(pr, map);
        if (r < 0) {
            //not fatal. Just log warning
            flogger_error(logger, "Delete map data failed for %s", map->volume);
        }
    }
    map->state &= ~MF_MAP_DELETING;
    return 0;
}

struct xseg_request *__load_map_metadata(struct peer_req *pr, struct map *map)
{
    int r;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    uint64_t datalen;

    flogger_info(logger, "Loading map metadata %s", map->volume);

    datalen = MAX_MAPHEADER_SIZE;
    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
                      datalen);
    if (!req) {
        flogger_error(logger, "Cannot get request for map %s", map->volume);
        goto out_err;
    }


    req->op = X_READ;
    req->size = datalen;
    req->offset = 0;

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      req, pr, map->volume);
        goto out_put;
    }

    flogger_info(logger, "Map %s loading metadata", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int load_map_metadata(struct peer_req *pr, struct map *map)
{
    int type, r = 0;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    char *data;
    uint32_t version;
    uint32_t signature;
    uint32_t assume_v0 = pr->req->flags & XF_ASSUMEV0;
    uint32_t signature_on_disk;
    uint32_t version1_on_disk;


    req = __load_map_metadata(pr, map);
    if (!req) {
        goto out_err;
    }
    wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
    if (req->state & XS_FAILED) {
        goto out_put;
    }
    if (req->serviced < req->size) {
        goto out_put;
    }

    data = xseg_get_data(peer->xseg, req);
    if (!data) {
        goto out_put;
    }

    signature_on_disk = __cpu_to_be32(MAP_SIGNATURE);
    version1_on_disk = __cpu_to_le32(MAP_V1);
    if (memcmp(data, &signature_on_disk, sizeof(MAP_SIGNATURE))) {
        if (assume_v0) {
            /* assume v0 */
            version = MAP_V0;
        } else if (!memcmp(data, &version1_on_disk, sizeof(uint32_t))) {
            version = MAP_V1;
        } else {
            flogger_error(logger, "No signature found");
            goto out_put;
        }
    } else {
        struct header_struct *hdr = (struct header_struct *) data;
        version = __be32_to_cpu(hdr->version);
    }

    switch (version) {
    case MAP_V0:
        r = read_map_header_v0(map, (struct v0_header_struct *) data);
        break;
    case MAP_V1:
        flogger_error(logger, "Mapfile version 1 is deprecated and no longer supported");
        r = -ENOTSUP;
        break;
    case MAP_V2:
        r = read_map_header_v2(map, (struct v2_header_struct *) data);
        break;
    case MAP_V3:
        r = read_map_header_v3(map, (struct v3_header_struct *) data);
        break;
    default:
        flogger_error(logger, "Loaded invalid version %u > "
                      "latest version %u", version, MAP_LATEST_VERSION);
        goto out_put;
    }
    if (r < 0) {
        goto out_put;
    }

    put_request(pr, req);

    if (!is_valid_blocksize(map->blocksize)) {
        flogger_error(logger, "%s has Invalid blocksize %llu", map->volume,
                      map->blocksize);
        goto out_err;
    }

    return 0;

  out_put:
    put_request(pr, req);
  out_err:
    flogger_error(logger, "Load map version for map %s failed", map->volume);
    return -1;
}

int load_map(struct peer_req *pr, struct map *map)
{
    //struct xseg_request *req;
    int r;
    struct map prev_map;
    uint64_t v0_size = NO_V0SIZE;
    uint64_t nr_objs = 0;

    flogger_info(logger, "Loading map %s", map->volume);

    map->state |= MF_MAP_LOADING;

    r = load_map_metadata(pr, map);
    if (r < 0) {
        goto out_err;
    }
    flogger_debug(logger, "Loaded map metadata. Found map version %u",
                  map->version);
    r = map->mops->load_map_data(pr, map);
    if (r < 0) {
        goto out_err;
    }

    v0_size = pr->req->v0_size;
    if (map->version == MAP_V0 && v0_size != NO_V0SIZE) {
        nr_objs = __calc_map_obj(v0_size, MAPPER_DEFAULT_BLOCKSIZE);
        if (map->nr_objs != nr_objs) {
            flogger_error(logger, "Size of v0 map invalid. "
                          "Read %llu objs vs %llu expected", map->nr_objs, nr_objs);
            goto out_err;
        } else {
            map->size = v0_size;
        }
    }

    if (map->version != MAP_LATEST_VERSION && (map->state & MF_MAP_EXCLUSIVE)) {
        /* update map to the latest version */
        prev_map = *map;
        /* Change necessary fields to update map */
        map->version = MAP_LATEST_VERSION;
        map->mops = MAP_LATEST_MOPS;
        r = write_map(pr, map);
        if (r < 0) {
            flogger_error(logger, "Could not update map %s to latest version",
                          map->volume);
            map->version = prev_map.version;
            map->mops = prev_map.mops;
            goto out_err;
        }
        /* It is safe to delete old map data, since map data from version 3 and
         * onwards are epoched.
         */
        r = delete_map_data(pr, &prev_map);
        if (r < 0) {
            flogger_warn(logger, "Could not delete old map data for map %s",
                         map->volume);
        }
    }

    map->state &= ~MF_MAP_LOADING;
    map->state |= MF_MAP_LOADED;
    flogger_info(logger, "Loading map %s completed", map->volume);

    return 0;

  out_err:
    flogger_error(logger, "Loading of map %s failed", map->volume);
    map->state &= ~MF_MAP_LOADING;
    restore_map(map);
    return -1;
}

static int copyup_copy_cb(struct peer_req *pr, struct xseg_request *req,
                            struct req_ctx *req_ctx)
{
    int r;
    struct peerd *peer = pr->peer;
    struct map *map;
    struct xseg_request *wreq;
    struct mapper_io *mio = __get_mapper_io(pr);

    req_ctx->orig_mapping->state &= ~MF_OBJECT_COPYING;

    map = req_ctx->map;
    //assert(map);
    if (!map) {
        return -1;
    }

    wreq = map->mops->prepare_write_object(pr, map, req_ctx->obj_idx, &req_ctx->copyup_mapping);
    if (!wreq) {
        flogger_error(logger,
                     "Cannot prepare write object request for object %llu of "
                     "map %s",
                     (unsigned long long)req_ctx->obj_idx, map->volume);
        return -EIO;
    }

    r = set_req_ctx(mio, wreq, req_ctx);
    if (r < 0) {
        flogger_error(logger, "Cannot set request ctx");
        goto out_put;
    }

    r = send_request(pr, wreq);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      wreq, pr, map->volume);
        goto out_unset_ctx;
    }

    flogger_info(logger, "Writing object %llu of map: %s",
                 (unsigned long long)req_ctx->obj_idx, map->volume);

    req_ctx->orig_mapping->state |= MF_OBJECT_WRITING;

    return 0;

out_unset_ctx:
    remove_req_ctx(mio, wreq);
out_put:
    put_request(pr, wreq);

    return -1;
}

static int copyup_write_cb(struct peer_req *pr, struct xseg_request *req,
                             struct req_ctx *req_ctx)
{
    //assert(req_ctx->orig_mapping)
    //assert(req_ctx->orig_mapping->state & MF_OBJECT_WRITING)

    // update mapping on cache
    req_ctx->orig_mapping->flags = req_ctx->copyup_mapping.flags;
    req_ctx->orig_mapping->vol_epoch = req_ctx->copyup_mapping.vol_epoch;
    req_ctx->orig_mapping->name_idx = req_ctx->copyup_mapping.name_idx;

    req_ctx->orig_mapping->state &= ~MF_OBJECT_WRITING;
    return 0;
}


void copyup_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct req_ctx *req_ctx;
    struct mapping *m;

    req_ctx = get_req_ctx(mio, req);
    if (!req_ctx) {
        flogger_error(logger, "Cannot get request ctx");
        goto out_err;
    }

    remove_req_ctx(mio, req);

    m = req_ctx->orig_mapping;

    if (req->state & XS_FAILED) {
        flogger_error(logger, "Req failed");
        m->state &= ~MF_OBJECT_COPYING;
        m->state &= ~MF_OBJECT_WRITING;
        goto out_err;
    }

    if (req->op == X_WRITE) {
        if (copyup_write_cb(pr, req, req_ctx) < 0) {
            goto out_err;
        }
        flogger_info(logger, "Object write of %llu completed successfully",
                     req_ctx->obj_idx);

        mio->pending_reqs--;
        signal_mapping(req_ctx->orig_mapping);
        free(req_ctx);
        signal_pr(pr);
    } else if (req->op == X_COPY) {
        if (copyup_copy_cb(pr, req, req_ctx) < 0) {
            goto out_err;
        }
        flogger_info(logger, "Object copy up completed. Pending writing.");
    } else {
        //wtf??
        ;
    }

out:
    put_request(pr, req);
    return;

out_err:
    mio->pending_reqs--;
    flogger_debug(logger, "Mio->pending_reqs: %u", mio->pending_reqs);
    mio->err = 1;
    if (req_ctx->orig_mapping) {
        signal_mapping(req_ctx->orig_mapping);
    }
    free(req_ctx);
    signal_pr(pr);
    goto out;
}

struct xseg_request *copyup_object(struct peer_req *pr, struct map *map,
                                   uint64_t obj_idx)
{
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct mapping copyup_mapping;
    struct xseg_request *req;
    struct xseg_request_copy *xcopy;
    struct req_ctx *req_ctx;
    uint32_t new_target_len = MAX_OBJECT_LEN + 1, orig_target_len = MAX_OBJECT_LEN + 1;
    char new_target[MAX_OBJECT_LEN + 1], orig_target[MAX_OBJECT_LEN + 1];
    int r = -1;


    if (obj_idx >= map->nr_objs) {
        return NULL;
    }

    req_ctx = calloc(1, sizeof(struct req_ctx));
    if (!req_ctx) {
        return NULL;
    }

    req_ctx->obj_idx = obj_idx;
    req_ctx->map = map;
    req_ctx->orig_mapping = &map->objects[obj_idx];
    req_ctx->copyup_mapping = map->objects[obj_idx];

    //assert(!(req_ctx->orig_mapping->flags & MF_OBJECT_WRITABLE));

    req_ctx->copyup_mapping.flags = MF_OBJECT_WRITABLE | MF_OBJECT_ARCHIP;
    req_ctx->copyup_mapping.name_idx = map->cur_vol_idx;
    req_ctx->copyup_mapping.vol_epoch = map->epoch;

    r = calculate_object_name(new_target, &new_target_len, map,
                              &req_ctx->copyup_mapping, obj_idx);
    if (r < 0) {
        goto out_err;
    }

    flogger_debug(logger, "New target: %s (len: %d)", new_target, new_target_len);

    if (req_ctx->orig_mapping->flags & MF_OBJECT_ZERO) {
        flogger_info(logger, "Copy up of zero block is not needed. "
                     "Proceeding in writing the new object in map");

        req = map->mops->prepare_write_object(pr, map, obj_idx, &req_ctx->copyup_mapping);
        if (!req) {
            flogger_error(logger,
                         "Cannot prepare write object request for object %llu "
                         "of map %s",
                         (unsigned long long)req_ctx->obj_idx, map->volume);
            goto out_err;
        }

        req_ctx->orig_mapping->state |= MF_OBJECT_WRITING;


    } else {
        r = calculate_object_name(orig_target, &orig_target_len, map,
                req_ctx->orig_mapping, obj_idx);
        if (r < 0) {
            goto out_err;
        }

        req = get_request(pr, mapper->bportno, new_target, new_target_len,
                sizeof(struct xseg_request_copy));

        xcopy = (struct xseg_request_copy *)xseg_get_data(peer->xseg, req);
        strncpy(xcopy->target, orig_target, orig_target_len);
        xcopy->targetlen = orig_target_len;

        req->offset = 0;
        req->size = map->blocksize;
        req->op = X_COPY;
    }

    r = set_req_ctx(mio, req, req_ctx);
    if (r < 0) {
        flogger_error(logger, "Cannot set request ctx");
        goto out_put;
    }

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                      req, pr, map->volume);
        goto out_unset_ctx;
    }

    if (req_ctx->orig_mapping->flags & MF_OBJECT_ZERO) {
        req_ctx->orig_mapping->state |= MF_OBJECT_WRITING;
        flogger_info(logger, "Object %s copy up completed. Pending writing.",
                     orig_target);
    } else {
        req_ctx->orig_mapping->state |= MF_OBJECT_COPYING;
        flogger_info(logger, "Copying up object %s to %s", orig_target,
                     new_target);
    }

    return req;


out_unset_ctx:
    remove_req_ctx(mio, req);
out_put:
    put_request(pr, req);
out_err:
    if (req_ctx->orig_mapping->flags & MF_OBJECT_ZERO) {
        flogger_error(logger, "Copying up zero object to %s failed", new_target);
    } else {
        flogger_error(logger, "Copying up object %s to %s failed",
                      orig_target, new_target);
    }

    req_ctx->orig_mapping->state &= ~MF_OBJECT_COPYING;
    req_ctx->orig_mapping->state &= ~MF_OBJECT_WRITING;

    free(req_ctx);

    return NULL;
}

void object_delete_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);
    struct peerd *peer = pr->peer;
    struct req_ctx *req_ctx;

    req_ctx = get_req_ctx(mio, req);
    if (!req_ctx) {
        flogger_error(logger, "Cannot get request context");
        mio->err = 1;
        goto out_err;
    }

    remove_req_ctx(mio, req);

    req_ctx->orig_mapping->state &= ~MF_OBJECT_DELETING;

    if (req->state & XS_FAILED) {
        flogger_error(logger, "Req failed");
        goto out_err;
    }

    req_ctx->orig_mapping->flags |= MF_OBJECT_DELETED;
    flogger_info(logger, "Deletion of object %llu of map %s completed.",
                 req_ctx->obj_idx, req_ctx->map);
    mio->pending_reqs--;
    signal_mapping(req_ctx->orig_mapping);
    signal_pr(pr);

  out:
    put_request(pr, req);
    return;

  out_err:
    mio->pending_reqs--;
    flogger_debug(logger, "Mio->pending_reqs: %u", mio->pending_reqs);
    mio->err = 1;
    signal_mapping(req_ctx->orig_mapping);
    signal_pr(pr);
    goto out;
}


struct xseg_request *object_delete(struct peer_req *pr, struct map *map,
                                   uint64_t obj_idx)
{
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    struct req_ctx *req_ctx;
    uint32_t orig_target_len = MAX_OBJECT_LEN + 1;
    char orig_target[MAX_OBJECT_LEN + 1];
    int r;

    if (obj_idx >= map->nr_objs) {
        return NULL;
    }

    req_ctx = calloc(1, sizeof(struct req_ctx));
    if (!req_ctx) {
        return NULL;
    }

    req_ctx->obj_idx = obj_idx;
    req_ctx->map = map;
    req_ctx->orig_mapping = &map->objects[obj_idx];

    r = calculate_object_name(orig_target, &orig_target_len, map,
                              req_ctx->orig_mapping, obj_idx);
    if (r < 0) {
        goto out_err;
    }

    flogger_info(logger, "Deleting object %s", orig_target);

    req = get_request(pr, mapper->bportno, orig_target, orig_target_len, 0);
    if (!req) {
        flogger_error(logger, "Cannot get request for object %llu", obj_idx);
        goto out_err;
    }

    req->op = X_DELETE;
    req->size = 0;
    req->offset = 0;

    r = set_req_ctx(mio, req, req_ctx);
    if (r < 0) {
        flogger_error(logger, "Cannot set request ctx");
        goto out_put;
    }

    r = send_request(pr, req);
    if (r < 0) {
        flogger_error(logger, "Cannot send request %p, pr: %p, object: %s",
                 req, pr, orig_target);
        goto out_unset_ctx;
    }

    req_ctx->orig_mapping->flags |= MF_OBJECT_DELETING;
    flogger_info(logger, "Object %s deletion pending", orig_target);

    mio->pending_reqs++;

    return req;

out_unset_ctx:
    remove_req_ctx(mio, req);
out_put:
    put_request(pr, req);
out_err:
    free(req_ctx);
    flogger_info(logger, "Object %llu deletion failed", obj_idx);
    return NULL;
}

#if 0
void hash_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);
    struct peerd *peer = pr->peer;
    struct mapping *mn = __get_node(mio, req);
    struct xseg_reply_hash *xreply;

    flogger_info(logger, "Callback of req %p", req);

    if (!mn) {
        flogger_error(logger, "Cannot get mapping");
        mio->err = 1;
        goto out_nonode;
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

    xreply = (struct xseg_reply_hash *) xseg_get_data(peer->xseg, req);
    if (xreply->targetlen != HEXLIFIED_SHA256_DIGEST_SIZE) {
        flogger_error(logger, "Reply targetlen != HEXLIFIED_SHA256_DIGEST_SIZE");
        mio->err = 1;
        goto out;
    }

    strncpy(mn->object, xreply->target, HEXLIFIED_SHA256_DIGEST_SIZE);
    mn->object[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
    mn->objectlen = HEXLIFIED_SHA256_DIGEST_SIZE;
    flogger_debug(logger, "Received hash object %llu: %s (%p)",
             mn->objectidx, mn->object, mn);
    mn->flags = 0;

  out:
    put_mapping(mn);
    __set_node(mio, req, NULL);
  out_nonode:
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}


int __hash_map(struct peer_req *pr, struct map *map, struct map *hashed_map)
{
    struct mapperd *mapper = __get_mapperd(pr->peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    uint64_t i;
    struct mapping *mn, *hashed_mn;
    struct xseg_request *req;
    int r;

    mio->priv = 0;

    for (i = 0; i < map->nr_objs; i++) {
        mn = get_mapping(map, i);
        if (!mn) {
            flogger_error(logger, "Cannot get mapping %llu of map %s ",
                     "(nr_objs: %llu)", i, map->volume, map->nr_objs);
            return -1;
        }
        hashed_mn = get_mapping(hashed_map, i);
        if (!hashed_mn) {
            flogger_error(logger, "Cannot get mapping %llu of map %s ",
                     "(nr_objs: %llu)", i, hashed_map->volume,
                     hashed_map->nr_objs);
            put_mapping(mn);
            return -1;
        }
        if (!(mn->flags & MF_OBJECT_ARCHIP)) {
            mio->priv++;
            strncpy(hashed_mn->object, mn->object, mn->objectlen);
            hashed_mn->objectlen = mn->objectlen;
            hashed_mn->object[hashed_mn->objectlen] = 0;
            hashed_mn->flags = mn->flags;

            put_mapping(mn);
            put_mapping(hashed_mn);
            continue;
        }

        req = get_request(pr, mapper->bportno, mn->object, mn->objectlen, 0);
        if (!req) {
            flogger_error(logger, "Cannot get request for map %s", map->volume);
            put_mapping(mn);
            put_mapping(hashed_mn);
            return -1;
        }

        req->op = X_HASH;
        req->offset = 0;
        req->size = map->blocksize;
        r = __set_node(mio, req, hashed_mn);
        if (r < 0) {
            flogger_error(logger, "Cannot set node");
            put_request(pr, req);
            put_mapping(mn);
            put_mapping(hashed_mn);
            return -1;
        }

        r = send_request(pr, req);
        if (r < 0) {
            flogger_error(logger, "Cannot send request %p, pr: %p, map: %s",
                     req, pr, map->volume);
            put_request(pr, req);
            __set_node(mio, req, NULL);
            put_mapping(mn);
            put_mapping(hashed_mn);
            return -1;
        }
        mio->pending_reqs++;
        put_mapping(mn);
    }

    return 0;
}

int hash_map(struct peer_req *pr, struct map *map, struct map *hashed_map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);

    flogger_info(logger, "Hashing map %s", map->volume);
    map->state |= MF_MAP_HASHING;
    mio->pending_reqs = 0;
    mio->cb = hash_cb;
    mio->err = 0;


    r = __hash_map(pr, map, hashed_map);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    mio->cb = NULL;
    map->state &= ~MF_MAP_HASHING;
    if (mio->err) {
        flogger_error(logger, "Hashing map %s failed", map->volume);
        return -1;
    } else {
        flogger_info(logger, "Hashing map %s completed", map->volume);
        return 0;
    }
}
#endif
