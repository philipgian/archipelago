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

#include <mapper.h>
#include <asm/byteorder.h>

static uint32_t nr_reqs = 0;
static uint32_t waiters_for_req = 0;
st_cond_t req_cond;
char buf[XSEG_MAX_TARGETLEN + 1];

char *null_terminate(char *target, uint32_t targetlen)
{
    if (targetlen > XSEG_MAX_TARGETLEN) {
        return NULL;
    }
    strncpy(buf, target, targetlen);
    buf[targetlen] = '\0';
    return buf;
}

#define wait_for_req() \
	do{ \
		ta--; \
		waiters_for_req++; \
		flogger_debug(logger, "Waiting for request. Waiters: %u", \
		       	      waiters_for_req); \
		st_cond_wait(req_cond); \
	}while(0)

#define signal_one_req() \
	do { \
		if (waiters_for_req) { \
			ta++; \
			waiters_for_req--; \
			flogger_debug(logger, "Siganling one request. Waiters: %u", \
                          waiters_for_req); \
			st_cond_signal(req_cond); \
		} \
	}while(0)

struct xseg_request *get_request(struct peer_req *pr, xport dst, char *target,
                                 uint32_t targetlen, uint64_t datalen)
{
    int r;
    struct peerd *peer = pr->peer;
    struct xseg_request *req;
    char *reqtarget;
  retry:
    req = xseg_get_request(peer->xseg, pr->portno, dst, X_ALLOC);
    if (!req) {
        if (!nr_reqs) {
            flogger_error(logger, "Cannot allocate request for target %s",
                          null_terminate(target, targetlen));
            return NULL;
        } else {
            wait_for_req();
            goto retry;
        }
    }
    r = xseg_prep_request(peer->xseg, req, targetlen, datalen);
    if (r < 0) {
        xseg_put_request(peer->xseg, req, pr->portno);
        if (!nr_reqs) {
            flogger_error(logger, "Cannot prepare request for target",
                          null_terminate(target, targetlen));
            return NULL;
        } else {
            wait_for_req();
            goto retry;
        }
    }

    reqtarget = xseg_get_target(peer->xseg, req);
    if (!reqtarget) {
        xseg_put_request(peer->xseg, req, pr->portno);
        return NULL;
    }
    strncpy(reqtarget, target, req->targetlen);

    nr_reqs++;
    return req;
}

void put_request(struct peer_req *pr, struct xseg_request *req)
{
    struct peerd *peer = pr->peer;
    xseg_put_request(peer->xseg, req, pr->portno);
    nr_reqs--;
    signal_one_req();
}

int send_request(struct peer_req *pr, struct xseg_request *req)
{
	int r;
	struct peerd *peer = pr->peer;
	void *dummy;

	r = xseg_set_req_data(peer->xseg, req, pr);
	if (r < 0){
		flogger_error(logger, "Cannot set request data for req %p, pr: %p",
                      req, pr);
		return -1;
	}
	xport p = xseg_submit(peer->xseg, req, pr->portno, X_ALLOC);
	if (p == NoPort){
		flogger_error(logger, "Cannot submit request %p, pr: %p",
                      req, pr);
		xseg_get_req_data(peer->xseg, req, &dummy);
		return -1;
	}
	r = xseg_signal(peer->xseg, p);
	if (r < 0)
		flogger_warn(logger, "Cannot signal port %u", p);

	return 0;
}

int resize_request(struct peer_req *pr, struct xseg_request *req, uint64_t size)
{
	int r;
	struct peerd *peer = pr->peer;
    char *target;
    char buf[XSEG_MAX_TARGETLEN];

    target = xseg_get_target(peer->xseg, pr->req);
    strncpy(buf, target, pr->req->targetlen);
    r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen, size);
    if (r < 0) {
        flogger_error(logger, "Cannot resize request");
        return -ENOMEM;
    }
    target = xseg_get_target(peer->xseg, pr->req);
    strncpy(target, buf, pr->req->targetlen);

    return 0;
}

static char * get_cas_name(struct map *map, uint64_t idx)
{
    if (map->cas_array == NULL || idx >= map->cas_nr) {
        return NULL;
    }

    return map->cas_names[idx];
}

static struct vol_idx * get_vol_name(struct map *map, uint64_t idx)
{
    if (map->vol_array == NULL || idx >= map->vol_nr) {
        return NULL;
    }

    return &map->vol_names[idx];
}

int calculate_object_name(char *object, uint32_t *object_len, struct map *map,
                          struct mapping *m, uint64_t obj_idx)
{
    if (m->flags & MF_OBJECT_ZERO) {
        // zero objects should not have names
        // do not call this if object is zero;
        return -EINVAL;
    } else if (m->flags & MF_OBJECT_V1) {
        // CAS object
        char *cas_object;

        cas_object = get_cas_name(map, m->name_idx);
        if (!cas_object) {
            return -EINVAL;
        }

        if (*object_len < MAPPER_PREFIX_LEN + map->hex_cas_size + 1) {
            return -ERANGE;
        }

        memcpy(object, MAPPER_PREFIX, MAPPER_PREFIX_LEN);
        memcpy(object + MAPPER_PREFIX_LEN, cas_object, map->hex_cas_size);
        object[MAPPER_PREFIX_LEN + map->hex_cas_size] = '\0';

        *object_len = MAPPER_PREFIX_LEN + map->hex_cas_size;

    } else if (m->flags & MF_OBJECT_ARCHIP) {
        int r;
        uint64_t be_epoch = __cpu_to_be64(m->vol_epoch);
        uint64_t be_index = __cpu_to_be64(obj_idx);
        char hexlified_index[HEXLIFIED_INDEX_LEN + 1];
        char hexlified_epoch[HEXLIFIED_EPOCH_LEN + 1];
        char *vol_name;
        struct vol_idx *vi;

        vi = get_vol_name(map, m->name_idx);
        if (!vi) {
            return -EINVAL;
        }

        hexlify((unsigned char *)&be_index, sizeof(be_index), hexlified_index);
        hexlified_epoch[HEXLIFIED_EPOCH_LEN] = '\0';
        hexlify((unsigned char *)&be_epoch, sizeof(be_epoch), hexlified_epoch);
        hexlified_index[HEXLIFIED_INDEX_LEN] = '\0';

        r = snprintf(object, *object_len, "%.*s_%s_%s",
                     vi->len, vi->name, hexlified_epoch, hexlified_index);
        if (r < 0) {
            return r;
        } else if (r >= *object_len) {
            return -ERANGE;
        } else {
            *object_len = r;
        }

        return 0;
    } else {
        // CAS object
        char *cas_object;

        cas_object = get_cas_name(map, m->name_idx);
        if (!cas_object) {
            return -EINVAL;
        }

        if (*object_len < map->hex_cas_size + 1) {
            return -ERANGE;
        }

        memcpy(object, cas_object, map->hex_cas_size);
        object[map->hex_cas_size] = '\0';

        *object_len = map->hex_cas_size;

        return 0;
    }
}

int get_object_name(char *object, uint32_t *object_len, struct map *map,
                    uint64_t idx)
{
    struct mapping *m;

    if (idx >= map->nr_objs) {
        return -EINVAL;
    }

    m = &map->objects[idx];
    if (m->flags & MF_OBJECT_ZERO) {
        return 1;
    }

    return calculate_object_name(object, object_len, map, m, idx);
}
