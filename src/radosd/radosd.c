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
#include <unistd.h>
#include <xseg/xseg.h>
#include <rados/librados.h>
#include <xseg/protocol.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <errno.h>
#include <hash.h>
#include <peer2.h>
#include <assert.h>
#include <util.h>

#define LOCK_SUFFIX "_lock"
#define LOCK_SUFFIX_LEN 5
#define HASH_SUFFIX "_hash"
#define HASH_SUFFIX_LEN 5

#define MAX_POOL_NAME 64
#define MAX_CEPHXID_NAME 256
#define MAX_OBJ_NAME (XSEG_MAX_TARGETLEN + LOCK_SUFFIX_LEN + 1)
#define RADOS_LOCK_NAME "RadosLock"
//#define RADOS_LOCK_COOKIE "Cookie"
#define RADOS_LOCK_COOKIE "foo"
#define RADOS_LOCK_TAG ""
#define RADOS_LOCK_DESC ""

void custom_peer_usage()
{
    fprintf(stderr, "Custom peer options:\n"
                    "--pool: Rados pool to connect\n"
                    "--cephx-id: Cephx id\n");
}

enum rados_state {
    ACCEPTED = 0,
    PENDING = 1,
    READING = 2,
    WRITING = 3,
    STATING = 4,
    PREHASHING = 5,
    POSTHASHING= 6
};

struct radosd {
    rados_t cluster;
    rados_ioctx_t ioctx;
    char pool[MAX_POOL_NAME + 1];
};

struct rados_io {
    char obj_name[MAX_OBJ_NAME + 1];
    char second_name[MAX_OBJ_NAME + 1];
    enum rados_state state;
    uint64_t size;
    char *buf;
    uint64_t read;
    uint64_t watch_handle;
    pthread_t tid;
    pthread_cond_t cond;
    pthread_mutex_t m;

    int aio_ret;
};


static void rados_cb(rados_completion_t c, void *arg)
{
    struct peer_req *pr = (struct peer_req*)arg;
    struct peerd *peer;
    int ret;
    struct rados_io *rio;

    assert(pr);
    peer = pr->peer;

    assert(peer);
    rio = (struct rados_io *)pr->priv;

    assert(rio);

    archipelago_mutex_lock(&rio->m);

    rados_aio_release(c);
    rio->aio_ret = rados_aio_get_return_value(c);

    archipelago_mutex_unlock(&rio->m);

    thread_pool_submit_work(peer->pool, pr);
}

static void rados_ack_cb(rados_completion_t c, void *arg)
{
    rados_cb(c, arg);
}

static void rados_commit_cb(rados_completion_t c, void *arg)
{
    rados_cb(c, arg);
}

static int do_aio_generic(struct peerd *peer, struct peer_req *pr, uint32_t op,
                          char *target, char *buf, uint64_t size,
                          uint64_t offset)
{
    struct radosd *rados = (struct radosd *)peer->priv;
    struct rados_io *rio = (struct rados_io *)pr->priv;
    int r;
    rados_completion_t rados_compl;

    switch (op) {
    case X_READ:
        r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
        if (r < 0) {
            return r;
        }
        r = rados_aio_read(rados->ioctx, target, rados_compl, buf, size, offset);
        break;
    case X_WRITE:
        r = rados_aio_create_completion(pr, NULL, rados_commit_cb, &rados_compl);
        if (r < 0) {
            return r;
        }
        r = rados_aio_write(rados->ioctx, target, rados_compl, buf, size, offset);
        break;
    case X_DELETE:
        r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
        if (r < 0) {
            return r;
        }
        r = rados_aio_remove(rados->ioctx, target, rados_compl);
        break;
    case X_INFO:
        r = rados_aio_create_completion(pr, rados_ack_cb, NULL, &rados_compl);
        if (r < 0) {
            return r;
        }
        r = rados_aio_stat(rados->ioctx, target, rados_compl, &rio->size, NULL);
        break;
    default:
        // assert(0);
        return -EINVAL;
        break;
    }

    if (r < 0) {
        rados_aio_release(rados_compl);
    }

    return r;
}

static int do_aio_read(struct peerd *peer, struct peer_req *pr)
{
    struct xseg_request *req = pr->req;
    struct rados_io *rio = (struct rados_io *) pr->priv;
    char *data = xseg_get_data(peer->xseg, pr->req);

    return do_aio_generic(peer, pr, X_READ, rio->obj_name, data + req->serviced,
                          req->size - req->serviced, req->offset + req->serviced);
}

static int do_aio_write(struct peerd *peer, struct peer_req *pr)
{
    struct xseg_request *req = pr->req;
    struct rados_io *rio = (struct rados_io *) pr->priv;
    char *data = xseg_get_data(peer->xseg, pr->req);

    return do_aio_generic(peer, pr, X_WRITE, rio->obj_name, data + req->serviced,
                          req->size - req->serviced, req->offset + req->serviced);
}

static int handle_delete(struct peer_req *pr)
{
    int r;
    struct peerd *peer = pr->peer;
    struct rados_io *rio = (struct rados_io *)pr->priv;

    switch (rio->state) {
    case ACCEPTED:
        XSEGLOG2(&lc, I, "Deleting %s", rio->obj_name);
        rio->state = PENDING;
        r = do_aio_generic(peer, pr, X_DELETE, rio->obj_name, NULL, 0, 0);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
            return r;
        }
        return 1;
    case PENDING:
        if (rio->aio_ret < 0) {
            XSEGLOG2(&lc, E, "Deletion of %s failed", rio->obj_name);
        } else {
            XSEGLOG2(&lc, I, "Deletion of %s completed", rio->obj_name);
        }

        return rio->aio_ret;
    default:
        assert(0);
    }

//    return -EINVAL;
}

static int handle_info(struct peer_req *pr)
{
    int r;
    struct peerd *peer = pr->peer;
    struct xseg_request *req = pr->req;
    struct rados_io *rio = (struct rados_io *)pr->priv;
    char *req_data;
    struct xseg_reply_info *xinfo;
    char buf[XSEG_MAX_TARGETLEN + 1];
    char *target;

    switch (rio->state) {
    case ACCEPTED:
        XSEGLOG2(&lc, I, "Getting info of %s", rio->obj_name);
        r = do_aio_generic(peer, pr, X_INFO, rio->obj_name, NULL, 0, 0);
        rio->state = PENDING;
        if (r < 0) {
            XSEGLOG2(&lc, E, "Getting info of %s failed", rio->obj_name);
            return r;
        }
        return 1;
    case PENDING:
        if (req->datalen < sizeof(struct xseg_reply_info)) {
            target = xseg_get_target(peer->xseg, req);
            strncpy(buf, target, req->targetlen);
            r = xseg_resize_request(peer->xseg, req, req->targetlen,
                                    sizeof(struct xseg_reply_info));
            if (r < 0) {
                XSEGLOG2(&lc, E, "Cannot resize request");
                return -ENOMEM;
            }
            target = xseg_get_target(peer->xseg, req);
            strncpy(target, buf, req->targetlen);
        }

        req_data = xseg_get_data(peer->xseg, req);
        xinfo = (struct xseg_reply_info *)req_data;

        if (rio->aio_ret < 0) {
            xinfo->size = 0;
            XSEGLOG2(&lc, E, "Getting info of %s failed", rio->obj_name);
        } else {
            xinfo->size = rio->size;
            XSEGLOG2(&lc, I, "Getting info of %s completed", rio->obj_name);
        }

        return rio->aio_ret;
    default:
        assert(0);
    }

    return r;
}

static int handle_read(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    struct rados_io *rio = (struct rados_io *) (pr->priv);
    struct xseg_request *req = pr->req;
    char *data;
    int r;

    if (req->datalen < req->size) {
        XSEGLOG2(&lc, E, "Request datalen is less than req size");
        return -EINVAL;
    }

    switch (rio->state) {
    case ACCEPTED:
        if (!req->size) {
            return 0;
        }

        rio->state = READING;
        XSEGLOG2(&lc, I, "Reading %s", rio->obj_name);

        r = do_aio_read(peer, pr);
        if (r < 0) {
            XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read",
                        rio->obj_name);
            return r;
        }

        return 1;
    case READING:
        XSEGLOG2(&lc, I, "Reading of %s callback", rio->obj_name);
        data = xseg_get_data(peer->xseg, pr->req);
        if (rio->aio_ret > 0) {
            req->serviced += rio->aio_ret;
        } else if (rio->aio_ret == 0) {
            XSEGLOG2(&lc, I, "Reading of %s reached end of file at "
                "%llu bytes. Zeroing out rest", rio->obj_name,
                (unsigned long long) req->serviced);
            /* reached end of object. zero out rest of data
             * requested from this object
             */
            memset(data + req->serviced, 0, req->size - req->serviced);
            req->serviced = req->size;
        } else {
            XSEGLOG2(&lc, E, "Reading of %s failed", rio->obj_name);
            return rio->aio_ret;
        }

        if (req->serviced >= req->size) {
            XSEGLOG2(&lc, I, "Reading of %s completed", rio->obj_name);
            return 0;
        }

        if (!req->size) {
            /* should not happen */
            return -EIO;
        }

        /* resubmit */
        XSEGLOG2(&lc, I, "Resubmitting read of %s", rio->obj_name);
        r = do_aio_read(peer, pr);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Reading of %s failed on do_aio_read",
                    rio->obj_name);
            return r;
        }

        return 1;
    default:
        assert(0);
    }
}

static int handle_write(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    struct rados_io *rio = (struct rados_io *)(pr->priv);
    struct xseg_request *req = pr->req;
    int r;

    switch (rio->state) {
    case ACCEPTED:
        if (pr->req->datalen < pr->req->size) {
            XSEGLOG2(&lc, E, "Request datalen is less than req size");
            return -EINVAL;
        }

        rio->state = WRITING;
        XSEGLOG2(&lc, I, "Writing %s", rio->obj_name);

        r = do_aio_write(peer, pr);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Writing of %s failed on do_aio_write",
                    rio->obj_name);
            return r;
        }
        return 1;

    case WRITING:
        /* rados writes return 0 if write succeeded or < 0 if failed
         * no resubmission occurs
         */
        XSEGLOG2(&lc, I, "Writing of %s callback", rio->obj_name);

        if (rio->aio_ret == 0) {
            XSEGLOG2(&lc, I, "Writing of %s completed", rio->obj_name);
            req->serviced = req->size;
        } else {
            XSEGLOG2(&lc, E, "Writing of %s failed", rio->obj_name);
            req->serviced = 0;
        }
        return rio->aio_ret;
    default:
        assert(0);
    }
}

static int handle_copy(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    struct xseg_request *req = pr->req;
    struct rados_io *rio = (struct rados_io *) pr->priv;
    int r;
    unsigned int end;
    struct xseg_request_copy *xcopy;

    xcopy = (struct xseg_request_copy *)xseg_get_data(peer->xseg, req);

    switch (rio->state) {
    case ACCEPTED:

        if (xcopy->targetlen > MAX_OBJ_NAME) {
            return -EINVAL;
        }

        if (!req->size) {
            return 0;
        }

        strncpy(rio->second_name, xcopy->target, xcopy->targetlen);
        rio->second_name[xcopy->targetlen] = '\0';
        rio->read = 0;

        XSEGLOG2(&lc, I, "Copy of object %s to object %s started",
                rio->second_name, rio->obj_name);

        rio->buf = malloc(req->size);
        if (!rio->buf) {
            return -ENOMEM;
        }

        rio->state = READING;
        rio->read = 0;
        XSEGLOG2(&lc, I, "Reading %s", rio->second_name);
        r = do_aio_generic(peer, pr, X_READ, rio->second_name,
                           rio->buf + rio->read, req->size - rio->read,
                           req->offset + rio->read);
        if (r < 0) {
            XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read",
                     rio->obj_name);
            goto out;
        }
        return 1;

    case READING:
        XSEGLOG2(&lc, I, "Reading of %s callback", rio->obj_name);
        if (rio->aio_ret > 0) {
            rio->read += rio->aio_ret;
        } else if (rio->aio_ret == 0) {
            XSEGLOG2(&lc, I, "Reading of %s reached end of file at "
                     "%llu bytes. Zeroing out rest", rio->obj_name,
                     (unsigned long long)req->serviced);
            memset(rio->buf + rio->read, 0, req->size - rio->read);
            rio->read = req->size ;
        } else {
            XSEGLOG2(&lc, E, "Reading of %s failed", rio->second_name);
            r = rio->aio_ret;
            goto out;
        }

        if (rio->read >= req->size) {
            XSEGLOG2(&lc, I, "Reading of %s completed", rio->obj_name);
            //do_aio_write
            rio->state = WRITING;
            XSEGLOG2(&lc, I, "Writing %s", rio->obj_name);
            r = do_aio_generic(peer, pr, X_WRITE, rio->obj_name,
                               rio->buf, req->size, req->offset);
            if (r < 0) {
                XSEGLOG2(&lc, E, "Writing of %s failed on do_aio_write",
                         rio->obj_name);
                goto out;
            }

            return 1;
        }

        XSEGLOG2(&lc, I, "Resubmitting read of %s", rio->obj_name);
        r = do_aio_generic(peer, pr, X_READ, rio->second_name,
                           rio->buf + rio->read, req->size - rio->read,
                           req->offset + rio->read);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Reading of %s failed on do_aio_read",
                     rio->obj_name);
            goto out;
        }
        return 1;
    case WRITING:
        XSEGLOG2(&lc, I, "Writing of %s callback", rio->obj_name);
        if (rio->aio_ret == 0) {
            XSEGLOG2(&lc, I, "Writing of %s completed", rio->obj_name);
            XSEGLOG2(&lc, I, "Copy of object %s to object %s completed",
                     rio->second_name, rio->obj_name);
            req->serviced = req->size;
        } else {
            XSEGLOG2(&lc, E, "Writing of %s failed", rio->obj_name);
            XSEGLOG2(&lc, E, "Copy of object %s to object %s failed",
                     rio->second_name, rio->obj_name);
        }

        r = rio->aio_ret;
        goto out;
    default:
        assert(0);
    }

out:
    free(rio->buf);
    rio->buf = NULL;

    return r;
}

static int handle_hash(struct peer_req *pr)
{
    struct peerd *peer = pr->peer;
    struct xseg_request *req = pr->req;
    struct rados_io *rio = (struct rados_io *) pr->priv;
    uint64_t trailing_zeros = 0;
    unsigned char sha[SHA256_DIGEST_SIZE];
    struct xseg_reply_hash *xreply;
    int r;
    char hash_name[MAX_OBJ_NAME + HASH_SUFFIX_LEN + 1];
    char tmp[XSEG_MAX_TARGETLEN];
    char *target;
    uint32_t pos;

    switch (rio->state) {
    case ACCEPTED:
        XSEGLOG2(&lc, I, "Starting hashing of object %s", rio->obj_name);

        if (!req->size) {
            return -EINVAL;
        }

        rio->buf = malloc(req->size);
        if (!rio->buf) {
            return -ENOMEM;
        }

        rio->second_name[0] = '\0';
        rio->state = PREHASHING;
        pos = 0;
        strncpy(hash_name, rio->obj_name, strlen(rio->obj_name));
        pos += strlen(rio->obj_name);
        strncpy(hash_name+pos, HASH_SUFFIX, HASH_SUFFIX_LEN);
        pos += HASH_SUFFIX_LEN;
        hash_name[pos] = '\0';

        r = do_aio_generic(peer, pr, X_READ, hash_name, rio->second_name,
                           HEXLIFIED_SHA256_DIGEST_SIZE, 0);
        if (r < 0) {
            XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read",
                     rio->obj_name);
            goto out;
        }

        return 1;
    case PREHASHING:
        if (rio->aio_ret < 0) {
            r = rio->aio_ret;
            goto out;
        }

        if (rio->aio_ret == HEXLIFIED_SHA256_DIGEST_SIZE) {
            assert(rio->second_name[0] != '\0');
            XSEGLOG2(&lc, D, "Precalculated hash found");
            goto out_complete;
        }

        rio->state = READING;
        rio->read = 0;
        XSEGLOG2(&lc, I, "Reading %s", rio->obj_name);
        r = do_aio_generic(peer, pr, X_READ, rio->obj_name,
                           rio->buf + rio->read, req->size - rio->read,
                           req->offset + rio->read);
        if (r < 0) {
            XSEGLOG2(&lc, I, "Reading of %s failed on do_aio_read",
                     rio->obj_name);
            goto out;
        }
        return 1;
    case READING:
        // TODO stat first and do not rely on req->size
        XSEGLOG2(&lc, I, "Reading of %s callback", rio->obj_name);
        if (rio->aio_ret >= 0)
            rio->read += rio->aio_ret;
        else {
            XSEGLOG2(&lc, E, "Reading of %s failed", rio->obj_name);
            r = rio->aio_ret;
            goto out;
        }

        if (!rio->aio_ret || rio->read >= req->size) {
            XSEGLOG2(&lc, I, "Reading of %s completed", rio->obj_name);
            //rstrip here in case zeros were written in the end
            for (; trailing_zeros < rio->read; trailing_zeros++)
                if (rio->buf[rio->read-trailing_zeros -1])
                    break;
            XSEGLOG2(&lc, D, "Read %llu, Trainling zeros %llu",
                     rio->read, trailing_zeros);

            rio->read -= trailing_zeros;
            SHA256((unsigned char *)rio->buf, rio->read, sha);
            hexlify(sha, SHA256_DIGEST_SIZE, rio->second_name);
            rio->second_name[HEXLIFIED_SHA256_DIGEST_SIZE] = '\0';

            XSEGLOG2(&lc, I, "Calculated %s as hash of %s",
                     rio->second_name, rio->obj_name);

            //aio_stat
            rio->state = STATING;
            r = do_aio_generic(peer, pr, X_INFO, rio->second_name, NULL, 0, 0);
            if (r < 0){
                XSEGLOG2(&lc, E, "Stating %s failed", rio->second_name);
                goto out;
            }

            return 1;
        }
        XSEGLOG2(&lc, I, "Resubmitting read of %s", rio->obj_name);
        r = do_aio_generic(peer, pr, X_READ, rio->obj_name,
                           rio->buf + rio->read, req->size - rio->read,
                           req->offset + rio->read);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Reading of %s failed on do_aio_read",
                     rio->obj_name);
            goto out;
        }
        return 1;
    case STATING:
        if (rio->aio_ret < 0) {
            /*
             * The following is not needed, since continuing
             * optimistically can cause no harm and maybe allow us
             * to seamlessly self heal.
             */
            // if (rio->aio_ret != -ENOENT) {
            //    r = rio->aio_ret;
            //    goto out;
            // }

            //write
            XSEGLOG2(&lc, I, "Stating %s failed. Writing.", rio->second_name);
            rio->state = WRITING;
            r = do_aio_generic(peer, pr, X_WRITE, rio->second_name, rio->buf,
                               rio->read, 0);
            if (r < 0) {
                XSEGLOG2(&lc, E, "Writing of %s failed on do_aio_write", rio->second_name);
                goto out;
            }
            return 1;
        } else {
            XSEGLOG2(&lc, I, "Stating %s completed Successfully."
                     "No need to write.", rio->second_name);
            XSEGLOG2(&lc, I, "Hash of object %s to object %s completed",
                     rio->obj_name, rio->second_name);
            req->serviced = req->size;
            r = 0;
            goto out_complete;
        }

    case WRITING:
        XSEGLOG2(&lc, I, "Writing of %s callback", rio->obj_name);
        if (rio->aio_ret == 0) {
            XSEGLOG2(&lc, I, "Writing of %s completed", rio->second_name);
            XSEGLOG2(&lc, I, "Hash of object %s to object %s completed",
                     rio->obj_name, rio->second_name);

            pos = 0;
            strncpy(hash_name, rio->obj_name, strlen(rio->obj_name));
            pos += strlen(rio->obj_name);
            strncpy(hash_name+pos, HASH_SUFFIX, HASH_SUFFIX_LEN);
            pos += HASH_SUFFIX_LEN;
            hash_name[pos] = '\0';

            rio->state = POSTHASHING;
            r = do_aio_generic(peer, pr, X_WRITE, hash_name, rio->second_name,
                               HEXLIFIED_SHA256_DIGEST_SIZE, 0);
            if (r < 0) {
                /* Not fatal, precalculating hashes is only an
                 * optimization.
                 */
                XSEGLOG2(&lc, W, "Failed to write precalculated hash %s", hash_name);
                r = 0;
                goto out_complete;
            }

            return 1;
        } else {
            XSEGLOG2(&lc, E, "Writing of %s failed", rio->obj_name);
            XSEGLOG2(&lc, E, "Hash of object %s failed", rio->obj_name);
            r = rio->aio_ret;
            goto out;
        }
    case POSTHASHING:
        XSEGLOG2(&lc, I, "Writing of prehashed value callback");
        if (rio->aio_ret == 0) {
            XSEGLOG2(&lc, I, "Writing of prehashed value completed");
            XSEGLOG2(&lc, I, "Hash of object %s to object %s completed",
                     rio->obj_name, rio->second_name);

        } else {
            XSEGLOG2(&lc, W, "Writing of prehash failed");
        }
        req->serviced = req->size;
        r = 0;
        goto out;
    default:
        assert(0);
    }

out:
    free(rio->buf);
    rio->buf = NULL;

    return r;

out_complete:

    target = xseg_get_target(peer->xseg, pr->req);
    strncpy(tmp, target, XSEG_MAX_TARGETLEN);

    r = xseg_resize_request(peer->xseg, pr->req, pr->req->targetlen,
                            sizeof(struct xseg_reply_hash));
    if (r < 0) {
        goto out;
    }

    target = xseg_get_target(peer->xseg, pr->req);
    strncpy(target, tmp, XSEG_MAX_TARGETLEN);

    xreply = (struct xseg_reply_hash*)xseg_get_data(peer->xseg, req);

    strncpy(xreply->target, rio->second_name, HEXLIFIED_SHA256_DIGEST_SIZE);
    xreply->targetlen = HEXLIFIED_SHA256_DIGEST_SIZE;

    XSEGLOG2(&lc, I, "Calculated %s as hash of %s",
             rio->second_name, rio->obj_name);

    goto out;
}

static void watch_cb(uint8_t opcode, uint64_t ver, void *arg)
{
    //assert pr valid
    struct peer_req *pr = (struct peer_req *)arg;
    //struct radosd *rados = (struct radosd *) pr->peer->priv;
    struct rados_io *rio = (struct rados_io *)(pr->priv);

    /* This should work, even with spurious watch callbacks, since the only
     * thing it does is signaling a pthread_cond that is guaranteed to
     * exist.
     *
     * TODO maybe implement a better synchronization
     */
    archipelago_mutex_lock(&rio->m);
    XSEGLOG2(&lc, I, "watch cb signaling rio of %s", rio->obj_name);
    pthread_cond_signal(&rio->cond);
    archipelago_mutex_unlock(&rio->m);
}

static int break_lock(struct radosd *rados, struct rados_io *rio)
{
    int r, exclusive;
    char *tag = NULL, *clients = NULL, *cookies = NULL, *addrs = NULL;
    size_t tag_len = 1024, clients_len = 1024, cookies_len = 1024;
    size_t addrs_len = 1024;
    ssize_t nr_lockers;

    for (;;) {
        tag = malloc(sizeof(char) * tag_len);
        clients = malloc(sizeof(char) * clients_len);
        cookies = malloc(sizeof(char) * cookies_len);
        addrs = malloc(sizeof(char) * addrs_len);
        if (!tag || !clients || !cookies || !addrs) {
            XSEGLOG2(&lc, E, "Out of memmory");
            r = -ENOMEM;
            break;
        }

        nr_lockers = rados_list_lockers(rados->ioctx, rio->obj_name,
                                        RADOS_LOCK_NAME, &exclusive, tag,
                                        &tag_len, clients, &clients_len,
                                        cookies, &cookies_len, addrs,
                                        &addrs_len);
        if (nr_lockers < 0 && nr_lockers != -ERANGE) {
            XSEGLOG2(&lc, E, "Could not list lockers for %s", rio->obj_name);
            r = nr_lockers;
            break;
        } else if (nr_lockers == -ERANGE) {
            // TODO set max len;
            free(tag);
            tag = NULL;
            tag_len *= 2;

            free(clients);
            clients = NULL;
            clients_len *= 2;

            free(cookies);
            cookies = NULL;
            tag_len *= 2;

            free(addrs);
            addrs = NULL;
            addrs_len *= 2;
        } else {
            if (nr_lockers != 1) {
                XSEGLOG2(&lc, E, "Number of lockers for %s != 1 !(%d)",
                         rio->obj_name, nr_lockers);
                r = -EIO;
                break;
            }

            if (!exclusive) {
                XSEGLOG2(&lc, E, "Lock for %s is not exclusive",
                         rio->obj_name);
                r = -EIO;
                break;
            }

            if (strcmp(RADOS_LOCK_TAG, tag)) {
                XSEGLOG2(&lc, E, "List lockers returned wrong tag "
                         "(\"%s\" vs \"%s\")", tag, RADOS_LOCK_TAG);
                r = -EIO;
                break;
            }

            r = rados_break_lock(rados->ioctx, rio->obj_name, RADOS_LOCK_NAME,
                                 clients, RADOS_LOCK_COOKIE);
            break;
        }
    }

    free(tag);
    free(clients);
    free(cookies);
    free(addrs);

    return r;
}

/*
 * Handle release is a synchronous operation.
 */
static int handle_release(struct peer_req *pr)
{
    struct radosd *rados = (struct radosd *)pr->peer->priv;
    struct rados_io *rio = (struct rados_io *)(pr->priv);
    uint32_t len = strlen(rio->obj_name);
    // FIXME can overflow
    strncpy(rio->obj_name + len, LOCK_SUFFIX, LOCK_SUFFIX_LEN);
    rio->obj_name[len + LOCK_SUFFIX_LEN] = '\0';
    int r;

    XSEGLOG2(&lc, I, "Starting unlock op for %s", rio->obj_name);
    if (pr->req->flags & XF_FORCE) {
        r = break_lock(rados, rio);
    } else {
        r = rados_unlock(rados->ioctx, rio->obj_name, RADOS_LOCK_NAME,
                         RADOS_LOCK_COOKIE);
    }

    if (r < 0){
        XSEGLOG2(&lc, E, "Rados unlock failed for %s (r: %d)", rio->obj_name, r);
    } else {
        if (rados_notify(rados->ioctx, rio->obj_name, 0, NULL, 0) < 0) {
            XSEGLOG2(&lc, E, "rados notify failed");
        }
        XSEGLOG2(&lc, I, "Successfull unlock op for %s", rio->obj_name);
    }

    return r;
}

/*
 * Handle acquire is a synchronous operation.
 */
static int handle_acquire(struct peer_req *pr)
{
    struct radosd *rados = (struct radosd *)pr->peer->priv;
    struct rados_io *rio = (struct rados_io *)(pr->priv);
    uint32_t len = strlen(rio->obj_name);
    int r;
    // FIXME can overflow
    strncpy(rio->obj_name + len, LOCK_SUFFIX, LOCK_SUFFIX_LEN);
    rio->obj_name[len + LOCK_SUFFIX_LEN] = '\0';

    XSEGLOG2(&lc, I, "Starting lock op for %s", rio->obj_name);
    if (!(pr->req->flags & XF_NOSYNC)){
        r = rados_watch(rados->ioctx, rio->obj_name, 0, &rio->watch_handle,
                        watch_cb, pr);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Rados watch failed for %s",
                     rio->obj_name);
            return r;
        }

        do {
            r = rados_lock_exclusive(rados->ioctx, rio->obj_name,
                                     RADOS_LOCK_NAME, RADOS_LOCK_COOKIE,
                                     RADOS_LOCK_DESC, NULL,
                                     LIBRADOS_LOCK_FLAG_RENEW);
            if (r == -EBUSY) {
                pthread_cond_wait(&rio->cond, &rio->m);
            }
        } while (r == -EBUSY);

        if (rados_unwatch(rados->ioctx, rio->obj_name, rio->watch_handle) < 0) {
            XSEGLOG2(&lc, E, "Rados unwatch failed");
        }
    } else {
        r = rados_lock_exclusive(rados->ioctx, rio->obj_name,
                                 RADOS_LOCK_NAME, RADOS_LOCK_COOKIE,
                                 RADOS_LOCK_DESC, NULL,
                                 LIBRADOS_LOCK_FLAG_RENEW);
    }
    XSEGLOG2(&lc, I, "Successfull lock op for %s", rio->obj_name);
    return r;
}


extern char radosd_pool[MAX_POOL_NAME + 1];
extern char radosd_cephxid[MAX_CEPHXID_NAME + 1];

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
    int i, j;
    struct radosd *rados = malloc(sizeof(struct radosd));
    char *cephx_id = radosd_cephxid;
    struct rados_io *rio;

    if (!rados) {
        perror("malloc");
        return -ENOMEM;
    }

    strcpy(rados->pool, radosd_pool);

    if (!rados->pool[0]) {
        XSEGLOG2(&lc, E , "Pool must be provided");
        free(rados);
        usage(argv[0]);
        return -1;
    }

    if (rados_create(&rados->cluster, (cephx_id[0] == '\0') ? NULL : cephx_id) < 0) {
        XSEGLOG2(&lc, E, "Rados create failed!");
        return -1;
    }

    if (rados_conf_read_file(rados->cluster, NULL) < 0) {
        XSEGLOG2(&lc, E, "Error reading rados conf files!");
        return -1;
    }
    if (rados_connect(rados->cluster) < 0) {
        XSEGLOG2(&lc, E, "Rados connect failed!");
        rados_shutdown(rados->cluster);
        free(rados);
        return -1;
    }
    if (rados_pool_lookup(rados->cluster, rados->pool) < 0) {
        XSEGLOG2(&lc, E, "Pool does not exists. Try creating it first");
        rados_shutdown(rados->cluster);
        free(rados);
        return -1;
        /*
        if (rados_pool_create(rados->cluster, rados->pool) < 0){
            XSEGLOG2(&lc, E, "Couldn't create pool %s", rados->pool);
            rados_shutdown(rados->cluster);
            free(rados);
            return -1;
        }
        XSEGLOG2(&lc, I, "Pool created.");
        */

    }
    if (rados_ioctx_create(rados->cluster, rados->pool, &rados->ioctx) < 0) {
        XSEGLOG2(&lc, E, "ioctx create problem.");
        rados_shutdown(rados->cluster);
        free(rados);
        return -1;
    }

    peer->priv = (void *)rados;
    for (i = 0; i < peer->nr_ops; i++) {
        rio = malloc(sizeof(struct rados_io));
        if (!rio) {
            //ugly
            //is this really necessary?
            for (j = 0; j < i; j++) {
                free(peer->peer_reqs[j].priv);
            }
            free(rados);
            perror("malloc");
            return -ENOMEM;
        }

        rio->buf = NULL;
        rio->read = 0;
        rio->size = 0;
        rio->watch_handle = 0;
        archipelago_init_mutex(&rio->m);
        pthread_cond_init(&rio->cond, NULL);
        peer->peer_reqs[i].priv = (void *)rio;
    }

    return 0;
}

// nothing to do here for now
void custom_peer_finalize(struct peerd *peer)
{
    return;
}


void handle_request(gpointer data, gpointer user_data)
{
    (void)user_data;

    int r;
    struct peer_req *pr = data;
    struct rados_io *rio;

    assert(pr);
    assert(pr->req);

    rio = pr->priv;

    archipelago_mutex_lock(&rio->m);

    switch (pr->req->op){
        case X_READ:
            r = handle_read(pr); break;
        case X_WRITE:
            r = handle_write(pr); break;
        case X_DELETE:
            r = handle_delete(pr); break;
        case X_INFO:
            r = handle_info(pr); break;
        case X_COPY:
            r = handle_copy(pr); break;
        case X_ACQUIRE:
            r = handle_acquire(pr); break;
        case X_RELEASE:
            r = handle_release(pr); break;
        case X_HASH:
            r = handle_hash(pr); break;
        default:
            assert(0);
    }

    archipelago_mutex_unlock(&rio->m);

    if (r > 0) {
        // pending
        return;
    }

    if (r < 0) {
        fail(pr, -r);
    } else {
        complete(pr);
    }
}

int dispatch_accepted(struct peer_req *pr)
{
    unsigned int end;
    struct peerd *peer = pr->peer;
    struct rados_io *rio = (struct rados_io *)(pr->priv);
    char *target = xseg_get_target(peer->xseg, pr->req);

    if (pr->req->targetlen > MAX_OBJ_NAME) {
        end = MAX_OBJ_NAME;
    } else {
        end = pr->req->targetlen;
    }

    strncpy(rio->obj_name, target, end);
    rio->obj_name[end] = '\0';
    rio->state = ACCEPTED;
    rio->read = 0;

    switch (pr->req->op) {
        case X_READ:
        case X_WRITE:
        case X_DELETE:
        case X_INFO:
        case X_COPY:
        case X_ACQUIRE:
        case X_RELEASE:
        case X_HASH:
            thread_pool_submit_work(peer->pool, pr);
            break;
        default:
            fail(pr, EINVAL);
    }

    return 0;
}

int dispatch_received(struct peer_req *pr, struct xseg_request *reply)
{
    // assert(0);
    return -1;
}
