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

#ifndef PEER_H

#define PEER_H

#include <stddef.h>
#include <xseg/xseg.h>
#include <string.h>
#include <thpool.h>


#define PEER_DEFAULT_UMASK     0007

/* main peer structs */
struct peer_req {
	struct peerd *peer;
	struct xseg_request *req;
	ssize_t retval;
	xport portno;
	void *priv;
};

struct peerd {
	struct xseg *xseg;
	xport portno_start;
	xport portno_end;
	long nr_ops;
	uint64_t threshold;
	struct peer_req *peer_reqs;
	struct xq free_reqs;
	int (*peerd_loop)(void *arg);
	void *sd;

	struct ArchipelagoThreadPool *pool;
	uint32_t nr_threads;

	void *priv;
};

void fail(struct peer_req *pr, int err);
void complete(struct peer_req *pr);

void log_pr(char *msg, struct peer_req *pr);
void free_peer_req(struct peerd *peer, struct peer_req *pr);
int submit_peer_req(struct peerd *peer, struct peer_req *pr);
void usage();
void print_req(struct xseg *xseg, struct xseg_request *req);
int all_peer_reqs_free(struct peerd *peer);
struct peer_req *alloc_peer_req(struct peerd *peer);
int check_ports(struct peerd *peer);

static inline struct peerd * __get_peerd(void * custom_peerd)
{
	return (struct peerd *)((unsigned long)custom_peerd  - offsetof(struct peerd, priv));
}



/* decration of "common" variables */
extern volatile unsigned int terminated;
extern struct log_ctx lc;

static inline int isTerminate(void)
{
	return terminated;
}

/********************************
 *   mandatory peer functions   *
 ********************************/

/* peer main function */

void custom_peer_usage();
int custom_peer_init(struct peerd *peer, int argc, char *argv[]);
void custom_peer_finalize(struct peerd *peer);

int dispatch_accepted(struct peer_req *pr);
int dispatch_received(struct peer_req *pr, struct xseg_request *reply);


void handle_request(gpointer data, gpointer user_data);

#endif /* end of PEER_H */
