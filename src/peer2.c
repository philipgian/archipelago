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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <glib.h>
#include <getopt.h>

#include <util.h>
#include <pidfile.h>

#include <xseg/xseg.h>

#include <peer2.h>

#define PEER_TYPE "posixfd"

//FIXME this should not be defined here probably
#define MAX_SPEC_LEN 128
#define MAX_PIDFILE_LEN 512

volatile unsigned int terminated = 0;
unsigned int verbose = 0;
struct log_ctx lc;

void signal_handler(int signal)
{
	terminated = 1;
}

/*
 * We want to both print the backtrace and dump the core. To do so, we fork a
 * process that prints its stack trace, that should be the same as the parents.
 * Then we wait for 1 sec and we abort. The reason we don't abort immediately
 * is because it may interrupt the printing of the backtrace.
 */
void segv_handler(int signal)
{
	if (fork() == 0) {
		xseg_printtrace();
		_exit(1);
	}

	sleep(1);
	abort();
}

void renew_logfile(int signal)
{
//	XSEGLOG2(&lc, I, "Caught signal. Renewing logfile");
	renew_logctx(&lc, NULL, verbose, NULL, REOPEN_FILE);
}

static int setup_signals(struct peerd *peer)
{
	int r;
	struct sigaction sa;
	struct rlimit rlim;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	r = sigaction(SIGTERM, &sa, NULL);
	if (r < 0)
		return r;
	r = sigaction(SIGINT, &sa, NULL);
	if (r < 0)
		return r;
	r = sigaction(SIGQUIT, &sa, NULL);
	if (r < 0)
		return r;

	/*
	 * Get the current limits for core files and raise them to the largest
	 * value possible
	 */
	if (getrlimit(RLIMIT_CORE, &rlim) < 0)
		return r;

	rlim.rlim_cur = rlim.rlim_max;

	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		return r;

	/* Install handler for segfaults */
	sa.sa_handler = segv_handler;
	r = sigaction(SIGSEGV, &sa, NULL);
	if (r < 0)
		return r;

	sa.sa_handler = renew_logfile;
	r = sigaction(SIGUSR1, &sa, NULL);
	if (r < 0)
		return r;

	return r;
}

void print_req(struct xseg *xseg, struct xseg_request *req)
{
	char target[64], data[64];
	char *req_target, *req_data;
	unsigned int end = (req->targetlen> 63) ? 63 : req->targetlen;
	req_target = xseg_get_target(xseg, req);
	req_data = xseg_get_data(xseg, req);

	if (1) {
		strncpy(target, req_target, end);
		target[end] = 0;
		strncpy(data, req_data, 63);
		data[63] = 0;
		printf("req id:%lu, op:%u %llu:%lu serviced: %lu, reqstate: %u\n"
			"src: %u, transit: %u, dst: %u effective dst: %u\n"
			"target[%u]:'%s', data[%llu]:\n%s------------------\n\n",
			(unsigned long)(req),
			(unsigned int)req->op,
			(unsigned long long)req->offset,
			(unsigned long)req->size,
			(unsigned long)req->serviced,
			(unsigned int)req->state,
			(unsigned int)req->src_portno,
			(unsigned int)req->transit_portno,
			(unsigned int)req->dst_portno,
			(unsigned int)req->effective_dst_portno,
			(unsigned int)req->targetlen, target,
			(unsigned long long)req->datalen, data);
	}
}

void log_pr(char *msg, struct peer_req *pr)
{
	char target[65], data[65];
	char *req_target, *req_data;
	struct peerd *peer = pr->peer;
	struct xseg *xseg = pr->peer->xseg;
	req_target = xseg_get_target(xseg, pr->req);
	req_data = xseg_get_data(xseg, pr->req);

	/*
	 * null terminate name in case of req->target is less than 63 characters,
	 * and next character after name (aka first byte of next buffer) is not
	 * null
	 */
	unsigned int end = (pr->req->targetlen > 64) ? 64 : pr->req->targetlen;
	if (verbose) {
		strncpy(target, req_target, end);
		target[end] = 0;
		strncpy(data, req_data, 64);
		data[64] = 0;
		printf("%s: req id:%u, op:%u %llu:%lu serviced: %lu, retval: %lu, reqstate: %u\n"
			"target[%u]:'%s', data[%llu]:\n%s------------------\n\n",
			msg,
			(unsigned int)(pr - peer->peer_reqs),
			(unsigned int)pr->req->op,
			(unsigned long long)pr->req->offset,
			(unsigned long)pr->req->size,
			(unsigned long)pr->req->serviced,
			(unsigned long)pr->retval,
			(unsigned int)pr->req->state,
			(unsigned int)pr->req->targetlen, target,
			(unsigned long long)pr->req->datalen, data);
	}
}

/*
 * free_reqs is a queue that simply contains pointer offsets to the peer_reqs
 * queue. If a pointer from peer_reqs is popped, we are certain that the
 * associated memory in peer_reqs is free to use
 */
inline struct peer_req *alloc_peer_req(struct peerd *peer)
{
	xqindex idx = xq_pop_head(&peer->free_reqs);
	if (idx == Noneidx)
		return NULL;
	return peer->peer_reqs + idx;
}

inline void free_peer_req(struct peerd *peer, struct peer_req *pr)
{
	xqindex idx = pr - peer->peer_reqs;
	pr->req = NULL;
	xq_append_head(&peer->free_reqs, idx);
}

/*
 * Count all free reqs in peer.
 */
int all_peer_reqs_free(struct peerd *peer)
{
	uint32_t free_reqs = 0;

	free_reqs = xq_count(&peer->free_reqs);

	if (free_reqs == peer->nr_ops) {
		return 1;
	}

	return 0;
}

//FIXME error check
static void respond(struct peer_req *pr, int err)
{
	struct peerd *peer = pr->peer;
	struct xseg_request *req = pr->req;
	uint32_t p;

	// assert(peer);
	// assert(req);

	if (err) {
		XSEGLOG2(&lc, D, "Failing req %u with error value %d",
				 (unsigned int)(pr - peer->peer_reqs), err);
		req->state |= XS_FAILED;
	} else {
		XSEGLOG2(&lc, D, "Completing req %u",
				 (unsigned int)(pr - peer->peer_reqs));
		req->state |= XS_SERVED;
	}

	//xseg_set_req_data(peer->xseg, pr->req, NULL);
	p = xseg_respond(peer->xseg, req, pr->portno, X_ALLOC);
	xseg_signal(peer->xseg, p);

	free_peer_req(peer, pr);
    xseg_signal(peer->xseg, peer->portno_start);
}

void fail(struct peer_req *pr, int err)
{
	// assert(err > 0);
	respond(pr, err);
}

void complete(struct peer_req *pr)
{
	respond(pr, 0);
}

static void handle_accepted(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *req)
{
	struct xseg_request *xreq = pr->req;

	//assert xreq == req;
	XSEGLOG2(&lc, D, "Handle accepted");
	xreq->serviced = 0;
	//xreq->state = XS_ACCEPTED;
	pr->retval = 0;

	dispatch_accepted(pr);
}

static void handle_received(struct peerd *peer, struct peer_req *pr,
				struct xseg_request *reply)
{
	XSEGLOG2(&lc, D, "Handle received \n");
	dispatch_received(pr, reply);

}

int check_ports(struct peerd *peer)
{
	struct xseg *xseg = peer->xseg;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	struct xseg_request *accepted, *received;
	struct peer_req *pr;
	xport i;
	int  r, c = 0;

	for (i = portno_start; i <= portno_end; i++) {
		accepted = NULL;
		received = NULL;
		if (!isTerminate()) {
			pr = alloc_peer_req(peer);
			if (pr) {
				accepted = xseg_accept(xseg, i, X_NONBLOCK);
				if (accepted) {
					pr->req = accepted;
					pr->portno = i;
					xseg_cancel_wait(xseg, i);
					handle_accepted(peer, pr, accepted);
					c = 1;
				}
				else {
					free_peer_req(peer, pr);
				}
			}
		}
		received = xseg_receive(xseg, i, X_NONBLOCK);
		if (received) {
			r =  xseg_get_req_data(xseg, received, (void **) &pr);
			if (r < 0 || !pr) {
				XSEGLOG2(&lc, W, "Received request with no pr data\n");
				xport p = xseg_respond(peer->xseg, received, peer->portno_start, X_ALLOC);
				if (p == NoPort) {
					XSEGLOG2(&lc, W, "Could not respond stale request");
					xseg_put_request(xseg, received, portno_start);
					continue;
				} else {
					xseg_signal(xseg, p);
				}
			} else {
				//maybe perform sanity check for pr
				xseg_cancel_wait(xseg, i);
				handle_received(peer, pr, received);
				c = 1;
			}
		}
	}

	return c;
}



static void process_wait_queue(struct peerd *peer)
{
	struct peer_req *pr;

	thread_pool_workqueue_lock(peer->pool);
	while (pr = thread_pool_workqueue_get_unlocked(peer->pool)) {
		thread_pool_submit_work(peer->pool, pr);
	}
	thread_pool_workqueue_unlock(peer->pool);
}

/*
 * generic_peerd_loop is a general-purpose port-checker loop that is
 * suitable both for multi-threaded and single-threaded peers.
 */
static int generic_peerd_loop(void *arg)
{
	struct peerd *peer = (struct peerd *) arg;
	struct xseg *xseg = peer->xseg;
	uint64_t threshold, loops;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	pid_t tid = syscall(SYS_gettid);


	threshold = peer->threshold;
	threshold /= (1 + portno_end - portno_start);
	threshold += 1;

	XSEGLOG2(&lc, I, "xseg thread has tid %u", tid);

	for (;!(isTerminate() && all_peer_reqs_free(peer));) {
		for(loops = threshold; loops > 0; loops--) {
			if (loops == 1) {
				xseg_prepare_wait(xseg, peer->portno_start);
			}

			process_wait_queue(peer);
			if (check_ports(peer)) {
				loops = threshold;
			}
		}

		XSEGLOG2(&lc, I, "xseg thread goes to sleep");
		xseg_wait_signal(xseg, peer->sd, 10000000UL);
		xseg_cancel_wait(xseg, peer->portno_start);
		XSEGLOG2(&lc, I, "xseg thread woke up");
	}
	return 0;
}

static int init_peerd_loop(struct peerd *peer)
{
	struct xseg *xseg = peer->xseg;
	int r;

	peer->peerd_loop(peer);
    // thread pool wait ?

	custom_peer_finalize(peer);

	xseg_quit_local_signal(xseg, peer->portno_start);

	return 0;
}

static struct xseg *join(char *spec)
{
	struct xseg_config config;
	struct xseg *xseg;

	(void)xseg_parse_spec(spec, &config);
	xseg = xseg_join(config.type, config.name, PEER_TYPE, NULL);
	if (xseg)
		return xseg;

	(void)xseg_create(&config);
	return xseg_join(config.type, config.name, PEER_TYPE, NULL);
}

static struct peerd* peerd_init(uint32_t nr_ops, char* spec, long portno_start,
			long portno_end, uint32_t nr_threads, uint64_t threshold)
{
	int i, r;
	struct peerd *peer;
	struct xseg_port *port;
	void *sd = NULL;
	xport p;

	peer = malloc(sizeof(struct peerd));
	if (!peer) {
		perror("malloc");
		return NULL;
	}
	peer->nr_ops = nr_ops;
	peer->nr_threads =nr_threads;
	peer->threshold = threshold;

	if (!xq_alloc_seq(&peer->free_reqs, nr_ops, nr_ops)) {
		goto malloc_fail;
	}

	if (peer->free_reqs.size < peer->nr_ops) {
		peer->nr_ops = peer->free_reqs.size;
	}

	peer->peer_reqs = calloc(nr_ops, sizeof(struct peer_req));
	if (!peer->peer_reqs){
malloc_fail:
		perror("malloc");
		return NULL;
	}

	if (xseg_initialize()){
		printf("cannot initialize library\n");
		return NULL;
	}

	peer->pool = thread_pool_init(handle_request, peer->nr_threads);
	if (peer->pool == NULL) {
		XSEGLOG2(&lc, E, "Thread pool couldn't be created due to "
				"resource shortage.");
		return NULL;
	}

	peer->xseg = join(spec);
	if (!peer->xseg)
		return NULL;

	peer->portno_start = (xport) portno_start;
	peer->portno_end = (xport) portno_end;

	/*
	 * Start binding ports from portno_start to portno_end.
	 * The first port we bind will have its signal_desc initialized by xseg
	 * and the same signal_desc will be used for all the other ports.
	 */
	peer->sd = NULL;
	for (p = peer->portno_start; p <= peer->portno_end; p++) {
		port = xseg_bind_port(peer->xseg, p, peer->sd);
		if (!port){
			printf("cannot bind to port %u\n", (unsigned int) p);
			return NULL;
		}
		if (p == peer->portno_start) {
			peer->sd = xseg_get_signal_desc(peer->xseg, port);
		}
	}

	XSEGLOG2(&lc, I, "Peer on ports  %u-%u",
			peer->portno_start, peer->portno_end);

	r = xseg_init_local_signal(peer->xseg, peer->portno_start);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Could not initialize local signals");
		return NULL;
	}

	for (i = 0; i < nr_ops; i++) {
		peer->peer_reqs[i].peer = peer;
		peer->peer_reqs[i].req = NULL;
		peer->peer_reqs[i].retval = 0;
		peer->peer_reqs[i].priv = NULL;
		peer->peer_reqs[i].portno = NoPort;
	}

	//Plug default peerd_loop. This can change later on by custom_peer_init.
	peer->peerd_loop = generic_peerd_loop;

	return peer;
}

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [general options] [custom peer options]\n\n", argv0);
	fprintf(stderr, "General peer options:\n"
		"  Option      | Default | \n"
		"  --------------------------------------------\n"
		"    -g        | None    | Segment spec to join\n"
		"    -sp       | NoPort  | Start portno to bind\n"
		"    -ep       | NoPort  | End portno to bind\n"
		"    -p        | NoPort  | Portno to bind\n"
		"    -n        | 16      | Number of ops\n"
		"    -v        | 0       | Verbosity level\n"
		"    -l        | None    | Logfile \n"
		"    -d        | No      | Daemonize \n"
		"    --pidfile | None    | Pidfile \n"
		"    -uid      | None    | Set real EUID \n"
		"    -gid      | None    | Set real EGID \n"
		"    -t        | No      | Number of processing threads\n"
		"\n"
	       );
	custom_peer_usage();
}

// TODO use NoPort
xport mapper_bportno = -1;
xport mapper_mbportno = -1;



#define MAX_PATH_SIZE 1024
#define MAX_PREFIX_LEN 10
#define MAX_UNIQUESTR_LEN 128
int filed_directio = 0;
int filed_migrate = 0;
long filed_maxfds = -1;
char filed_vpath[MAX_PATH_SIZE + 1] = "";
char filed_prefix[MAX_PREFIX_LEN + 1] = "";
char filed_uniquestr[MAX_UNIQUESTR_LEN + 1] = "";
char filed_lockpath[MAX_PATH_SIZE + 1] = "";

#define MAX_POOL_NAME 64
#define MAX_CEPHXID_NAME 256
char radosd_pool[MAX_POOL_NAME + 1] = "";
char radosd_cephxid[MAX_CEPHXID_NAME + 1] = "";

int main(int argc, char *argv[])
{
	struct peerd *peer = NULL;
	//parse args
	int r;
	long portno_start = -1, portno_end = -1, portno = -1;

	//set defaults here
	int daemonize = 0, help = 0;
	uint32_t nr_ops = 16;
	uint32_t nr_threads = 1;
	uint64_t threshold = 1000;
	unsigned int debug_level = 0;
	pid_t old_pid = 0;
	int pid_fd = -1;
	uid_t cur_uid, uid = -1;
	gid_t cur_gid, gid = -1;
	mode_t peer_umask = PEER_DEFAULT_UMASK;

	char spec[MAX_SPEC_LEN + 1];
	char logfile[MAX_LOGFILE_LEN + 1];
	char pidfile[MAX_PIDFILE_LEN + 1];

	char *username = NULL;

	logfile[0] = 0;
	pidfile[0] = 0;
	spec[0] = 0;

	enum longopts_vals {
		LONGOPT_PIDFILE = 256,
		LONGOPT_UID,
		LONGOPT_GID,
		LONGOPT_THRESHOLD,
		LONGOPT_UMASK,
		LONGOPT_STARTPORT,
		LONGOPT_ENDPORT,

		LONGOPT_MAPPEROPT_BLOCKERBPORT,
		LONGOPT_MAPPEROPT_BLOCKERMPORT,

		LONGOPT_FILEDOPT_MAXFDS,
		LONGOPT_FILEDOPT_DIRECTIO,
		LONGOPT_FILEDOPT_MIGRATE,
		LONGOPT_FILEDOPT_VPATH,
		LONGOPT_FILEDOPT_PREFIX,
		LONGOPT_FILEDOPT_UNIQUESTR,
		LONGOPT_FILEDOPT_LOCKPATH,

		LONGOPT_RADOSDOPT_CEPHXID,
		LONGOPT_RADOSDOPT_POOL,
	};

	const struct option longopts[] = {
		{"pidfile", required_argument, NULL, LONGOPT_PIDFILE},
		{"uid", required_argument, NULL, LONGOPT_UID},
		{"gid", required_argument, NULL, LONGOPT_GID},
		{"umask", required_argument, NULL, LONGOPT_UMASK},
		{"threshold", required_argument, NULL, LONGOPT_THRESHOLD},
		{"sp", required_argument, NULL, LONGOPT_STARTPORT},
		{"ep", required_argument, NULL, LONGOPT_ENDPORT},
		{"help", no_argument, NULL, 'h'},
		/* mapper specific options */
		{"bp", required_argument, NULL, LONGOPT_MAPPEROPT_BLOCKERBPORT},
		{"mbp", required_argument, NULL, LONGOPT_MAPPEROPT_BLOCKERMPORT},
		/* filed specific options */
		{"fdcache", required_argument, NULL, LONGOPT_FILEDOPT_MAXFDS},
		{"directio", no_argument, NULL, LONGOPT_FILEDOPT_DIRECTIO},
		{"pithos-migrate", no_argument, NULL, LONGOPT_FILEDOPT_MIGRATE},
		{"archip", required_argument, NULL, LONGOPT_FILEDOPT_VPATH},
		{"lockdir", required_argument, NULL, LONGOPT_FILEDOPT_LOCKPATH},
		{"prefix", required_argument, NULL, LONGOPT_FILEDOPT_PREFIX},
		{"uniquestr", required_argument, NULL, LONGOPT_FILEDOPT_UNIQUESTR},
		/* radosd specific options */
		{"pool", required_argument, NULL, LONGOPT_RADOSDOPT_POOL},
		{"cephx-id", required_argument, NULL, LONGOPT_RADOSDOPT_CEPHXID},
		{0, 0, 0, 0}
	};

	const char *opts = ":dg:n:v:p:l:t:";
	int c, long_idx;

	opterr = 0;
	while ((c = getopt_long_only(argc, argv, opts, longopts, NULL)) != -1) {
		switch (c) {
		case 0:
			// For future use
			/* a flag was set */
			break;
		case LONGOPT_PIDFILE:
			strncpy(pidfile, optarg, MAX_PIDFILE_LEN);
			pidfile[MAX_PIDFILE_LEN] = '\0';
			break;
		case LONGOPT_UID:
			uid = strtoul(optarg, NULL, 10);
			break;
		case LONGOPT_GID:
			gid = strtoul(optarg, NULL, 10);
			break;
		case LONGOPT_UMASK:
			peer_umask = strtoul(optarg, NULL, 10);
			break;
		case LONGOPT_THRESHOLD:
			threshold = strtoul(optarg, NULL, 10);
			break;
		case LONGOPT_STARTPORT:
			portno_start = strtoul(optarg, NULL, 10);
			break;
		case LONGOPT_ENDPORT:
			portno_end= strtoul(optarg, NULL, 10);
			break;

		case LONGOPT_MAPPEROPT_BLOCKERBPORT:
			mapper_bportno = strtoul(optarg, NULL, 10);
			break;
		case LONGOPT_MAPPEROPT_BLOCKERMPORT:
			mapper_mbportno = strtoul(optarg, NULL, 10);
			break;

		case LONGOPT_FILEDOPT_DIRECTIO:
			filed_directio = 1;
			break;
		case LONGOPT_FILEDOPT_MIGRATE:
			filed_migrate = 1;
			break;
		case LONGOPT_FILEDOPT_MAXFDS:
			filed_maxfds = strtol(optarg, NULL, 10);
			break;
		case LONGOPT_FILEDOPT_VPATH:
			/* use MAX_PATH_SIZE - 1 here to be able to terminate
			 * string with a '/'.
			 */
			strncpy(filed_vpath, optarg, MAX_PATH_SIZE-1);
			filed_vpath[MAX_PATH_SIZE-1] = '\0';
			break;
		case LONGOPT_FILEDOPT_LOCKPATH:
			strncpy(filed_lockpath, optarg, MAX_PATH_SIZE-1);
			filed_lockpath[MAX_PATH_SIZE-1] = '\0';
			break;
		case LONGOPT_FILEDOPT_PREFIX:
			strncpy(filed_prefix, optarg, MAX_PREFIX_LEN);
			filed_prefix[MAX_PREFIX_LEN] = '\0';
			break;
		case LONGOPT_FILEDOPT_UNIQUESTR:
			strncpy(filed_uniquestr, optarg, MAX_UNIQUESTR_LEN);
			filed_uniquestr[MAX_UNIQUESTR_LEN] = '\0';
			break;

		case LONGOPT_RADOSDOPT_POOL:
			strncpy(radosd_pool, optarg, MAX_POOL_NAME);
			radosd_pool[MAX_POOL_NAME] = '\0';
			break;
		case LONGOPT_RADOSDOPT_CEPHXID:
			strncpy(radosd_cephxid, optarg, MAX_CEPHXID_NAME);
			radosd_cephxid[MAX_CEPHXID_NAME] = '\0';
			break;

		case 'd':
			daemonize = 1;
			break;
		case 'g':
			strncpy(spec, optarg, MAX_SPEC_LEN);
			spec[MAX_SPEC_LEN] = '\0';
			break;
		case 'n':
			nr_ops = strtoul(optarg, NULL, 10);
			break;
		case 'v':
			debug_level = strtoul(optarg, NULL, 10);
			break;
		case 'p':
			portno = strtoul(optarg, NULL, 10);
			break;
		case 'l':
			strncpy(logfile, optarg, MAX_LOGFILE_LEN);
			logfile[MAX_LOGFILE_LEN] = '\0';
			break;
		case 't':
			nr_threads = strtoul(optarg, NULL, 10);
			break;
		case 'h':
			help = 1;
			break;
		case ':':   /* missing option argument */
			fprintf(stderr, "%s: option `-%c' requires an argument\n",
				argv[0], optopt);
			break;
		case '?':
			/* Skip unrecognized options */
			break;
		default:
			break;
		}
	}

	if (help) {
		usage(argv[0]);
		return 0;
	}

	if (gid != -1) {
		struct group *gr;
		gr = getgrgid(gid);
		if (!gr) {
			XSEGLOG2(&lc, E, "Group %d not found", gid);
			return -1;
		}
	}

	if (uid != -1) {
		struct passwd *pw;
		pw = getpwuid(uid);
		if (!pw) {
			XSEGLOG2(&lc, E, "User %d not found", uid);
			return -1;
		}
		username = pw->pw_name;
		if (gid == -1) {
			gid = pw->pw_gid;
		}
	}

	cur_uid = geteuid();
	cur_gid = getegid();

	if (gid != -1 && cur_gid != gid && setregid(gid, gid)) {
		XSEGLOG2(&lc, E, "Could not set gid to %d", gid);
		return -1;
	}

	if (uid != -1) {
		if ((cur_gid != gid || cur_uid != uid)
				&& initgroups(username, gid)) {
			XSEGLOG2(&lc, E, "Could not initgroups for user %s, "
					"gid %d", username, gid);
			return -1;
		}

		if (cur_uid != uid && setreuid(uid, uid)) {
			XSEGLOG2(&lc, E, "Failed to set uid %d", uid);
		}
	}

	/* set umask of the process. Only keep permission bits */
	peer_umask &= 0777;
	umask(peer_umask);

	r = init_logctx(&lc, argv[0], debug_level, logfile,
			REDIRECT_STDOUT|REDIRECT_STDERR);
	if (r < 0){
		XSEGLOG("Cannot initialize logging to logfile");
		return -1;
	}

	XSEGLOG2(&lc, D, "Main thread has tid %ld.\n", syscall(SYS_gettid));

	if (pidfile[0]){
		pid_fd = pidfile_open(pidfile, &old_pid);
		if (pid_fd < 0) {
			if (old_pid) {
				XSEGLOG2(&lc, E, "Daemon already running, pid: %d.", old_pid);
			} else {
				XSEGLOG2(&lc, E, "Cannot open or create pidfile");
			}
			return -1;
		}
	}

	if (daemonize){
		if (close(STDIN_FILENO)){
			XSEGLOG2(&lc, W, "Could not close stdin");
		}
		if (daemon(0, 1) < 0){
			XSEGLOG2(&lc, E, "Cannot daemonize");
			r = -1;
			goto out;
		}
		/* Break away from process group */
		(void) setpgrp();
	}

	pidfile_write(pid_fd);

	// TODO perform argument sanity checks
	verbose = debug_level;

	if (portno != -1) {
		portno_start = portno;
		portno_end = portno;
	}

	if (portno_start == -1 || portno_end == -1){
		XSEGLOG2(&lc, E, "Portno or {portno_start, portno_end} must be supplied");
		usage(argv[0]);
		r = -1;
		goto out;
	}

	peer = peerd_init(nr_ops, spec, portno_start, portno_end, nr_threads,
			threshold);
	if (!peer) {
		r = -1;
		goto out;
	}

	setup_signals(peer);

	r = custom_peer_init(peer, argc, argv);
	if (r < 0) {
		goto out;
	}

	r = init_peerd_loop(peer);

out:
	if (pid_fd > 0) {
		pidfile_remove(pidfile, pid_fd);
	}

	return r;
}
