import gevent
import signal
from gevent import pool as gpool
from gevent.monkey import patch_select
from daemon import DaemonContext
from daemon.pidlockfile import PIDLockFile
import argparse
import sys
import os
import logging

patch_select()
from .common import (
        Segment, Xseg_ctx, XsegRequest, Reply
        )


logger = logging.getLogger()
VERBOSITY_ENUM =  {
                 0: logging.ERROR,
                 1: logging.WARN,
                 2: logging.INFO,
                 3: logging.DEBUG
            }

def setup_logging(logfile=None, verbosity=None, **kwargs):
    import logging.handlers

    formatter = logging.Formatter("%(asctime)s %(name)s %(module)s"
                                      " [%(levelname)s] %(message)s")
    if logfile == "":
        logfile = None

    if logfile is not None:
        log_handler = logging.handlers.WatchedFileHandler(logfile)
        log_handler.setFormatter(formatter)
    else:
        log_handler = logging.StreamHandler()
        log_handler.setFormatter(formatter)

    logger.addHandler(log_handler)
    logger.setLevel(logging.ERROR)

    if verbosity is None:
        verbosity = 0

    loglevel = VERBOSITY_ENUM.get(verbosity, logging.ERROR)
    peerlogger = logging.getLogger("peer")
    peerlogger.setLevel(loglevel)

def fail_on_exception(func):
    """decorator"""
    def dispatch_wrapper(self, request):
        """fooo"""
        try:
            return func(self, request)
        except Exception as e:
            reply = Reply.get_failed_reply(request)
            reply.reply()
            raise e

    return dispatch_wrapper


class Peer(object):
    """Peer class"""
    serverthread = None
    pool = None
    ops = {}
    xsegctx = None
    terminated = False

    def __init__(self, spec=None, start_portno=None, end_portno = None,
            nr_ops=None, **kwargs):

        if not nr_ops:
            nr_ops = 16


        portno = start_portno
        segment = Segment.fromSpec(spec)
        xsegctx = Xseg_ctx(segment, portno)
        self.pool = gpool.Pool(nr_ops+1)
        self.xsegctx = xsegctx
        self._install_signal_handlers()

    def _install_signal_handlers(self):
        """Installs signal handlers for handling SIGINT and SIGTERM
        gracefully.
        """

        def request_stop(*args, **kwargs):
            """Stops the current worker loop but waits for child processes to
            end gracefully (warm shutdown).
            """

            self.terminated = True

        signal.signal(signal.SIGINT, request_stop)
        gevent.signal(signal.SIGINT, request_stop)
        gevent.signal(signal.SIGTERM, request_stop)

    def dispatch_unknown(self, request):
        reply = Reply.get_failed_reply(request)
        reply.reply()

    @fail_on_exception
    def dispatch(self, request):
        """Fooo"""
        func = self.ops.get(request.get_op())
        if func:
            func(request)
        else:
            self.dispatch_unknown(request)

    def loop(self):
        """foo"""
        while not self.terminated:
            self.pool.wait_available()
            xreq = self.xsegctx._wait_request()
            if xreq:
                request = XsegRequest(self.xsegctx, xreq)
                self.pool.spawn(self.dispatch, request)


    def launch_loop(self):
        """foo"""
        self.serverthread = self.pool.spawn(self.loop)
        self.pool.join()



peer_main = None
def register_main(main):
    global peer_main
    peer_main = main

def launch_peer(kwargs):
    setup_logging(**kwargs)

    if kwargs.get('daemon') is True:
        pidf = kwargs.get('pidfile')
        if pidf == "":
            pidf = None
        if pidf is not None:
            pidf = PIDLockFile(pidf, threaded=False)

        for handler in logger.handlers:
            files_preserve = []
            stream = getattr(handler, 'stream')
            if stream and hasattr(stream, 'fileno'):
                files_preserve.append(handler.stream)

        stderr_stream = None
        for handler in logger.handlers:
            stream = getattr(handler, 'stream')
            if stream and hasattr(handler, 'baseFilename'):
                stderr_stream = stream


        daemonctx = DaemonContext(
                pidfile=pidf,
#                detach_process=True,
                prevent_core=False,
                stdout=stderr_stream,
                stderr=stderr_stream,
                files_preserve=files_preserve
                )

        with daemonctx:
            gevent.reinit()
            peer_main(kwargs)
    else:
        setup_logging(**kwargs)
        peer_main(kwargs)

def get_peer_parser():
    parser = argparse.ArgumentParser(description='Peer')
    parser.add_argument('-d', dest='daemon', action='store_true', default=False,
            help='Daemonize')
    parser.add_argument('-g', dest='spec', type=str, nargs='?', help='spec',
            required=True)
    parser.add_argument('-n', dest='nr_ops', type=int, help='Number of ops')
    parser.add_argument('-v', dest='verbosity', type=int, help='Log verbosity')
    parser.add_argument('-sp', dest='start_portno', type=int, help='Start port',
            required=True)
    parser.add_argument('-ep', dest='end_portno', type=int, help='Start port',
            required=True)
    parser.add_argument('-l', dest='logfile', type=str, nargs='?',
            help='logfile')
    parser.add_argument('--pidfile', dest='pidfile', type=str, nargs='?',
            help='pidfile')
    parser.add_argument('--threshold', dest='threshold', type=str, nargs='?',
            help='threshold')

    return parser

