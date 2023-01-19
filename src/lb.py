import logging
import re
import os
import signal
import socket
import socketserver
import threading
import time
import random
import argparse
import ssl
from collections import deque
from util import parse_host_and_port_list, EnvDefault

logging.basicConfig(level=logging.DEBUG if 'LB_DEBUG' in os.environ.keys() else logging.INFO,
                    format="%(asctime)s [%(levelname)-7s] [%(threadName)-12s] %(message)s")


class Deque(deque):
    """
    Customized double-ended queue class.

    Because pop/popleft will not block, an Event is used to wait if the queue is empty.
    Appending an item signals the waiters to continue processing.
    """
    def __init__(self, max_length=None):
        super().__init__(maxlen=max_length)
        self.not_empty = threading.Event()
        self.senders = []
        self._sender_shutdown = False
        self._receiver_shutdown = False

    def len(self):
        return super().__len__()

    def append(self, elem):
        super().append(elem)
        self.not_empty.set()

    def pop(self, timeout=None):
        self.not_empty.wait(timeout=timeout)  # Wait until not empty, or next append call

        if not self.len():
            self.not_empty.clear()

        return super().popleft()

    def shutdown_receiver(self):
        self._receiver_shutdown = True

    def shutdown(self):
        logging.warning("Signaling senders waiting on queue for shutdown... (this could take up to 30 seconds)")
        self._sender_shutdown = True
        self.not_empty.set()

    def shutting_down(self):
        return self._sender_shutdown

    def add_sender(self, s):
        self.senders.append(s)

    def remove_sender(self, s):
        if sender in self.senders:
            self.senders.remove(s)

    def can_receive(self):
        if len(self.senders) > 0 and not self._receiver_shutdown:
            return True

        return False


class ThreadedTLSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, certfile, keyfile, ssl_version, bind_and_activate=True,
                 queue=None):
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
        self.queue = queue
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)

    def get_request(self):
        new_socket, from_addr = self.socket.accept()
        conn_stream = ssl.wrap_socket(new_socket, server_side=True, certfile=self.certfile, keyfile=self.keyfile,
                                      ssl_version=self.ssl_version)
        return conn_stream, from_addr


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, queue=None):
        self.allow_reuse_address = True
        self.queue = queue
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.buf = b''  # buffer per thread/connection
        self.breaker = re.compile(rb"[\n\r]+(?!\s)")
        super().__init__(request, client_address, server)

    def handle(self):
        self.request.settimeout(60)
        size = 1024

        logging.debug("Connection opened from %s:%d.", self.request.getpeername()[0], self.request.getpeername()[1])

        while True and self.server.queue.can_receive():
            if len(self.buf) > 0:
                logging.debug("Current buffer %s", self.buf)

            try:
                data = self.request.recv(size)
                if data:
                    logging.debug("Data received %s", data)
                    self.buf += data

                    try:
                        match = self.breaker.search(self.buf)
                        while match is not None:
                            logging.debug("Regex match string %s", self.buf[:match.end()])
                            self.server.queue.append(self.buf[:match.end()])
                            self.buf = self.buf[match.end():]
                            match = self.breaker.search(self.buf)
                    except Exception as e:
                        logging.error("Regex error", exc_info=e)
                else:
                    logging.debug('Connection closed by remote system. %s:%d', self.request.getpeername()[0], self.request.getpeername()[1])
                    return False
            except socket.timeout:
                logging.debug("Closing socket due to timeout.")
                break
            except Exception as e:
                logging.exception("Unhandled exception in ThreadedTCPRequestHandler", exc_info=e)


class Receiver(object):
    def __init__(self, host, port, queue, key_file=None, cert_file=None, ssl_version=int(ssl.PROTOCOL_TLSv1_2)):
        self.host = host
        self.port = port
        self.queue = queue
        if key_file:
            logging.debug("Starting TLS encrypted listener...")
            self.server = ThreadedTLSServer((host, port), ThreadedTCPRequestHandler, cert_file, key_file, ssl_version,
                                            queue=self.queue)
        else:
            logging.debug("Starting unencrypted listener...")
            self.server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler, queue=queue)

    def run(self):
        logging.info("Starting receiver on %s:%d...", self.host, self.port)
        self.server.serve_forever()

    def shutdown(self, *args):
        logging.warning("Shutting down receiver... (this could take up to 60 seconds)")
        self.queue.shutdown_receiver()
        self.server.shutdown()
        self.server.server_close()


class ThreadedSender(object):
    def __init__(self, host, port, queue, use_tls=False, ssl_verify=False, path_to_ca_certs=None):
        self.host = host
        self.port = port
        self.queue = queue
        self.context = None
        self.conn = None

        if use_tls:
            self.context = ssl.create_default_context()
            self.context.load_default_certs()

            if not ssl_verify:
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE

            if path_to_ca_certs and ssl_verify:
                if os.path.isdir(path_to_ca_certs):
                    self.context.load_verify_locations(capath=path_to_ca_certs)
                elif os.path.isfile(path_to_ca_certs):
                    self.context.load_verify_locations(cafile=path_to_ca_certs)

    def run(self):
        while True and not self.queue.shutting_down():
            try:
                logging.info("Starting sender...")

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.settimeout(5)

                if self.context:
                    logging.debug("Sender will use encryption.")
                    s = self.context.wrap_socket(s, server_hostname=self.host)

                s.connect((self.host, self.port))
                logging.info("Opened sender connection. %s:%d -> %s:%d", s.getsockname()[0],
                             s.getsockname()[1], s.getpeername()[0], s.getpeername()[1])

                sockname = f"{s.getsockname()[0]}:{s.getsockname()[1]}"
                self.queue.add_sender(sockname)
                while True:
                    try:
                        if self.queue.shutting_down() and self.queue.len() == 0:
                            logging.warning('Shutting down sender...')
                            if s:
                                s.close()
                            return
                        value = self.queue.pop(timeout=None if not self.queue.shutting_down() else 0)
                        logging.debug("Consumed: %s via %s:%d", value, s.getsockname()[0], s.getsockname()[1])
                        s.send(value)
                    except IndexError:
                        pass
                    except (socket.timeout, BrokenPipeError):
                        logging.warning("Sender timeout or failure! Removing peer from senders list. %s", sockname)
                        self.queue.append(value)
                        self.queue.remove_sender(sockname)
                    except Exception as e:
                        logging.error("Unhandled exception in sender...", exc_info=e)

            except (ConnectionRefusedError, socket.timeout) as e:
                logging.warning("Unable to connect to remote system to forward logs... %s Server: %s:%d", e, self.host, self.port)
                if not self.queue.shutting_down():
                    time.sleep(random.randrange(15, 30, 1))
            except Exception as e:
                logging.error("Unhandled exception in sender...", exc_info=e)


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--help", action="help")
parser.add_argument("-h", "--host", default="0.0.0.0", action=EnvDefault, envvar="LB_RECEIVER_HOST",
                    help="Receiver host IP address (defaults to 0.0.0.0)")
parser.add_argument("-p", "--port", default=1514, type=int, action=EnvDefault, envvar="LB_RECEIVER_PORT",
                    help="Receiver port (defaults to 1514)")
parser.add_argument("-t", "--threads", default=10, type=int, action=EnvDefault,
                    envvar="LB_WORKER_THREADS_PER_SENDER_HOST",
                    help="The number of threads per sending host (defaults to 10)")
parser.add_argument("-s", "--senders", required=True, action=EnvDefault, envvar="LB_SENDER_HOSTS",
                    help="Comma separated list of sending hosts. Hosts should be in host:port format.")
parser.add_argument("-k", "--key", required=False, action=EnvDefault, envvar="LB_RECEIVER_TLS_KEY_FILE",
                    help="TLS private key file location")
parser.add_argument("-c", "--cert", required=False, action=EnvDefault, envvar="LB_RECEIVER_TLS_CERT_FILE",
                    help="TLS certificate file location")
parser.add_argument("--usetls", required=False, type=bool, default=False, action=EnvDefault, envvar="LB_SENDER_TLS",
                    help="Enable TLS connections for senders.")
parser.add_argument("--tlsverify", required=False, type=bool, default=False, action=EnvDefault,
                    envvar="LB_SENDER_TLS_VERIFY", help="Verify TLS certificate information for senders.")
parser.add_argument("--cacert", required=False, type=str, default=None, action=EnvDefault,
                    envvar="LB_SENDER_TLS_CACERT", help="Sender TLS CA Certificate file or directory.")
args = parser.parse_args()

if (args.key or args.cert) and not (args.key and args.cert):
    parser.error("Both --key and --cert flags are required when using TLS!")

shared_queue = Deque()
max_workers = args.threads
server = Receiver(args.host, args.port, shared_queue, key_file=args.key, cert_file=args.cert)
senders = parse_host_and_port_list(args.senders)


def handle_shutdown(*args):
    server.shutdown()
    shared_queue.shutdown()


signal.signal(signal.SIGINT, handle_shutdown)

logging.info("Starting threads...")

logging.info("Starting %d sending threads...", max_workers * len(senders))
for sender in senders:
    for _ in range(max_workers):
        threading.Thread(target=ThreadedSender(sender[0], sender[1], shared_queue, use_tls=args.usetls,
                                               ssl_verify=args.tlsverify, path_to_ca_certs=args.cacert).run).start()

threading.Thread(target=server.run).start()
