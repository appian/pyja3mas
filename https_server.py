"""HTTPS server for collecting JA3 Fingerprints.

This script stands up a simple working HTTPS server that users can connnect to
and create a TLS connection.

It currently requires valid certificates to become a reputable and trusted
HTTPS server.
"""

import argparse
import logging
import logging.config
import os
import re
import socket
import ssl
import sys
import select

import queue
import httpagentparser

import log_conf
import ja3


CERTFILE = "./certs/fullchain.pem"
"""str Obj: file path to the certificate PEM file"""
KEYFILE = "./certs/privkey.pem"
"""str Obj: file path to the private key PEM file"""

HOST = ""
"""str Obj: hostname to bind to"""
PORT = 4443
"""int: port number where the https server will be accepting connections"""

_LOGGER = None
"""Logger Obj: Global private module variable to store the logger for the program"""

CURL_RE = r"(curl\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting cURL data"""
WGET_RE = r"([wW]get\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting wget data"""
REQUESTS_RE = r"(python-requests\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting python-requests data"""
POWERSHELL_RE = r"([pP]ower[sS]hell\/(\d+\.)?(\d+\.)?(\d+))"
"""str Obj: regex string specifically for extracting PowerShell data"""
GO_RE = r"([gG]o\D+\/(\d\.)?(\d\.)?(\d+))"
"""str Obj: regex string specifically for extracting Go data"""

LOG_FNAME = "server.log"
LOG_DIR = "logs"
# 60 MB rollover byte length
ROLLOVER_BYTES = 64*1024*1024


EXIT_SUCC = 0
PARAM_ERROR = 1
CONFIG_ERROR = 2
"""int: module variables for return codes"""

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
READ_WRITE = READ_ONLY | select.POLLOUT
TIMEOUT = 1000

def check_for_headless_browsers(request):
    """Given a UA string, determines if the request came from a headless
    browser.

    Args:
        request (:obj: `str`) UA string or full HTTP request to parse for
            headless browsers

    Returns:
        (:obj: `re`) regex object that is parseable if a match for a headless
            browser is found, None otherwise
    """

    # performs the regex matching
    # starts with curl
    match_obj = re.search(CURL_RE, request)
    # if not curl, then tries wget
    if match_obj is None:
        match_obj = re.search(WGET_RE, request)
    # if not wget, then tries requests module
    if match_obj is None:
        match_obj = re.search(REQUESTS_RE, request)
    # if not requests, then tries powershell
    if match_obj is None:
        match_obj = re.search(POWERSHELL_RE, request)
    # if not powershell, then tries Go
    if match_obj is None:
        match_obj = re.search(GO_RE, request)

    if match_obj is not None:
        return match_obj.group()

    return None


def extract_ua_str(request):
    """Attempts to extract a User-Agent string from an HTTP GET request.

    If the GET request contains a User-Agent string, it will extract just the
    UA string.

    Args:
        request (:obj: `str`) full HTTP GET Request

    Returns:
        (:obj: `bytes`) the UA string, or 'Unknown' if it is not found
    """

    _LOGGER.debug("Attempting to Extract User-Agent String")

    ua_idx = request.lower().find(b"user-agent")
    if ua_idx >= 0:
        new_substr = request[ua_idx + len("User-Agent: "):]
        end_ua_idx = new_substr.find(b"\r\n")
        # returns the UA string if found
        return new_substr[:end_ua_idx]

    # returns unknown if no UA string
    return b"Unknown"


def setup_arguments(parser):
    """Sets up command line arguments

    Args:
        parser (:obj: `ArgParse`) parser object to add arguments to

    Returns:
        void
    """

    parser.add_argument("--debug", help="Turn on debug logging",
                        action="store_true")


def init_logger(debug_on):
    """Initializes the private module variable logger

    Adds the file formatter and logging file to the default logging
    configuration.

    Args:
        debug_on (bool): boolean determining if debug mode is set via the
            command line

    Returns:
        void
    """

    global _LOGGER

    # prod-level stdout
    log_conf.LOGGING_CONFIG["handlers"]["consoleHandler"]["formatter"] = "fileFormatter"
    log_conf.LOGGING_CONFIG["handlers"]["fileHandler"]["filename"] = "%s/%s" % (LOG_DIR, LOG_FNAME)
    log_conf.LOGGING_CONFIG["handlers"]["fileHandler"]["maxBytes"] = ROLLOVER_BYTES

    if not os.path.isdir(LOG_DIR):
        os.mkdir(LOG_DIR)

    logging.config.dictConfig(log_conf.LOGGING_CONFIG)

    if debug_on:
        _LOGGER = logging.getLogger("debug")
    else:
        _LOGGER = logging.getLogger("user")
    _LOGGER.info("Logger created")
    _LOGGER.debug("Debug On")


def handle_new_conn(sock, fd_to_socket, poller):
    """Handles a new connection to the server.

    Accepts the socket sonnection and registers the socket with the poller
    appropriately.

    Arguments:
        sock (:obj: `socket`) socket object associated with the server socket
        fd_to_socket (:obj: `dict`) Dictionary mapping file descriptors to
            socket objects for new connections.
        poller (:obj: `select.poll`) polling object from the select module for
            concurrent socket IO

    Returns:
        void
    """

    conn, addr = sock.accept()
    conn.setblocking(0)
    fd_to_socket[conn.fileno()] = conn
    poller.register(conn, READ_ONLY)
    _LOGGER.debug("New TCP Connection Created: %s", addr)


def retrieve_http_req(sock, message_queues, sock_to_ja3, poller):
    """Attempts to process incoming bytes and get the HTTP GET request.

    Reads input from the given socket and if it sees a GET request, it parses
    the User-Agent string for browser metadata.

    Arguments:
        sock (:obj: `socket`) socket object to process any incoming bytes on
        message_queues (:obj: `queue.queue`) standard queue for outgoing messages
        sock_to_ja3 (:obj: `dict`) Dictionary mapping socket object to ja3 fingerprints
        poller (:obj: `select.poll`) polling object from the select module for
            concurrent socket IO.

    Returns:
        bool: True on successful GET request, False otherwise and on error
    """

    # hopefully get the GET request here for UA string processing
    try:
        init_request = sock.recv(2048)
    except BlockingIOError as err:
        _LOGGER.warning("Nothing to read")
        return False

    except ConnectionResetError as err:
        _LOGGER.warning("Connection reset: %s", err)
        return False

    # data exists from the previous read
    if init_request:
        try:
            # it's a GET request
            if b"GET" in init_request:
                _LOGGER.debug(init_request)
                ua_str = extract_ua_str(init_request)
                browser_name = "Unknown"
                browser_version = "Unknown"

                # it could extract the UA section of the header
                if ua_str != b"Unknown":
                    # real quick check for any headless browser(s)
                    found_headless = \
                        check_for_headless_browsers(ua_str.decode("utf-8"))

                    # it got a hit from a headless browser
                    if found_headless is not None:
                        _LOGGER.debug("Detected headless")
                        # splits and extracts name/version
                        headless_info = found_headless.split("/")
                        browser_name = headless_info[0]
                        browser_version = headless_info[1]

                    else:
                        # need to decode utf-8 because the agent
                        # parser requires a str input
                        parsed_ua = httpagentparser.detect(ua_str.decode("utf-8"))
                        browser = parsed_ua.get("browser", None)
                        # the UA parser was able to
                        # successfully extract a browser
                        if browser is not None:
                            browser_name = parsed_ua["browser"].get("name", None)
                            browser_version = \
                                parsed_ua["browser"].get("version", None)

                # grab the ja3 associated with the socket
                ja3_digest = sock_to_ja3[sock]
                browser_info = [ja3_digest, browser_name, \
                        browser_version, \
                        ua_str.decode("utf-8")]

                _LOGGER.info(browser_info)

                # real quick edge case if we can't parse the UA
                # string properly, it won't crash the server
                b_name = b""
                b_version = b""

                if browser_name is not None:
                    b_name = browser_name.encode("utf-8")
                if browser_version is not None:
                    b_version = browser_version.encode("utf-8")

                reply = b"HTTP/1.1 200 OK\r\n" \
                        +b"Content-Type: text/html\r\n" \
                        +b"\r\n" \
                        +b"<html><h1>%b</h1><h1>%b</h1><h1>%b</h1></html>" % \
                        (ja3_digest.encode("utf-8"), b_name, b_version)

                # add the message reply to the queue
                message_queues[sock].put(reply)
                # tell the poller we ready to send it
                poller.modify(sock, READ_WRITE)

                return True

        except (OSError, NameError)  as err:
            # this needs to be warning because these errors are
            # always expected to happen
            # don't want this printing out every time
            _LOGGER.warning(err)
            return False

    _LOGGER.warning("Nothing Read")
    return False


def tls_handshake(sock, message_queues, fd_to_socket, sock_to_ja3, poller):
    """Takes a given connection and completes the TLS handshake to obtain the
    JA3 fingerprint.

    Arguments:
        sock (:obj: `socket`) current TCP connection with a client to complete
            the TLS handshake with.
        message_queues (:obj: `queue.queue`) standard queue for message IO for
            the given socket
        fd_to_socket (:obj: `dict`) Dictionary mapping file descriptor integers
            to socket objects
        sock_to_ja3 (:obj: `dict`) Dictionary mapping socket objects to ja3
            fingerprints
        poller (:obj: `select.poll`) poller object for concurrent IO on the socket
    """

    try:
        # peek and get the client HELLO for the TLS handshake
        # we have an ssl socket, then we've already completed the TLS handshake
        if isinstance(sock, ssl.SSLSocket):
            _LOGGER.info("returning the ssl socket for false")
            return False

        # otherwise, we peek at the TLS handshake
        _LOGGER.info("receiving client hello")
        client_hello = sock.recv(2048, socket.MSG_PEEK)

        addr = sock.getpeername()

        # we got data from it and it didn't hangup
        if client_hello:
            ja3_record = ja3.process_ssl(client_hello)
            # handles if the client_hello is not TLS handshake or just plain HTTP
            if ja3_record is not None:
                ja3_digest = ja3_record.get("ja3_digest", None)

                # gets rid of the non-ssl socket
                del fd_to_socket[sock.fileno()]
                poller.unregister(sock)

                # need to set to blocking for a hot sec so it can complete the TLS handshake
                sock.setblocking(1)

                # complete the TLS handshake by wrapping the
                # socket in the ssl module
                _LOGGER.debug("Attempting to wrap the socket with SSL")

                ssock = ssl.wrap_socket(sock, certfile=CERTFILE, \
                        keyfile=KEYFILE, server_side=True, \
                        ssl_version=ssl.PROTOCOL_TLSv1_2)


                _LOGGER.debug("got peername")
                # set the ssl socket to be nonblocking
                ssock.setblocking(0)
                _LOGGER.debug("created TLS connection, adding SSL socket to poller")

                # add the ssl socket for later use
                fd_to_socket[ssock.fileno()] = ssock
                # add the ja3 digest to the socket
                sock_to_ja3[ssock] = ja3_digest

                # it's a new ssl socket client, so register the poller to
                # look out for it
                poller.register(ssock, READ_ONLY)
                message_queues[ssock] = queue.Queue()

                _LOGGER.info("New TLS Connection Established: %s", addr)
                _LOGGER.info("JA3: (%s,%s) :: %s", addr[0], addr[1], ja3_digest)

                # successful TLS handshake
                return True

            # equivalent of an else block
            _LOGGER.debug("Did not receive TLS handshake from %s", addr)

            # no message queue yet or ja3 digest
            return False

        # equivalent of an else block
        _LOGGER.info("Client %s Hung Up before initiating TLS Handshake", addr)
        _LOGGER.debug(sock)
        cleanup_connection(sock, poller)
        return None

    except BlockingIOError as err:
        _LOGGER.warning("Blocking IO Err: %s", err)
        return False

    except ssl.SSLError as err:
        # error typically associated with browsers complaining about a
        # self-signed cert
        _LOGGER.warning("SSL Err: %s", err)
        # cleanup_connection(sock, poller)
        return None

    except OSError as err:
        _LOGGER.warning(err)
        cleanup_connection(sock, poller)
        return None



def cleanup_connection(sock, poller, message_queues=None, sock_to_ja3=None):
    """Cleans up the connection for the given TCP socket.

    Arguments:
        sock (:obj: `socket`) current connected socket to close the connection
            with
        poller (:obj: `select.poll`) poller for concurrent IO operations
        message_queues (:obj: `queue.queue`) Optionally provided queue for the
            socket's outgoing messages
        sock_to_ja3 (:obj: `dict`) Optional dictionary that maps socket objects
            to its ja3 fingerprint
    """

    try:
        _LOGGER.info("Closing connection to %s", sock.getpeername())
    except OSError as err:
        _LOGGER.error(err)
        _LOGGER.info("Closing connection to %s", sock)

        if sock.fileno() == -1:
            _LOGGER.warning("Socket prematurely closed on client end: fd == -1")
            return

    poller.unregister(sock)
    # gracefully shutdown to eliminate RST packets
    sock.close()

    if message_queues is not None:
        del message_queues[sock]
    if sock_to_ja3 is not None:
        del sock_to_ja3[sock]


def main():
    """Main method that runs and handles the HTTPs server concurrently

    Args:
        void

    Returns:
        void
    """

    parser = argparse.ArgumentParser()
    setup_arguments(parser)
    args = parser.parse_args()

    init_logger(args.debug)

    _LOGGER.debug("Initializing Socket")

    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.setblocking(0)
    serv.bind((HOST, PORT))
    serv.listen(10)

    # queue for sending messages back to the clients
    message_queues = {}

    poller = select.poll()
    poller.register(serv, READ_ONLY)

    fd_to_socket = {serv.fileno(): serv,}
    sock_to_ja3 = {}

    _LOGGER.info("Launching Server on https://%s:%d", ("localhost" if HOST == "" else HOST), PORT)

    while True:
        events = poller.poll(TIMEOUT)

        for file_desc, flag in events:
            sock = fd_to_socket[file_desc]

            if flag & (select.POLLIN | select.POLLPRI):
                # server socket gets a new connection
                if sock is serv:
                    handle_new_conn(sock, fd_to_socket, poller)

                # not init connection to the server
                else:
                    # checks if this is the second event fired and need to grab the TLS handshake
                    handshake = tls_handshake(sock, message_queues, \
                            fd_to_socket, sock_to_ja3, poller)
                    # checks either error or non tls handshake
                    if handshake is not None and not handshake:
                        # check if there is an HTTP GET request because
                        # tls_handshake returned False
                        if not retrieve_http_req(sock, message_queues, sock_to_ja3, poller):
                            # we didn't get a GET, so close it
                            cleanup_connection(sock, poller, message_queues, sock_to_ja3)

            # client hangs up
            elif flag & select.POLLHUP:
                cleanup_connection(sock, poller)

            # we have output to send to the client
            elif flag & select.POLLOUT:
                try:
                    next_msg = message_queues[sock].get_nowait()
                # we've got nothing to send it
                except queue.Empty:
                    poller.modify(sock, READ_ONLY)

                else:
                    # respond with the message
                    try:
                        sock.send(next_msg)
                    except OSError as _:
                        _LOGGER.error("Client hung up before we could send back"
                                      "HTTP response")
                    # we do not keep any more connections after we use the client
                    # for the JA3 fingerprint
                    finally:
                        cleanup_connection(sock, poller, message_queues, sock_to_ja3)

            # little error happened
            elif flag & select.POLLERR:
                # close everything
                cleanup_connection(sock, poller, message_queues, sock_to_ja3)


if __name__ == "__main__":
    main()
    sys.exit(EXIT_SUCC)
