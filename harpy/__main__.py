"""hARPy — Active/passive ARP discovery tool."""

import atexit
import os
import signal
import socket
import threading

from harpy.cli import Namespace, parser
from harpy.consts import (
    CLS,
    GGP,
    LOGO,
    PORT,
    WAIT_PRINT,
)
from harpy.globs import controller, interrupts, sent
from harpy.handlers import Echo, Is
from harpy.net import Sender, Sniffer
from harpy.utils import get_manuf_db, ignore, safesignal


def start() -> list[threading.Thread]:
    """Start the program."""
    opts = parser.parse_args(namespace=Namespace())

    safesignal(signal.SIGINT, stop)

    Echo.disable()

    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(GGP))

    atexit.register(sock.close)

    sock.setblocking(False)  # Non-blocking mode

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    sock.bind((opts.device, PORT))

    db = get_manuf_db(os.path.join(os.path.dirname(__file__), 'db.json'))

    threads = []  # type: list[threading.Thread]

    network = opts.network

    sniffer = Sniffer(sock, network, db, opts.F, opts.S)
    threads.append(sniffer)

    if not opts.p:
        sender = Sender(sock, network, opts.node, opts.sleep, opts.f, opts.R)
        threads.append(sender)

    for thread in threads:
        thread.start()

    while not controller.wait(WAIT_PRINT):  # Non-blocking wait
        with ignore(signal.SIGINT):
            print(CLS, *LOGO, *sniffer, opts() + '>\t' + sent.get(), sep='\n')

    return threads


def stop(*args) -> None:
    """Stop the program."""
    safesignal(signal.SIGINT, signal.SIG_IGN)
    controller.set()


def join(threads: list[threading.Thread]) -> None:
    """Join all threads."""
    for thread in threads:
        thread.join()


def log() -> None:
    """Print the interrupt messages, if any."""
    for message in interrupts:
        print(message)


def main() -> None:
    """Entry point."""
    if not Is.atty():  # Order matters!
        return
    if not Is.fore():
        return
    if not Is.root():
        parser.print_help()
        return

    join(start())

    log()


if __name__ == '__main__':
    main()
