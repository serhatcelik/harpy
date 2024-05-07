"""General utilities."""

import json
import os
import signal
import socket
import threading
from contextlib import contextmanager, suppress
from typing import Generator


def get_devices() -> list[str]:
    """Return a list of network devices."""
    names = []

    for _, name in socket.if_nameindex():
        if name == 'lo':
            continue

        operstate = os.path.join('/sys/class/net', name, 'operstate')

        with suppress(OSError), open(operstate, 'rb') as file:
            if file.readline().rstrip() == b'up':
                names.append(name)

    return names


def get_manuf(manuf_db: dict[str, str], mac: str) -> str:
    """Get a manufacturer."""
    return manuf_db.get(mac[:6], '')


def get_manuf_db(path: str) -> dict[str, str]:
    """Get manufacturer database."""
    try:
        with open(path, encoding='utf-8') as file:
            return json.load(file)
    except(OSError, json.JSONDecodeError):
        return {}


@contextmanager
def ignore(signum: signal.Signals) -> Generator[None, None, None]:
    """Ignore the given signal during the execution."""
    handler = signal.getsignal(signum)
    safesignal(signum, signal.SIG_IGN)
    yield
    safesignal(signum, handler)


def safesignal(signum: signal.Signals, handler) -> None:
    """Thread-safe signal."""
    if threading.current_thread() is not threading.main_thread():
        return
    # https://github.com/python/cpython/issues/67584
    with suppress(TypeError):
        signal.signal(signum, handler)
