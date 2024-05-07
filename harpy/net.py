"""Custom network threads."""

import binascii
import dataclasses
import ipaddress
import os
import socket
import struct
import textwrap
import threading
from itertools import cycle
from typing import Generator

from harpy.consts import (
    BUFSIZE,
    BUF_ETH,
    DEFAULT_SLEEP,
    FMT_ARP,
    FMT_ETH,
    WAIT_BLOCK,
)
from harpy.globs import controller, interrupts, sent
from harpy.utils import get_manuf


class Thread(threading.Thread):
    """Base class for network threads."""

    def __init__(self, so: socket.socket, nw: ipaddress.IPv4Network) -> None:
        super().__init__()

        self.sock = so
        self.network = nw

        self.src = so.getsockname()[-1].hex()
        self.sha = self.src


class Sender(Thread):
    """Sender thread."""

    name = 'Sender'

    def __init__(self, so, nw, node: int, ms: int, f: bool, R: bool) -> None:
        super().__init__(so, nw)

        self.node = node
        self.sleep = ms / 1000
        self.fast = f
        self.repeat = R

        self.hosts = iter(nw.hosts()) if not R else cycle(nw.hosts())

    def run(self) -> None:
        """Method representing the thread's activity."""
        while not controller.is_set() and (host := next(self.hosts, None)):
            tpa = str(host)

            node = int(tpa.rsplit('.', 1)[-1])

            if self.fast and node not in (1, 2, 100, 127, 200, 254):
                continue

            # Fix gratuitous ARP
            spa = str(host - node + (node != self.node) * self.node)

            # https://en.wikipedia.org/wiki/Ethernet_frame
            eth = struct.pack(
                FMT_ETH,
                b'\xff' * 6,  # Destination MAC Address
                binascii.unhexlify(self.src),  # Source MAC Address
                b'\x08\x06',  # EtherType
            )

            # https://en.wikipedia.org/wiki/Address_Resolution_Protocol
            arp = struct.pack(
                FMT_ARP,
                b'\x00\x01',  # Hardware Type
                b'\x08\x00',  # Protocol Type
                b'\x06',  # Hardware Address Length
                b'\x04',  # Protocol Address Length
                b'\x00\x01',  # Operation Code
                binascii.unhexlify(self.sha),  # Sender Hardware Address
                socket.inet_aton(spa),  # Sender Protocol Address
                b'\xff' * 6,  # Target Hardware Address
                socket.inet_aton(tpa),  # Target Protocol Address
            )

            try:
                self.sock.send(eth + arp)
            except BlockingIOError:
                controller.wait(WAIT_BLOCK)
                continue
            except OSError as err:
                controller.set()
                interrupts.append([self.name, err])
                break
            else:
                sent.set(spa + '->' + tpa)
                try:
                    controller.wait(self.sleep)
                except OverflowError:
                    self.sleep = DEFAULT_SLEEP / 1000
                    controller.wait(self.sleep)
        else:
            sent.set('')


@dataclasses.dataclass
class Scent:
    """Sniff result fields."""

    spa: str

    who_has: int
    is_at: int

    source: dict[str, str]
    sender: dict[str, str]


class Sniffer(Thread):
    """Sniffer thread."""

    name = 'Sniffer'

    def __init__(self, so, nw, db: dict[str, str], F: bool, S: bool) -> None:
        super().__init__(so, nw)

        self.db = db
        self.exclude = F
        self.strict = S

        self.scents = []  # type: list[Scent]

    def __iter__(self) -> Generator[str, None, None]:
        for scent in self.scents:
            yield textwrap.shorten(str(scent), os.get_terminal_size().columns)

    def run(self) -> None:
        """Method representing the thread's activity."""
        while not controller.is_set():
            try:
                packet = self.sock.recv(BUFSIZE)
            except BlockingIOError:
                controller.wait(WAIT_BLOCK)  # Performance improvement!
                continue
            except OSError as err:
                controller.set()
                interrupts.append([self.name, err])
                break
            else:
                if len(packet) < BUFSIZE:
                    continue

            eth = struct.unpack(FMT_ETH, packet[:BUF_ETH])

            src = eth[1].hex()

            if src == self.src:
                continue

            if eth[2] != b'\x08\x06':
                continue

            arp = struct.unpack(FMT_ARP, packet[BUF_ETH:BUFSIZE])

            spa = socket.inet_ntoa(arp[6])

            if self.exclude and ipaddress.IPv4Address(spa) not in self.network:
                continue

            who_has = int(arp[4] == b'\x00\x01')
            is_at = 1 - who_has

            sha = arp[5].hex()

            source = {src: get_manuf(self.db, src)}
            sender = {sha: get_manuf(self.db, sha)}

            for scent in self.scents:
                if (scent.spa, scent.source) == (spa, source):
                    if self.strict:
                        if scent.sender != sender:
                            continue
                    scent.who_has += who_has
                    scent.is_at += is_at
                    break
            else:
                self.scents.append(Scent(spa, who_has, is_at, source, sender))
