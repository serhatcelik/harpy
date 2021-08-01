# coding=utf-8

# This file is part of hARPy
# Released under the MIT license
# Copyright (C) Serhat Çelik

from __future__ import print_function

import argparse
import binascii
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading

from harpy import __license__, data
from harpy.data import get_logo, get_banner, add_colons, add_dots, run_main


class ExceptionHandler(object):
    def __init__(self, who=None):
        self.who = who  # Responsible for the error

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except (IOError, OSError, socket.error, termios.error) as err:
                # 5: Input/output error
                if err.args[0] == 5:
                    # Mostly for "print" errors
                    pass
                elif err.args[0] in (6, 9, 19, 100):
                    # 6: No such device or address
                    # 9: Bad file descriptor
                    # 19: No such device
                    # 100: Network is down
                    self.add_exception(err.args[0], err.args[1])
                else:
                    raise

            return run_main(False)

        return wrapper

    def add_exception(self, errnum, error):
        """
        Update the exit messages container with a new error message.

        :param errnum: Error number.
        :param error: Error content.
        """

        data.EXIT_MSGS.add("[!] %s -> [Errno %d] %s" % (self.who,
                                                        errnum, error))


class ArgumentHandler(object):
    def __init__(self):
        pass

    @staticmethod
    def handle_count(count):
        if count < data.MIN_CNT:
            data.CNT = data.MIN_CNT

    @staticmethod
    @ExceptionHandler()
    def handle_interface(interface):
        if interface is False:
            print("[!] No available interface in %s" % data.SYS_PATH)
            sys.stdout.flush()
            return False
        if interface == "lo":
            print("[!] '%s': This is not an Ethernet interface" % interface)
            sys.stdout.flush()
            return False
        if interface not in InterfaceHandler().members:
            print("[!] '%s': No such interface" % interface)
            sys.stdout.flush()
            return False
        if InterfaceHandler().members[interface] != "up":
            print("[!] '%s': Interface not available (dormant?)" % interface)
            sys.stdout.flush()
            return False
        return True

    @staticmethod
    def handle_log():
        if os.path.isfile(data.LOG_FILE):
            with open(data.LOG_FILE, "r") as log:
                return log.read()
        return "No log"

    @staticmethod
    def handle_node(node):
        if not data.MIN_NOD <= node <= data.MAX_NOD:
            data.NOD = data.DEF_NOD

    @staticmethod
    def handle_passive(passive):
        if passive:
            # Fast mode only makes sense in active mode, so...
            data.FST = None

    @staticmethod
    @ExceptionHandler()
    def handle_range(range_):
        if range_ is None:
            # Filtering is only allowed if a scanning range is specified, so...
            data.FLT = None
            # Repeat is only allowed if a scanning range is specified, so...
            data.REP = None
            range_ = data.RNG = data.DEF_RNG

        # Do this only if the scanning range is different from the default
        if range_ != data.DEF_RNG:
            octet = "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            pattern = r"^({0}\.{0}\.{0}\.{0}/(8|16|24))$".format(octet)

            set_range_ = list()
            # Remove repetitive scanning ranges
            for _ in range_:
                if _ not in set_range_:
                    set_range_.append(_)
            range_ = set_range_

            problem = [_ for _ in range_ if not bool(re.search(pattern, _))]
            if problem:
                print("Problem with scanning range(s):", end=" ")
                for i, _ in enumerate(problem):
                    # Last error?
                    if i == len(problem) - 1:
                        print(_)
                    else:
                        print(_, end=data.SEPARATOR)
                sys.stdout.flush()
                return False

        data.RNG = [[
            _.split(".")[0],
            _.split(".")[1],
            _.split(".")[2],
            _.split(".")[-1].split("/")[0],
            _.split(".")[-1].split("/")[-1],
        ] for _ in range_]  # Convert the scanning range to list format

        return True

    @staticmethod
    def handle_sleep(sleep):
        if sleep < data.MIN_SLP:
            data.SLP = data.MIN_SLP
        elif sleep > data.MAX_SLP:
            data.SLP = data.MAX_SLP

    @staticmethod
    def handle_timeout(timeout):
        if timeout < data.MIN_TIM:
            data.TIM = data.MIN_TIM


class EchoHandler(object):
    def __init__(self):
        self.descriptor = sys.stdin.fileno()

    @ExceptionHandler()
    def enable(self):
        """
        Enable terminal echo.
        """

        new = termios.tcgetattr(self.descriptor)
        new[3] |= termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, new)

    @ExceptionHandler()
    def disable(self):
        """
        Disable terminal echo.
        """

        new = termios.tcgetattr(self.descriptor)
        new[3] &= ~termios.ECHO
        termios.tcsetattr(self.descriptor, termios.TCSANOW, new)


class InterfaceHandler(object):
    members = dict()  # All interfaces

    def __init__(self):
        if hasattr(socket, "if_nameindex"):
            if_nameindex = socket.if_nameindex()  # pylint: disable=E1101
            self.members = {_[-1]: None for _ in if_nameindex}
        else:
            if os.path.isdir(data.SYS_PATH):
                self.members = {_: None for _ in os.listdir(data.SYS_PATH)}

        for _ in self.members:
            if _ != "lo":
                operstate_file = os.path.join(data.SYS_PATH, _, "operstate")
                if os.path.isfile(operstate_file):
                    with open(operstate_file, "r") as operstate:
                        try:
                            self.members[_] = operstate.read().strip().lower()
                        except (IOError, OSError) as err:
                            # 22: Invalid argument
                            if err.args[0] == 22:
                                pass
                            else:
                                raise

    def __call__(self):
        for _ in self.members:
            if self.members[_] == "up":
                return _
        return False

    @staticmethod
    def get_mac(l2soc):
        """
        Return the MAC address of an interface.

        :param l2soc: Layer 2 RAW socket.
        """

        return binascii.hexlify(l2soc.getsockname()[-1]).decode("utf-8")


class PacketHandler(object):
    def __init__(self):
        pass

    @staticmethod
    def create_eth_frame():
        return struct.pack(
            "!6s6s2s",
            binascii.unhexlify(data.DST_MAC),
            binascii.unhexlify(data.SRC_MAC),
            binascii.unhexlify(data.ETH_TYP),
        )

    @staticmethod
    def create_arp_header():
        return struct.pack(
            "!2s2s1s1s2s6s4s6s4s",
            binascii.unhexlify(data.ARP_HWT),
            binascii.unhexlify(data.ARP_PRT),
            binascii.unhexlify(data.ARP_HWS),
            binascii.unhexlify(data.ARP_PRS),
            binascii.unhexlify(data.ARP_REQ),
            binascii.unhexlify(data.SND_MAC),
            socket.inet_aton(data.SND_IP),
            binascii.unhexlify(data.TGT_MAC),
            socket.inet_aton(data.TGT_IP),
        )


class ParserHandler(object):
    def __init__(self):
        pass

    @staticmethod
    def create_arguments():
        parser = argparse.ArgumentParser(
            prog="harpy", usage="%(prog)s [optional_arguments]",
            description="hARPy - Active/passive ARP discovery tool\n"
                        "Written by Serhat Çelik "
                        "(with the help of my family and a friend)",
            epilog="It is recommended that you enable passive mode on "
                   "networks with heavy packet flow.\n"
                   "See https://github.com/serhatcelik/harpy "
                   "for more information.",
            formatter_class=argparse.RawTextHelpFormatter,
        )

        ######################
        # Optional Arguments #
        ######################
        parser.add_argument(
            "-c", default=data.DEF_CNT, type=int, metavar="COUNT", dest="c",
            help="send each request COUNT times "
                 "[default:%%(default)s|min:%d]" % data.MIN_CNT,
        )
        parser.add_argument(
            "-f", "--fast", action="store_true", dest="f",
            help="enable fast mode, only scan for specific hosts",
        )
        parser.add_argument(
            "-F", "--filter", action="store_true", dest="F",
            help="filter the sniff results using the given scanning range",
        )
        parser.add_argument(
            "-i", default=InterfaceHandler()(), metavar="INTERFACE", dest="i",
            help="use INTERFACE as network device to send/sniff packets",
        )
        parser.add_argument(
            "-L", "--license", version=__license__.__doc__,
            action="version", help="show license and exit",
        )
        parser.add_argument(
            "-l", "--log", action="version",
            version=ArgumentHandler.handle_log(), help="show log and exit",
        )
        parser.add_argument(
            "-n", default=data.DEF_NOD, type=int, metavar="NODE", dest="n",
            help="use NODE as last ip octet to send packets "
                 "[default:%%(default)s|min:%d|max:%d]" % (data.MIN_NOD,
                                                           data.MAX_NOD),
        )
        parser.add_argument(
            "-p", "--passive", action="store_true", dest="p",
            help="enable passive mode, do not send any packets",
        )
        parser.add_argument(
            "-R", "--repeat", action="store_true", dest="R",
            help="enable repeat mode, never stop sending packets"
        )
        parser.add_argument(
            "-r", nargs="+", metavar="RANGE", dest="r",
            help="use RANGE as scanning range",
        )
        parser.add_argument(
            "-s", default=data.DEF_SLP, type=int, metavar="TIME", dest="s",
            help="sleep TIME milliseconds between each request "
                 "[default:%%(default)s|min:%d|max:%d]" % (data.MIN_SLP,
                                                           data.MAX_SLP),
        )
        parser.add_argument(
            "-t", default=data.DEF_TIM, type=int, metavar="TIMEOUT", dest="t",
            help="stop scanning after TIMEOUT seconds "
                 "[default:%%(default)s|min:%d]" % data.MIN_TIM,
        )
        parser.add_argument(
            "-v", "--version", version="v" + __license__.VERSION,
            action="version", help="show program version and exit",
        )

        return parser.parse_args()

    @staticmethod
    def create_links(commands):
        """
        Create shortcuts to the commands.

        :param commands: Parsed command-line arguments.
        """

        data.CNT = commands.c
        data.FST = commands.f
        data.FLT = commands.F
        data.INT = commands.i
        data.NOD = commands.n
        data.PAS = commands.p
        data.RNG = commands.r
        data.REP = commands.R
        data.SLP = commands.s
        data.TIM = commands.t

    @staticmethod
    def check_arguments():
        return False not in [
            ArgumentHandler.handle_count(data.CNT),
            ArgumentHandler.handle_interface(data.INT),
            ArgumentHandler.handle_node(data.NOD),
            ArgumentHandler.handle_passive(data.PAS),
            ArgumentHandler.handle_range(data.RNG),
            ArgumentHandler.handle_sleep(data.SLP),
            ArgumentHandler.handle_timeout(data.TIM),
        ]


class ResultHandler(object):
    snd_ip = None
    src_mac = None
    snd_mac = None
    arp_opc = None

    def __init__(self):
        self.ouis = self.open_ouis()  # Get OUIs database

    def __call__(self, results):
        for _ in range(0, len(results), data.CONT_STP_SIZ):
            if (self.snd_ip in results) and (self.snd_ip == results[_]):
                if self.src_mac == results[_ + 1]:
                    if self.snd_mac == results[_ + 2]:
                        if self.arp_opc != data.ARP_REQ:
                            results[_ + 3] += 1
                        else:
                            results[_ + 4] += 1
                        return results

        results.append(self.snd_ip)  # Sender IP address
        results.append(self.src_mac)  # Source MAC address
        results.append(self.snd_mac)  # Sender MAC address
        results.append(1 if self.arp_opc != data.ARP_REQ else 0)  # Reply
        results.append(1 if self.arp_opc == data.ARP_REQ else 0)  # Request
        results.append(self.get_vendor(self.src_mac))  # Ethernet vendor
        results.append(self.get_vendor(self.snd_mac))  # ARP vendor

        return results

    @staticmethod
    def open_ouis():
        """
        Obtain the contents of the file that contains OUIs.
        """

        ouis_file = os.path.join(os.path.dirname(__file__), "ouis.json")
        if os.path.isfile(ouis_file):
            with open(ouis_file, "r") as ouis:
                try:
                    return json.load(ouis)
                except ValueError:
                    pass
        return None

    def get_vendor(self, mac):
        """
        Find a vendor using the given MAC address.

        :param mac: MAC address to find the vendor.
        """

        if self.ouis is not None:
            if mac[:6] in self.ouis:
                # Prevent the "ordinal not in range(128)" error in 2.7
                # Also prevent for incorrect measurement of text length
                return self.ouis[mac[:6]].encode("ascii", "ignore").decode()
            return "unknown"
        return ""


class SignalHandler(object):
    def __init__(self):
        self.main_thread = vars(threading)["_MainThread"]

    def __call__(self, _signum, _frame):
        data.EXIT_MSGS.add("Exiting, received signal %d" % _signum)
        run_main(False)

    def catch(self, *signals):
        if isinstance(threading.current_thread(), self.main_thread):
            for _ in signals:
                signal.signal(_, self.__call__)

    def ignore(self, *signals):
        # Be sure to ignore the signals
        while isinstance(threading.current_thread(), self.main_thread):
            try:
                for _ in signals:
                    signal.signal(_, signal.SIG_IGN)
                return
            except TypeError:
                # Workaround for _thread.interrupt_main bug from:
                #   https://bugs.python.org/issue23395
                pass


class SocketHandler(object):
    def __init__(self, protocol):
        self.l2soc = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol)
        )  # Open a socket

    def set_options(self):
        self.l2soc.setblocking(False)  # Non-blocking mode
        self.l2soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l2soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    @ExceptionHandler(data.SOCKET)
    def bind(self, interface, port):
        """
        Bind the socket to an interface.

        :param interface: Network device to send/sniff packets.
        :param port: Port to bind to an interface.
        """

        self.l2soc.bind((interface, port))

    def close(self):
        self.l2soc.close()


class WindowHandler(object):
    logo = get_logo()

    def __init__(self, results):
        self.results = results

        self.col_length = self.get_column_length()

        self.banner = get_banner()
        self.banner_results = [
            len(list(_ for _ in range(0, len(results), data.CONT_STP_SIZ))),
            sum(results[_] for _ in range(3, len(results), data.CONT_STP_SIZ)),
            sum(results[_] for _ in range(4, len(results), data.CONT_STP_SIZ)),
        ]

        for i, _ in enumerate(self.banner_results):
            self.banner[i] += str(_)

    @ExceptionHandler()
    def __call__(self):
        for _ in range(0, len(self.results), data.CONT_STP_SIZ):
            ip_address = self.results[_]
            eth_mac_address = add_colons(self.results[_ + 1])
            arp_mac_address = add_colons(self.results[_ + 2])
            arp_rep = str(self.results[_ + 3])
            rep_space_len = data.MAX_REP_LEN - len(arp_rep)
            # Prevent column distortion
            arp_rep = str(float("inf")) if rep_space_len < 0 else arp_rep
            arp_req = str(self.results[_ + 4])
            req_space_len = data.MAX_REQ_LEN - len(arp_req)
            arp_req = str(float("inf")) if req_space_len < 0 else arp_req
            eth_vendor = self.results[_ + 5]
            arp_vendor = self.results[_ + 6]

            # Suspicious packet?!
            if eth_mac_address != arp_mac_address:
                if data.ETHER_TO_ARP:
                    mac_address = arp_mac_address + "!"
                    vendor = arp_vendor
                else:
                    mac_address = eth_mac_address + "!"
                    vendor = eth_vendor
            else:
                mac_address = eth_mac_address
                vendor = eth_vendor

            print(ip_address.ljust(data.MAX_IP_LEN), end=data.SEPARATOR)
            print(mac_address.ljust(data.MAX_MAC_LEN), end=data.SEPARATOR)
            print(arp_rep.ljust(data.MAX_REP_LEN), end=data.SEPARATOR)
            print(arp_req.ljust(data.MAX_REQ_LEN), end=data.SEPARATOR)
            vendor = add_dots(vendor, self.col_length, data.MAX_ALL_LEN)
            print(vendor)
            sys.stdout.flush()

    @staticmethod
    @ExceptionHandler()
    def get_column_length():
        if hasattr(os, "get_terminal_size"):
            return os.get_terminal_size().columns  # pylint: disable=E1101
        return int(subprocess.check_output(["tput", "cols"]).strip())

    @ExceptionHandler()
    def draw_a_line(self):
        print("-" * self.col_length)
        sys.stdout.flush()

    @staticmethod
    @ExceptionHandler()
    def draw_a_row(*args):
        """
        Draw a row for the result window.

        :param args: Container that stores column texts.
        """

        for i, _ in enumerate(args):
            # Last column?
            if i == len(args) - 1:
                print(_)
                sys.stdout.flush()
            else:
                print(_, end=data.SEPARATOR)

    @ExceptionHandler()
    def draw_skeleton(self):
        #################
        # Logo & Banner #
        #################
        for i, j in zip(self.logo, self.banner):
            print(i + (" " * (data.MAX_IP_LEN - len(i))), end=data.SEPARATOR)
            print(j)
        sys.stdout.flush()

        ######################
        # MAC Address Column #
        ######################
        data.ETHER_TO_ARP = not data.ETHER_TO_ARP

        ########
        # Rows #
        ########
        if data.TGT_IP is None:
            info_col = "Sending disabled"
        elif data.TGT_IP is False:
            info_col = "Sending finished"
        else:
            info_col = "Sending .%d -> %s" % (data.NOD, data.TGT_IP)
            if data.REP:
                info_col = "R/" + info_col

        self.draw_a_line()
        self.draw_a_row("Ctrl+C to exit".ljust(data.MAX_IP_LEN), info_col)
        self.draw_a_line()
        self.draw_a_row(
            "IP Address".ljust(data.MAX_IP_LEN),
            "MAC Address".ljust(data.MAX_MAC_LEN),
            "Reply".ljust(data.MAX_REP_LEN),
            "Request".ljust(data.MAX_REQ_LEN),
            "Vendor",
        )
        self.draw_a_line()
