# coding=utf-8

# This file is part of hARPy
# Released under the MIT license
# Copyright (C) Serhat Çelik

"""
hARPy -who uses ARP- - Active/passive ARP discovery tool.
"""

from __future__ import print_function

import atexit
import logging.config
import os
import subprocess
import sys
import time
import traceback

from harpy import data
from harpy.data import run_main
from harpy.handlers import ExceptionHandler, EchoHandler, InterfaceHandler
from harpy.handlers import ParserHandler, ResultHandler, SignalHandler
from harpy.handlers import SocketHandler, WindowHandler
from harpy.threads import SendThread, SniffThread


def setup_py_main():
    if sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty():
        if os.getpgrp() == os.tcgetpgrp(sys.stdout.fileno()):
            if os.geteuid() == 0:
                main()
                terminate()
            else:
                print("[!] Run me as superuser (a.k.a. root)")
                sys.exit(2)
        else:
            sys.exit(2)
    else:
        sys.exit(2)


def main():
    sys.excepthook = terminate_hard

    setattr(main, data.SIGNAL, SignalHandler())
    vars(main)[data.SIGNAL].catch(*data.CATCH_SIGNALS)
    vars(main)[data.SIGNAL].ignore(*data.IGNORE_SIGNALS)

    setattr(main, data.ECHO, EchoHandler())
    atexit.register(vars(main)[data.ECHO].enable)
    vars(main)[data.ECHO].disable()

    setattr(main, data.PARSER, ParserHandler())
    commands = vars(main)[data.PARSER].create_arguments()
    vars(main)[data.PARSER].create_links(commands)

    if not vars(main)[data.PARSER].check_arguments():
        sys.exit(2)

    setattr(main, data.SOCKET, SocketHandler(data.SOC_PRO))
    vars(main)[data.SOCKET].set_options()
    vars(main)[data.SOCKET].bind(data.INT, data.SOC_POR)

    data.SRC_MAC = InterfaceHandler.get_mac(vars(main)[data.SOCKET].l2soc)
    data.SND_MAC = data.SRC_MAC

    setattr(main, data.SNIFF, SniffThread(vars(main)[data.SOCKET].l2soc))
    vars(main)[data.SNIFF].name = data.SNIFF

    # Create a container to store all threads and then store one
    setattr(main, "threads", [vars(main)[data.SNIFF].name])
    vars(main)[data.SNIFF].start()  # Start sniffing the packets

    # Active mode?
    if not data.PAS:
        setattr(main, data.SEND, SendThread(vars(main)[data.SOCKET].l2soc))
        vars(main)[data.SEND].name = data.SEND
        vars(main)["threads"].append(vars(main)[data.SEND].name)
        vars(main)[data.SEND].start()  # Start sending the packets

    # This line is not in loop for performance
    setattr(main, data.RESULT, ResultHandler())

    time_timeout = time.time()  # Countdown start time
    while data.RUN_MAIN:
        vars(main)[data.SIGNAL].ignore(*data.IGNORE_SIGNALS)
        setattr(main, data.WINDOW, WindowHandler(data.RESULT_ALL))
        subprocess.call(["clear"])  # Better than os.system
        vars(main)[data.WINDOW].draw_skeleton()
        vars(main)[data.WINDOW]()
        vars(main)[data.SIGNAL].catch(*data.CATCH_SIGNALS)

        time_main = time.time()  # Create a new one at every step
        while data.RUN_MAIN and ((time.time() - time_main) < data.WAIT_MAIN):
            run_main(data.RUN_MAIN, (time.time() - time_timeout) >= data.TIM)

            # Improve packet sending performance in other thread
            time.sleep(float(1) / 100)  # Float division for 2.7

            if data.RESULT_A:
                result = data.RESULT_A.pop(0)
                vars(main)[data.RESULT].snd_ip = result[0]
                vars(main)[data.RESULT].src_mac = result[1]
                vars(main)[data.RESULT].snd_mac = result[2]
                vars(main)[data.RESULT].arp_opc = result[3]
                data.RESULT_ALL = vars(main)[data.RESULT](data.RESULT_ALL)


@ExceptionHandler()
def terminate():
    """
    Terminate all threads and close the socket.
    """

    data.CATCH_SIGNALS = []  # No more catch
    data.IGNORE_SIGNALS = data.CATCHABLE_SIGNALS  # Update to ignore all

    # Disable the signal handler (__call__) to prevent activating it again
    getattr(main, data.SIGNAL, SignalHandler()).ignore(*data.IGNORE_SIGNALS)

    # Join first to prevent the "Set changed size during iteration" error
    for _ in getattr(main, "threads", []):
        vars(main)[_].flag.set()  # Tell the thread to terminate itself
        vars(main)[_].join()

    if hasattr(main, data.SOCKET):
        vars(main)[data.SOCKET].close()  # Close the socket

    print("\n")
    for _ in data.EXIT_MSGS:
        print(_)
    sys.stdout.flush()

    # Exit status (0: All is well, 2: Error, 34: Fatal)
    status = 0 if all("signal" in _ for _ in data.EXIT_MSGS) else 2
    sys.exit(status)


def terminate_hard(*args):
    """
    Log the exception and terminate all threads the hard way.

    :param args: Container that stores type, value and traceback.
    """

    log_conf_file = os.path.join(os.path.dirname(__file__), "logging.conf")
    logging.config.fileConfig(log_conf_file)
    logger = logging.getLogger("harpy")
    logger.error("%s\n", traceback.format_exception(args[0], args[1], args[2]))

    # atexit.register will not work when os._exit is called, so...
    getattr(main, data.ECHO, EchoHandler()).enable()
    if hasattr(main, data.SOCKET):
        vars(main)[data.SOCKET].close()
    vars(os)["_exit"](34)  # Force exiting with code 34 (fatal)


if __name__ == "__main__":
    setup_py_main()
