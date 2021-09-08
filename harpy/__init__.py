# coding=utf-8

# This file is part of hARPy
# Released under the MIT license
# Copyright (C) Serhat Çelik

"""
hARPy -who uses ARP- - Active/passive ARP discovery tool.
"""

from __future__ import print_function

import os
import sys
import threading

if sys.version_info[0] == 2:
    _MAJOR = 2
    _MINOR_MIN = 7
    _MINOR_MAX = _MINOR_MIN
else:
    _MAJOR = 3
    _MINOR_MIN = 4
    _MINOR_MAX = 9

###############
# Requirement #
###############
_OS_REQ = "posix"
_MAJOR_REQ = _MAJOR
_MINOR_REQ = range(_MINOR_MIN, _MINOR_MAX + 1)
_PYTHON_REQ = "%d.%d-%d" % (_MAJOR, _MINOR_MIN, _MINOR_MAX)

###########
# Current #
###########
_OS_NOW = os.name
_MAJOR_NOW = sys.version_info[0]
_MINOR_NOW = sys.version_info[1]
_PYTHON_NOW = "%d.%d" % (_MAJOR_NOW, _MINOR_NOW)

if _OS_NOW != _OS_REQ:
    print("[!] Unsupported operating system for hARPy: %s" % _OS_NOW)
    sys.exit(2)
if _MAJOR_NOW != _MAJOR_REQ or _MINOR_NOW not in _MINOR_REQ:
    print("[!] Expected Python %s, got Python %s" % (_PYTHON_REQ, _PYTHON_NOW))
    sys.exit(2)


def install_thread_excepthook():
    """
    Workaround for sys.excepthook thread bug from:
      https://bugs.python.org/issue1230540
    """

    init_original = threading.Thread.__init__

    def init(self, *args, **kwargs):
        init_original(self, *args, **kwargs)
        run_original = self.run

        def run(*args2, **kwargs2):
            try:
                run_original(*args2, **kwargs2)
            except Exception:
                sys.excepthook(*sys.exc_info())

        self.run = run

    threading.Thread.__init__ = init


install_thread_excepthook()
