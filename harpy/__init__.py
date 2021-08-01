# coding=utf-8

# This file is part of hARPy
# Released under the MIT license
# Copyright (C) Serhat Çelik

"""
hARPy -who uses ARP- - Active/passive ARP discovery tool.
"""

import sys
import threading


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
            except Exception:  # pylint: disable=W0703
                sys.excepthook(*sys.exc_info())

        self.run = run

    threading.Thread.__init__ = init


install_thread_excepthook()
