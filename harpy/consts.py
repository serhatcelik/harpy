"""This file contains constants."""

import re

############
# Argument #
############
DEFAULT_OCTET = 43
DEFAULT_SLEEP = 1

##########
# Socket #
##########
GGP = 3  # https://www.iana.org/assignments/protocol-numbers
PORT = 0  # auto

##########
# Packet #
##########
BUF_ETH = sum(map(int, re.findall(r'\d', (FMT_ETH := '!6s6s2s'))))
BUF_ARP = sum(map(int, re.findall(r'\d', (FMT_ARP := '!2s2s1s1s2s6s4s6s4s'))))
BUFSIZE = BUF_ETH + BUF_ARP

##########
# Thread #
##########
WAIT_PRINT = 1
WAIT_BLOCK = .001

############
# Terminal #
############
CLS = '\x1b[H\x1b[2J\x1b[3J'  # https://en.wikipedia.org/wiki/ANSI_escape_code
LOGO = (
    r'|_  _  _ _   ',
    r'| |(_|| |_)\/',
    r'        |  / ',
)
