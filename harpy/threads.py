# coding=utf-8

# This file is part of hARPy
# Released under the MIT license
# Copyright (C) Serhat Çelik

import binascii
import socket
import struct
import threading

from harpy import data
from harpy.data import check_ip, get_first_last
from harpy.handlers import ExceptionHandler, PacketHandler


class SendThread(threading.Thread):
    def __init__(self, l2soc):
        super(SendThread, self).__init__()

        self.l2soc = l2soc
        self.flag = threading.Event()

    def run(self):
        while not self.flag.is_set():
            for _ in data.RNG:
                if self.flag.is_set():
                    return

                self.send(_)

            # No repeat?
            if not data.REP:
                break

        # Only works if repeat mode is not enabled
        data.TGT_IP = False  # False means packet sending has finished

    @ExceptionHandler(data.SEND)
    def send(self, range_):
        first_ip, last_ip = get_first_last(range_)

        start = struct.unpack("!I", socket.inet_aton(first_ip))[0]
        stop = struct.unpack("!I", socket.inet_aton(last_ip))[0]

        for _ in range(start, stop + 1):
            if self.flag.is_set():
                return

            data.TGT_IP = socket.inet_ntoa(struct.pack("!I", _))

            tgt_ip_node = int(data.TGT_IP.split(".")[3])
            if data.FST and (tgt_ip_node not in data.FAST_NODE):
                continue

            new_count = data.CNT  # Restore the original at every step
            while (not self.flag.is_set()) and (new_count > 0):
                tgt_ip_no_node = data.TGT_IP.split(".")[:3]
                # Gratuitous ARP?
                if tgt_ip_node == data.NOD:
                    data.SND_IP = ".".join(tgt_ip_no_node + ["0"])
                else:
                    data.SND_IP = ".".join(tgt_ip_no_node + [str(data.NOD)])

                eth_frame = PacketHandler.create_eth_frame()
                arp_header = PacketHandler.create_arp_header()

                try:
                    self.l2soc.send(eth_frame + arp_header)  # Send the packet
                except socket.error as err:
                    # 11: Resource temporarily unavailable
                    if err.args[0] == 11:
                        self.flag.wait(data.WAIT_SEND)
                    else:
                        raise  # Go to except clause in the wrapper
                else:
                    new_count -= 1
                    self.flag.wait(float(data.SLP) / 1000)  # Non-blocking wait


class SniffThread(threading.Thread):
    packet = None

    def __init__(self, l2soc):
        super(SniffThread, self).__init__()

        self.l2soc = l2soc
        self.flag = threading.Event()

    @ExceptionHandler(data.SNIFF)
    def run(self):
        while not self.flag.is_set():
            try:
                self.packet = self.l2soc.recv(data.SOC_BUF)  # Receive a packet
            except socket.error as err:
                # 11: Resource temporarily unavailable
                if err.args[0] == 11:
                    self.flag.wait(data.WAIT_SNIFF)
                else:
                    raise
            else:
                # Packet valid?
                if len(self.packet) >= data.MIN_BUF:
                    self.sniff()

    def sniff(self):
        # Ethernet frame from the packet
        eth_frame = struct.unpack("!6s6s2s", self.packet[:14])
        # ARP header from the packet
        arp_header = struct.unpack("!2s2s1s1s2s6s4s6s4s", self.packet[14:42])

        src_mac = binascii.hexlify(eth_frame[1]).decode("utf-8")
        # Not your MAC address?
        if src_mac != data.SRC_MAC:
            eth_typ = binascii.hexlify(eth_frame[2]).decode("utf-8")
            # EtherType ARP?
            if eth_typ == data.ETH_TYP:
                arp_opc = binascii.hexlify(arp_header[4]).decode("utf-8")
                snd_mac = binascii.hexlify(arp_header[5]).decode("utf-8")
                snd_ip = socket.inet_ntoa(arp_header[6])
                if (not data.FLT) or (data.FLT and check_ip(snd_ip, data.RNG)):
                    data.RESULT_A.append([snd_ip, src_mac, snd_mac, arp_opc])
