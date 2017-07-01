# -*- coding: utf-8 -*-

import os
import sys
import time
import signal
import argparse
from random import randrange
from multiprocessing import Process

from scapy.all import sniff
from scapy.layers.dot11 import Dot11Beacon

from core.packet import PacketHandler


class ScapyScanner(PacketHandler):

    def __init__(self, scan_int, power, connect_int):
        super(ScapyScanner, self).__init__(power, connect_int)
        self.process_channel_hop = Process(target=self._channel_hopper)
        self.scan_int = scan_int

    def _packet_filter(self, packet):
        if packet.haslayer(Dot11Beacon):
            self.parser_elements(packet)

    def _signal_handler(self, signal, frame):
        self.process_channel_hop.terminate()
        self.process_channel_hop.join()

    def _channel_hopper(self):
        while True:
            try:
                channel = randrange(1, 14)
                os.system('iw dev {} set channel {}'.format(self.scan_int, channel))
                time.sleep(1.15)
            except:
                pass

    def run(self):
        self.process_channel_hop.start()
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            sniff(iface=self.scan_int, lfilter=self._packet_filter)
        except KeyboardInterrupt:
            sys.exit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-scan_int', help='interface for scan wireless')
    parser.add_argument('-power', type=int, help='limit by power access point signal ')
    parser.add_argument('-con_int', help='interface for connect an access point')
    apt = parser.parse_args()

    object_scanner = ScapyScanner(apt.scan_int, apt.power, apt.con_int)
    try:
        if apt.scan is not None and apt.con_int is not None:
            try:
                object_scanner.run()
            except Exception:
                pass
    except AttributeError as error:
        print error


if __name__ == '__main__':
    main()
