# -*- coding: utf-8 -*-
import struct
import sys

import bluetooth._bluetooth as bluez


def get_socket(device_id):
    return bluez.hci_open_dev(device_id)


def hci_enable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x01)


def hci_disable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x00)


def hci_toggle_le_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, 0x08, 0x000C, cmd_pkt)


def hci_le_set_scan_parameters(sock):
    sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)


def get_events(sock, loop_count=10000):
    old_filter = sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)
    blacklist=[]
    for i in range(0, loop_count):  # pylint: disable=unused-variable
        pkt = sock.recv(255)
        print(find_mac(pkt,blacklist))
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)


def find_mac(pkt,blacklist):
    ptype, event, plen = struct.unpack("BBB", pkt[:3])  # b'\x04>+' -> (4, 62, 40)  # pylint:disable=unused-variable  # noqa
    if event == 0x3e:  # 62 -> 0x3e -> HCI Event: LE Meta Event (0x3e) plen 44
        subevent, = struct.unpack("B", pkt[3:4])  # b'\x02' -> (2,)
        if subevent == 0x02:  # if 0x02 (2) -> all iBeacons use this
            if pkt not in blacklist:
                print('Looking for: 09:77:01:03:01:02')
                found=0
                for i in range(0, len(pkt)):
                    _hex = "%02x" % struct.unpack("<B", pkt[i:i+1])[0]
                    if _hex == "09" or _hex == '77' or _hex == '03':
                        found+=1
                    print("[%d:%d] %s" % (i, i+1, _hex))
                if found > 2:
                    import pdb
                    pdb.set_trace()

_socket = bluez.hci_open_dev(0)
hci_le_set_scan_parameters(_socket)
hci_enable_le_scan(_socket)
get_events(_socket)
