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
    for i in range(0, loop_count):  # pylint: disable=unused-variable
        pkt = sock.recv(255)
        print(find_mac(pkt))
    sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)


def packed_bdaddr_to_string(bdaddr_packed):
    #  iBeacon packets have the mac byte-reversed, reverse with bdaddr_packed[::-1]  # noqa
    #  b'ID\x8b\xea&b' -> b'b&\xea\x8bDI'
    #  decode to int -> (98, 38, 234, 139, 68, 73) , join by : as hex -> '62:26:ea:8b:44:49'  # noqa
    return ':'.join('%02x' % i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))  # noqa


def find_mac(pkt):
    ptype, event, plen = struct.unpack("BBB", pkt[:3])  # b'\x04>+' -> (4, 62, 40)  # pylint:disable=unused-variable  # noqa
    if event == 0x3e:  # 62 -> 0x3e -> HCI Event: LE Meta Event (0x3e) plen 44
        subevent, = struct.unpack("B", pkt[3:4])  # b'\x02' -> (2,)
        if subevent == 0x02:  # if 0x02 (2) -> all iBeacons use this
            return packed_bdaddr_to_string(pkt[3:9])
