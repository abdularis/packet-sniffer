from protocols.defines import *
from common import *
from struct import calcsize
import struct


class ARP:
    """ Address Resolution Protocol Packet

    """

    def __init__(self):
        # hdr = hardware type,
        # pro = protocol type,
        # hln = hardware address length,
        # pln = protocol address length,
        # opcode = operation code
        # sha = sender hw address
        # spa = sender protocol address
        # tha = target hw address
        # tpa = target protocol address
        self.hdr = HW_T_ETHERNET
        self.pro = ETH_P_IP
        self.hln = 6
        self.pln = 4
        self.opcode = ARP_REQUEST
        self.sha = "ff:ff:ff:ff:ff:ff"
        self.spa = "0.0.0.0"
        self.tha = "ff:ff:ff:ff:ff:ff"
        self.tpa = "0.0.0.0"

    def __str__(self):
        return "=================== ARP ===================\n" \
               "Hw Type : {0}\nProto Type : {1} - 0x{1:x}\n" \
               "Hw Addr Len : {2} bytes\nProto Addr Len : {3} bytes\n" \
               "Op Code : {4} - {9}\nSender Hw Addr : {5}\nSender Proto Addr : {6}\n" \
               "Target Hw Addr : {7}\nTarget Proto Addr : {8}\n".format(
            self.hdr, self.pro, self.hln, self.pln, self.opcode, self.sha,
            self.spa, self.tha, self.tpa, ARP_OPCODE_DESC[self.opcode]
        )

    def __bytes__(self):
        data = struct.pack('! HHccH6s4s6s4s', self.hdr, self.pro,
                           bytes(chr(self.hln), 'utf-8'), bytes(chr(self.pln), 'utf-8'), self.opcode,
                           get_bytes_from_mac(self.sha), get_bytes_from_ip(self.spa),
                           get_bytes_from_mac(self.tha), get_bytes_from_ip(self.tpa))
        return data

    @staticmethod
    def create(opcode, sender_mac, sender_ip, target_mac, target_ip):
        arp = ARP()
        arp.opcode = opcode
        arp.sha = sender_mac
        arp.spa = sender_ip
        arp.tha = target_mac
        arp.tpa = target_ip
        return arp


    @staticmethod
    def create_from_raw_data(data):
        arp = ARP()
        length = calcsize('! HHccH')
        arp.hdr, arp.pro, arp.hln, arp.pln, arp.op = struct.unpack('! HHccH', data[:length])
        arp.hln = int.from_bytes(arp.hln, 'little')
        arp.pln = int.from_bytes(arp.pln, 'little')

        arp.sha = get_mac_address(data[length:length + arp.hln])
        length += arp.hln
        arp.spa = get_ip_address(data[length:length + arp.pln])
        length += arp.pln

        arp.tha = get_mac_address(data[length:length + arp.hln])
        length += arp.hln
        arp.tpa = get_ip_address(data[length:length + arp.pln])

        return arp

