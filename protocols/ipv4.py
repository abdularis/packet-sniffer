from common import *
from protocols.defines import IP_PROTO_NAME
import struct


class IPv4:
    """ Ip version 4 Packet

    """

    def __init__(self):
        self.version = 4
        self.header_length = 0
        self.tos = 0
        self.total_length = 0
        self.identification = 0
        self.flags = 0
        self.frag_offset = 0
        self.ttl = 0
        self.proto = 0
        self.checksum = 0
        self.src_ip = '0.0.0.0'
        self.dst_ip = '0.0.0.0'
        self.opts = 0
        self.payload = b''

    def __str__(self):
        return "=================== IP ===================\n" \
               "Version : {0}\nHeader Len : {1} bytes\nTotal Length : {2} bytes\nTTL : {3}\n" \
               "Protocol : {4} - 0x{4:x} ({5})\nChecksum : {6} - 0x{6:x}\nSource Ip : {7}\nDest Ip : {8}\n" \
               "Payload Size : {9} bytes\n".format(self.version, self.header_length,
                                                  self.total_length, self.ttl, self.proto,
                                                  IP_PROTO_NAME[self.proto], self.checksum,
                                                  self.src_ip, self.dst_ip, len(self.payload)
        )

    def __bytes__(self):
        first = (self.version << 12) | (self.header_length << 8) | self.tos
        fourth = (self.flags << 13) | self.frag_offset
        fifth = (self.ttl << 8) | self.proto

        data = struct.pack("! H H H H H H 4s 4s", first, self.total_length, self.identification,
                           fourth, fifth, self.checksum, get_bytes_from_ip(self.src_ip),
                           get_bytes_from_ip(self.dst_ip))
        data += self.payload
        return data

    @staticmethod
    def calc_checksum(ip):
        src_ip = int.from_bytes(get_bytes_from_ip(ip.src_ip), "big")
        dst_ip = int.from_bytes(get_bytes_from_ip(ip.dst_ip), "big")

        res = (ip.version << 12) | (ip.header_length << 8) | ip.tos
        res += ip.total_length
        res += ip.identification
        res += (ip.flags << 13) | ip.frag_offset
        res += (ip.ttl << 8) | ip.proto
        res += (src_ip & 0xFFFF0000) >> 16
        res += (src_ip & 0x0000FFFF)
        res += (dst_ip & 0xFFFF0000) >> 16
        res += (dst_ip & 0x0000FFFF)

        carry = (res & 0xFFFF0000) >> 16
        res &= 0x0000FFFF
        res += carry

        return (~res) & 0x0000FFFF

    @staticmethod
    def create_from_raw_data(data):
        ip = IPv4()

        ip.version = int(data[0]) >> 4
        ip.header_length = int(data[0]) & 0x0f

        ip.tos = data[1]
        ip.total_length, ip.identification = struct.unpack('! H H', data[2:6])
        ip.flags = int(data[6]) >> 5
        ip.frag_offset, ip.ttl, ip.proto, ip.checksum, ip.src_ip, ip.dst_ip = struct.unpack(
            '! H c c H 4s 4s', data[6:20]
        )

        ip.frag_offset &= 0x1fff
        ip.ttl = int(ip.ttl[0])
        ip.proto = int(ip.proto[0])
        ip.src_ip = get_ip_address(ip.src_ip)
        ip.dst_ip = get_ip_address(ip.dst_ip)

        ip.payload = data[ip.header_length*4:]

        return ip

