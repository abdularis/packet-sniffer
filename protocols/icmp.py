from protocols.defines import ICMP_TYPE_DESCRIPTION
import struct


class ICMP:
    """ Internet Control Message Protocol Packet

    """

    def __init__(self):
        self.type = 0
        self.code = 0
        self.checksum = 0
        self.other_header = ''
        self.payload = b''

    def __str__(self):
        return "=================== ICMP ===================\n" \
               "Type : {} - {} \nCode : {}\nChecksum : {} - 0x{:x}\n".format(
            self.type, self.get_description(), self.code, self.checksum, self.checksum
        )

    def get_description(self):
        return ICMP_TYPE_DESCRIPTION[self.type]

    @staticmethod
    def calc_checksum():
        pass

    @staticmethod
    def create_from_raw_data(data):
        icmp = ICMP()
        icmp.type, icmp.code, icmp.checksum, icmp.other_header = struct.unpack(
            '! c c H 4s', data[:8]
        )

        icmp.type = int(icmp.type[0])
        icmp.code = int(icmp.code[0])
        icmp.payload = data[8:]

        return icmp

