import struct
from common import *
from protocols.defines import ETH_PROTO_NAME


class Ethernet:
    """ Ethernet Frame

    """

    def __init__(self):
        self.r_mac = "ff:ff:ff:ff:ff:ff" # receiver mac address
        self.s_mac = "ff:ff:ff:ff:ff:ff" # sender mac address
        self.proto = 0
        self.payload = b''

    def __str__(self):
        return "=================== Eth ===================\n" \
               "Receiver : {0}\nSender : {1}\nProto : {2} - 0x{2:x} ({3})\n" \
               "Payload Size : {4} bytes\n".format(
            self.r_mac, self.s_mac, self.proto, ETH_PROTO_NAME[self.proto], len(self.payload)
        )

    def __bytes__(self):
        fmt = '! 6s6sH{}s'.format(str(len(self.payload)))
        data = struct.pack(fmt, get_bytes_from_mac(self.r_mac),
                           get_bytes_from_mac(self.s_mac), self.proto, self.payload)
        return data

    @staticmethod
    def create(r_mac, s_mac, proto, payload):
        ef = Ethernet()
        ef.r_mac = r_mac
        ef.s_mac = s_mac
        ef.proto = proto
        ef.payload = payload
        return ef

    @staticmethod
    def create_from_raw_data(data):
        ef = Ethernet()
        # receiver mac, sender mac, protocol type, payload
        ef.r_mac = get_mac_address(data[0:6])
        ef.s_mac = get_mac_address(data[6:12])
        ef.proto = struct.unpack('! H', data[12:14])[0]
        ef.payload = data[14:]
        return ef
