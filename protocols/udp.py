import struct


class UDP:
    """ User Datagram Protocol Packet

    """

    def __init__(self):
        self.s_port = 0
        self.d_port = 0
        self.length = 0
        self.checksum = 0
        self.payload = b''

    def __str__(self):
        return "=================== UDP ===================\n" \
               "Source Port : {0}\nDest Port : {1}\n" \
               "Checksum : {2} - 0x{2:x}\n" \
               "Length : {3} bytes\nPayload Size : {4} bytes\n".format(
            self.s_port, self.d_port, self.checksum, self.length, len(self.payload)
        )

    def __bytes__(self):
        data = struct.pack("! H H H H {}s".format(len(self.payload)),
                           self.s_port, self.d_port, self.length, self.checksum)
        return data

    @staticmethod
    def create(s_port, d_port, payload=b''):
        udp = UDP()
        udp.s_port = s_port
        udp.d_port = d_port
        udp.length = len(payload)
        udp.payload = payload
        return udp

    @staticmethod
    def create_from_raw_data(data):
        udp = UDP()
        udp.s_port, udp.d_port, udp.length, udp.checksum = struct.unpack(
            '! H H H H', data[:8]
        )

        udp.payload = data[8:udp.length]

        return udp
