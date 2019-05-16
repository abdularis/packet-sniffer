import struct


class TCP:

    def __init__(self):
        self.s_port = 0
        self.d_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.offset = 0
        self.flags = 0
        self.window = 0
        self.checksum = 0
        self.urget_pointer = 0
        self.opts = 0
        self.payload = b''

    def is_fin(self):
        return bool(self.flags & 0x01)

    def is_syn(self):
        return bool(self.flags & 0x02)

    def is_rst(self):
        return bool(self.flags & 0x04)

    def is_psh(self):
        return bool(self.flags & 0x08)

    def is_ack(self):
        return bool(self.flags & 0x10)

    def is_urg(self):
        return bool(self.flags & 0x20)

    def __str__(self):
        flg = "{} = FIN:{}, SYN:{}, RST:{}, PSH:{}, ACK:{}, URG:{}".format(
            self.flags,
            int(self.is_fin()), int(self.is_syn()), int(self.is_rst()), int(self.is_psh()), int(self.is_ack()),
            int(self.is_urg())
        )

        return "=================== TCP ===================\n" \
               "Source Port : {}\nDestination Port : {}\nSeq Num : {}\nAck Num : {}\n" \
               "Data Offset : {} * 4 bytes\nFlags : {}\nWindow : {}\nChecksum : {}\nUrg Pointer : {}\n" \
               "Payload Size : {} bytes\n".format(
            self.s_port, self.d_port, self.seq_num, self.ack_num,
            self.offset, flg, self.window, self.checksum, self.urget_pointer,
            len(self.payload)
        )

    @staticmethod
    def create_from_raw_data(data):
        tcp = TCP()
        tcp.s_port, tcp.d_port, tcp.seq_num, tcp.ack_num, tcp.offset, tcp.flags,\
            tcp.window, tcp.checksum, tcp.urget_pointer = struct.unpack(
            '! H H I I c c H H H', data[:20]
        )

        tcp.flags = int(tcp.flags[0])
        tcp.offset = int(tcp.offset[0]) >> 4
        tcp.payload = data[tcp.offset * 4:]

        return tcp