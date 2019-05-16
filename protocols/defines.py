# Protocol Ethernet Id
ETH_P_ALL = 0x0003      # Every packet
ETH_P_LOOP = 0x0060	    # Ethernet Loopback packet
ETH_P_IP = 0x0800       # Internet Protocol packet
ETH_P_ARP = 0x0806		# Address Resolution packet
ETH_P_RARP = 0x8035	    # Reverse Addr Res packet
ETH_P_IPX = 0x8137		# IPX packet
ETH_P_IPV6 = 0x86DD		# IPv6 packet
ETH_P_LOOPBACK = 0x9000	# Ethernet loopback packet, per IEEE 802.3


# Standard (Popular) Ip Protocol
IPPROTO_ICMP = 1       # Internet Control Message Protocol
IPPROTO_IGMP = 2       # Internet Group Management Protocol
IPPROTO_IPIP = 4       # IPIP tunnels (older KA9Q tunnels use 94)
IPPROTO_TCP = 6        # Transmission Control Protocol
IPPROTO_UDP = 17       # User Datagram Protocol
IPPROTO_DCCP = 33      # Datagram Congestion Control Protocol
IPPROTO_IPV6 = 41      # IPv6-in-IPv4 tunnelling
IPPROTO_AH = 51        # Authentication Header protocol
IPPROTO_ENCAP = 98     # Encapsulation Header
IPPROTO_COMP = 108     # Compression Header Protocol
IPPROTO_UDPLITE = 136   # UDP-Lite (RFC 3828)
IPPROTO_MPLS = 137     # MPLS in IP (RFC 4023)
IPPROTO_RAW = 255      # Raw IP packets


# ARP hw type
HW_T_ETHERNET = 1


# ARP operation code
ARP_REQUEST = 1
ARP_REPLY = 2
R_ARP_REQUEST = 3
R_ARP_REPLY = 4
D_ARP_REQUEST = 5
D_ARP_REPLY = 6
D_ARP_ERROR = 7
IN_ARP_REQUEST = 8
IN_ARP_REPLY = 9


ARP_OPCODE_DESC = {
    ARP_REQUEST : "Request",
    ARP_REPLY : "Replay"
};


ETH_PROTO_NAME = {
    0x0800 : "IP",
    0x0806 : "ARP",
    0x8035 : "RARP",
    0x8137 : "IPX",
    0x86DD : "IPV6"
}


IP_PROTO_NAME = {
    1 : "ICMP",
    2 : "IGMP",
    4 : "IPIP",
    6 : "TCP",
    17 : "UDP",
    33 : "DCCP",
    41 : "IPV6",
    51 : "AH",
    98 : "ENCAP",
    108 : "COMP",
    136 : "UDPLITE",
    137 : "MPLS",
    255 : "RAW"
}

ICMP_TYPE_DESCRIPTION = {
    0 : "Echo Reply",
    1 : "Unassigned",
    2 : "Unassigned",
    3 : "Destination Unreachable",
    4 : "Source Quench",
    5 : "Redirect",
    6 : "Alternate Host Address",
    7 : "Unassigned",
    8 : "Echo",
    9 : "Router Advertisement",
    10 : "Router Selection",
    11 : "Time Exceeded",
    12 : "Parameter Problem",
    13 : "Timestamp",
    14 : "Timestamp Reply",
    15 : "Information Request",
    16 : "Information Reply",
    17 : "Address Mask Request",
    18 : "Address Mask Reply",
    30 : "Traceroute",
    31 : "Datagram Conversion Error"
}
