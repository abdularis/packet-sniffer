import struct
import socket
import fcntl


def get_ip_address(raw_data):
    ints_str = map("{:d}".format, raw_data[:4])
    return '.'.join(ints_str)


def get_mac_address(raw_data):
    ints_str = map("{:02x}".format, raw_data[:6])
    return ':'.join(ints_str)


def get_bytes_from_mac(mac_string):
    return struct.pack('! 6B', *(int(x, 16) for x in mac_string.split(':')))


def get_bytes_from_ip(ip_string):
    return struct.pack('! 4B', *(int(x) for x in ip_string.split('.')))


def calc_checksum(data):
    length = len(data) // 2

    shorts = struct.unpack("!{}H".format(length), data)
    res = sum(shorts)

    carry = (res & 0xFFFF0000) >> 16
    res &= 0xFFFF
    res += carry

    res = (~res) & 0xFFFF
    return res


# See for details
# netinet/in.h
# bits/socket.h
# net/if.h
#
# brief
# struct ifreq {
# # define IFNAMSIZ	16
#     union {
# 		char ifrn_name[IFNAMSIZ];	/* Interface name, e.g. "en0".  */
#     } ifr_ifrn;
#
#     union {
# 		struct sockaddr ifru_addr;
# 		struct sockaddr ifru_dstaddr;
# 		struct sockaddr ifru_broadaddr;
# 		struct sockaddr ifru_netmask;
# 		struct sockaddr ifru_hwaddr;
# 		short int ifru_flags;
# 		int ifru_ivalue;
# 		int ifru_mtu;
# 		struct ifmap ifru_map;
# 		char ifru_slave[IFNAMSIZ];	/* Just fits the size */
# 		char ifru_newname[IFNAMSIZ];
# 		__caddr_t ifru_data;
#     } ifr_ifru;
# };
# sizeof(struct ifreq) // = 40 bytes
# sizeof(struct sockaddr) // = 16 bytes


SIOCGIFADDR	= 0x8915
SIOCGIFHWADDR = 0x8927


# struct sockaddr {
#     __SOCKADDR_COMMON (sa_);	/* Common data: address family and length.  */
#     char sa_data[14];		    /* Address data. (MAC Address) */
# };
def get_mac_address_from_if(ifname):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR,
                            struct.pack('40s', bytes(ifname[:16], 'utf8')))
        sock.close()
    except OSError as msg:
        print(msg)
        return ''
    return get_mac_address(ifreq[18:24])


# /* Structure describing an Internet socket address.  */
# struct sockaddr_in {
#     __SOCKADDR_COMMON (sin_); /* 2 bytes */
#     in_port_t sin_port;			/* Port number. 2 bytes */
#     struct in_addr sin_addr;		/* Internet address. 4 bytes (IP addr starts from offs 4) */
#
#     /* Pad to size of `struct sockaddr'.  8 bytes */
#     unsigned char sin_zero[sizeof (struct sockaddr) -
# 			   __SOCKADDR_COMMON_SIZE -
# 			   sizeof (in_port_t) -
# 			   sizeof (struct in_addr)];
# };
def get_ip_address_from_if(ifname):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = fcntl.ioctl(sock.fileno(), SIOCGIFADDR,
                            struct.pack('40s', bytes(ifname[:16], 'utf8')))
        sock.close()
    except OSError as msg:
        print(msg)
        return ''
    return socket.inet_ntoa(ifreq[20:24])


def get_arp_table(ip_filter):
    arp_list = []
    try:
        file = open("/proc/net/arp", 'r')
        # skip first line
        file.readline()
        for line in file:
            # IP address    HW type     Flags       HW address      Mask    Device
            cols = line.strip().split()
            if int(cols[2], 16) == 0x2:
                if cols[0] in ip_filter:
                    arp_list.append((cols[0], cols[3]))
    except FileNotFoundError:
        print("Not Supported")

    return arp_list


def get_list_of_ip(ip_addr, sub_mask):
    subnet_mask = struct.unpack('I', get_bytes_from_ip(sub_mask))[0]
    net_id = struct.unpack('I', get_bytes_from_ip(ip_addr))[0] & subnet_mask
    host_count = ((0xffffffff ^ subnet_mask) // subnet_mask) + 1

    for i in range(1, host_count):
        host_id = socket.htonl(i)
        yield get_ip_address(struct.pack('I', net_id | host_id))

#
# ip = get_list_of_ip("192.168.0.10", "255.255.255.0")
# print(ip)

# print(get_ip_address_from_if("enp2s0"))
# print(get_mac_address_from_if("enp2s0"))
# d = b'\x45\xc0\x00\x5d\xc5\x76\x00\x00\x40\x01\x00\x00\xc0\xa8\x00\x01\xc0\xa8\x00\x0a'
# # d = b'\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\xc0\xa8\x00\x01\xc0\xa8\x00\xc7'
# print('{:x}'.format(calc_checksum(d)))

