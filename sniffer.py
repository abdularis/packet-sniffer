import socket
import protocols
import os
import sys
import argparse


TAB_1 = "    "
TAB_2 = TAB_1 * 2
TAB_3 = TAB_1 * 3


args = None
net_iface = None
out_file = None


def indent(tab, string):
    return ''.join(tab + line for line in string.splitlines(True))


def main():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, protocols.ETH_P_ALL)
        sock.bind((net_iface, protocols.ETH_P_ALL))
    except OSError as msg:
        print(msg)
        return

    packet_count = 0
    while True:
        data = sock.recv(2014)
        if data != b'':
            eth = protocols.Ethernet.create_from_raw_data(data)
            packet_count += 1
            dt_str = "-= " + str(packet_count) + " =-\n" + str(eth)
            if eth.proto == protocols.ETH_P_IP:
                ip = protocols.IPv4.create_from_raw_data(eth.payload)
                dt_str += indent(TAB_1, str(ip))

                if ip.proto == protocols.IPPROTO_ICMP:
                    icmp = protocols.ICMP.create_from_raw_data(ip.payload)
                    dt_str += indent(TAB_2, str(icmp))

                elif ip.proto == protocols.IPPROTO_TCP:
                    tcp = protocols.TCP.create_from_raw_data(ip.payload)
                    dt_str += indent(TAB_2, str(tcp))
                    if len(tcp.payload) > 0:
                        dt_str += indent(TAB_2, tcp.payload.strip().decode('utf-8'))

                elif ip.proto == protocols.IPPROTO_UDP:
                    udp = protocols.UDP.create_from_raw_data(ip.payload)
                    dt_str += indent(TAB_2, str(udp))

            elif eth.proto == protocols.ETH_P_ARP:
                arp = protocols.ARP.create_from_raw_data(eth.payload)
                dt_str += indent(TAB_1, str(arp))

            print(dt_str)
            if out_file:
                out_file.write(dt_str)

        else:
            break


if __name__ == '__main__':
    if os.getuid() != 0:
        print("Please run this program as root.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Traffic Network Sniffer")
    parser.add_argument("iface", help="network interface")
    parser.add_argument("-o", help="output file")
    args = parser.parse_args()

    net_iface = args.iface
    out_file = open(args.o, 'w')

    try:
        main()
    except KeyboardInterrupt:
        pass
