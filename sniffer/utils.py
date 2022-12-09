import socket
import struct
import re
import sys

from _socket import timeout


def receive_data(conn):
    data = ''
    try:
        data = conn.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print('Error of receiving data')
        sys.exc_info()
    return data[0]


def ipv4_packet(data):
    unpacked_data = struct.unpack('! BBHHHBBH4s4s', data[:20])
    version_ihl = unpacked_data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    tos = unpacked_data[1]
    total_length = unpacked_data[2]
    packet_id = unpacked_data[3]
    flags = unpacked_data[4]
    fragment_offset = unpacked_data[4] & 0x1FFF
    ttl = unpacked_data[5]
    protocol_num = unpacked_data[6]
    checksum = unpacked_data[7]
    source_address = socket.inet_ntoa(unpacked_data[8])
    dest_address = socket.inet_ntoa(unpacked_data[9])

    return version_ihl, version, ihl, tos, total_length, packet_id, flags, fragment_offset, ttl, protocol_num, \
        checksum, source_address, dest_address


HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
conn.bind((HOST, 0))
# Include IP Headers
conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

r_data = receive_data(conn)
unpacked_data = struct.unpack('! BBHHHBBH4s4s', r_data[:20])


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto, data[14:]


def get_flags(data):
    flagR = {0: '0 - Reserved bit'}
    flagDF = {0: '0 - Fragment if necessary', 1: '1 - Do not fragment'}
    flagMF = {0: '0 - Last fragment', 1: 'More fragments'}

    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags


def get_tos(tos_data):
    precedence = {0: 'Routine', 1: 'Priority', 2: "Immediate", 3: "Flash", 4: 'Flash override', 5: "CRITIC/ECP",
                  6: 'Internetwork control', 7: 'Network Control'}
    delay = {0: 'Normal delay', 1: 'Low delay'}
    throughput = {0: 'Normal throughput', 1: 'High throughput'}
    reliability = {0: 'Normal Reliability', 1: 'High reliability'}
    cost = {0: 'Normal monetary cost', 1: 'Minimize monetary cost'}

    D = tos_data & 0x10
    D >>= 4
    T = tos_data & 0x8
    T >>= 3
    R = tos_data & 0x4
    R >>= 2
    M = tos_data & 0x2
    M >>= 1
    tabs = '\n\t\t\t'
    TOS = precedence[tos_data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TOS


def get_protocol(protocol_num):
    protocol_num = unpacked_data[6]
    proto_file = open('proto.txt', 'r')
    proto_data = proto_file.read()
    protocol = re.findall(r'\n' + str(protocol_num) + r'(?:.)+\n', proto_data)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(protocol_num), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return 'No such protocol'


def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, \
        flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[:8]


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


