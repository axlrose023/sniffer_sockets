from django.shortcuts import render
from .models import IPv4, EthernetFrame, Flags, Tos, IcmpPacket, Udp, Tcp
from .utils import r_data, get_protocol, ipv4_packet, icmp_packet, udp_segment, tcp_segment, get_tos, unpacked_data, \
    ethernet_frame, get_flags


def main(request):
    ipv4_pack()
    tos_packet()
    icmp_pack()
    flags_packet()
    tcp_packet()
    udp_packet()
    eth_frame_pack()

    # IP packet
    version_ihl, version, ihl, tos, total_length, packet_id, flags, fragment_offset, ttl, protocol_num, \
        checksum_ip, source_address, dest_address = ipv4_packet(r_data)
    protocol = get_protocol(protocol_num)
    # ICMP
    icmp_type, code, icmp_checksum, icmp_data = icmp_packet(r_data)
    # TOS
    tos_data = get_tos(unpacked_data[1])
    # Flags
    flags_data = get_flags(unpacked_data[4])
    # TCP
    src_port_tcp, dest_port_tcp, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, \
        flag_fin, tcp_data = tcp_segment(r_data)
    # UDP
    src_port_udp, dest_port_udp, size_udp, udp_data = udp_segment(r_data)
    # Eth Frame
    dest_mac, src_mac, eth_proto, eth_data = ethernet_frame(r_data)
    context_all = {'version_ihl': version_ihl, 'version': version, 'ihl': ihl,
                   'tos': tos, 'total_length': total_length, 'packet_id': packet_id, 'flags': flags,
                   'fragment_offset': fragment_offset, 'ttl': ttl, 'protocol_num': protocol_num,
                   'checksum': checksum_ip,
                   'source_address': source_address, 'dest_address': dest_address, 'protocol': protocol,
                   'src_port_tcp': src_port_tcp, 'dest_port_tcp': dest_port_tcp, 'sequence': sequence,
                   'acknowledgement': acknowledgement, 'flag_urg': flag_urg, 'flag_ack': flag_ack,
                   'flag_psh': flag_psh,
                   'flag_rst': flag_rst, 'flag_syn': flag_syn, 'flag_fin': flag_fin, 'tcp_data': tcp_data,
                   'src_port_udp': src_port_udp, 'dest_port_udp': dest_port_udp, 'size_udp': size_udp,
                   'udp_data': udp_data, 'dest_mac': dest_mac, 'src_mac': src_mac, 'eth_proto': eth_proto,
                   'eth_data': eth_data, 'flags_data': flags_data, 'tos_data': tos_data, 'icmp_type': icmp_type,
                   'icmp_code': code,
                   'icmp_checksum': icmp_checksum, 'icmp_data': icmp_data}
    return render(request, 'sniffer/index.html', context_all)


def ipv4_pack():

    version_ihl, version, ihl, tos, total_length, packet_id, flags, fragment_offset, ttl, protocol_num, \
        checksum_ip, source_address, dest_address = ipv4_packet(r_data)
    protocol = get_protocol(protocol_num)

    ipv4 = IPv4.objects.create(version_ihl=version_ihl, version=version, ihl=ihl, tos=tos, total_length=total_length,
                               packed_id=packet_id, flags=flags, fragment_offset=fragment_offset, ttl=ttl,
                               protocol_num=protocol_num, checksum=checksum_ip, source_address=source_address,
                               dest_address=dest_address, protocol=protocol)

    return ipv4


def tos_packet():
    tos_data = get_tos(unpacked_data[1])
    tos = Tos.objects.create(tos=tos_data)
    return tos


def icmp_pack():
    icmp_type, code, icmp_checksum, icmp_data = icmp_packet(r_data)
    icmp = IcmpPacket.objects.create(type=icmp_type, code=code, checksum=icmp_checksum, data=icmp_data)
    return icmp


def flags_packet():
    flags_data = get_flags(unpacked_data[4])
    flags = Flags.objects.create(flags=flags_data)

    return flags


def tcp_packet():
    src_port_tcp, dest_port_tcp, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, \
        flag_fin, tcp_data = tcp_segment(r_data)
    tcp = Tcp.objects.create(src_port_tcp=src_port_tcp, dest_port_tcp=dest_port_tcp, sequence=sequence,
                             acknowledgement=acknowledgement, flag_urg=flag_urg, flag_ack=flag_ack, flag_psh=flag_psh,
                             flag_rst=flag_rst, flag_syn=flag_syn, flag_fin=flag_fin, tcp_data=tcp_data)
    return tcp


def udp_packet():
    src_port_udp, dest_port_udp, size_udp, udp_data = udp_segment(r_data)
    udp = Udp.objects.create(src_port_udp=src_port_udp, dest_port_udp=dest_port_udp,
                             size_udp=size_udp, udp_data=udp_data)

    return udp


def eth_frame_pack():
    dest_mac, src_mac, eth_proto, eth_data = ethernet_frame(r_data)
    eth_frame = EthernetFrame.objects.create(dest_mac=dest_mac, src_mac=src_mac, eth_proto=eth_proto, eth_data=eth_data)

    return eth_frame
