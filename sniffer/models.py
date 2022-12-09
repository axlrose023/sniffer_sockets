from django.db import models


# Create your models here.


class IPv4(models.Model):
    version_ihl = models.IntegerField(blank=False, verbose_name='IP Header Length')
    version = models.IntegerField(blank=False, verbose_name='version')
    ihl = models.IntegerField(blank=False, verbose_name='IP Header Length')
    tos = models.IntegerField(verbose_name='Type Of Service', null=True)
    total_length = models.IntegerField(blank=False, verbose_name='Total Length')
    packed_id = models.IntegerField(blank=False, verbose_name='Packet ID')
    flags = models.CharField(blank=False, verbose_name='Flags', max_length=255)
    fragment_offset = models.IntegerField(verbose_name='Fragment offset')
    ttl = models.IntegerField(verbose_name='Time to Live')
    protocol_num = models.IntegerField(verbose_name='Protocol Number')
    checksum = models.IntegerField(verbose_name='checksum')
    source_address = models.CharField(verbose_name='IP source address', max_length=255)
    dest_address = models.CharField(verbose_name='IP destination address', max_length=255)
    protocol = models.CharField(max_length=255, null=True)


class EthernetFrame(models.Model):
    dest_mac = models.CharField(verbose_name='dest_mac', max_length=255)
    src_mac = models.CharField(verbose_name='src_mac', max_length=255)
    eth_proto = models.CharField(verbose_name='Protocol', max_length=255)
    eth_data = models.CharField(max_length=255, null=True)


class Flags(models.Model):
    flags = models.CharField(verbose_name='Flags', max_length=255)

    def __str__(self):
        return self.flags


class Tos(models.Model):
    tos = models.CharField(verbose_name='Time of Service', max_length=255)

    def __str__(self):
        return self.tos


class IcmpPacket(models.Model):
    type = models.CharField(verbose_name='ICMP type', max_length=255)
    code = models.CharField(verbose_name='Icmp code', max_length=255)
    checksum = models.IntegerField(verbose_name='checksum')
    data = models.CharField(max_length=255)


class Udp(models.Model):
    src_port_udp = models.IntegerField(verbose_name='Source UDP Port')
    dest_port_udp = models.IntegerField(verbose_name='Destination Udp Port')
    size_udp = models.IntegerField(verbose_name='size of Udp')
    udp_data = models.CharField(max_length=255)


class Tcp(models.Model):
    src_port_tcp = models.IntegerField(verbose_name='Source TCP Port ')
    dest_port_tcp = models.IntegerField(verbose_name='Destination Tcp Port')
    sequence = models.IntegerField()
    acknowledgement = models.IntegerField()
    flag_urg = models.IntegerField()
    flag_ack = models.IntegerField()
    flag_psh = models.IntegerField()
    flag_rst = models.IntegerField()
    flag_syn = models.IntegerField()
    flag_fin = models.IntegerField()
    tcp_data = models.CharField(max_length=255)
