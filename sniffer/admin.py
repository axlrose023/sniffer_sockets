from django.contrib import admin

# Register your models here.
from .models import IPv4, EthernetFrame, IcmpPacket, Flags, Tos, Udp, Tcp

admin.site.register(IPv4)


