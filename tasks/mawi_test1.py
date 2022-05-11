from lemon_lang.primitives import *

m1 = Match('match1', "ethernet.ether_type == 0x0800")
a1 = Count('ipv4_flow', "lambda(): { ipv4_flow = ipv4_flow + 1}")

m2 = Match('match2', "ethernet.ether_type == 0x86dd")
a2 = Count('ipv6_flow', "lambda(): { ipv6_flow = ipv6_flow + 1}")

m3 = Match('match3', "ethernet.ether_type == 0x0806")
a3 = Count('arp_flow', "lambda(): { arp_flow = arp_flow + 1}")

m4 = Match('match4', "ipv4.protocol == 0x06")
a4 = Count('tcp_flow', "lambda(): { tcp_flow = tcp_flow + 1}")

m5 = Match('match5', "ipv4.protocol == 0x11")
a5 = Count('udp_flow', "lambda(): { udp_flow = udp_flow + 1}")

m6 = Match('match6', "ipv4.protocol == 0x01")
a6 = Count('icmp_flow', "lambda(): { icmp_flow = icmp_flow + 1}")


measurement = (m1 >> a1) + (m2 >> a2) + (m3 >> a3) + (m4 >> a4) + (m5 >> a5) + (m6 >> a6)
measurement.duration = 600
measurement.window = 1

