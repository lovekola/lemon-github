from my_lang.primitives import *

m1 = Match('match_ipv4_dst_leilei', "ipv4.dst_addr == 10.22.0.201 && tcp.flags == 0x002 && tcp.src_port == 0x0053 && ipv4.protocol == 0x6")
a1 = Count('packet_counter_add_1', "lambda(): { packet_counter1 = 1 + packet_counter1 }")


measurement = m1 >> a1