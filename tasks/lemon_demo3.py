from my_lang.primitives import *

# packet_counter1 = Counter('packet_counter1', 8, 32)
# packet_counter2 = Counter('packet_counter2', 8, 32)
# packet_counter3_1 = Counter('packet_counter3_1', 8, 32)
# packet_counter3_2 = Counter('packet_counter3_2', 8, 32)

m1 = Match('match_ipv4_dst1', "ipv4.protocol == 0x06")
a1 = Count('tcp_count', "lambda(): { tcp = 1 + tcp }")

m2 = Match('match_ipv4_dst2', "ipv4.protocol == 0x06")
a2 = Sketch('flow_cordinality', "hash_key: { ipv4.src_addr, tcp.dst_port }", "TOP10")

measurement = (m1 >> a1) + (m2 >> a2)
# measurement = m1 >> a1

m3 = Match('match_ipv4_dst2', "ipv4.dst_addr == 10.22.0.201")
a3 = Sketch('flow_cordinality', "hash_key: { ipv4.src_addr, tcp.dst_port }", "TOP10")
