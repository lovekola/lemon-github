from my_lang.primitives import *

m1 = Match('match_ipv4_dst_leilei', "ipv4.dst_addr == 10.22.0.201")
a1 = Count('packet_counter_add_1', "lambda(): { packet_counter1 = 1 + packet_counter1 }")

m2 = Match('match_ipv4_dst2', "ipv4.dst_addr == 10.22.0.201")
a2 = Reduce('flow_num_count', "hash_key: { ipv4.src_addr, ipv4.dst_addr }")

# m3 = Match('match_ipv4_dst3', "ipv4.dst_addr == 10.22.0.201")
# a3 = Sketch('flow_cordinality', "hash_key: { ipv4.src_addr, tcp.dst_port }", "TOP10")

# measurement = (m1 >> a1) + (m2 >> a2) + (m3 >> a3)
measurement = (m1 >> a1) + (m2 >> a2) 
measurement.duration = 60
measurement.window = 5