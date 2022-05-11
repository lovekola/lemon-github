

# packet_counter1 = Counter('packet_counter1', 8, 32)
# packet_counter2 = Counter('packet_counter2', 8, 32)
# packet_counter3_1 = Counter('packet_counter3_1', 8, 32)
# packet_counter3_2 = Counter('packet_counter3_2', 8, 32)
from my_lang.primitives import *
m1 = Match('match_ipv4_dst1', "ipv4.dst_addr == 10.22.0.201")
a1 = Count('packet_counter_add_1', "lambda(): { packet_counter1 = 1 + packet_counter1 }")

m2 = Match('match_ipv4_dst2', "ipv4.dst_addr == 10.0.0.2")
a2 = Count('packet_counter_add_2', "lambda(): { packet_counter2 = packet_counter2 + 2 }")

m3 = Match('match_ipv4_dst3', "ipv4.dst_addr == 10.0.0.3")
a3_1 = Count('packet_counter_add_3_1', "lambda(): { packet_counter3_1 = packet_counter3_1 + 3 }")
a3_2 = Count('packet_counter_add_3_2', "lambda(): { packet_counter3_2 = packet_counter3_2 + 4 }")

measurement = (m1 >> a1) + (m2 >> a2) + (m3 >> (a3_1 + a3_2))
