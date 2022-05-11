
from my_lang.primitives import *

# packet_counter1 = Counter('packet_counter1', 8, 32)
# packet_counter2 = Counter('packet_counter2', 8, 32)
# packet_counter3_1 = Counter('packet_counter3_1', 8, 32)
# packet_counter3_2 = Counter('packet_counter3_2', 8, 32)

m1 = Match('match_ipv4_dst1', "ipv4.dst_addr == 10.22.0.201")
a1 = Count('packet_counter_add_1', "lambda(): { packet_counter1 = 1 + packet_counter1 }")

m2 = Match('match_ipv4_dst2', "ipv4.dst_addr == 10.22.0.201")
a2 = Reduce('flow_num_count', "hash_key: { ipv4.src_addr, tcp.dst_port }")

measurement = (m1 >> a1) + (m2 >> a2)
measurement.duration = 60
measurement.window = 5