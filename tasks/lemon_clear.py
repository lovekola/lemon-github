from my_lang.primitives import *
m1 = Match('match_tcp', "ipv4.protocol == 0x06")
a1 = Count('packet_counter_add_1', "lambda(): { packet_counter1 = 1 + packet_counter1 }")
m3 = Match('tcp', "ipv4.protocol == 0x06")
a3 = Sketch('flow_cordinality', "hash_key: { ipv4.src_addr, ipv4.dst_addr }", "TOP16-shadow",100)
measurement = (m1 >> a1) + m3 >> a3
measurement.duration = 120
measurement.window = 5