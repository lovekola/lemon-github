from my_lang.primitives import *
m1 = Match('match_dst_ip', "ipv4.dst_addr == 10.22.0.201")
a1 = Count('count_all', "lambda(): { all = 1 + all }")

m2 = Match('match_dst_ip', "ipv4.dst_addr == 10.22.0.201 && ipv4.protocol == 0x06")
a2 = Count('count_tcp', "lambda(): { tcp = 1 + tcp }")

m3 = Match('match_dst_ip', "ipv4.dst_addr == 10.22.0.201 && ipv4.src_addr == 10.22.0.201")
a3 = Count('packet_count3', "lambda(): { packet_counter3 = 1 + packet_counter3 }")

measurement = (m1 >> a1) + (m2 >> a2)+ (m3 >> a3)
measurement.duration = 60
measurement.window = 1
