from my_lang.primitives import *

m1 = Match('match1', "ipv4.protocol == 0x06")
a1 = Count('tcp_flow', "lambda(): { tcp = tcp + 1 }")

m2 = Match('match2', "ipv4.protocol == 0x06")
a2 = Reduce('ip_pair', "hash_key: { ipv4.src_addr, ipv4.dst_addr }")

measurement = (m1 >> a1) + (m2 >> a2)
measurement.duration = 600
measurement.window = 1