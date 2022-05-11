from my_lang.primitives import *

m1 = Match('match1', "ipv4.dst_addr == 10.22.0.201 && ipv4.protocol == 0x06")
a1 = Reduce('flow_num1', "hash_key: { tcp.dst_port }")

# m2 = Match('match2', "ipv4.dst_addr == 10.22.0.201 && ipv4.protocol == 0x06")
# a2 = Reduce('flow_num2', "hash_key: { ipv4.src_addr}")

measurement = m1 >> a1
measurement.duration = 60
measurement.window = 1