from my_lang.primitives import *
m1 = Match('match1', "ipv4.src_addr == 10.22.0.200/24 && ipv4.dst_addr == 10.22.0.201")
a1 = Count('one_flow_size', "lambda(): { counter = counter + 1 }")

m2 = Match('match2', "ipv4.dst_addr == 10.22.0.201 && ipv4.protocol == 0x06")
a2 = Reduce('tcp_flow_num', "hash_key: { ipv4.src_addr, ipv4.dst_addr }")

m3 = Match('match3', "ipv4.protocol == 0x06")
a3 = Sketch('heavy_hitter_detection', "hash_key: { ipv4.src_addr, ipv4.dst_addr }","TOP16",1000)

m4 = Match('match4', "ipv4.protocol == 0x11 && udp.dst_port == 53")
a4 = Mirror('dns_request_flow', "egress_port == 1")

measurement = (m1 >> a1) + (m2 >> a2) + (m3 >> a3) + (m4 >> a4)
# measurement = (m3 >> (a1 + a2 + a3)) + (m4 >> (a1 + a4)) 
measurement.duration = 60
measurement.window = 5
