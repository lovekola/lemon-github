from my_lang.primitives import *
m1 = Match('match1', "ipv4.src_addr == 10.10.0.1 && ipv4.dst_addr == 10.22.0.201 && ipv4.protocol == 0x06")
a1 = Count('one_flow_size1', "lambda(): { counter1 = counter1 + 1 }")

m2 = Match('match2', "ipv4.src_addr == 10.10.0.2 && ipv4.dst_addr == 10.22.0.201 && ipv4.protocol == 0x06")
a2 = Count('one_flow_size2', "lambda(): { counter2 = counter2 + 1 }")

m3 = Match('match3', "ipv4.src_addr == 10.10.0.3 && ipv4.dst_addr == 10.22.0.201 && ipv4.protocol == 0x06")
a3 = Count('one_flow_size3', "lambda(): { counter3 = counter3 + 1 }")

measurement = (m1 >> a1) + (m2 >> a2) + (m3 >> a3)
measurement.duration = 60
measurement.window = 1