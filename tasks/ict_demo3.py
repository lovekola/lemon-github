from my_lang.primitives import *

m1 = Match('match1', "ipv4.protocol == 0x06")
a1 = Sketch('flow_cordinality', "hash_key: { ipv4.src_addr, ipv4.dst_addr }", "TOP16-shadow", 100)

measurement = m1 >> a1
measurement.duration = 60
measurement.window = 5