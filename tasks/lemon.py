from my_lang.primitives import *

# syn flood detection 
m1 = Match('match_ipv4_dst', "ipv4.dst == 10.22.0.201 && tcp.flag == SYN")
a1 = Count("syn_num", "+= 1", "syn_num")
measurement1 = m1 >> a1

# port-scan detection
m2 = Match('match_ipv4_dst', "ipv4.dst == 10.22.0.201")
a2 = Reduce("cock_num",'{hdr.tcp.dst_port, hdr.tcp.src_port}', "scan_num")
measurement2 = m2 >> a2

# heavy-hitter detection
m3 = Match('match_ipv4_dst', "ipv4.dst == 10.22.0.201")
a3 = Sketch('flow_size_map', "top-10", "top_10_list")
measurement3 = m3 >> a3
