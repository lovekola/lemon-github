
lemon_count_code = """
from my_lang.primitives import *

m1 = Match('match_flow', "%s")
a1 = Count('flood_flood_size', "lambda(): { flow_counter = 1 + flow_counter }")

measurement = (m1 >> a1)
"""

lemon_reduce_code = """
from my_lang.primitives import *

m2 = Match('match_stream', "%s")
a2 = Reduce('flow_num_count', "hash_key: %s")

measurement = (m2 >> a2)
"""

lemon_sketch_code = """
from my_lang.primitives import *

m3 = Match('match_stream', "%s")
a3 = Sketch('flow_cordinality', "hash_key: %s", "TOP16", 100)

measurement = (m3 >> a3)
"""

control_code = """measurement.duration = %s
measurement.window = %s
"""