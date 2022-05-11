

p4ctrl = """control %s{
    %s
}"""

p4ctrl_in = """
apply{
    //head tail execute
%s
    //port-forward
    if(ig_intr_md.ingress_port == 142){
        ig_tm_md.ucast_egress_port = 141;
        ig_tm_md.bypass_egress = 1;
    }
    if(ig_intr_md.ingress_port == 141){
        ig_tm_md.ucast_egress_port = 142;
        ig_tm_md.bypass_egress = 1;
    }
    all_flow_lemon_op.execute(1);
    //table_route_next_hop.apply();
    //table apply
%s
    //tail execute
%s
}"""
# apply(table_src_mac_overwrite); 

p4ctrl_out = """apply{
%s
}"""

p4bf_head = """
ig_md.bf_switch = bf_switch_reg_op.execute(0);
"""

p4bf_tail = """
if(ig_md.bf_switch == 0 && ig_md.bf_reg == 1){
    %s_op.execute(0);
}else if(ig_md.bf_switch == 1 && ig_md.bf_reg_shadow == 1){
    %s_op.execute(0);
}
"""
p4ctrl_cond = """if(%s){
    %s
}"""

p4table = """table %s{
%s
}"""

p4table_keys = """key = {
%s
}"""

p4table_actions = """actions = {
    %s
}
"""

p4table_actions_without_key = """actions = {
    %s
}
const default_action = %s;
"""


p4table_apply = "%s.apply()"
p4table_apply_reduce = """%s.apply();
ig_md.bf_reg_shadow = bf_shadow_op.execute(ig_md.bf_hash);
"""

p4table_apply_sketch_shadow = """%s.apply();
ig_md.sketch_reg1_shadow = sketch_reg1_shadow_op.execute(ig_md.sketch_hash1);
"""
p4table_apply_sketch = """%s.apply();
"""

p4table_apply_with_children = "switch(%s.apply().action_run)"

# p4table_block = """{
#     %s
# }"""

p4table_block = """{\n%s\n}"""


p4table_hit_count = """a_set_flow_index : {\n%s}
default : {}
"""
p4table_hit_reduce = """a_compute_hash_bf : {\n%s}
default : {}
"""
p4table_hit_sketch = """a_compute_hash_sketch : {\n%s}
default : {}
"""
p4table_hit_mirror = """a_set_mirror_configuration : {\n%s}
default : {}
"""

p4table_miss = """miss{
%s
}"""

p4action = """action %s(%s){
%s
}"""

p4action_call = "%s(%s);"


p4action_modify_field          = "modify_field( %s, %s );"
p4action_add                   = "add( %s, %s, %s );"
p4action_add_to_field          = "add_to_field( %s, %s );"
p4action_subtract              = "subtract( %s, %s, %s );"
p4action_subtract_from_field   = "subtract_from_field( %s, %s );"
p4action_shift_left            = "shift_left( %s, %s, %s );"
p4action_shift_right           = "shift_right( %s, %s, %s );"
p4action_bit_or                = "bit_or( %s, %s, %s );"
p4action_bit_and               = "bit_and( %s, %s, %s );"
p4action_register_read         = "register_read( %s, %s, %s );"
p4action_register_write        = "register_write( %s, %s, %s );"
p4action_register_access       = "%s_op.execute(ig_md.register_index);"
p4action_hash                  = "modify_field_with_hash_based_offset( %s, %s, %s, %s);"
p4action_duplicate             = "clone_ingress_pkt_to_egress( %s, %s );"
# p4action_collect               = "clone_ingress_pkt_to_egress( %s, %s );"

p4RegisterAction = """RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> value, out bit<%s> value_out){
        value = value %s %s;
        value_out = value;
    }
};"""

p4action_set_register_index    = "ig_md.register_index = 1;"
p4action_apply_hash_bf =   "ig_md.bf_reg = bf_op.execute(ig_md.bf_hash);"
p4action_compute_hash_bf   =   "ig_md.bf_hash = bf_hash.get(BF_HASH_KEY);"
p4action_compute_hash_sketch   =   "ig_md.sketch_topk_hash1 = sketch_topk_hash.get(SKETCH_HASH_KEY);"
p4action_set_mirror_configuration = "// set mirror session and mirror id"
p4action_apply_hash_sketch  =   "ig_md.sketch_reg1 = sketch_reg1_op.execute(ig_md.sketch_hash1);\nig_md.sketch_flag = 0b0001;"
#p4header = "header_type %s {\n%s\n}"
p4header = "header %s {\n%s\n}"
p4header_struct = "struct %s {\n%s\n}"
#p4headerfields = "fields{\n%s\n}"
p4headerfields = "%s"

p4Box = """
struct box {
    bit<32>     key1;
    bit<32>     key2;
}
"""

p4register = "Register<bit<%s>,_>(%s,%s) %s;"
p4register_count = ""
p4register_width = "bit<%d>"

p4registerBox = "Register<box,_>(size=%d, initial_value={0, 0}) %s;"
p4registerActionBox = """
RegisterAction<box, _ , bit<32>>(%s) %s_op = {
        void apply(inout box data, out bit<32> rv){
            data.key1 = hdr.ipv4.src_addr;
            data.key2 = hdr.ipv4.dst_addr;
        }
    };
"""
p4RegisterActionCounter = """
RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> value, out bit<%s> value_out){
        value = value %s %s;
        value_out = value;
    }
};"""


p4RegisterActionSwitch = """
RegisterAction<bit<8>,_,bit<8>>(%s) %s_op = {
    void apply(inout bit<8> val, out bit<8> rv) {
        rv = val;
    }
};
"""
p4RegisterActionBF = """
RegisterAction<bit<8>,_,bit<8>>(%s) %s_op = {
    void apply(inout bit<8> val, out bit<8> rv) {
        if(ig_md.bf_switch == 0){
            rv = val + 1;
            val = 1;
        }else{
            rv = val + 1;
            val = 0;
        }
    }
};
"""
p4RegisterActionBF_SHADOW = """
RegisterAction<bit<8>,_,bit<8>>(%s) %s_op = {
    void apply(inout bit<8> val, out bit<8> rv) {
        if(ig_md.bf_switch == 1){
            rv = val + 1;
            val = 1;
        }else{
            rv = val + 1;
            val = 0;
        }
    }
};
"""
p4RegisterActionSketchReg1 = """
RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> val, out bit<%s> rv) {
        val = val + 1;
        if(val >= ig_md.sketch_threshold){
            rv = val;
        }else{
            rv = 0;
        }
    }
};
"""
p4RegisterActionSketchRegx = """
RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> val, out bit<%s> rv) {
        val = val + 1;
        if(val >= ig_md.sketch_threshold && %s){
            rv = val;
        }else{
            rv = 0;
        }
    }
};
"""
p4RegisterActionSketchReg1_default = """
RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> val, out bit<%s> rv) {
        if(ig_md.sketch_switch == 0){
            val = val + 1;
        }
        else{
            val = 0;
        }
        if(val >= ig_md.sketch_threshold){
            rv = val;
        }else{
            rv = 0;
        }
    }
};
"""
p4RegisterActionSketchRegx_default = """
RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> val, out bit<%s> rv) {
        if(ig_md.sketch_switch == 0){
            val = val + 1;
        }
        else{
            val = 0;
        }
        if(%s){
            rv = val;
        }else{
            rv = 0;
        }
    }
};
"""
p4RegisterActionSketchReg1_shadow = """
RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> val, out bit<%s> rv) {
        if(ig_md.sketch_switch == 1){
            val = val + 1;
        }
        else{
            val = 0;
        }
        if(val >= ig_md.sketch_threshold){
            rv = val;
        }else{
            rv = 0;
        }
    }
};
"""

p4RegisterActionSketchRegx_shadow = """
RegisterAction<bit<%s>,_,bit<%s>>(%s) %s_op = {
    void apply(inout bit<%s> val, out bit<%s> rv) {
        if(ig_md.sketch_switch == 1){
            val = val + 1;
        }
        else{
            val = 0;
        }
        if(%s){
            rv = val;
        }else{
            rv = 0;
        }
    }
};
"""
# if(val >= ig_md.sketch_threshold && %s){

p4RegisterActionSketchThreshold = """
RegisterAction<bit<32>,_,bit<32>>(%s) %s_op = {
    void apply(inout bit<32> val, out bit<32> rv) {
        rv = val;
    }
};
"""



# p4 sketch extra actions

p4sketch_load_threshold = """
action load_threshold(){
    ig_md.sketch_threshold = sketch_reg_threshold_op.execute(0);
}
"""
p4sketch_compute_hash1 = """
action compute_hash1(){
    ig_md.sketch_hash1 = sketch_hash1.get(SKETCH_HASH_KEY);
    ig_md.sketch_hash2 = sketch_hash2.get(SKETCH_HASH_KEY);
}
"""
p4sketch_compute_hash2 = """
action compute_hash2(){
    ig_md.sketch_hash3 = sketch_hash3.get(SKETCH_HASH_KEY);
    ig_md.sketch_hash4 = sketch_hash4.get(SKETCH_HASH_KEY);
}
"""
p4sketch_apply_hash2 = """
action apply_hash2() {
    ig_md.sketch_reg2 = sketch_reg2_op.execute(ig_md.sketch_hash2);
}
"""
p4sketch_apply_hash3 = """
action apply_hash3() {
    ig_md.sketch_reg3 = sketch_reg3_op.execute(ig_md.sketch_hash3);
}
"""
p4sketch_apply_hash4 = """
action apply_hash4() {
    ig_md.sketch_reg4 = sketch_reg4_op.execute(ig_md.sketch_hash4);
}
"""

p4update_topk_info = """
action update_topk_info(){
    top_flow_info_op.execute(ig_md.sketch_topk_hash1);
}  
"""
p4update_topk_size = """
action update_topk_size(){
    top_flow_size_op.execute(ig_md.sketch_topk_hash1);
}  
"""
p4sketch_head = """
load_threshold();
compute_hash1();
compute_hash2();        
"""
p4sketch_head_shadow = """
ig_md.sketch_switch = sketch_switch_reg_op.execute(0);
load_threshold();
compute_hash1();
compute_hash2();        
"""

p4sketch_tail = """
if(ig_md.sketch_flag == 1){
    apply_hash2();
    apply_hash3();  
    apply_hash4();
}
else if(ig_md.sketch_reg4 != 0){
    update_topk_info();
    update_topk_size();
}
"""
p4sketch_tail_shadow = """
if(ig_md.sketch_flag == 1){
    apply_hash2();
    apply_hash3();  
    apply_hash4();
    ig_md.sketch_reg2_shadow = sketch_reg2_shadow_op.execute(ig_md.sketch_hash2);
    ig_md.sketch_reg3_shadow = sketch_reg3_shadow_op.execute(ig_md.sketch_hash3);
    ig_md.sketch_reg4_shadow = sketch_reg4_shadow_op.execute(ig_md.sketch_hash4);
}
if(ig_md.sketch_switch == 0 && ig_md.sketch_reg4 != 0){
    update_topk_info();
    update_topk_size();
}
else if(ig_md.sketch_switch == 1 && ig_md.sketch_reg4_shadow != 0){
    update_topk_info();
    update_topk_size();
}
"""

p4_metadata = """
struct metadata_t {
%s
}
"""
p4field_list = "field_list %s {\n%s;\n}"
p4hash = "field_list_calculation %s {\n%s\n}"
p4hash_input = "input{ %s; }"
p4hash_output = "output_width: %s;"
p4hash_algorithm = "algorithm: %s;"

p4_ingress = """
control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
//hash
%s
//register
    Register<bit<32>,_>(2,0) all_flow_lemon;
    
    RegisterAction<bit<32>,_,bit<32>>(all_flow_lemon) all_flow_lemon_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
%s  
//action
%s
//table
%s
//pipline
%s          
}"""

p4_egress = """"""
p4_main = """
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;"""