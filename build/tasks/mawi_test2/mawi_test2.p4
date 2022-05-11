
struct metadata_t {
    bit<32> register_index;
    bit<11>	bf_hash;
    bit<8>	bf_reg;
    bit<8>	bf_reg_shadow;
    bit<8>	bf_switch;
    bit<4>	sketch_topk_hash1;
}
#include <core.p4> 
#if __TARGET_TOFINO__ == 2 
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "./common/headers.p4" 
#include "./common/util.p4" 

#define BF_HASH_KEY	{hdr.ipv4.src_addr,hdr.ipv4.dst_addr}
#define SKETCH_HASH_KEY	{hdr.ipv4.src_addr}

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
//hash
    Hash<bit<11>>(HashAlgorithm_t.CRC64) bf_hash;
    Hash<bit<4>>(HashAlgorithm_t.CRC8) sketch_topk_hash;
//register
    Register<bit<32>,_>(2,0) all_flow_lemon;
    
    RegisterAction<bit<32>,_,bit<32>>(all_flow_lemon) all_flow_lemon_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2,0) tcp;
    
    RegisterAction<bit<32>,_,bit<32>>(tcp) tcp_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<8>,_>(2048,0) bf;
    
    RegisterAction<bit<8>,_,bit<8>>(bf) bf_op = {
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
    
    Register<bit<8>,_>(2048,0) bf_shadow;
    
    RegisterAction<bit<8>,_,bit<8>>(bf_shadow) bf_shadow_op = {
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
    
    Register<bit<8>,_>(1,0) bf_switch_reg;
    
    RegisterAction<bit<8>,_,bit<8>>(bf_switch_reg) bf_switch_reg_op = {
        void apply(inout bit<8> val, out bit<8> rv) {
            rv = val;
        }
    };
    
    Register<bit<32>,_>(1,0) flow_num;
    
    RegisterAction<bit<32>,_,bit<32>>(flow_num) flow_num_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };  
//action
    action a_set_flow_index(){
        ig_md.register_index = 1;
    }
    action a_compute_hash_bf(){
        ig_md.bf_hash = bf_hash.get(BF_HASH_KEY);
    }
    action a_compute_hash_sketch(){
        ig_md.sketch_topk_hash1 = sketch_topk_hash.get(SKETCH_HASH_KEY);
    }
    action a_set_mirror_configuration(){
        // set mirror session and mirror id
    }
    action _no_op(){
        
        //do nothing
    }
    action a_tcp_flow(){
        tcp_op.execute(ig_md.register_index);
    }
    action a_ip_pair(){
        ig_md.bf_reg = bf_op.execute(ig_md.bf_hash);
    }
//table
    table t_match_match10{
        key = {
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_tcp_flow{
        actions = {
            a_tcp_flow;
        }
        const default_action = a_tcp_flow;
    }
    table t_match_match28{
        key = {
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_ip_pair{
        actions = {
            a_ip_pair;
        }
        const default_action = a_ip_pair;
    }
//pipline
    
    apply{
        //head tail execute
        
        ig_md.bf_switch = bf_switch_reg_op.execute(0);
        
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
        switch(t_match_match10.apply().action_run){
            a_set_flow_index : {
                t_tcp_flow.apply();}
            default : {}
        }
        switch(t_match_match28.apply().action_run){
            a_compute_hash_bf : {
                t_ip_pair.apply();
                ig_md.bf_reg_shadow = bf_shadow_op.execute(ig_md.bf_hash);}
            default : {}
        }
        //tail execute
        
        if(ig_md.bf_switch == 0 && ig_md.bf_reg == 1){
            flow_num_op.execute(0);
        }else if(ig_md.bf_switch == 1 && ig_md.bf_reg_shadow == 1){
            flow_num_op.execute(0);
        }
        
    }          
}
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;