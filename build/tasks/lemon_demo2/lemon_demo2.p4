
struct metadata_t {
    bit<32> register_index;
    bit<10>	bf_hash;
    bit<8>	bf_reg;
    bit<4>	sketch_topk_reg;
}
#include <core.p4> 
#if __TARGET_TOFINO__ == 2 
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "./common/headers.p4" 
#include "./common/util.p4" 

#define BF_HASH_KEY	{hdr.ipv4.src_addr,hdr.tcp.dst_port}
#define SKETCH_HASH_KEY	{hdr.ipv4.src_addr}

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
//hash
    Hash<bit<10>>(HashAlgorithm_t.CRC64) bf_hash;
    Hash<bit<4>>(HashAlgorithm_t.CRC8) sketch_topk_hash;
//register
    Register<bit<32>,_>(2,0) packet_counter1;
    
    RegisterAction<bit<32>,_,bit<32>>(packet_counter1) packet_counter1_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<8>,_>(2048,0) bf;
    
    RegisterAction<bit<8>,_,bit<8>>(bf) bf_op = {
        void apply(inout bit<8> val, out bit<8> rv) {
            rv = val + 1;
            if(val[0:0] == 0){
                val = val | 0b00000001;
            }else{
            }  
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
        ig_md.sketch_topk_reg = sketch_topk_hash.get(SKETCH_HASH_KEY);
    }
    action _no_op(){
        
        //do nothing
    }
    action a_packet_counter_add_1(){
        packet_counter1_op.execute(ig_md.register_index);
    }
    action a_flow_num_count(){
        ig_md.bf_reg = bf_op.execute(ig_md.bf_hash);
    }
//table
    table t_match_hdr_ipv4_dst_addr0{
        key = {
            hdr.ipv4.dst_addr: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;_no_op;
        }
    }
    table t_packet_counter_add_1{
        actions = {
            a_packet_counter_add_1;
        }
        const default_action = a_packet_counter_add_1;
    }
    table t_match_hdr_ipv4_dst_addr7{
        key = {
            hdr.ipv4.dst_addr: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;_no_op;
        }
    }
    table t_flow_num_count{
        actions = {
            a_flow_num_count;
        }
        const default_action = a_flow_num_count;
    }
//pipline
    
    apply{
    
        //port-forward
        if(ig_intr_md.ingress_port == 142){
            ig_tm_md.ucast_egress_port = 141;
            ig_tm_md.bypass_egress = 1;
        }
        if(ig_intr_md.ingress_port == 141){
            ig_tm_md.ucast_egress_port = 142;
            ig_tm_md.bypass_egress = 1;
        }
        //table_route_next_hop.apply();
    //table apply
        switch(t_match_hdr_ipv4_dst_addr0.apply().action_run){
            a_set_flow_index : {
                t_packet_counter_add_1.apply();}
            default : {}
        }
        switch(t_match_hdr_ipv4_dst_addr7.apply().action_run){
            a_compute_hash_bf : {
                t_flow_num_count.apply();}
            default : {}
        }
    //tail execute
        
        if(ig_md.bf_reg == 1){
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