
struct metadata_t {
    bit<32> register_index;
    bit<10>	bf_hash;
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

#define BF_HASH_KEY	{hdr.ipv4.src_addr}
#define SKETCH_HASH_KEY	{hdr.ipv4.src_addr}

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
//hash
    Hash<bit<10>>(HashAlgorithm_t.CRC8) bf_hash;
    Hash<bit<4>>(HashAlgorithm_t.CRC8) sketch_topk_hash;
//register
    Register<bit<32>,_>(2,0) all;
    
    RegisterAction<bit<32>,_,bit<32>>(all) all_op = {
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
    Register<bit<32>,_>(2,0) packet_counter3;
    
    RegisterAction<bit<32>,_,bit<32>>(packet_counter3) packet_counter3_op = {
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
    action _no_op(){
        
        //do nothing
    }
    action a_count_all(){
        all_op.execute(ig_md.register_index);
    }
    action a_count_tcp(){
        tcp_op.execute(ig_md.register_index);
    }
    action a_packet_count3(){
        packet_counter3_op.execute(ig_md.register_index);
    }
//table
    table t_match_match_dst_ip0{
        key = {
            hdr.ipv4.dst_addr: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;_no_op;
        }
    }
    table t_count_all{
        actions = {
            a_count_all;
        }
        const default_action = a_count_all;
    }
    table t_match_match_dst_ip7{
        key = {
            hdr.ipv4.dst_addr: ternary;
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;_no_op;
        }
    }
    table t_count_tcp{
        actions = {
            a_count_tcp;
        }
        const default_action = a_count_tcp;
    }
    table t_match_match_dst_ip14{
        key = {
            hdr.ipv4.dst_addr: ternary;
            hdr.ipv4.src_addr: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;_no_op;
        }
    }
    table t_packet_count3{
        actions = {
            a_packet_count3;
        }
        const default_action = a_packet_count3;
    }
//pipline
    
    apply{
        //head tail execute
    
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
        switch(t_match_match_dst_ip0.apply().action_run){
            a_set_flow_index : {
                t_count_all.apply();}
            default : {}
        }
        switch(t_match_match_dst_ip7.apply().action_run){
            a_set_flow_index : {
                t_count_tcp.apply();}
            default : {}
        }
        switch(t_match_match_dst_ip14.apply().action_run){
            a_set_flow_index : {
                t_packet_count3.apply();}
            default : {}
        }
        //tail execute
    
    }          
}
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;