
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
    Register<bit<32>,_>(2,0) all_flow_lemon;
    
    RegisterAction<bit<32>,_,bit<32>>(all_flow_lemon) all_flow_lemon_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2,0) ipv4_flow;
    
    RegisterAction<bit<32>,_,bit<32>>(ipv4_flow) ipv4_flow_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2,0) ipv6_flow;
    
    RegisterAction<bit<32>,_,bit<32>>(ipv6_flow) ipv6_flow_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2,0) arp_flow;
    
    RegisterAction<bit<32>,_,bit<32>>(arp_flow) arp_flow_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2,0) tcp_flow;
    
    RegisterAction<bit<32>,_,bit<32>>(tcp_flow) tcp_flow_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2,0) udp_flow;
    
    RegisterAction<bit<32>,_,bit<32>>(udp_flow) udp_flow_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2,0) icmp_flow;
    
    RegisterAction<bit<32>,_,bit<32>>(icmp_flow) icmp_flow_op = {
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
    action a_ipv4_flow(){
        ipv4_flow_op.execute(ig_md.register_index);
    }
    action a_ipv6_flow(){
        ipv6_flow_op.execute(ig_md.register_index);
    }
    action a_arp_flow(){
        arp_flow_op.execute(ig_md.register_index);
    }
    action a_tcp_flow(){
        tcp_flow_op.execute(ig_md.register_index);
    }
    action a_udp_flow(){
        udp_flow_op.execute(ig_md.register_index);
    }
    action a_icmp_flow(){
        icmp_flow_op.execute(ig_md.register_index);
    }
//table
    table t_match_match10{
        key = {
            hdr.ethernet.ether_type: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_ipv4_flow{
        actions = {
            a_ipv4_flow;
        }
        const default_action = a_ipv4_flow;
    }
    table t_match_match28{
        key = {
            hdr.ethernet.ether_type: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_ipv6_flow{
        actions = {
            a_ipv6_flow;
        }
        const default_action = a_ipv6_flow;
    }
    table t_match_match316{
        key = {
            hdr.ethernet.ether_type: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_arp_flow{
        actions = {
            a_arp_flow;
        }
        const default_action = a_arp_flow;
    }
    table t_match_match424{
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
    table t_match_match532{
        key = {
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_udp_flow{
        actions = {
            a_udp_flow;
        }
        const default_action = a_udp_flow;
    }
    table t_match_match640{
        key = {
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_icmp_flow{
        actions = {
            a_icmp_flow;
        }
        const default_action = a_icmp_flow;
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
        all_flow_lemon_op.execute(1);
        //table_route_next_hop.apply();
        //table apply
        switch(t_match_match10.apply().action_run){
            a_set_flow_index : {
                t_ipv4_flow.apply();}
            default : {}
        }
        switch(t_match_match28.apply().action_run){
            a_set_flow_index : {
                t_ipv6_flow.apply();}
            default : {}
        }
        switch(t_match_match316.apply().action_run){
            a_set_flow_index : {
                t_arp_flow.apply();}
            default : {}
        }
        switch(t_match_match424.apply().action_run){
            a_set_flow_index : {
                t_tcp_flow.apply();}
            default : {}
        }
        switch(t_match_match532.apply().action_run){
            a_set_flow_index : {
                t_udp_flow.apply();}
            default : {}
        }
        switch(t_match_match640.apply().action_run){
            a_set_flow_index : {
                t_icmp_flow.apply();}
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