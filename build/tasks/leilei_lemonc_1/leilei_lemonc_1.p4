#include <core.p4> 
#if __TARGET_TOFINO__ == 2 
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4" 
#include "util.p4" 



struct metadata_t {
    bit<32> register_index;
}

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    Register<bit<32>,_>(2,0) packet_counter1;
    RegisterAction<bit<32>,_,bit<32>>(packet_counter1) packet_counter1_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    }
    Register<bit<32>,_>(2,0) packet_counter2;
    RegisterAction<bit<32>,_,bit<32>>(packet_counter2) packet_counter2_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 2;
            value_out = value;
        }
    }
    Register<bit<32>,_>(2,0) packet_counter3_1;
    RegisterAction<bit<32>,_,bit<32>>(packet_counter3_1) packet_counter3_1_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 3;
            value_out = value;
        }
    }
    Register<bit<32>,_>(2,0) packet_counter3_2;
    RegisterAction<bit<32>,_,bit<32>>(packet_counter3_2) packet_counter3_2_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 4;
            value_out = value;
        }
    }  
    action a_set_flow_index(){
        ig_md.register_index = 1;
    }
    action _no_op(){
        
        //do nothing
    }
    action a_packet_counter_add_1(){
        packet_counter1_op.execute(ig_md.register_index);
    }
    action a_packet_counter_add_2(){
        packet_counter2_op.execute(ig_md.register_index);
    }
    action a_packet_counter_add_3_1(){
        packet_counter3_1_op.execute(ig_md.register_index);
    }
    action a_packet_counter_add_3_2(){
        packet_counter3_2_op.execute(ig_md.register_index);
    }
    table t_match_ipv4_src0{
        key = {
            ipv4.src: exact;
        }
        actions = {
            a_set_flow_index;_no_op;
        }
    }
    table t_packet_counter_add_1{
        actions = {
            a_packet_counter_add_1;
        }
    }
    table t_match_ipv4_dst5{
        key = {
            ipv4.dst: exact;
        }
        actions = {
            a_set_flow_index;_no_op;
        }
    }
    table t_packet_counter_add_2{
        actions = {
            a_packet_counter_add_2;
        }
    }
    table t_match_ipv4_dst10{
        key = {
            ipv4.dst: exact;
        }
        actions = {
            a_set_flow_index;_no_op;
        }
    }
    table t_packet_counter_add_3_1{
        actions = {
            a_packet_counter_add_3_1;
        }
    }
    table t_packet_counter_add_3_2{
        actions = {
            a_packet_counter_add_3_2;
        }
    }
    apply{
    
    
        table_route_next_hop.apply();
        switch(t_match_ipv4_src0.apply().action_run){
            a_set_flow_index : {
                t_packet_counter_add_1.apply();}
            default : {}
        }
        switch(t_match_ipv4_dst5.apply().action_run){
            a_set_flow_index : {
                t_packet_counter_add_2.apply();}
            default : {}
        }
        switch(t_match_ipv4_dst10.apply().action_run){
            a_set_flow_index : {
                t_packet_counter_add_3_1.apply();
            
                t_packet_counter_add_3_2.apply();}
            default : {}
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