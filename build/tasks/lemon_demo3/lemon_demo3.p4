
struct metadata_t {
    bit<32> register_index;
    bit<10>	sketch_hash1;
    bit<10>	sketch_hash2;
    bit<10>	sketch_hash3;
    bit<10>	sketch_hash4;
    bit<32>	sketch_reg1;
    bit<32>	sketch_reg2;
    bit<32>	sketch_reg3;
    bit<32>	sketch_reg4;
    bit<32>	sketch_threshold;
    bit<32>	sketch_flag;
    bit<4>	sketch_topk_reg;
    bit<10>	bf_hash;
}

struct box {
    bit<32>     key1;
    bit<32>     key2;
}

#include <core.p4> 
#if __TARGET_TOFINO__ == 2 
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "./common/headers.p4" 
#include "./common/util.p4" 

#define SKETCH_HASH_KEY	{hdr.ipv4.src_addr,hdr.tcp.dst_port}
#define BF_HASH_KEY	{hdr.ipv4.src_addr}

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
//hash
    Hash<bit<10>>(HashAlgorithm_t.CRC8) sketch_hash1;
    Hash<bit<10>>(HashAlgorithm_t.CRC16) sketch_hash2;
    Hash<bit<10>>(HashAlgorithm_t.CRC32) sketch_hash3;
    Hash<bit<10>>(HashAlgorithm_t.CRC64) sketch_hash4;
    Hash<bit<4>>(HashAlgorithm_t.CRC64) sketch_topk_hash;
    Hash<bit<10>>(HashAlgorithm_t.CRC8) bf_hash;
//register
    Register<bit<32>,_>(2,0) packet_counter1;
    
    RegisterAction<bit<32>,_,bit<32>>(packet_counter1) packet_counter1_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<32>,_>(2048,0) sketch_reg1;
    Register<bit<32>,_>(2048,0) sketch_reg2;
    Register<bit<32>,_>(2048,0) sketch_reg3;
    Register<bit<32>,_>(2048,0) sketch_reg4;
    
    RegisterAction<bit<32>,_,bit<32>>(sketch_reg1) sketch_reg1_op = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + 1;
                if(val >= ig_md.sketch_threshold){
                    rv = val;
                }else{
                    rv = 0;
                }
            }
        };
    
    
    RegisterAction<bit<32>,_,bit<32>>(sketch_reg2) sketch_reg2_op = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + 1;
                if(val >= ig_md.sketch_threshold && val < ig_md.sketch_reg1){
                    rv = val;
                }else{
                    rv = 0;
                }
            }
        };
    
    
    RegisterAction<bit<32>,_,bit<32>>(sketch_reg3) sketch_reg3_op = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + 1;
                if(val >= ig_md.sketch_threshold && val < ig_md.sketch_reg2){
                    rv = val;
                }else{
                    rv = 0;
                }
            }
        };
    
    
    RegisterAction<bit<32>,_,bit<32>>(sketch_reg4) sketch_reg4_op = {
            void apply(inout bit<32> val, out bit<32> rv) {
                val = val + 1;
                if(val >= ig_md.sketch_threshold && val < ig_md.sketch_reg3){
                    rv = val;
                }else{
                    rv = 0;
                }
            }
        };
    
    Register<bit<32>,_>(1,0) sketch_reg_threshold;
    
    Register<bit<32>,_>(1,10000) reg_threshold;
        RegisterAction<bit<32>,_,bit<32>>(sketch_reg_threshold) sketch_reg_threshold_op = {
            void apply(inout bit<32> val, out bit<32> rv) {
                rv = val;
            }
        };
    
    Register<box,_>(size=16, initial_value={0, 0}) top_flow_info;
    Register<bit<32>,_>(16,0) top_flow_size;
    
    RegisterAction<box, _ , bit<32>>(top_flow_info) top_flow_info_op = {
            void apply(inout box data, out bit<32> rv){
                data.key1 = hdr.ipv4.src_addr;
                data.key2 = hdr.ipv4.dst_addr;
            }
        };
    
    
    RegisterAction<bit<32>,_,bit<32>>(top_flow_size) top_flow_size_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };  
//action
    
    action load_threshold(){
        ig_md.sketch_threshold = sketch_reg_threshold_op.execute(0);
    }
    
    
    action compute_hash1(){
        ig_md.sketch_hash1 = sketch_hash1.get(SKETCH_HASH_KEY);
        ig_md.sketch_hash2 = sketch_hash2.get(SKETCH_HASH_KEY);
    }
    
    
    action compute_hash2(){
        ig_md.sketch_hash3 = sketch_hash3.get(SKETCH_HASH_KEY);
        ig_md.sketch_hash4 = sketch_hash4.get(SKETCH_HASH_KEY);
    }
    
    
    action apply_hash2() {
        ig_md.sketch_reg2 = sketch_reg2_op.execute(ig_md.sketch_hash2);
    }
    
    
    action apply_hash3() {
        ig_md.sketch_reg3 = sketch_reg3_op.execute(ig_md.sketch_hash3);
    }
    
    
    action apply_hash4() {
        ig_md.sketch_reg4 = sketch_reg4_op.execute(ig_md.sketch_hash4);
    }
    
    
    action update_topk_info(){
        top_flow_info_op.execute(ig_md.sketch_topk_reg);
    }  
    
    
    action update_topk_size(){
        top_flow_size_op.execute(ig_md.sketch_topk_reg);
    }  
    
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
    action a_flow_cordinality(){
        ig_md.sketch_reg1 = sketch_reg1_op.execute(ig_md.sketch_hash1);
        ig_md.sketch_flag = 0b0001;
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
    table t_flow_cordinality{
        actions = {
            a_flow_cordinality;
        }
        const default_action = a_flow_cordinality;
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
            a_compute_hash_sketch : {
                t_flow_cordinality.apply();}
            default : {}
        }
    //tail execute
        
        load_threshold();
        compute_hash1();
        compute_hash2();
        if(ig_md.sketch_flag == 1){
            apply_hash2();
            apply_hash3();  
            apply_hash4();
        }
        if(ig_md.sketch_reg4 != 0){
            update_topk_info();
            update_topk_size();
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