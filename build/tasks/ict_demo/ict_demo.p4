
struct metadata_t {
    bit<32> register_index;
    bit<10>	bf_hash;
    bit<8>	bf_reg;
    bit<8>	bf_reg_shadow;
    bit<8>	bf_switch;
    bit<10> sketch_hash1;
    bit<10> sketch_hash2;
    bit<10> sketch_hash3;
    bit<10> sketch_hash4;
    bit<32> sketch_reg1;
    bit<32> sketch_reg2;
    bit<32> sketch_reg3;
    bit<32> sketch_reg4;
    bit<32> sketch_threshold;
    bit<32> sketch_flag;
    bit<4> sketch_topk_hash1;
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

#define BF_HASH_KEY	{hdr.ipv4.src_addr,hdr.ipv4.dst_addr}
#define SKETCH_HASH_KEY	{hdr.ipv4.src_addr,hdr.ipv4.dst_addr}

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
//hash
    Hash<bit<10>>(HashAlgorithm_t.CRC64) bf_hash;
    Hash<bit<10>>(HashAlgorithm_t.CRC8) sketch_hash1;
    Hash<bit<10>>(HashAlgorithm_t.CRC16) sketch_hash2;
    Hash<bit<10>>(HashAlgorithm_t.CRC32) sketch_hash3;
    Hash<bit<10>>(HashAlgorithm_t.CRC64) sketch_hash4;
    Hash<bit<4>>(HashAlgorithm_t.CRC64) sketch_topk_hash;
//register
    Register<bit<32>,_>(2,0) counter;
    
    RegisterAction<bit<32>,_,bit<32>>(counter) counter_op = {
        void apply(inout bit<32> value, out bit<32> value_out){
            value = value + 1;
            value_out = value;
        }
    };
    Register<bit<8>,_>(1024,0) bf;
    
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
    
    Register<bit<8>,_>(1024,0) bf_shadow;
    
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
    Register<bit<32>,_>(1024,0) sketch_reg1;
    Register<bit<32>,_>(1024,0) sketch_reg2;
    Register<bit<32>,_>(1024,0) sketch_reg3;
    Register<bit<32>,_>(1024,0) sketch_reg4;
    
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
    
    Register<bit<32>,_>(1,100) sketch_reg_threshold;
    
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
        top_flow_info_op.execute(ig_md.sketch_topk_hash1);
    }  
    
    
    action update_topk_size(){
        top_flow_size_op.execute(ig_md.sketch_topk_hash1);
    }  
    
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
    action a_one_flow_size(){
        counter_op.execute(ig_md.register_index);
    }
    action a_tcp_flow_num(){
        ig_md.bf_reg = bf_op.execute(ig_md.bf_hash);
    }
    action a_heavy_hitter_detection(){
        ig_md.sketch_reg1 = sketch_reg1_op.execute(ig_md.sketch_hash1);
        ig_md.sketch_flag = 0b0001;
    }
//table
    table t_match_match10{
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_one_flow_size{
        actions = {
            a_one_flow_size;
        }
        const default_action = a_one_flow_size;
    }
    table t_match_match28{
        key = {
            hdr.ipv4.dst_addr: ternary;
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_tcp_flow_num{
        actions = {
            a_tcp_flow_num;
        }
        const default_action = a_tcp_flow_num;
    }
    table t_match_match316{
        key = {
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            a_set_flow_index;a_compute_hash_bf;a_compute_hash_sketch;a_set_mirror_configuration;_no_op;
        }
    }
    table t_heavy_hitter_detection{
        actions = {
            a_heavy_hitter_detection;
        }
        const default_action = a_heavy_hitter_detection;
    }
//pipline
    
    apply{
        //head tail execute
        
        ig_md.bf_switch = bf_switch_reg_op.execute(0);
        
        
        load_threshold();
        compute_hash1();
        compute_hash2();        
        
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
        switch(t_match_match10.apply().action_run){
            a_set_flow_index : {
                t_one_flow_size.apply();}
            default : {}
        }
        switch(t_match_match28.apply().action_run){
            a_compute_hash_bf : {
                t_tcp_flow_num.apply();
                ig_md.bf_reg_shadow = bf_shadow_op.execute(ig_md.bf_hash);}
            default : {}
        }
        switch(t_match_match316.apply().action_run){
            a_compute_hash_sketch : {
                t_heavy_hitter_detection.apply();}
            default : {}
        }
        //tail execute
        
        if(ig_md.bf_switch == 0 && ig_md.bf_reg == 1){
            flow_num_op.execute(0);
        }else if(ig_md.bf_switch == 1 && ig_md.bf_reg_shadow == 1){
            flow_num_op.execute(0);
        }
        
        
        if(ig_md.sketch_flag == 1){
            apply_hash2();
            apply_hash3();  
            apply_hash4();
        }
        else if(ig_md.sketch_reg4 != 0){
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