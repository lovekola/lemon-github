
from .p4objects.p4ast       import *
from .p4objects.p4syntax    import *
from .p4objects.p4code      import *
from .p4objects.p4hash      import *
from .p4objects.p4state     import *
from .p4objects.p4objects   import *
from .p4objects.p4actions   import *
from .operators             import Operator
from .util.util             import *
from functools              import reduce
# from .util.lambdacode       import get_lambda_source
import re


class Match(Operator):

    def __init__(self, name, lambda_f, obj = None):
        super(Match, self).__init__()
        self.name = name
        # self.lambda_f = lambda_f
        # self.lambda_str = get_lambda_source(self.lambda_f)
        self.lambda_str = lambda_f
        self.obj = obj
        self.p4object = None

    def on_next(self, item):
        if self.lambda_f(item):
            self._notify_next(item) 
            return True
        return False
    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):

        # (lhs, bool_op, rhs) = mafia_syntax_parse_match(self.lambda_str)
        # lhs_symbol = mafia_syntax_interpret_symbol(lhs)  # 返回变量类型
        # rhs_symbol = mafia_syntax_interpret_symbol(rhs)  
        # bool_op = mafia_syntax_interpret_bool_op(bool_op) # 返回操作符类型
        
        # (lhs, bool_op, rhs) = lemon_syntax_parse_match(self.lambda_str)

        expr = lemon_syntax_parse_match(self.lambda_str)
        allowed_key_field = ["ethernet.ether_type", "ipv4.src_addr", "ipv4.dst_addr", "ipv4.protocol", "tcp.flags", "tcp.src_port", "tcp.dst_port", "udp.src_port", "udp.dst_port"]
        table_key = {}
        table_entry = []
        for e in expr:
            if(e[0].strip() in allowed_key_field):
                table_key[ "hdr."+e[0].strip() ] = "ternary"
                table_entry.append(("hdr."+e[0].strip(),e[2].strip()))
                pass
            else:
                raise MafiaSyntaxError("Syntax error", "match key not allowed")


        self.p4object = []
        table_name = "t_match_" + self.name.replace('.','_') + str(P4Table.count)
        # def __init__(self, name, condition, keys, actions, type, entry=[], parent = None):
        table_match = P4Table(table_name, None, table_key, [], "Match", table_entry) \
                    + \
                    P4SetRegisterIndex("a_set_flow_index", "ig_md.metadata") \
                    + \
                    P4ActionComputeHashBF("a_compute_hash_bf", "ig_md.metadata") \
                    + \
                    P4ActionComputeHashSketch("a_compute_hash_sketch", "ig_md.metadata") \
                    + \
                    P4ActionSetMirrorConfiguration("a_set_mirror_configuration", "ig_md.metadata") \
                    + \
                    P4ActionNoOp("_no_op")
        # p4_program.add_command("add_entry" + '\t' + table_name + '\t' +lhs + '\t' + rhs + '\t' + "a_set_flow_index")
        self.p4object += [table_match]

        if not ingress_egress_flag:
            return (self.p4object, [])
        else:
            return ([], self.p4object)

    def __repr__(self):
        return "Match [ %s ]" % self.lambda_str

    def on_compile_old(self, root, p4_program, ingress_egress_flag, parent_type):
        (lhs, bool_op, rhs) = mafia_syntax_parse_match(self.lambda_str)
        lhs_symbol = mafia_syntax_interpret_symbol(lhs)
        rhs_symbol = mafia_syntax_interpret_symbol(rhs)
        bool_op = mafia_syntax_interpret_bool_op(bool_op)

        if isinstance(lhs_symbol, (MafiaSymbolStateVarBF, MafiaSymbolStateVarSketch)):
            raise MafiaSemanticError("Semantic Error: %s" % self.lambda_str, "Sketch and Bloom filters need to be accessed with aggregation functions")
        elif isinstance(lhs_symbol, (MafiaSymbolStateVar)):
            (name, state) = p4_program.state.lookup(lhs_symbol.id)
            if isinstance(state, (Counter, Timestamp)):
                table_load_state = P4Table("t_load_" + lhs_symbol.id, None, { }, []) \
                                    + \
                                   P4ActionRegisterRead("a_load_"+lhs_symbol.id, 'mafia_metadata.'+lhs_symbol.id, lhs_symbol.id, "mafia_metadata.flow_index", [])
                table_match = P4Table("t_" + self.name, 'mafia_metadata.'+lhs_symbol.id + '' + bool_op + '' + rhs_symbol.id, {}, [])
                self.p4object = [table_load_state, table_match]
                p4_program.add_command("table_set_default " + "t_load_" + lhs_symbol.id + " " + "a_load_" + lhs_symbol.id)
            elif isinstance(state, Random):
                table_match = P4Table("t_" + self.name, 'mafia_metadata.'+lhs_symbol.id + '' + bool_op + '' + rhs_symbol.id, {}, [])
                self.p4object = [table_match]
            else:
                raise MafiaSemanticError("Semantic Error", self.lambda_str)
        elif isinstance(lhs_symbol, MafiaSymbolAggregateFunction):
            (fun, hashset, var) = mafia_syntax_parse_aggregate(lhs_symbol.id)
            (_, h) = p4_program.state.lookup(hashset)
            hash_fun = p4_program.lookup_hash(h)
            table_hash = hash_fun.compile(p4_program, self.name, h.n, h.inputs, h.outputs)
            
            var_symbol = mafia_syntax_interpret_symbol(var)
            if isinstance(var_symbol, MafiaSymbolStateVarBF):
                (bf, index) = mafia_syntax_parse_bf_ref(var)
                (name, bf_obj) = p4_program.state.lookup(bf)
                table_load_cells = P4Table("t_" + self.name + "_read_"+name, None, {}, [])
                i = 0
                actions = []
                conds = []
                while i < h.n:
                    p4_program.headers.register_mafia_metadata_field([(self.name+'_'+name+'_cell_'+str(i), bf_obj.width)])
                    symbol_index = mafia_syntax_interpret_symbol(index)
                    if isinstance(symbol_index, MafiaSymbolDecimal) or isinstance(symbol_index, MafiaSymbolHeaderField) or isinstance(symbol_index, MafiaSymbolMetadata):
                        param_index = symbol_index.id
                    elif isinstance(symbol_index, MafiaSymbolStateVar):
                        param_index = "mafia_metadata."+h.family+"_"+symbol_index.id+"_"+str(i)
                    actions += [P4ActionRegisterRead("a_"+self.name, "mafia_metadata."+self.name+'_'+name+'_cell_'+str(i), name, param_index, [])]
                    conds += ["mafia_metadata."+self.name+'_'+name+'_cell_'+str(i) + bool_op + rhs_symbol.id]
                    i = i+1

                table_load_cells += (reduce((lambda x, y: x + y), actions))
                p4_program.add_command("table_set_default " + "t_" + self.name + " " + "a_" + self.name)
                if fun == 'all':
                    table_match = P4Table("t_" + self.name, ' and '.join(c for c in conds), {}, [])
                    self.p4object = table_hash + [table_load_cells, table_match]
                elif fun == 'any':
                    table_match = P4Table("t_" + self.name, ' or '.join(c for c in conds), {}, [])
                    self.p4object = table_hash + [table_load_cells, table_match]
                else:
                    raise MafiaSemanticError("Semantic error", "Invalid aggregation function for bloom filter object")
            
            elif isinstance(var_symbol, MafiaSymbolStateVarSketch):
                (sketch, row, col) = mafia_syntax_parse_sketch_ref(var)
                (name, sketch_obj) = p4_program.state.lookup(sketch)
                table_load_cells = P4Table("t_" + self.name + "_read_"+name, None, {}, [])
                i = 0
                actions = []
                conds = []
                while i < h.n:
                    p4_program.headers.register_mafia_metadata_field([(self.name+'_'+name+'_cell_'+str(i), sketch_obj.width)])
                    symbol_row = mafia_syntax_interpret_symbol(row)
                    symbol_col = mafia_syntax_interpret_symbol(col)
                    if isinstance(symbol_row, MafiaSymbolDecimal) or isinstance(symbol_row, MafiaSymbolHeaderField) or isinstance(symbol_row, MafiaSymbolMetadata):
                        param_row = symbol_row.id
                    elif isinstance(symbol_row, MafiaSymbolStateVar):
                        param_row = "mafia_metadata."+h.family+"_"+symbol_row.id+"_"+str(i)
                    if isinstance(symbol_col, MafiaSymbolDecimal) or isinstance(symbol_col, MafiaSymbolHeaderField) or isinstance(symbol_col, MafiaSymbolMetadata):
                        param_col = symbol_col.id
                    elif isinstance(symbol_col, MafiaSymbolStateVar):
                        param_col = "mafia_metadata."+h.family+"_"+symbol_col.id+"_"+str(i)
                    param_index = param_row  + "*" + str(sketch_obj.m) + "+" + param_col
                    actions += [P4ActionRegisterRead("a_"+self.name, "mafia_metadata."+self.name+'_'+name+'_cell_'+str(i), name, param_index, [])]
                    conds += ["mafia_metadata."+self.name+'_'+name+'_cell_'+str(i) + bool_op + rhs_symbol.id]
                    i = i+1
                table_load_cells += (reduce((lambda x, y: x + y), actions))
                p4_program.add_command("table_set_default " + "t_" + self.name + " " + "a_" + self.name)
                if fun == 'all':
                    table_match = P4Table("t_" + self.name, '\n and '.join(c for c in conds), {}, [])
                    self.p4object = table_hash + [table_load_cells, table_match]
                elif fun == 'any':
                    table_match = P4Table("t_" + self.name, '\n or '.join(c for c in conds), {}, [])
                    self.p4object = table_hash + [table_load_cells, table_match]
                elif fun == 'min':
                    p4_program.headers.register_mafia_metadata_field([(self.name+'_'+name+'_min', sketch_obj.width)])
                    table_min = []
                    min_conds = []
                    i = 0
                    while i < h.n:
                        j = 0
                        min_conds = []
                        while j < h.n:
                            if i!=j:
                                min_conds += ["mafia_metadata."+self.name+'_'+name+'_cell_'+str(i) + " <= " + "mafia_metadata."+self.name+'_'+name+'_cell_'+str(j)]
                            j = j+1
                        # table_min += [P4Table("t_" + self.name+"_update_min_"+str(i), '\n and '.join(c for c in min_conds), {}, [])]
                        table_min += [P4Table("t_" + self.name+"_update_min_"+str(i), '\n and '.join(c for c in min_conds), {}, []) + P4ActionModifyField("a_"+self.name+"_update_min_"+str(i), "mafia_metadata."+self.name+'_'+name+'_min', "mafia_metadata."+self.name+'_'+name+'_cell_'+str(i), [])]
                        
                        i = i+1
                    table_match = P4Table("t_" + self.name, "mafia_metadata."+self.name+'_'+name+'_min ' + bool_op + ' ' + rhs_symbol.id, {}, [])
                    self.p4object = table_hash + [table_load_cells] + table_min + [table_match]
                elif fun == 'max':
                    p4_program.headers.register_mafia_metadata_field([(self.name+'_'+name+'_max', sketch_obj.width)])
                    table_max = []
                    max_conds = []
                    i = 0
                    j = 0
                    while i < h.n:
                        while j < h.n:
                            if i!=j:
                                max_conds += ["mafia_metadata."+self.name+'_'+name+'_cell_'+str(i) + " <= " + "mafia_metadata."+self.name+'_'+name+'_cell_'+str(j)]
                            j = j+1
                        table_min += [P4Table("t_" + self.name+"_update_max", '\n and '.join(c for c in max_conds), {}, []) + P4ActionModifyField("a_"+self.name+"_update_max_"+str(i), "mafia_metadata."+self.name+'_'+name+'_max', "mafia_metadata."+self.name+'_'+name+'_cell_'+str(i), [])]
                        p4_program.add_command("table_set_default " + "t_" + self.name+"_update_max" + " " + "a_"+self.name+"_update_max_"+str(i))
                        i = i+1
                    table_match = P4Table("t_" + self.name, "mafia_metadata."+self.name+'_'+name+'_max ' + bool_op + ' ' + rhs_symbol.id, {}, [])
                    self.p4object = table_hash + [table_load_cells] + table_max + [table_match]
                elif fun == 'sum':
                    table_sum = P4Table("t_" + self.name, None, {}, [])
                    table_sum += P4ActionModifyField('', "mafia_metadata."+self.name+'_'+name+'_sum', 0, [])
                    i = 0
                    p4_program.headers.register_mafia_metadata_field([(self.name+'_'+name+'_sum', sketch_obj.width)])
                    while i < h.n:
                        table_sum += P4ActionFieldAdd('', self.name+'_'+name+'_sum', "mafia_metadata."+self.name+'_'+name+'_cell_'+str(i))
                    table_match = P4Table("t_" + self.name, "mafia_metadata."+self.name+'_'+name+'_min' + bool_op + rhs_symbol.id, {}, [])
                    self.p4object = table_hash + [table_load_cells, table_sum, table_match]
            else:
                raise MafiaSemanticError("Semantic Error: %s" % lhs_symbol.id, "Aggregate function can be used only with sketch or bloom filters objects")
            # raise MafiaSemanticError("Semantic Error: %s" % self.lambda_str, "Not implemented")
        elif isinstance(lhs_symbol, (MafiaSymbolHeaderField, MafiaSymbolMetadata)):
            # address = mafia_syntax_check_ip_address(rhs)
            # table_load_state = P4Table("t_" + self.name, None, { "ipv4.src": ('exact', ""), "ipv4.dst": ('exact', "") }, []) \
            if lhs_symbol.id == 'ipv4.src':
                table_match = P4Table("t_match_ip_src", None, { "ipv4.src": ('lpm', "") }, []) \
                            + \
                            P4ActionModifyField("a_set_flow_index", "mafia_metadata.flow_index", "flow_index", ["flow_index"]) \
                            + \
                            P4ActionNoOp("_no_op")
                p4_program.add_command("table_set_default " + "t_match_ip_src" + " " + "_no_op")
                self.p4object = [table_match]
            elif lhs_symbol.id == 'ipv4.dst':
                table_match = P4Table("t_match_ip_dst", None, { "ipv4.dst": ('lpm', "") }, []) \
                            + \
                            P4ActionModifyField("a_set_flow_index", "mafia_metadata.flow_index", "flow_index", ["flow_index"]) \
                            + \
                            P4ActionNoOp("_no_op")
                p4_program.add_command("table_set_default " + "t_match_ip_dst" + " " + "_no_op")
                self.p4object = [table_match]
            elif lhs_symbol.id == 'mafia_metadata.is_first_hop' or lhs_symbol.id == 'mafia_metadata.is_last_hop':
                table_hop = None
                if lhs_symbol.id == 'mafia_metadata.is_first_hop':
                    table_hop = P4Table("t_check_" + self.name, None, { "ipv4.src": ('exact', ""), "ipv4.dst": ('exact', "") }, []) \
                                + \
                                P4ActionModifyField("a_" + self.name, "mafia_metadata.is_first_hop", "is_first_hop", ["is_first_hop"])
                    p4_program.add_command("table_set_default " + "t_" + self.name + " " + "a_" + self.name)
                elif lhs_symbol.id == 'mafia_metadata.is_last_hop':
                    table_hop = P4Table("t_check_" + self.name, None, { "ipv4.src": ('exact', ""), "ipv4.dst": ('exact', "") }, []) \
                                + \
                                P4ActionModifyField("a_" + self.name, "mafia_metadata.is_last_hop", "is_last_hop", ["is_last_hop"])
                    p4_program.add_command("table_set_default " + "t_" + self.name + " " + "a_" + self.name)
                table_match = P4Table("t_" + self.name, lhs_symbol.id + '' + bool_op + '' + rhs, {}, [])
                self.p4object = [table_hop, table_match]
            else:
                table_match = P4Table("t_" + self.name, lhs_symbol.id + '' + bool_op + '' + rhs, {}, [])
                self.p4object = [table_match]
        elif isinstance(lhs_symbol, (MafiaSymbolDecimal)):
            table_match = P4Table("t_" + self.name, lhs_symbol.id + '' + bool_op + '' + rhs, {}, [])
            self.p4object = [table_match]
        else:
            raise MafiaSemanticError("Semantic Error", self.lambda_str)

        if not ingress_egress_flag:
            return (self.p4object, [])
        else:
            return ([], self.p4object)


class Count(Operator):
    def __init__(self, name, lambda_f, counter=None):
        super(Count, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        # self.lambda_f = lambda_f
        # self.lambda_str = get_lambda_source(self.lambda_f)
        self.lambda_str = lambda_f
        self.p4object = None
        # if(not isinstance(counter, Counter)):
        #     raise TypeError('Count works only on Counter object types')
        # self.counter = counter

    def on_next(self, item):
        self._notify_next(item)
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        self.p4object = P4Table(self.table_name, None, { }, [], "Count")
        # counter_ast = MafiaASTCounter(self.name, self.lambda_str)
        counter_ast = LemonASTCounter(self.name, self.lambda_str)
        actions = counter_ast.compile(p4_program)
        self.p4object +=  ( \
                            P4ActionBase(self.action_name, []) \
                            + \
                            (reduce((lambda x, y: x + y), actions)) \
                          )
        # p4_program.add_command("table_set_default" + " " + self.table_name + " "  + self.action_name)
        p4_program.metadata["counter_meta"] = "bit<32> register_index;"
        return self.on_compile_return(ingress_egress_flag)

    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])

    def configure_table_commands(self, p4_program):
        p4_program.add_command("table_set_default " + self.table_name + " " + self.action_name)

    def __repr__(self):
        # return "Count [ %s, %s ]" % (self.lambda_str, self.counter.name)
        return "Count [ %s ]" % (self.lambda_str)



class Reduce(Operator):
    def __init__(self, name, hash_key):
        super(Reduce, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        self.hash_key = hash_key
        self.p4object = None
    def on_next(self, item):
        self._notify_next(item)
        return True
    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        
        self.p4object = P4Table(self.table_name, None, { }, [], "Reduce") \
                        + \
                        P4ActionApplyHash(self.action_name, "ig_md.metadata")
        
        hash_key = re.findall(r"hash_key: {(.+?)}", self.hash_key)[0]
        hash_key_list = hash_key.strip().split(',')
        hash_key_res = ','.join("hdr." + i.strip() for i in hash_key_list)
        p4_program.define["BF_HASH_KEY"] = "#define BF_HASH_KEY\t" + '{' + hash_key_res + '}'
        hash_width = 11
        reg_width = 8
        reg_num = 1<<hash_width
        p4_program.registers["bf"] = p4register % (reg_width, reg_num, 0, "bf") 
        p4_program.registers["bf_op"] = p4RegisterActionBF % ("bf", "bf")        
        p4_program.registers["bf_shadow"] = p4register % (reg_width, reg_num, 0, "bf_shadow") 
        p4_program.registers["bf_shadow_op"] = p4RegisterActionBF_SHADOW % ("bf_shadow", "bf_shadow")

        p4_program.registers["bf_switch_reg"] = p4register % (8, 1, 0, "bf_switch_reg") 
        p4_program.registers["bf_switch_reg_op"] = p4RegisterActionSwitch % ("bf_switch_reg", "bf_switch_reg")   

        p4_program.hashes["bf_hash1"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC64) bf_hash;" % (hash_width)
        p4_program.metadata["bf_meta1"] = "bit<%s>\tbf_hash;" % (hash_width)
        p4_program.metadata["bf_meta2"] = "bit<%s>\tbf_reg;" % (reg_width)
        p4_program.metadata["bf_meta3"] = "bit<%s>\tbf_reg_shadow;" % (reg_width)
        p4_program.metadata["bf_meta4"] = "bit<8>\tbf_switch;"
        
        reduce_tail = p4bf_tail % ("flow_num","flow_num")
        
        p4_program.head["bf_flow_count"] = p4bf_head
        p4_program.tail["bf_flow_count"] = reduce_tail
        p4_program.registers["flow_num"] = p4register % (32, 1, 0, "flow_num")
        p4_program.registers["flow_num_op"] = p4RegisterActionCounter % (32,32,"flow_num", "flow_num",32,32,'+',1)

        p4_program.add_command("read_register_bf" +'\t' + "flow_num" + '\t' + '0')

        return self.on_compile_return(ingress_egress_flag)

    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])
    def __repr__(self):
        # return "Count [ %s, %s ]" % (self.lambda_str, self.counter.name)
        return "Reduce [ %s ]" % (self.hash_key)

class Sketch(Operator):
    def __init__(self, name, hash_key, sketch_type, hh_threshold=None):
        super(Sketch, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        self.hash_key = hash_key
        self.type = sketch_type
        self.hh_threshold = hh_threshold
        self.p4object = None
    def on_next(self, item):
        self._notify_next(item)
        return True
    
    def addDataStructure_with_shadow(self,p4_program):
        """ Define count-min-sketch and topk flow box  """
        if(self.hh_threshold):
            hh_threshold = self.hh_threshold
        else:
            hh_threshold = 100

        if(self.type == "TOP16"):
            topk_width = 4
        elif(self.type == "TOP32"):
            topk_width = 5
        else:
            topk_width = 4
        
        reg_width = 32
        hash_width = 13
        reg_num = 1 << hash_width
        
        # 1.define hash_key
        hash_keys = re.findall(r"hash_key: {(.+?)}", self.hash_key)[0]
        hash_keys_list = hash_keys.strip().split(',')
        hash_keys_res = ','.join("hdr." + i.strip() for i in hash_keys_list)
        p4_program.define["SKETCH_HASH_KEY"] = "#define SKETCH_HASH_KEY\t" + '{' + hash_keys_res + '}'
        
        # 2.define two-step heavy-hitter detection data structure
            # count-min-skech reg

        p4_program.registers["sketch_reg1"] = p4register % (reg_width, reg_num, 0, "sketch_reg1") 
        p4_program.registers["sketch_reg2"] = p4register % (reg_width, reg_num, 0, "sketch_reg2") 
        p4_program.registers["sketch_reg3"] = p4register % (reg_width, reg_num, 0, "sketch_reg3") 
        p4_program.registers["sketch_reg4"] = p4register % (reg_width, reg_num, 0, "sketch_reg4") 
        p4_program.registers["sketch_reg1_op"] = p4RegisterActionSketchReg1_default % (reg_width, reg_width, "sketch_reg1", "sketch_reg1",reg_width, reg_width)
        p4_program.registers["sketch_reg2_op"] = p4RegisterActionSketchRegx_default % (reg_width, reg_width, "sketch_reg2", "sketch_reg2",reg_width, reg_width, "val < ig_md.sketch_reg1")
        p4_program.registers["sketch_reg3_op"] = p4RegisterActionSketchRegx_default % (reg_width, reg_width, "sketch_reg3", "sketch_reg3",reg_width, reg_width, "val < ig_md.sketch_reg2")
        p4_program.registers["sketch_reg4_op"] = p4RegisterActionSketchRegx_default % (reg_width, reg_width, "sketch_reg4", "sketch_reg4",reg_width, reg_width, "val < ig_md.sketch_reg3")
            # count-min-skech shadow reg
        p4_program.registers["sketch_switch_reg"] = p4register % (8, 1, 0, "sketch_switch_reg") 
        p4_program.registers["sketch_switch_reg_op"] = p4RegisterActionSwitch % ("sketch_switch_reg", "sketch_switch_reg") 

        p4_program.registers["sketch_reg1_shadow"] = p4register % (reg_width, reg_num, 0, "sketch_reg1_shadow") 
        p4_program.registers["sketch_reg2_shadow"] = p4register % (reg_width, reg_num, 0, "sketch_reg2_shadow") 
        p4_program.registers["sketch_reg3_shadow"] = p4register % (reg_width, reg_num, 0, "sketch_reg3_shadow") 
        p4_program.registers["sketch_reg4_shadow"] = p4register % (reg_width, reg_num, 0, "sketch_reg4_shadow") 
        p4_program.registers["sketch_reg1_shadow_op"] = p4RegisterActionSketchReg1_shadow % (reg_width, reg_width, "sketch_reg1_shadow", "sketch_reg1_shadow",reg_width, reg_width)
        p4_program.registers["sketch_reg2_shadow_op"] = p4RegisterActionSketchRegx_shadow % (reg_width, reg_width, "sketch_reg2_shadow", "sketch_reg2_shadow",reg_width, reg_width, "val < ig_md.sketch_reg1_shadow")
        p4_program.registers["sketch_reg3_shadow_op"] = p4RegisterActionSketchRegx_shadow % (reg_width, reg_width, "sketch_reg3_shadow", "sketch_reg3_shadow",reg_width, reg_width, "val < ig_md.sketch_reg2_shadow")
        p4_program.registers["sketch_reg4_shadow_op"] = p4RegisterActionSketchRegx_shadow % (reg_width, reg_width, "sketch_reg4_shadow", "sketch_reg4_shadow",reg_width, reg_width, "val < ig_md.sketch_reg3_shadow")
            # threshold
        p4_program.registers["sketch_reg_threshold"] = p4register % (32, 1, hh_threshold, "sketch_reg_threshold") 
        p4_program.registers["sketch_reg_threshold_op"] = p4RegisterActionSketchThreshold % ("sketch_reg_threshold", "sketch_reg_threshold")
            # topk flow box
        
        p4_program.struct["box"] = p4Box
        p4_program.registers["top_flow_info"] = p4registerBox % (1<<topk_width, "top_flow_info")
        p4_program.registers["top_flow_size"] = p4register % (32, 1<<topk_width, 0, "top_flow_size")
        p4_program.registers["top_flow_info_op"] = p4registerActionBox % ("top_flow_info","top_flow_info")
        p4_program.registers["top_flow_size_op"] = p4RegisterActionCounter % (32,32,"top_flow_size","top_flow_size",32,32,'+',1)

        # 3.define hash
        
        p4_program.hashes["sketch_hash1"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC8) sketch_hash1;" % (hash_width)
        p4_program.hashes["sketch_hash2"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC16) sketch_hash2;" % (hash_width)
        p4_program.hashes["sketch_hash3"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC32) sketch_hash3;" % (hash_width)
        p4_program.hashes["sketch_hash4"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC64) sketch_hash4;" % (hash_width)
        
        p4_program.hashes["sketch_topk_hash"] = "Hash<bit<%d>>(HashAlgorithm_t.CRC64) sketch_topk_hash;" % topk_width

        # 4.define metadata
        p4_program.metadata["sketch_meta1"] = "bit<%s> sketch_hash1;" % (hash_width)
        p4_program.metadata["sketch_meta2"] = "bit<%s> sketch_hash2;" % (hash_width)
        p4_program.metadata["sketch_meta3"] = "bit<%s> sketch_hash3;" % (hash_width)
        p4_program.metadata["sketch_meta4"] = "bit<%s> sketch_hash4;" % (hash_width)
        p4_program.metadata["sketch_meta5"] = "bit<%s> sketch_reg1;" % (reg_width)
        p4_program.metadata["sketch_meta6"] = "bit<%s> sketch_reg2;" % (reg_width)
        p4_program.metadata["sketch_meta7"] = "bit<%s> sketch_reg3;" % (reg_width)
        p4_program.metadata["sketch_meta8"] = "bit<%s> sketch_reg4;" % (reg_width)

        p4_program.metadata["sketch_switch"] = "bit<%s> sketch_switch;" % (8)
        p4_program.metadata["sketch_reg1_shadow"] = "bit<%s> sketch_reg1_shadow;" % (reg_width)
        p4_program.metadata["sketch_reg2_shadow"] = "bit<%s> sketch_reg2_shadow;" % (reg_width)
        p4_program.metadata["sketch_reg3_shadow"] = "bit<%s> sketch_reg3_shadow;" % (reg_width)
        p4_program.metadata["sketch_reg4_shadow"] = "bit<%s> sketch_reg4_shadow;" % (reg_width)

        p4_program.metadata["sketch_meta9"] = "bit<%s> sketch_threshold;" % (reg_width)

        p4_program.metadata["sketch_meta10"] = "bit<%s> sketch_flag;" % (reg_width)
        p4_program.metadata["sketch_meta11"] = "bit<%d> sketch_topk_hash1;" % topk_width

        # 5.define actions
        p4_program.actions["load_threshold"] = p4sketch_load_threshold
        
        p4_program.actions["compute_sketch_hash1_2"] = p4sketch_compute_hash1
        p4_program.actions["compute_sketch_hash3_4"] = p4sketch_compute_hash2
        p4_program.actions["apply_hash2"] = p4sketch_apply_hash2
        p4_program.actions["apply_hash3"] = p4sketch_apply_hash3
        p4_program.actions["apply_hash4"] = p4sketch_apply_hash4

        p4_program.actions["update_topk_info"] = p4update_topk_info
        p4_program.actions["update_topk_size"] = p4update_topk_size

        # 6.define head & tail in apply
        p4_program.tail["sketch_top_flow_record"] = p4sketch_tail_shadow
        p4_program.head["sketch_load_threshold"] = p4sketch_head_shadow

        # 7. define command
        p4_program.add_command("read_register_sketch" +'\t' + "sketch_reg_threshold" + '\t' +  "0\t" + str(hh_threshold))
        p4_program.add_command("read_register_sketch" +'\t' + "top_flow_info" + '\t' + str(1<<topk_width))
        p4_program.add_command("read_register_sketch" +'\t' + "top_flow_size" + '\t' + str(1<<topk_width))


    def addDataStructure(self,p4_program):
        """ Define count-min-sketch and topk flow box  """
        
        if(self.type == "TOP16"):
            topk_width = 4
        elif(self.type == "TOP32"):
            topk_width = 5
        else:
            topk_width = 4
        
        reg_width = 32
        hash_width = 10
        reg_num = 1 << hash_width
        
        # 1.define hash_key
        hash_keys = re.findall(r"hash_key: {(.+?)}", self.hash_key)[0]
        hash_keys_list = hash_keys.strip().split(',')
        hash_keys_res = ','.join("hdr." + i.strip() for i in hash_keys_list)
        p4_program.define["SKETCH_HASH_KEY"] = "#define SKETCH_HASH_KEY\t" + '{' + hash_keys_res + '}'
        
        # 2.define two-step heavy-hitter detection data structure
            # count-min-skech reg

        p4_program.registers["sketch_reg1"] = p4register % (reg_width, reg_num, 0, "sketch_reg1") 
        p4_program.registers["sketch_reg2"] = p4register % (reg_width, reg_num, 0, "sketch_reg2") 
        p4_program.registers["sketch_reg3"] = p4register % (reg_width, reg_num, 0, "sketch_reg3") 
        p4_program.registers["sketch_reg4"] = p4register % (reg_width, reg_num, 0, "sketch_reg4") 
        p4_program.registers["sketch_reg1_op"] = p4RegisterActionSketchReg1 % (reg_width, reg_width, "sketch_reg1", "sketch_reg1",reg_width, reg_width)
        p4_program.registers["sketch_reg2_op"] = p4RegisterActionSketchRegx % (reg_width, reg_width, "sketch_reg2", "sketch_reg2",reg_width, reg_width, "val < ig_md.sketch_reg1")
        p4_program.registers["sketch_reg3_op"] = p4RegisterActionSketchRegx % (reg_width, reg_width, "sketch_reg3", "sketch_reg3",reg_width, reg_width, "val < ig_md.sketch_reg2")
        p4_program.registers["sketch_reg4_op"] = p4RegisterActionSketchRegx % (reg_width, reg_width, "sketch_reg4", "sketch_reg4",reg_width, reg_width, "val < ig_md.sketch_reg3")
            # threshold
        p4_program.registers["sketch_reg_threshold"] = p4register % (32, 1, 100, "sketch_reg_threshold") 
        p4_program.registers["sketch_reg_threshold_op"] = p4RegisterActionSketchThreshold % ("sketch_reg_threshold", "sketch_reg_threshold")
            # topk flow box
        
        p4_program.struct["box"] = p4Box
        p4_program.registers["top_flow_info"] = p4registerBox % (1<<topk_width, "top_flow_info")
        p4_program.registers["top_flow_size"] = p4register % (32, 1<<topk_width, 0, "top_flow_size")
        p4_program.registers["top_flow_info_op"] = p4registerActionBox % ("top_flow_info","top_flow_info")
        p4_program.registers["top_flow_size_op"] = p4RegisterActionCounter % (32,32,"top_flow_size","top_flow_size",32,32,'+',1)

        # 3.define hash
        
        p4_program.hashes["sketch_hash1"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC8) sketch_hash1;" % (hash_width)
        p4_program.hashes["sketch_hash2"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC16) sketch_hash2;" % (hash_width)
        p4_program.hashes["sketch_hash3"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC32) sketch_hash3;" % (hash_width)
        p4_program.hashes["sketch_hash4"] = "Hash<bit<%s>>(HashAlgorithm_t.CRC64) sketch_hash4;" % (hash_width)
        
        p4_program.hashes["sketch_topk_hash"] = "Hash<bit<%d>>(HashAlgorithm_t.CRC64) sketch_topk_hash;" % topk_width

        # 4.define metadata
        p4_program.metadata["sketch_meta1"] = "bit<%s> sketch_hash1;" % (hash_width)
        p4_program.metadata["sketch_meta2"] = "bit<%s> sketch_hash2;" % (hash_width)
        p4_program.metadata["sketch_meta3"] = "bit<%s> sketch_hash3;" % (hash_width)
        p4_program.metadata["sketch_meta4"] = "bit<%s> sketch_hash4;" % (hash_width)
        p4_program.metadata["sketch_meta5"] = "bit<%s> sketch_reg1;" % (reg_width)
        p4_program.metadata["sketch_meta6"] = "bit<%s> sketch_reg2;" % (reg_width)
        p4_program.metadata["sketch_meta7"] = "bit<%s> sketch_reg3;" % (reg_width)
        p4_program.metadata["sketch_meta8"] = "bit<%s> sketch_reg4;" % (reg_width)

        p4_program.metadata["sketch_meta9"] = "bit<%s> sketch_threshold;" % (reg_width)

        p4_program.metadata["sketch_meta10"] = "bit<%s> sketch_flag;" % (reg_width)
        p4_program.metadata["sketch_meta11"] = "bit<%d> sketch_topk_hash1;" % topk_width

        # 5.define actions
        p4_program.actions["load_threshold"] = p4sketch_load_threshold
        
        p4_program.actions["compute_sketch_hash1_2"] = p4sketch_compute_hash1
        p4_program.actions["compute_sketch_hash3_4"] = p4sketch_compute_hash2
        p4_program.actions["apply_hash2"] = p4sketch_apply_hash2
        p4_program.actions["apply_hash3"] = p4sketch_apply_hash3
        p4_program.actions["apply_hash4"] = p4sketch_apply_hash4

        p4_program.actions["update_topk_info"] = p4update_topk_info
        p4_program.actions["update_topk_size"] = p4update_topk_size

        # 6.define head & tail in apply
        p4_program.tail["sketch_top_flow_record"] = p4sketch_tail
        p4_program.head["sketch_load_threshold"] = p4sketch_head

        # 7. define command
        p4_program.add_command("read_register_sketch" +'\t' + "sketch_reg_threshold" + '\t' + "0")
        p4_program.add_command("read_register_sketch" +'\t' + "top_flow_info" + '\t' + str(1<<topk_width))
        p4_program.add_command("read_register_sketch" +'\t' + "top_flow_size" + '\t' + str(1<<topk_width))

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        
        if(self.type == "TOP16-shadow"):
            self.p4object = P4Table(self.table_name, None, { }, [], "Sketch-shadow") \
                        + \
                        P4ActionApplyHashSketch(self.action_name, "ig_md.metadata")
            self.addDataStructure_with_shadow(p4_program)
        else:
            self.p4object = P4Table(self.table_name, None, { }, [], "Sketch") \
                + \
                P4ActionApplyHashSketch(self.action_name, "ig_md.metadata")
            self.addDataStructure(p4_program)

        return self.on_compile_return(ingress_egress_flag)
    
    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])
    def __repr__(self):
        # return "Count [ %s, %s ]" % (self.lambda_str, self.counter.name)
        return "Sketch [ %s ]" % (self.hash_key)


class Mirror(Operator):
    def __init__(self, name, egress_port):
        super(Mirror, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = 'a_' + self.name
        self.p4object = None
        self.egress_port = egress_port
    
    def on_next(self, item):
        self._notify_next(item)
        return True
    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        
        self.p4object = P4Table(self.table_name, None, { }, [], "Mirror") \
                    + \
                    P4ActionSetMirrorConfiguration(self.action_name, "ig_md.metadata")
        self.configure_table_commands(p4_program)
        return self.on_compile_return(ingress_egress_flag)

    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])
    
    def configure_table_commands(self, p4_program):
        # p4_program.add_command("table_set_default " + self.table_name + " " + self.action_name)
        pass
    
    def __repr__(self):
        return "Mirror [ copy packets to port %s ]" % self.egress_port

class Timestamp_get(Operator):

    def __init__(self, name, timestamp):
        super(Timestamp_get, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = 'a_' + self.name
        self.p4object = None
        if(not isinstance(timestamp, Timestamp)):
            raise TypeError('Timestamp_get works only on Timestamp object types')
        self.timestamp = timestamp

    def on_next(self, item):
        self._notify_next(item)
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        
        self.p4object = P4Table(self.table_name, None, { }, []) \
                        + \
                        P4ActionGetTimestamp(self.action_name, self.timestamp.name, "mafia_metadata.flow_index", [])
        # self.p4object = P4Table(self.table_name, None, { }, []) \
        #                 + \
        #                 self.timestamp.write(self.action_name, "mafia_metadata."+self.timestamp.name)
        self.configure_table_commands(p4_program)
        return self.on_compile_return(ingress_egress_flag)

    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])

    def configure_table_commands(self, p4_program):
        p4_program.add_command("table_set_default " + self.table_name + " " + self.action_name)

    def _compile(self):
        pass

    def __repr__(self):
        return "Timestamp_get [ %s ]" % self.timestamp.name



class Sketch_op(Operator):
    def __init__(self, name, lambda_f, sketch):
        super(Sketch_op, self).__init__()
        self.name = name
        # self.lambda_f = lambda_f
        # self.lambda_str = get_lambda_source(self.lambda_f)
        self.lambda_str = lambda_f
        self.p4object = None
        if(not isinstance(sketch, Sketch)):
            raise TypeError('Sketch_op works only on Sketch object types')
        self.sketch = sketch

    def on_next(self, item):
        # self.counter.add(self.lambda_f(item))
        # self.lambda_f(item)
        self._notify_next(item)
        return True

    def compile_hash_function(self, p4_program, h):
        hash_fun = p4_program.lookup_hash(h)
        return hash_fun.compile(p4_program, self.name, h.n, h.inputs, h.outputs)

    def generate_sketch_index(self, h, row, col, nh):
        symbol_row = mafia_syntax_interpret_symbol(row)
        symbol_col = mafia_syntax_interpret_symbol(col)
        if isinstance(symbol_row, MafiaSymbolDecimal) or isinstance(symbol_row, MafiaSymbolHeaderField) or isinstance(symbol_row, MafiaSymbolMetadata):
            param_row = symbol_row.id
        elif isinstance(symbol_row, MafiaSymbolStateVar):
            param_row = "mafia_metadata."+h.family+"_"+symbol_row.id+"_"+str(nh)
        if isinstance(symbol_col, MafiaSymbolDecimal) or isinstance(symbol_col, MafiaSymbolHeaderField) or isinstance(symbol_col, MafiaSymbolMetadata):
            param_col = symbol_col.id
        elif isinstance(symbol_col, MafiaSymbolStateVar):
            param_col = "mafia_metadata."+h.family+"_"+symbol_col.id+"_"+str(nh)

        return (param_row, param_col)

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        table_name = "t_" + self.name
        action_name = "a_" + self.name
        self.p4object = P4Table(table_name, None, {}, [])
        tmp = mafia_syntax_parse_sketch(self.lambda_str)
        (hashfun, [lhs, [term, *expr]]) = tmp
        (name, h) = p4_program.state.lookup(hashfun)
        if not isinstance(h, HashFunction):
            raise MafiaSemanticError("Semantic error: %s" % h, "Supplied function in lambda parameter is not an hash")

        table_hash = self.compile_hash_function(p4_program, h)

        (sketch, row, col) = mafia_syntax_parse_sketch_ref(lhs)
        (name, sketch_obj) = p4_program.state.lookup(sketch)
        p4_program.headers.register_mafia_metadata_field([(self.name+'_lambda_val', sketch_obj.width)])
        tmp_lambda_result = "mafia_metadata."+self.name+"_lambda_val"

        nh = 0
        action = P4ActionBase(action_name, [])
        while nh < h.n:
            # param = "mafia_metadata."+row+"_"+str(nh) + "*" + str(sketch_obj.m) + "+" + "mafia_metadata."+col+"_"+str(nh)
            (param_row, param_col) = self.generate_sketch_index(h, row, col, nh)
            param = param_row  + "*" + str(sketch_obj.m) + "+" + param_col
            # action += P4ActionRegisterRead(action_name, "mafia_metadata."+sketch_obj.name, sketch_obj.name, param, [])
            (hashfun, [lhs, [term, *expr]]) = tmp
            symbol = mafia_syntax_interpret_symbol(term)
            if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
                action += P4ActionModifyField(action_name, tmp_lambda_result, symbol.id, [])
            elif isinstance(symbol, MafiaSymbolStateVar):
                (name, var) = p4_program.state.lookup(symbol.id)
                if isinstance(var, HashOutputVar):
                    action += P4ActionModifyField(action_name, tmp_lambda_result, "mafia_metadata."+h.family+"_"+var.name+"_"+str(nh), [])
                else:
                    action += P4ActionRegisterRead(action_name, tmp_lambda_result, name, "mafia_metadata.flow_index", [])
            elif isinstance(symbol, MafiaSymbolStateVarSketch):
                # p4_program.state.lookup(symbol.id)
                action += P4ActionRegisterRead(action_name, tmp_lambda_result, self.sketch.name, param, [])
            else:
                raise MafiaSemanticError("Semantic error: \"%s\"", "Invalid symbol in BloomFilter primitive")

            while (expr):
                [op, term, *rest] = unpack_list(expr)
                expr = rest
                symbol = mafia_syntax_interpret_symbol(term)
                if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
                    if op == "+":
                        action += P4ActionFieldAdd(action_name, tmp_lambda_result, symbol.id)
                    elif op == "-":
                        action += P4ActionFieldSub(action_name, tmp_lambda_result, symbol.id)
                    elif op == ">>":
                        action += P4ActionFieldShiftRight(action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                    elif op == "<<":
                        action += P4ActionFieldShiftLeft(action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                    elif op == "&":
                        action += P4ActionFieldBitAnd(action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                    elif op == "|":
                        action += P4ActionFieldBitOr(action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                    else:
                        raise TypeError("Unknown arithmetic operation %s" % op)
                elif isinstance(symbol, MafiaSymbolStateVar):
                    p4_program.state.lookup(symbol.id)
                    if isinstance(var, HashOutputVar):
                        action += P4ActionModifyField(action_name, tmp_lambda_result, "mafia_metadata."+h.family+"_"+var.name+"_"+str(nh), [])
                    else:
                        action += P4ActionRegisterRead(action_name, "mafia_metadata."+symbol.id, symbol.id, "mafia_metadata.flow_index", [])

                    if op == "+":
                        action += P4ActionFieldAdd(action_name, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    elif op == "-":
                        action += P4ActionFieldSub(action_name, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    elif op == ">>":
                        action += P4ActionFieldShiftRight(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    elif op == "<<":
                        action += P4ActionFieldShiftLeft(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    elif op == "&":
                        action += P4ActionFieldBitAnd(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    elif op == "|":
                        action += P4ActionFieldBitOr(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    else:
                        raise TypeError("Unknown arithmetic operation %s" % op)
            action += P4ActionRegisterWrite(action_name, sketch_obj.name, tmp_lambda_result, param, [])
            nh += 1
        self.p4object += action

        p4_program.add_command("table_set_default " + table_name + " " + action_name)
        if not ingress_egress_flag:
            return (table_hash + [self.p4object], [])
        else:
            return ([], table_hash + [self.p4object])

    def __repr__(self):
        return "Sketch_op [ %s, %s ]" % (self.lambda_str, self.sketch.name)

class BloomFilter_op(Operator):
    def __init__(self, name, lambda_f, bf):
        super(BloomFilter_op, self).__init__()
        self.name = name
        # self.lambda_f = lambda_f
        # self.lambda_str = get_lambda_source(self.lambda_f)
        self.lambda_str = lambda_f
        self.p4object = None
        if(not isinstance(bf, BloomFilter)):
            raise TypeError('BloomFilter_op works only on BloomFilter object types')
        self.bf = bf

    def on_next(self, item):
        # self.counter.add(self.lambda_f(item))
        # self.lambda_f(item)
        self._notify_next(item)
        return True

    def compile_hash_function(self, p4_program, h):
        hash_fun = p4_program.lookup_hash(h)
        return hash_fun.compile(p4_program, self.name, h.n, h.inputs, h.outputs)

    def generate_bf_index(self, h, index, nh):
        symbol_index = mafia_syntax_interpret_symbol(index)
        if isinstance(symbol_index, MafiaSymbolDecimal) or isinstance(symbol_index, MafiaSymbolHeaderField) or isinstance(symbol_index, MafiaSymbolMetadata):
            param_index = symbol_index.id
        elif isinstance(symbol_index, MafiaSymbolStateVar):
            param_index = "mafia_metadata."+h.family+"_"+symbol_index.id+"_"+str(nh)

        return param_index

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        table_name = "t_" + self.name
        action_name = "a_" + self.name
        self.p4object = P4Table(table_name, None, {}, [])
        tmp = mafia_syntax_parse_bf(self.lambda_str)
        (hashfun, [lhs, [term, *expr]]) = tmp
        (name, h) = p4_program.state.lookup(hashfun)
        if not isinstance(h, HashFunction):
            raise MafiaSemanticError("Semantic error: %s" % h, "Supplied function in lambda parameter is not an hash")

        table_hash = self.compile_hash_function(p4_program, h)

        (bf, index) = mafia_syntax_parse_bf_ref(lhs)
        (name, bf_obj) = p4_program.state.lookup(bf)
        p4_program.headers.register_mafia_metadata_field([(self.name+'_lambda_val', bf_obj.width)])
        tmp_lambda_result = "mafia_metadata."+self.name+"_lambda_val"

        nh = 0
        action = P4ActionBase(action_name, [])
        while nh < h.n:
            param = self.generate_bf_index(h, index, nh)
            (hashfun, [lhs, [term, *expr]]) = tmp
            symbol = mafia_syntax_interpret_symbol(term)
            if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
                action += P4ActionModifyField(action_name, tmp_lambda_result, symbol.id, [])
            elif isinstance(symbol, MafiaSymbolStateVar):
                (name, var) = p4_program.state.lookup(symbol.id)
                if isinstance(var, HashOutputVar):
                    action += P4ActionModifyField(action_name, tmp_lambda_result, 'mafia_metadata.'+name, [])
                else:
                    action += P4ActionRegisterRead(action_name, tmp_lambda_result, 'mafia_metadata.'+name, "mafia_metadata.flow_index", [])
            elif isinstance(symbol, MafiaSymbolStateVarBF):
                # p4_program.state.lookup(symbol.id)
                action += P4ActionRegisterRead(action_name, tmp_lambda_result, self.bf.name, param, [])
            else:
                raise MafiaSemanticError("Semantic error: \"%s\"", "Invalid symbol in BloomFilter primitive")

            while (expr):
                [op, term, *rest] = unpack_list(expr)
                expr = rest
                symbol = mafia_syntax_interpret_symbol(term)
                if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
                    if op == "+":
                        action += P4ActionFieldAdd(action_name, tmp_lambda_result, symbol.id)
                    elif op == "-":
                        action += P4ActionFieldSub(action_name, tmp_lambda_result, symbol.id)
                    elif op == ">>":
                        action += P4ActionFieldShiftRight(action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                    elif op == "<<":
                        action += P4ActionFieldShiftLeft(action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                    elif op == "&":
                        action += P4ActionFieldBitAnd(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    elif op == "|":
                        action += P4ActionFieldBitOr(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+symbol.id)
                    else:
                        raise TypeError("Unknown arithmetic operation %s" % op)
                elif isinstance(symbol, MafiaSymbolStateVar):
                    p4_program.state.lookup(symbol.id)
                    (name, var) = p4_program.state.lookup(symbol.id)
                    if isinstance(var, HashOutputVar):
                        name = name+"_"+str(nh)
                        action += P4ActionModifyField(action_name, tmp_lambda_result, "mafia_metadata."+h.family+"_"+var.name+"_"+str(nh), [])
                    else:
                        action += P4ActionRegisterRead(action_name, "mafia_metadata."+name, name, "mafia_metadata.flow_index", [])
                    if op == "+":
                        action += P4ActionFieldAdd(action_name, tmp_lambda_result, "mafia_metadata."+name)
                    elif op == "-":
                        action += P4ActionFieldSub(action_name, tmp_lambda_result, "mafia_metadata."+name)
                    elif op == ">>":
                        action += P4ActionFieldShiftRight(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                    elif op == "<<":
                        action += P4ActionFieldShiftLeft(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                    elif op == "&":
                        action += P4ActionFieldBitAnd(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                    elif op == "|":
                        action += P4ActionFieldBitOr(action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                    else:
                        raise TypeError("Unknown arithmetic operation %s" % op)
            action += P4ActionRegisterWrite(action_name, bf_obj.name, tmp_lambda_result, param, [])
            nh += 1
        self.p4object += action

        p4_program.add_command("table_set_default " + table_name + " " + action_name)
        if not ingress_egress_flag:
            return (table_hash + [self.p4object], [])
        else:
            return ([], table_hash + [self.p4object])

    def __repr__(self):
        return "BloomFilter_op [ %s, %s ]" % (self.lambda_str, self.bf.name)


class Tag(Operator):

    def __init__(self, name, lambda_f, field):
        super(Tag, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        self.lambda_str = lambda_f
        self.p4object = None
        # if(not isinstance(field, P4HeaderField)):
        #     raise TypeError('Tag works only on P4HeaderField object types')
        self.field = field

    def on_next(self, item):
        self._notify_next(item)
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        self.p4object = P4Table(self.table_name, None, {}, []) #+ P4ActionNoOp('_no_op')

        tmp = mafia_syntax_parse_tag(self.lambda_str)
        (term, *expr) = tmp

        (name, field) = p4_program.headers.lookup(self.field.split('.')[0], self.field.split('.')[1])

        p4_program.headers.register_mafia_metadata_field([(self.name+'_lambda_val', field.width)])
        tmp_lambda_result = "mafia_metadata."+self.name+"_lambda_val"

        nh = 0
        action = P4ActionBase(self.action_name, [])

        symbol = mafia_syntax_interpret_symbol(term)
        if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
            action += P4ActionModifyField(self.action_name, tmp_lambda_result, symbol.id, [])
        elif isinstance(symbol, MafiaSymbolStateVar):
            (name, var) = p4_program.state.lookup(symbol.id)
            action += P4ActionRegisterRead(self.action_name, tmp_lambda_result, name, "mafia_metadata.flow_index", [])
        elif isinstance(symbol, MafiaSymbolStateVarBF):
            (name, index) = mafia_syntax_parse_bf_ref(symbol.id)
            (bf_name, var) = p4_program.state.lookup(name)
            # action += P4ActionRegisterRead(action_name, tmp_lambda_result, name, index, [])
            for i in range(0,var.n):
                action += P4ActionRegisterRead(self.action_name, "mafia_metadata."+bf_name+"_serialized", bf_name, i, [])
                action += P4ActionFieldShiftLeft(self.action_name, "mafia_metadata."+bf_name+"_serialized", "mafia_metadata."+bf_name+"_serialized", var.n - 1 - i)
            
            action += P4ActionModifyField(self.action_name, tmp_lambda_result, "mafia_metadata."+bf_name+"_serialized", [])
        elif isinstance(symbol, MafiaSymbolStateVarSketch):
            (name, index_1, index_2) = mafia_syntax_parse_sketch_ref(symbol.id)
            (sketch_name, var) = p4_program.state.lookup(name)
            # action += P4ActionRegisterRead(action_name, tmp_lambda_result, name, index_1*symbol.m+index_2, [])

        while (expr):
            [op, term, *rest] = unpack_list(expr)
            expr = rest
            symbol = mafia_syntax_interpret_symbol(term)
            if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
                if op == "+":
                    action += P4ActionFieldAdd(self.action_name, tmp_lambda_result, symbol.id)
                elif op == "-":
                    action += P4ActionFieldSub(self.action_name, tmp_lambda_result, symbol.id)
                elif op == ">>":
                    action += P4ActionFieldShiftRight(self.action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                elif op == "<<":
                    action += P4ActionFieldShiftLeft(self.action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                elif op == "&":
                    action += P4ActionFieldBitAnd(self.action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                elif op == "|":
                    action += P4ActionFieldBitOr(self.action_name, tmp_lambda_result, tmp_lambda_result, symbol.id)
                else:
                    raise TypeError("Unknown arithmetic operation %s" % op)
            elif isinstance(symbol, MafiaSymbolStateVar):
                p4_program.state.lookup(symbol.id)
                (name, var) = p4_program.state.lookup(symbol.id)
                action += P4ActionRegisterRead(self.action_name, "mafia_metadata."+name, name, "mafia_metadata.flow_index", [])
                if op == "+":
                    action += P4ActionFieldAdd(self.action_name, tmp_lambda_result, "mafia_metadata."+name)
                elif op == "-":
                    action += P4ActionFieldSub(self.action_name, tmp_lambda_result, "mafia_metadata."+name)
                elif op == ">>":
                    action += P4ActionFieldShiftRight(self.action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                elif op == "<<":
                    action += P4ActionFieldShiftLeft(self.action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                elif op == "&":
                    action += P4ActionFieldBitAnd(self.action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                elif op == "|":
                    action += P4ActionFieldBitOr(self.action_name, tmp_lambda_result, tmp_lambda_result, "mafia_metadata."+name)
                else:
                    raise TypeError("Unknown arithmetic operation %s" % op)
        action += P4ActionModifyField(self.action_name, self.field, tmp_lambda_result, [])
        self.p4object += action

        self.configure_table_commands(p4_program)
        return self.on_compile_return(ingress_egress_flag)

    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])

    def configure_table_commands(self, p4_program):
        p4_program.add_command("table_set_default " + self.table_name + " " + self.action_name)

    def _compile(self):
        pass

    def __repr__(self):
        return "Tag [ %s ]" % self.field

class Stream_op(Operator):
    def __init__(self, name, stream):
        super(Stream_op, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        self.stream = stream
        self.p4object = None
        if(not isinstance(stream, Stream)):
            raise TypeError('Stream_op works only on Stream object types')

    def on_next(self, item):
        self._notify_next(item)
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        # self.p4object = P4Table(self.table_name, "standard_metadata.instance_type == " + str(self.stream.identifier), {}, []) #+ P4ActionNoOp('_no_op')
        self.p4object = P4Table(self.table_name, "standard_metadata.instance_type == 1", {}, [])
        return ([], [self.p4object])

    def _compile(self):
        pass

    def __repr__(self):
        return "Stream_op [ %s ]" % self.stream.name

class Duplicate(Operator):
    def __init__(self, name, stream):
        super(Duplicate, self).__init__()
        self.name = name
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        self.stream = stream
        self.p4object = None

    def on_next(self, item):
        self._notify_next(item)
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        self.p4object = P4Table(self.table_name, None, {}, []) \
                        + \
                        P4ActionDuplicate(self.action_name, str(self.stream.identifier), 'sample_copy_fields', [])
        self.configure_table_commands(p4_program)
        return self.on_compile_return(ingress_egress_flag)


    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            raise MafiaSemanticError("Semantic error", "Duplicate in egress pipeline not allowed")

    def configure_table_commands(self, p4_program):
        p4_program.add_command("table_set_default " + self.table_name + " " + self.action_name)
        p4_program.add_command("mirroring_add " + str(self.stream.identifier) + " 0")

    def _compile(self):
        pass

    def __repr__(self):
        return "Duplicate [ %s ]" % self.stream.name

class Collect(Operator):
    def __init__(self, name, endpoint_spec):
        super(Collect, self).__init__()
        self.name = name
        self.endpoint_spec = endpoint_spec
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        self.p4object = None
        if not self.endpoint_spec:
            raise MafiaSemanticError("Semantic error", "Missing endpoint specification in Collect primitive")

    def on_next(self, item):
        self._notify_next(item)
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        self.p4object = P4Table(self.table_name, None, {}, [])
        actions = list()
        actions += [P4ActionAddHeader("a_header_vlan", "vlan")]
        for spec in self.endpoint_spec:
            (lhs, rhs) = mafia_syntax_parse_assignment(spec)
            lhs_symbol = mafia_syntax_interpret_symbol(lhs)
            rhs_symbol = mafia_syntax_interpret_symbol(rhs)
            if not isinstance(lhs_symbol, MafiaSymbolHeaderField): #and not isinstance(rhs_symbol, MafiaSymbolConstant):
                raise MafiaSemanticError("Semantic error: %s" % spec, "Invalid endpoint specification parameter")
            actions += [P4ActionModifyField(self.action_name, lhs_symbol.id, rhs, [])]
        self.p4object += (reduce((lambda x, y: x + y), actions))
        self.configure_table_commands(p4_program)
        return self.on_compile_return(ingress_egress_flag)

    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])

    def configure_table_commands(self, p4_program):
        p4_program.add_command("table_set_default " + self.table_name + " " + self.action_name)

    def _compile(self):
        pass

    def __repr__(self):
        return "Collect [ %s ]" % (','.join(spec for spec in self.endpoint_spec))

class Random_op(Operator):
    def __init__(self, name, min_bound, max_bound):
        super(Random_op, self).__init__()
        self.name = name
        self.min_bound = min_bound
        self.max_bound = max_bound
        self.table_name = "t_" + self.name
        self.action_name = "a_" + self.name
        self.p4object = None

    def on_next(self, item):
        self._notify_next(item)
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        p4_program.headers.register_mafia_metadata_field([(self.name, 32)])
        self.p4object = P4Table("t_" + self.name, None, {}, []) \
                        + \
                        P4ActionHash(self.action_name, "mafia_metadata."+self.name, "uniform_probability_hash", self.max_bound, [])
        self.configure_table_commands(p4_program)
        return self.on_compile_return(ingress_egress_flag)

    def on_compile_return(self, flag):
        if not flag:
            return ([self.p4object], [])
        else:
            return ([], [self.p4object])

    def configure_table_commands(self, p4_program):
        p4_program.add_command("table_set_default " + self.table_name + " " + self.action_name)

    def _compile(self):
        pass

    def __repr__(self):
        return "Random_op [ {%d:%d} ]" % (self.min_bound, self.max_bound)
