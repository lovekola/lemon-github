
from anytree    import NodeMixin
from .p4hash    import *
from .p4state   import *
from .p4syntax  import *
from ..util.util import *

class MafiaAST(NodeMixin):
    def __init__(self, name, parent = None):
        self.id = name
        self.parent = parent

    def set_parent(self, parent):
        if parent is None:
            raise TypeError
        self.parent = parent

    def build_ast(self):
        pass

    def compile(self, p4_program):
        pass


class MafiaSymbol(MafiaAST):
    def __init__(self, symbol):
        super(MafiaSymbol, self).__init__(symbol)

class MafiaSymbolConstant(MafiaSymbol):
    def __init__(self, symbol):
        super(MafiaSymbolConstant, self).__init__(symbol)

class MafiaSymbolDecimal(MafiaSymbolConstant):
    def __init__(self, symbol):
        super(MafiaSymbolDecimal, self).__init__(symbol)

class MafiaSymbolBinary(MafiaSymbolConstant):
    def __init__(self, symbol):
        super(MafiaSymbolBinary, self).__init__(symbol)

class MafiaSymbolHex(MafiaSymbolConstant):
    def __init__(self, symbol):
        super(MafiaSymbolHex, self).__init__(symbol)

class MafiaSymbolStateVar(MafiaSymbol):
    def __init__(self, symbol):
        super(MafiaSymbolStateVar, self).__init__(symbol)

class MafiaSymbolStateVarBF(MafiaSymbol):
    def __init__(self, symbol):
        super(MafiaSymbolStateVarBF, self).__init__(symbol)

class MafiaSymbolStateVarSketch(MafiaSymbol):
    def __init__(self, symbol):
        super(MafiaSymbolStateVarSketch, self).__init__(symbol)

class MafiaSymbolAggregateFunction(MafiaSymbol):
    def __init__(self, symbol):
        super(MafiaSymbolAggregateFunction, self).__init__(symbol)

class MafiaSymbolHeaderField(MafiaSymbol):
    def __init__(self, symbol):
        super(MafiaSymbolHeaderField, self).__init__(symbol)

class MafiaSymbolMetadata(MafiaSymbol):
    def __init__(self, symbol):
        super(MafiaSymbolMetadata, self).__init__(symbol)


class LemonASTCounter(MafiaAST):
    def __init__(self, name, counter_op):
        super(LemonASTCounter, self).__init__(name)
        self.counter_op = counter_op
        self.build_ast()

    def build_ast(self):
        (lhs, rhs) = mafia_syntax_parse_counter(self.counter_op)# 等号隔开的左右两部分
        lhs_symbol = mafia_syntax_interpret_symbol(lhs) # 返回左值的类型
        expr = MafiaASTArithmeticExpr(self.id, rhs)
        # 生成两个子节点，类型分别是左右两部分代表的class
        lhs_symbol.set_parent(self)
        expr.set_parent(self)

    def compile(self, p4_program):
        lhs = self.children[0] # p4ast.MafiaSymbolStateVar
        rhs = self.children[1] # p4ast.MafiaASTArithmeticExpr
        
        actions = []
        actions += rhs.compile(p4_program)


        (lambda_flag, counter, *rest) = mafia_syntax_parse_arithmetic(self.counter_op)
        for i in rest:
            if(i != counter):
                if(i == '+' or i =='-'):
                    op =i
                else:
                    num = i
        width = 32
        p4_program.registers[counter] = p4register % (width, 2, 0, counter)
        p4_program.registers[counter+"_op"] = p4RegisterActionCounter % (width, width, counter, counter, width, width, op, num)
        p4_program.add_command("read_register" + '\t' + counter + '\t' + "1")
        actions = [P4ActionRegisterAccess(counter, counter)]
        return actions


class MafiaASTCounter(MafiaAST):
    def __init__(self, name, counter_op):
        super(MafiaASTCounter, self).__init__(name)
        self.counter_op = counter_op
        self.build_ast()

    def build_ast(self):
        (lhs, rhs) = mafia_syntax_parse_counter(self.counter_op)# 等号隔开的左右两部分
        lhs_symbol = mafia_syntax_interpret_symbol(lhs) # 返回左值的类型
        (term, *rest) = mafia_syntax_parse_arithmetic(rhs)
        expr = MafiaASTArithmeticExpr(self.id, rhs)

        # 生成两个子节点，类型分别是左右两部分代表的class
        lhs_symbol.set_parent(self)
        expr.set_parent(self)

    def compile(self, p4_program):
        lhs = self.children[0] # p4ast.MafiaSymbolStateVar
        rhs = self.children[1] # p4ast.MafiaASTArithmeticExpr
        
        actions = []
        actions += rhs.compile(p4_program)

        tmp_lambda_result = "mafia_metadata."+self.id+"_lambda_val"
        if not isinstance(lhs, MafiaSymbolStateVar):
            raise MafiaSemanticError("Semantic error: %s" % lhs.id, "Left-hand side of expression in Counter primitive is not referenceable")
        (_, var) = p4_program.state.lookup(lhs.id)

        actions += [P4ActionRegisterWrite('', lhs.id, tmp_lambda_result, "mafia_metadata.flow_index", [])]

        p4_program.headers.register_mafia_metadata_field([(self.id+'_lambda_val', var.width)])
        return actions

class MafiaASTAggregate(MafiaAST):
    def __init__(self, name, aggregate_op):
        super(MafiaASTAggregate, self).__init__(name)
        self.aggregate_op = aggregate_op
        self.build_ast()

    def build_ast(self):
        
        (fun, hashset, expr) = mafia_syntax_parse_aggregate(self.aggregate_op)
        (lhs, bool_op, rhs) = mafia_syntax_parse_boolean(expr)
        hash_ast = MafiaASTHash(self.id, hashset)
        hash_ast.set_parent(self)

        


    def compile(self, p4_program):
        actions = []

        (fun, hashset, expr) = mafia_syntax_parse_aggregate(self.aggregate_op)

        actions += [P4ActionRegisterWrite('', lhs.id, tmp_lambda_result, "mafia_metadata.flow_index", [])]

        p4_program.headers.register_mafia_metadata_field([(self.id+'_lambda_val', var.width)])

        p4_program.headers.register_mafia_metadata_field([(self.id+'_'+self.func, 32)])
        if self.func == 'min':
            condition = ''
            # for i in self.items:

        if self.func == 'max':
            pass
        if self.func == 'sum':
            pass
        if self.func == 'avg':
            pass
        if self.func == 'any':
            pass
        if self.func == 'all':
            pass

        return actions

class MafiaASTHash(MafiaAST):
    def __init__(self, name, hashset):
        super(MafiaASTHash, self).__init__(name)
        self.hashset = hashset
        self.build_ast()

    def build_ast(self):
        pass


    def compile(self, p4_program):
        (_, h) = p4_program.lookup_hash(self.hashset)
        return h.compile(p4_program, self.id, h.n, h.inputs, h.outputs)

class MafiaASTArithmeticExpr(MafiaAST):
    def __init__(self, name, expression):
        super(MafiaASTArithmeticExpr, self).__init__(name)
        self.expression = expression
        # self.op = None
        self.build_ast()

    def build_ast(self):
        pass

    def compile(self, p4_program):
        tmp_lambda_result = "mafia_metadata."+self.id+"_lambda_val"
        actions = []

        (term, *rest) = mafia_syntax_parse_arithmetic(self.expression)
        symbol = mafia_syntax_interpret_symbol(term)
        # print("@@@@@@@@@@@@@@@@@@@@@@")
        # print(term)# 1
        # print(rest)# ['+', 'packet_counter']
        # print(symbol) # MafiaSymbolDecimal object
        if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
            actions += [P4ActionModifyField('', tmp_lambda_result, symbol.id, [])]
        elif isinstance(symbol, MafiaSymbolStateVar):
            actions += [P4ActionRegisterRead('', "mafia_metadata."+symbol.id, symbol.id, "mafia_metadata.flow_index", [])]
            actions += [P4ActionModifyField('', tmp_lambda_result, "mafia_metadata."+symbol.id, [])]

        while rest:
            [op, term, *rest] = unpack_list(rest)#op:"+"  term:"packet_counter"
            # print("@@@@@@@@@@@@@@@@@@@@@@")
            # print(op)
            # print(term)
            expr = rest
            symbol = mafia_syntax_interpret_symbol(term)

            if isinstance(symbol, MafiaSymbolDecimal) or isinstance(symbol, MafiaSymbolHeaderField) or isinstance(symbol, MafiaSymbolMetadata):
                symbol_value = symbol.id
            elif isinstance(symbol, MafiaSymbolStateVar):
                # p4_program.state.lookup(symbol.id)
                actions += [P4ActionRegisterRead('', "mafia_metadata."+symbol.id, symbol.id, "mafia_metadata.flow_index", [])]
                symbol_value = "mafia_metadata."+symbol.id

            if op == "+":
                actions += [P4ActionFieldAdd('', tmp_lambda_result, symbol_value)]
                #P4ActionFieldAdd.__init__(name,targrt,value)
            elif op == "-":
                actions += [P4ActionFieldSub('', tmp_lambda_result, symbol_value)]
            elif op == ">>":
                actions += [P4ActionFieldShiftRight('', tmp_lambda_result, tmp_lambda_result, symbol_value)]
            elif op == "<<":
                actions += [P4ActionFieldShiftLeft('', tmp_lambda_result, tmp_lambda_result, symbol_value)]
            elif op == "&":
                actions += [P4ActionFieldBitAnd('', tmp_lambda_result, tmp_lambda_result, symbol_value)]
            elif op == "|":
                actions += [P4ActionFieldBitOr('', tmp_lambda_result, tmp_lambda_result, symbol_value)]
            else:
                raise MafiaSyntaxError("Syntax error: %s" % op, "Unknown arithmetic operation")
        
        return actions

def mafia_syntax_interpret_symbol(symbol):
    regex = re.match( regex_numeric_const, symbol, re.M|re.I)
    if(not regex):
        regex = re.match( regex_metadata, symbol, re.M|re.I)
        if(not regex):
            regex = re.match( regex_header_field, symbol, re.M|re.I)
            if(not regex):
                regex = re.match( regex_var_sketch, symbol, re.M|re.I)
                if(not regex):
                    regex = re.match( regex_var_bf, symbol, re.M|re.I)
                    if(not regex):
                        regex = re.match( regex_aggregate, symbol, re.M|re.I)
                        if(not regex):
                            regex = re.match( regex_var, symbol, re.M|re.I)
                            if(not regex):
                                raise MafiaSemanticError("Semantic error: identifier %s" % symbol, "undefined symbol.")
                            else:
                                return MafiaSymbolStateVar(symbol)
                        else:
                            return MafiaSymbolAggregateFunction(symbol)
                    else:
                        return MafiaSymbolStateVarBF(symbol)
                else:
                    return MafiaSymbolStateVarSketch(symbol)
            else:
                return MafiaSymbolHeaderField(symbol)
        else:
            return MafiaSymbolMetadata(mafia_syntax_sanitize_metadata(symbol))
            # return MafiaSymbolMetadata('standard_metadata.'+regex.group(1))
    else:
        if(re.match( regex_binary, symbol, re.M|re.I)): return MafiaSymbolBinary(symbol)
        if(re.match( regex_hexadecimal, symbol, re.M|re.I)): return MafiaSymbolHex(symbol)
        if(re.match( regex_decimal, symbol, re.M|re.I)): return MafiaSymbolDecimal(symbol)
        else: raise MafiaSyntaxError("Syntax error: %s" % symbol, "Unknown numeric constant")
        # return MafiaSymbolDecimal(symbol)


