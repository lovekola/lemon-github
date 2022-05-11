
# from abc import ABCMeta, abstractmethod
from anytree    import NodeMixin
from .p4code    import *
from .p4state   import *
from .p4headers import *
from .p4actions import *
from ..util.log import *

_SCOPE_TYPE = ['PARALLEL', 'SEQUENTIAL']


class P4Program(object):

    def __init__(self, tables = {}, hashes = {}, actions = {}, registers = {}, metadata = {}, tail = {}, head = {}, define = {}, struct ={}):
        self.state = P4MeasurementState()
        self.headers = P4Headers()
        self.tables = dict(tables)
        self.hashes = dict(hashes)
        self.actions = dict(actions)
        self.registers = dict(registers)
        self.metadata = dict(metadata)
        self.tail = dict(tail)
        self.head = dict(head)
        self.define = dict(define)
        self.struct = dict(struct)
        self.duration = None
        self.window = None
        self.commands = list()
        self.ctrl_loop = ''
        self.egress_loop = ''
        self.ingress_loop = ''

    def register_hash(self, h):
        self.hashes[h.name] = h

    def lookup_hash(self, h):
        hash_fun = None
        try:
            hash_fun = self.hashes[h.family]
        except:
            raise MafiaSemanticError("Semantic error: %s" % h.family, "Hash function family is not defined")
        return hash_fun

    def register_state(self, s):
        self.state.add_p4statevariable(s)
        state_metadata = s.declare_metadata()
        if state_metadata: self.headers.register_mafia_metadata_field(state_metadata)

    def add_command(self, command):
        self.commands.append(command)

class P4Scope(NodeMixin):

    def __init__(self, parent = None):
        self._parent = parent
        self.p4object = None

class P4ObjectASTBase(object):
    def __init__(self, name, parent = None):
        self.name = name
        self.logger = logging.getLogger(__name__)
        self.objects = list()

    def generate_code(self, p4_program, p4_scope, indent = 0):
        pass

    def to_string(self):
        pass

    def __str__(self):
        return self.to_string()

class P4ObjectAST(P4ObjectASTBase, NodeMixin):

    def __init__(self, name, parent = None):
        self.name = name
        self.parent = parent

    def set_parent(self, parent):
        if parent is None:
            raise TypeError
        self.parent = parent

    def inner_child(self):
        if(not self.children):
            return self
        else:
            cur = self.children[len(self.children)-1]
            while(cur is not None and cur.children):
                cur = cur.children[len(cur.children)-1]
            return cur

    def generate_code(self, p4_program, p4_scope, indent = 0):
        return '\n\n'.join("%s" % c.compile() for c in self.children)

    def to_string(self):
        s = ""
        for o in self.children:
            s += o.to_string() + "\n\n"
        return s

    def __str__(self):
        return self.to_string()

class P4Table(P4ObjectAST):

    count = 0
    def __init__(self, name, condition, keys, actions, type, entry=[], parent = None):
        super(P4Table, self).__init__(name, parent)
        self.table_name = name
        self.condition = condition
        self.keys = keys
        self.actions = actions
        self.type = type
        self.entry = entry
        P4Table.count += 1
        # self.add_action('_no_op;')

    def add_action(self, action):
        self.actions.append(action)

    def generate_code(self, p4_program, p4_scope, indent = 0):
        logging.debug("%s: compile", self.name)
        entry = ""
        for i in self.entry:
            entry += i[0] + '\t' + i[1] + '\t'
        if(self.type == "Match"):
            if(self.children[0].type == "Count"):
                p4_program.add_command("add_entry" + '\t' + self.table_name + '\t' + entry + "a_set_flow_index")
            elif(self.children[0].type == "Reduce"):
                p4_program.add_command("add_entry" + '\t' + self.table_name + '\t' + entry + '\t' + "a_compute_hash_bf")
            elif(self.children[0].type == "Sketch" or self.children[0].type == "Sketch-shadow"):
                p4_program.add_command("add_entry" + '\t' + self.table_name + '\t' + entry + '\t' + "a_compute_hash_sketch")
            
            # for Compatibility, add define and metadata
            if not("counter_meta" in p4_program.metadata):
                p4_program.metadata["counter_meta"] = "bit<32> register_index;"
            if not("BF_HASH_KEY" in p4_program.define):
                p4_program.define["BF_HASH_KEY"] = "#define BF_HASH_KEY\t" + '{' + "hdr.ipv4.src_addr" + '}'
                p4_program.hashes["bf_hash1"] = "Hash<bit<10>>(HashAlgorithm_t.CRC8) bf_hash;"
                p4_program.metadata["bf_meta1"] = "bit<10>\tbf_hash;"
            if not("SKETCH_HASH_KEY" in p4_program.define):
                p4_program.define["SKETCH_HASH_KEY"] = "#define SKETCH_HASH_KEY\t" + '{' + "hdr.ipv4.src_addr" + '}'
                p4_program.metadata["sketch_topk_hash1"] = "bit<4>\tsketch_topk_hash1;"
                p4_program.hashes["sketch_topk_hash"] = "Hash<bit<4>>(HashAlgorithm_t.CRC8) sketch_topk_hash;"


        p4_program.tables[self.name] = self.to_string()
        for a in self.actions:
            p4_program.actions[a.name] = a.to_string() 
        children_str = '\n\n'.join("%s" % c.generate_code(p4_program, p4_scope, indent) for c in self.children)# super.compile(p4_program)

        if(self.condition is not None):
            if(self.keys or self.actions):
                ctrl_loop = indent_str(p4ctrl_cond % (self.condition, indent_str( p4table_apply % self.name, indent) + ';' + children_str) , indent)
            else:
                ctrl_loop = indent_str(p4ctrl_cond % (self.condition, children_str), indent)
        else:
            if(self.children):
                if self.keys:
                    if(self.children[0].type == "Count"):
                        ctrl_loop = indent_str((p4table_apply_with_children % self.name) + (p4table_block % indent_str(p4table_hit_count % children_str, indent)), indent)
                    elif(self.children[0].type == "Reduce"):
                        ctrl_loop = indent_str((p4table_apply_with_children % self.name) + (p4table_block % indent_str(p4table_hit_reduce % children_str, indent)), indent)
                    elif(self.children[0].type == "Sketch" or self.children[0].type == "Sketch-shadow"):
                        ctrl_loop = indent_str((p4table_apply_with_children % self.name) + (p4table_block % indent_str(p4table_hit_sketch % children_str, indent)), indent)
                    elif(self.children[0].type == "Mirror"):
                        ctrl_loop = indent_str((p4table_apply_with_children % self.name) + (p4table_block % indent_str(p4table_hit_mirror % children_str, indent)), indent)
                    else:
                        ctrl_loop = ""

                else: 
                    ctrl_loop = indent_str((p4table_apply_with_children % self.name) + (p4table_block % indent_str(p4table_miss % children_str, indent)), indent)
            else:
                if(self.type == "Reduce"):
                    ctrl_loop = indent_str((p4table_apply_reduce % self.name), indent)
                elif(self.type == "Sketch"):
                    ctrl_loop = indent_str((p4table_apply_sketch % self.name), indent)
                elif(self.type == "Sketch-shadow"):
                    ctrl_loop = indent_str((p4table_apply_sketch_shadow % self.name), indent)
                else:
                    ctrl_loop = indent_str((p4table_apply % self.name) + ';', indent)
        
        return ctrl_loop

    def to_string(self):
        if(not self.keys):
            return p4table % (self.name, "%s%s" % \
                ( "" if (not self.keys) else indent_str(p4table_keys % indent_str('\n'.join("%s: %s;" % (f, m) for f,m in self.keys.items()),4), 4) + "\n", \
                    indent_str(p4table_actions_without_key % (';'.join("%s" % a.name for a in self.actions) + ';', self.actions[0].name), 4) \
                ))
        elif(self.keys):
            return p4table % (self.name, "%s%s" % \
                ( "" if (not self.keys) else indent_str(p4table_keys % indent_str('\n'.join("%s: %s;" % (f, m) for f,m in self.keys.items()),4), 4) + "\n", \
                    indent_str(p4table_actions % (';'.join("%s" % a.name for a in self.actions) + ';'), 4) \
                ))
        else:
            return ""

    def __str__(self):
        return self.to_string()

    def __add__(self, other):
        res = None
        if(isinstance(other, P4Table)):
            res = P4Table(self.name + '_' + other.name, self.condition + '&&' + other.condition, {**self.keys, **other.keys}, self.actions + other.actions)
        elif(isinstance(other, P4ActionBase) ): #or isinstance(other, P4ActionBundle)):
            res = P4Table(self.name, self.condition, {**self.keys}, self.actions + [other], self.type, self.entry)
        else:
            raise RuntimeError
        return res
