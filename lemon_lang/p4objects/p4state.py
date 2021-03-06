
from .p4code import *
from .p4actions import *
from ..exception import *
from ..util.util import indent_str

class P4MeasurementState(object):
    def __init__(self):
        self.state_vars = dict()

    def add_p4statevariable(self, var):
        self.state_vars[var.name] = var

    def lookup(self, name):
        try:
            return (name, self.state_vars[name])
        except KeyError:
            for (_, state) in  self.state_vars.items():
                if isinstance(state, HashFunction):
                    for hash_output in state.outputs:
                        if hash_output.name == name:
                            return (state.family+'_'+hash_output.name, hash_output)

            raise MafiaSymbolLookupError("Semantic error: %s" % name, "Undefined variable")

    def to_string(self):
        return '\n'.join("%s" % s for name, s in self.state_vars.items())

    def __str__(self):
        return self.to_string()

class P4StateVariable(object):
    def __init__(self, name):
        self.name = name

    def declare_metadata(self):
        return []

    def validate(self):
        pass

    def read(self, action_name, target):
        pass

    def write(self, action_name, value):
        pass

    def to_string(self):
        return ""

    def __str__(self):
        return self.to_string()

class Counter(P4StateVariable):

    def __init__(self, name, n, width = -1):
        super(Counter, self).__init__(name)
        self.n = n
        self.width = width
        self.val = 0

    def read(self, action_name, target):
        return P4ActionRegisterRead('', target, self.name, "mafia_metadata.flow_index", [])

    def write(self, action_name, value):
        return P4ActionRegisterWrite('', self.name, "mafia_metadata.flow_index", value, [])

    def declare_metadata(self):
        return [(self.name, self.width)]

    def to_string(self):
        return p4register % (p4register_width % self.width,self.n,self.name)


class Timestamp(P4StateVariable):
    def __init__(self, name, n, width = 48):
        super(Timestamp, self).__init__(name)
        self.n = n
        self.width = width
        self.val = 0

    def read(self, action_name, target):
        return P4ActionRegisterRead(action_name, target, self.name, "mafia_metadata.flow_index", [])

    def write(self, action_name, value):
        return P4ActionRegisterWrite(action_name, self.name, value, "mafia_metadata.flow_index", [])

    def declare_metadata(self):
        return [(self.name, self.width)]

    def to_string(self):
        return p4register % (self.name, indent_str(p4register_width % self.width, 2) + '\n' + indent_str(p4register_count % self.n, 2))

class BloomFilter(P4StateVariable):
    def __init__(self, name, n, width = 32):
        super(BloomFilter, self).__init__(name)
        self.n = n
        self.width = width
        # if width == 1:
        #     self.width = n
        #     self.n = width

        self.val = 0

    def declare_metadata(self):
        return [(self.name, self.width), (self.name+"_serialized", self.n*self.width)]

    def to_string(self):
        return p4register % (self.name, indent_str(p4register_width % self.width, 2) + '\n' + indent_str(p4register_count % self.n, 2))

class Sketch(P4StateVariable):
    def __init__(self, name, n, m, width = 32):
        super(Sketch, self).__init__(name)
        self.n = n
        self.m = m
        self.width = width
        self.val = 0

    def declare_metadata(self):
        return [(self.name, self.width)]
        # return [(self.name, self.width), (self.name+"_serialized", self.n*self.m*self.width)]

    def to_string(self):
        return p4register % (self.name, indent_str(p4register_width % self.width, 2) + '\n' + indent_str(p4register_count % (self.n * self.m), 2))

class Random(P4StateVariable):
    def __init__(self, name, identifier):
        super(Random, self).__init__(name)
        self.identifier = identifier

class Stream(P4StateVariable):
    def __init__(self, name, identifier):
        super(Stream, self).__init__(name)
        self.identifier = identifier

class HashFunction(P4StateVariable):
    def __init__(self, name, family, n, inputs, outputs):
        super(HashFunction, self).__init__(name)
        self.n = n
        self.family = family
        self.inputs = inputs
        self.outputs = outputs
        self.val = 0
        self.validate()

    def validate(self):
        if(self.n <= 0 or self.n >=25):
            raise MafiaSemanticError("Semantic error in hash_set %s definition" % self.name, "Parameter \"n\" must be a positive, non-zero value")
        if(not self.inputs):
            raise MafiaSemanticError("Error in hash_set %s definition" % self.name, "Input fields of the hash function cannot be empty")
        if(not self.outputs):
            raise MafiaSemanticError("Error in hash_set %s definition" % self.name, "Output generated by the hash function cannot be empty")

    def declare_metadata(self):
        ret = []
        h = 0
        while h < self.n:
            for o in self.outputs:
                (name, width) = o.declare_metadata()
                ret += [(self.family + '_' + name+'_'+str(h), width)]
            h += 1
        return ret

    def to_string(self):
        return ""

class HashOutputVar(P4StateVariable):
    def __init__(self, name, width = -1):
        super(HashOutputVar, self).__init__(name)
        self.width = width
        self.val = 0

    def declare_metadata(self):
        return (self.name, self.width)

    def to_string(self):
        return ""

class HashFunctionImpl(P4StateVariable):
    def __init__(self, name, algorithm, inputs, output):
        super(HashFunctionImpl, self).__init__(name)
        self.algorithm = algorithm
        self.inputs = inputs
        self.output = output

    def to_string(self):
        return p4hash % (self.name, indent_str(p4hash_input % ("; ".join(f for f in self.inputs)) + '\n' + (p4hash_algorithm % self.algorithm) + '\n' + (p4hash_output % self.output), 2))

class HashFieldList(P4StateVariable):
    def __init__(self, name, fields):
        super(HashFieldList, self).__init__(name)
        self.fields = fields

    def to_string(self):
        return p4field_list % (self.name, indent_str("; ".join(f for f in self.fields), 2))
