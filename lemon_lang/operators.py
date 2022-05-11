
from .util.util import repr_plus, traverse
from .p4objects.p4objects import *
from .observer import Observable, Observer

class Operator(Observable, Observer):

    def __add__(self, ob):
        """
        The parallel composition operator.

        :param ob: the Policy to the right of the operator
        :type ob: Policy
        :rtype: Parallel
        """
        p = Parallel([self, ob])
        return p

    def __rshift__(self, ob):
        """
        The sequential composition operator.

        :param pol: the Policy to the right of the operator
        :type pol: Policy
        :rtype: Sequential
        """
        s = Sequential([self, ob])
        return s

    def name(self):
        return self.__class__.__name__

    def __repr__(self):
        return "%s : %d" % (self.name(), id(self))

    def _compile(self):
        pass

    def get_combinator_type(self):
        return None


class Combinator(Operator):
    """
    Abstract class for policy combinators.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """

    ### init : List Policy -> unit
    def __init__(self, observers=[]):
        super(Combinator, self).__init__()
        self.observers = list(observers)
        self.p4object = None
        self.duration = None
        self.window = None

    def on_next(self, item):
        self._next(item)

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        pass

    def get_combinator_type(self):
        if(isinstance(self, Parallel)):
            return 'Parallel'
        elif(isinstance(self, Sequential)):
            return 'Sequential'
        else:
            raise TypeError

    def link(self, ast, ast_tmp, flag):
        if(not ast):
            ast = ast + ast_tmp
        else:
            if(not flag):
                for t in ast_tmp:
                    if isinstance(self, Parallel):
                        ast = ast + ast_tmp
                    elif isinstance(self, Sequential):
                        t.set_parent(ast[(len(ast)-1)].inner_child())
                    else:
                        raise RuntimeError
                    # t.set_parent(p4trees[(len(p4trees)-1)])
            else:
                if(self.get_combinator_type() == 'Sequential'):
                    bo = ast[(len(ast)-1)].inner_child()
                    for t in ast_tmp:
                        # t.set_parent(p4trees[(len(p4trees)-1)].children[0])
                        t.set_parent(bo)
                elif(self.get_combinator_type() == 'Parallel'):
                    ast = ast + ast_tmp
                else:
                    raise TypeError
        return ast

    def __repr__(self):
        return "%s:\n%s" % (self.name(), repr_plus(self.observers))

    def __eq__(self, other):
        return ((self.__class__ == other.__class__) and (self.observers == other.observers))

class Parallel(Combinator):
    """
    Combinator for several policies in Parallel.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """

    def __new__(cls, observers=[]):
        # Hackety hack.
        if not observers:
            raise ValueError("No observers")
        else:
            rv = super().__new__(Parallel)
            rv.__init__(observers)
            return rv

    def __init__(self, observers=[]):
        if not observers:
            raise TypeError
        super(Parallel, self).__init__(observers)

    def __add__(self, ob):
        return Parallel(self.observers + [ob])

    def on_next(self, item):
        ret = False
        for o in self.observers:
            ret |= o.on_next(item)
        return ret

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        # self.p4object = P4ObjectAST(self.get_combinator_type(), p4_ast)
        (ingress, egress) = (list(), list())
        for o in self.observers:
            (ingress_tmp, egress_tmp) = o.on_compile(root, p4_program, ingress_egress_flag, self.get_combinator_type())
            ingress = self.link(ingress, ingress_tmp, isinstance(o, (Parallel, Sequential)))
            egress = self.link(egress, egress_tmp, isinstance(o, (Parallel, Sequential)))
            # if egress:
            #     ingress_egress_flag = 1  
        if(self.duration):
            p4_program.duration = self.duration
        if(self.window):
            p4_program.window = self.window

        return (ingress, egress)

    def _compile(self):
        pass

class Sequential(Combinator):
    """
    Combinator for several policies in sequence.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """

    def __new__(cls, observers=[]):
        # Hackety hack.
        if not observers:
            raise ValueError("No observers")
        else:
            rv = super().__new__(Sequential)
            rv.__init__(observers)
            return rv

    def __init__(self, observers=[]):
        if not observers:
            raise TypeError
        super(Sequential, self).__init__(observers)

    def __rshift__(self, ob):
        return Sequential(self.observers + [ob])

    def on_next(self, item):
        for o in self.observers:
            if not o.on_next(item):
                break
        return True

    def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
        # self.p4object = P4ObjectAST(self.get_combinator_type(), p4_ast)
        (ingress, egress) = (list(), list())
        for o in self.observers:
            (ingress_tmp, egress_tmp) = o.on_compile(root, p4_program, ingress_egress_flag, self.get_combinator_type())
            ingress = self.link(ingress, ingress_tmp, isinstance(o, (Parallel, Sequential)))
            egress = self.link(egress, egress_tmp, isinstance(o, (Parallel, Sequential)))
            if egress:
                ingress_egress_flag = 1
        
        if(self.duration):
            p4_program.duration = self.duration
        if(self.window):
            p4_program.window = self.window
        
        return (ingress, egress)

    def _compile(self):
        pass
