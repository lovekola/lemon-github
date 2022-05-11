import argparse
import importlib
import logging
import os
import errno

from lemon_lang.operators              import *
from lemon_lang.primitives             import *
from lemon_lang.p4objects.p4hash       import *
from lemon_lang.p4objects.p4headers    import *
from lemon_lang.p4objects.p4objects    import *
from lemon_lang.p4objects.p4state      import *
from lemon_lang.util.util import  indent_str

_LOG_LEVEL_STRINGS = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']

# int [50,40,30,20,10]
def _log_level(log_level_string):
    log_level_int = getattr(logging, log_level_string, logging.INFO)
    return log_level_int

def get_arg():
    parser = argparse.ArgumentParser(description="Lemon-P4 Compiler")
    parser.add_argument('--measurement', '-u', 
        type=str, help='Measurement to be compiled.', 
        required=True, 
        default=None, 
        dest='measurement', 
        nargs='?')
    parser.add_argument('--log', '-l', 
        type=_log_level, 
        help='Logging level. {0}'.format(_LOG_LEVEL_STRINGS), 
        required=False, 
        default='DEBUG', 
        dest='loglevel', 
        #choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'],
        nargs='?')    
    return parser

def create_build_dir(task_object):
    name = task_object.__name__
    directory = 'build/'+name.replace('.', '/')
    try:
        os.makedirs(directory)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise Exception("Unknown error!")
        else:
            pass
    build_dir = directory
    common_dir = directory + "/common"
    try:
        os.makedirs(common_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise Exception("Unknown error!")
        else:
            pass
    p4_filename = directory+'/'+name.split('.')[1]+'.p4'
    cmd_filename = directory+'/'+'commands.txt'

    return (build_dir, common_dir, p4_filename, cmd_filename)

def generate_header(p4_program):
    p4_program.headers.declare_ethernet()
    #p4_program.headers.declare_vlan()
    p4_program.headers.declare_ipv4()
    #p4_program.headers.declare_udp()
    p4_program.headers.declare_tcp()
    #p4_program.headers.declare_icmp()

    p4_program.headers.declare_metadata()
    p4_program.headers.declare_forwarding_metadata()
    p4_program.headers.declare_mafia_metadata()
    #p4_program.headers.declare_rng_fake_metadata()
    p4_program.headers.declare_header()

    
def generate_state(p4_program,example):
    example_vars = vars(example)# return a dict() {key:value}
    print()
    
    #logging.info(example_vars)
    for var in example_vars:# var is key of the dict
        #print(var)
        s = example_vars[var] # s is value of the dict
        #print(s)
        if isinstance(s, P4StateVariable):
            p4_program.register_state(s) 

if __name__ == '__main__':
#  argparse
    parser = get_arg()
    args = parser.parse_args()

#  logging
    log_format ='%(funcName)-12s: %(name)-12s: Line %(lineno)-4d - %(levelname)-8s - %(message)s'
    logging.basicConfig(level=args.loglevel, format=log_format)
    logger = logging.getLogger(__name__)
    logger.info("hello")
    
#  importlib    
    example = importlib.import_module('tasks.'+args.measurement)
    name = example.__name__
    task = example.measurement
    logging.debug(name)
    print(type(task))
    print(task)
    print(task.duration)

#  compile
    (build_dir, sub_dir, p4_filename, cmd_filename) = create_build_dir(example)
    p4_file = open(p4_filename,"w")
    p4headers_file = open(sub_dir+'/headers.p4', "w")
    p4util_file = open(sub_dir+'/util.p4', "w")
    bf_runtime_port = open(sub_dir+'/ports.py', "w")
    bf_runtime_table = open(sub_dir+'/table.py', "w")
    bf_runtime_lemon = open(sub_dir+'/lemon.py', "w")
    bf_runtime_test = open(build_dir+'/test.py', "w")
    bf_runtime_test_local = open(build_dir+'/test_local.py', "w")
    cmd_file = open(cmd_filename,"w")

    p4_ast_root = P4ObjectAST("ingress")
    p4_program = P4Program()

#   headers and states
    generate_header(p4_program)
    generate_state(p4_program,example)
    
    # print(type(task))
    # print(len(task.observers))
    # print(task.observers[0])
    # print(len(task.observers[0].observers))


    logging.debug("Compiling...")

    print("task.on_compile() Start")
    # transfer AST to P4Object tree
    (p4_ast_in, p4_ast_out) = task.on_compile(p4_ast_root, p4_program, 0, task.get_combinator_type())
    #def on_compile(self, root, p4_program, ingress_egress_flag, parent_type):
    print("task.on_compile() Down")

    # print(type(p4_ast_in)) # list
    # print(len(p4_ast_in)) #
    # print(type(p4_ast_in[0]))
    # print(p4_ast_in[0].name) #
    # print(len(p4_ast_in[0].children)) #
    # print(p4_ast_in[0].children[0].name) #
    
    head_code = ""
    for a,b in p4_program.head.items():
        head_code += (b + '\n')

    tail_code = ""
    for a,b in p4_program.tail.items():
        tail_code += (b + '\n')

    print("P4Table.generate_code() in p4_program")
    p4_program.ingress_loop = p4ctrl_in % (indent_str(head_code,4), '\n'.join(p.generate_code(p4_program, None, 4) for p in p4_ast_in), indent_str(tail_code,4))
    p4_program.egress_loop = p4ctrl_out % ('\n'.join(p.generate_code(p4_program, None, 4) for p in p4_ast_out))


# output: bf_runtime related
    logging.debug("bf-runtime files:\n")
    with open('./lemon_lang/util/ports.py', 'r') as f:
        bf_runtime_port.write(f.read())
    with open('./lemon_lang/util/table.py', 'r') as f:
        bf_runtime_table.write(f.read())
    with open('./lemon_lang/util/lemon.py', 'r') as f:
        bf_runtime_lemon.write(f.read())
        
    with open('./lemon_lang/util/test.py', 'r') as f:
        bf_runtime_test.write(f.read())
    with open('./lemon_lang/util/test_local.py', 'r') as f:
        bf_runtime_test_local.write(f.read())

# output:header
    logging.debug("Header definitions:\n")
    #print(p4_program.headers)
    # p4headers_file.write("\n#include <tofino/intrinsic_metadata.p4>\n\n")
    # p4headers_file.write(p4_program.headers.to_string() + "\n")
    with open('./lemon_lang/util/headers.p4', 'r') as f:
        p4headers_file.write(f.read())
# output: util
    logging.debug("Utils(parser,deparser,empty pipline) definitions:\n")
    with open('./lemon_lang/util/util.p4', 'r') as f:
        p4util_file.write(f.read())

# output: metadata
    logging.debug("Metadata definition:\n")
    metadata_code = ""
    for a,b in p4_program.metadata.items():
        metadata_code += (b + '\n')
    metadata_code = p4_metadata % (indent_str(metadata_code,4))
    p4_file.write(metadata_code)
# output: user defined struct
    logging.debug("Struct definition:\n")
    struct_code = ""
    for a,b in p4_program.struct.items():
        struct_code += (b + '\n')
    p4_file.write(struct_code)

# output: include&define
    logging.debug("State and hash declaration:\n")  
    p4_file.write("#include <core.p4> \n#if __TARGET_TOFINO__ == 2 \n#include <t2na.p4>\n#else\n#include <tna.p4>\n#endif\n")
    p4_file.write('\n#include "./common/headers.p4" \n#include "./common/util.p4" \n\n')
    define_code = ""
    for a,b in p4_program.define.items():
        define_code += (b + '\n')
        print(b)
    p4_file.write(define_code)
    
# output:state and hash
    logging.debug("State and hash declaration:\n")
    hash_code = ""
    for a,b in p4_program.hashes.items():
        hash_code += (b + '\n')
        # print(b)
    #print(p4_program.state)
    #print(len(p4_program.state.state_vars))


# output:ingress
    logging.debug("Ingress pipeline:\n")
    #print(p4_program.ingress_loop)

# output:egress
    logging.debug("Egress pipeline:\n")
    #print(p4_program.egress_loop)
    # p4_file.write(p4_program.egress_loop + "\n")

# output:rigister
    logging.debug("Register definition:\n")
    register_code = ""
    for a,b in p4_program.registers.items():
        # print(a)
        # print(b)
        register_code += (b+'\n')
        #p4tables_file.write(b + "\n")

# output:action
    logging.debug("Action definition:\n")
    action_code = ""
    for a,b in p4_program.actions.items():
        # print(a)
        # print(b)
        action_code += (b+'\n')
        #p4tables_file.write(b + "\n")

# output:table
    logging.debug("Table definition:\n")
    table_code = ""
    for a,b in p4_program.tables.items():
        # print(a)
        #print(b)
        table_code += (b+'\n')
        #p4tables_file.write(b + "\n")


    ingress_code = p4_ingress % (indent_str(hash_code,4),indent_str(register_code,4), indent_str(action_code,4), indent_str(table_code,4), indent_str(p4_program.ingress_loop,4))
    p4_file.write(ingress_code)

# output:command
    logging.debug("Command definition:\n")    
    cmd_file.write("read_register\tall_flow_lemon\t1\n") # default all packet counter
    for c in p4_program.commands:
        #print(c)
        cmd_file.write(c + "\n")
    if(p4_program.duration):
        print(p4_program.duration)
        cmd_file.write("duration" + "\t" + str(p4_program.duration) + '\n')
    if(p4_program.window):
        cmd_file.write("window" + "\t" + str(p4_program.window) + '\n')

# output: p4_main
    p4_file.write(p4_main)

# close generated files
    p4_file.close()
    cmd_file.close()
