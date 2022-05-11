
import os
import sys
import glob
import signal
import argparse
import logging
import time
# Add BF Python to search path
bfrt_location = '{}/lib/python*/site-packages/tofino'.format(
    os.environ['SDE_INSTALL'])
sys.path.append(glob.glob(bfrt_location)[0])

import bfrt_grpc.client as gc

from common.ports import Ports
from common.table import Table

class Lemon(object):
    ''' test by BF runtime '''
    def __init__(self):
        super(Lemon,self).__init__()

        self.log = logging.getLogger(__name__)
        self.log.info('Test for p4 programs')

        # CPU PCIe port
        self.cpu_port = 192
        self.port_list = [
            (2,0,10,'none',2),
            (2,1,10,'none',2), # 141 -- 10.21.0.233-eth2-10.22.0.201
            (2,2,10,'none',2), # 142 -- 10.21.0.230-eth2-10.22.0.200
            (2,3,10,'none',2)]

    def critical_error(self, msg):
        self.log.critical(msg)
        print(msg, file=sys.stderr)
        logging.shutdown()
        #sys.exit(1)
        os.kill(os.getpid(), signal.SIGTERM)

    def setup(self, p4_name, bfrt_ip, bfrt_port):
        self.dev = 0
        self.target = gc.Target(self.dev, pipe_id=0xFFFF)
        
        # Connect to BFRT server
        try:
            interface = gc.ClientInterface('{}:{}'.format(bfrt_ip, bfrt_port),
                                           client_id=0,
                                           device_id=self.dev)
        except RuntimeError as re:
            msg = re.args[0] % re.args[1]
            self.critical_error(msg)
        else:
            self.log.info('Connected to BFRT server {}:{}'.format(
                bfrt_ip, bfrt_port))

        try:
            interface.bind_pipeline_config(p4_name)
        except gc.BfruntimeForwardingRpcException:
            self.critical_error('P4 program {} not found!'.format(p4_name))

        try:
            # Get all tables for program
            self.bfrt_info = interface.bfrt_info_get(p4_name)
            # Ports table
            self.ports = Ports(self.target, gc, self.bfrt_info)
            # Port configuration
            self.ports.add_ports(self.port_list)

        except KeyboardInterrupt:
            self.critical_error('Stopping controller.')
        except Exception as e:
            self.log.exception(e)
            self.critical_error('Unexpected error. Stopping controller.')

    def add_entry(self):
        with open("./commands.txt", 'r') as f:
            # self.commands = f.readlines()
            self.commands = f.read().splitlines()
        for i in self.commands:
            print(i)
            j = i.split('\t')
            if(j[0] == "add_entry"):
                print(j)
                table = Table(self.target, gc, self.bfrt_info, j[1])
                table.clearEntry()
                keys = [(j[2], j[3], "255.255.255.255")]
                print(keys)
                table.addEntry("ternary",keys,j[4],[])
                table.readTable_tbl()
            else:
                pass
    
    def run_test(self):
        ''' complete the test code using bfrt API to debug p4 program'''
        registers = []
        for i in self.commands:
            j = i.split('\t')
            if(j[0] == "read_register"):
                registers.append((j[1],j[2]))
            else:
                pass
        
        print(registers)
        for j in range(100):
            data = []
            for i in registers:
                reg = Table(self.target, gc, self.bfrt_info, i[0])
                data.append(reg.readRegister(int(i[1])))
            print(data)
            time.sleep(1)


if __name__ =='__main__':

#-----------------------------------------------------------------------------------------------------
    # Parse arguments
    argparser = argparse.ArgumentParser(description='Lemon controller.')
    argparser.add_argument('--p4_name',
                           type=str,
                           default='leilei_lemon',
                           help='P4 program name. Default: leilei_lemon')
    argparser.add_argument(
        '--bfrt-ip',
        type=str,
        default='127.0.0.1',
        help='Name/address of the BFRuntime server. Default: 127.0.0.1')
    argparser.add_argument('--bfrt-port',
                           type=int,
                           default=50052,
                           help='Port of the BFRuntime server. Default: 50052')
    argparser.add_argument('--log-level',
                           default='INFO',
                           choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'],
                           help='Default: INFO')
    args = argparser.parse_args()

    # Configure logging
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        sys.exit('Invalid log level: {}'.format(args.log_level))

    logformat = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='lemon.log',
                        filemode='w',
                        level=numeric_level,
                        format=logformat,
                        datefmt='%H:%M:%S')
#---------------------------------------------------------------------------------------------

    args.bfrt_ip = args.bfrt_ip.strip()

    ctrl = Lemon()
    ctrl.setup(args.p4_name, args.bfrt_ip, args.bfrt_port)
    ctrl.add_entry()
    ctrl.run_test()
