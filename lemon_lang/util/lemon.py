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

from ports import Ports
from table import Table

class Lemon(object):
    ''' test by BF runtime '''
    def __init__(self, p4_name, bfrt_ip="127.0.0.1", bfrt_port=50052):
        super(Lemon, self).__init__()
        self.p4_name = p4_name
        self.bfrt_ip = bfrt_ip
        self.bfrt_port = bfrt_port
        # CPU PCIe port
        self.cpu_port = 192
        self.port_list = [
            (2,0,10,'none',2),
            (2,1,10,'none',2), # 141 -- 10.21.0.233-eth2-10.22.0.201
            (2,2,10,'none',2), # 142 -- 10.21.0.230-eth2-10.22.0.200
            (2,3,10,'none',2)]
        self.commands = []
        self.title = []

    def critical_error(self, msg):
        self.log.critical(msg)
        print(msg, file=sys.stderr)
        logging.shutdown()
        #sys.exit(1)
        os.kill(os.getpid(), signal.SIGTERM)

    def setup(self):
        self.dev = 0
        self.target = gc.Target(self.dev, pipe_id=0xFFFF)
        
        # Connect to BFRT server
        try:
            interface = gc.ClientInterface('{}:{}'.format(self.bfrt_ip, self.bfrt_port),
                                           client_id=0,
                                           device_id=self.dev)
        except RuntimeError as re:
            msg = re.args[0] % re.args[1]
            self.critical_error(msg)
        else:
            self.log.info('Connected to BFRT server {}:{}'.format(
                bfrt_ip, bfrt_port))

        try:
            interface.bind_pipeline_config(self.p4_name)
        except gc.BfruntimeForwardingRpcException:
            self.critical_error('P4 program {} not found!'.format(self.p4_name))

        try:
            # Get all tables for program
            self.bfrt_info = interface.bfrt_info_get(self.p4_name)
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
            j = i.split('\t')
            if(j[0] == "add_entry"):
                table = Table(self.target, gc, self.bfrt_info, j[1])
                table.clearEntry()
                keys = [(j[2], j[3], "255.255.255.255")]
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
                registers.append([j[0],j[1],j[2]])
            elif(j[0] == "read_register_sketch"):
                registers.append([j[0],j[1],j[2]])
            else:
                pass
        for i in registers:
            self.title.append(i[1])
        print(self.title)
        for j in range(1):
            data = []
            for i in registers:
                if(i[0]=="read_register"):
                    reg = Table(self.target, gc, self.bfrt_info, i[1])
                    data.append(reg.readRegister(int(i[2])))
                    # print(data)
                    print()
                elif(i[0] == "read_register_sketch" and i[1] == "top_flow_info"):
                    reg_info = Table(self.target, gc, self.bfrt_info, "top_flow_info")
                    reg_size = Table(self.target, gc, self.bfrt_info, "top_flow_size")
                    for k in range(int(i[2])):

                        key1 = reg_info.readRegister(k,"key1",True)
                        print(hex_to_ip(key1),end = '\t')
                        key2 = reg_info.readRegister(k,"key2",True)
                        print(hex_to_ip(key2),end = '\t')
                        value = reg_size.readRegister(k)
                        print()
                    print()
            time.sleep(1)