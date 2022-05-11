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

from runtime.ports import Ports
from runtime.table import Table

def hex_to_ip(hex_ip):
        bin_str = bin(hex_ip)
        length = len(bin_str)
        while(length<34):
            bin_str = bin_str[0:2] + '0' + bin_str[2:]
            length +=1
        ip = "%d.%d.%d.%d"%(int(bin_str[2:10],2),int(bin_str[10:18],2),int(bin_str[18:26],2),int(bin_str[26:34],2))
        return ip

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
        self.title1 = []
        self.title2 = []
        self.registers = []
        self.topk = False
        self.duration = 100
        self.window = 5

    def critical_error(self, msg):
        # self.log.critical(msg)
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
            pass
            # self.log.info('Connected to BFRT server {}:{}'.format(
                # bfrt_ip, bfrt_port))

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
            # self.log.exception(e)
            self.critical_error('Unexpected error. Stopping controller.')
        
        # Read command from command.txt
        target_dir = self.p4_name
        with open("/root/lemon-v1.0/build/tasks/"+ target_dir +"/commands.txt", 'r') as f:
            # self.commands = f.readlines()
            self.commands = f.read().splitlines()
        # print(self.commands)

    def add_entry(self):
        for i in self.commands:
            j = i.split('\t')
            if(j[0] == "add_entry"):
                length = len(j)
                keys= []
                table = Table(self.target, gc, self.bfrt_info, j[1])
                table.clearEntry()
                for e in range(2,length,2):
                    if(j[e] == "hdr.ipv4.src_addr" or j[e] == "hdr.ipv4.dst_addr"):
                        keys.append((j[e], j[e+1], "255.255.255.255"))
                    #bit<8>-0xFF
                    elif(j[e] == "hdr.ipv4.protocol" or j[e] == "hdr.tcp.flags"): 
                        keys.append((j[e], int(j[e+1][2:], 16), 0xFF))
                    #bit<16>-0xFFFF
                    elif(j[e] == "hdr.tcp.src_port" or j[e] == "hdr.tcp.dst_port" or j[e] == "hdr.udp.src_port" or j[e] == "hdr.udp.dst_port" or j[e] == "hdr.ethernet.ether_type"):
                        keys.append((j[e], int(j[e+1][2:], 16), 0xFFFF))
                    else:
                        pass
                table.addEntry("ternary",keys,j[length-1],[])
                table.readTable_tbl()
            elif(j[0] == "read_register"):
                self.title1.append(j[1])
                self.registers.append([j[0],j[1],j[2]])
            elif(j[0] == "read_register_bf"):
                self.title2.append(j[1])
                self.registers.append([j[0],j[1],j[2]])
            elif(j[0] == "read_register_sketch"):
                self.topk = True
                self.registers.append(j)
            elif(j[0] == "read_register_sketch" and j[1] == "sketch_reg_threshold"):
                # set threshold for topk flow
                table = Table(self.target, gc, self.bfrt_info, j[1])
                table.writeRegister(int(j[2]),int(j[3]))
                self.topk = True
            elif(j[0] == "duration"):
                self.duration = int(j[1])
            elif(j[0] == "window"):
                self.window = int(j[1])
            else:
                print("Unexpected configuration in command.txt!")

    def add_entry_old(self):
        for i in self.commands:
            j = i.split('\t')
            if(j[0] == "add_entry"):
                length = len(j)
                keys= []
                table = Table(self.target, gc, self.bfrt_info, j[1])
                table.clearEntry()
                for e in range(2,length,2):
                    if(j[e] == "hdr.ipv4.src_addr" or j[e] == "hdr.ipv4.dst_addr"):
                        keys.append((j[e], j[e+1], "255.255.255.255"))
                    elif(j[e] == "hdr.ipv4.protocol" or j[e] == "hdr.tcp.flags"):
                        keys.append((j[e], int(j[e+1][2:]), 0xFF))
                    elif(j[e] == "hdr.tcp.src_port" or j[e] == "hdr.tcp.dst_port" or j[e] == "hdr.udp.src_port" or j[e] == "hdr.udp.dst_port"):
                        keys.append((j[e], int(j[e+1][2:]), 0xFFFF))
                    else:
                        pass
                table.addEntry("ternary",keys,j[length-1],[])
                table.readTable_tbl()
            elif(j[0] == "read_register"):
                self.registers.append([j[0],j[1],j[2]])
            elif(j[0] == "read_register_sketch" and j[1] == "sketch_reg_threshold"):
                print(i)
                print(j)
                table = Table(self.target, gc, self.bfrt_info, j[1])
                table.writeRegister(int(j[2]),int(j[3]))
                self.topk = True
            else:
                pass

    def get_data(self):
        data = []
        for i in self.registers:
            if(i[0]=="read_register"):
                reg = Table(self.target, gc, self.bfrt_info, i[1])
                data.append(reg.readRegister(int(i[2])))
            else:
                pass
        if(self.topk):
            data = []
            reg_info = Table(self.target, gc, self.bfrt_info, "top_flow_info")
            reg_size = Table(self.target, gc, self.bfrt_info, "top_flow_size")
            for k in range(16):
                key1 = reg_info.readRegister(k,"key1",True)
                key2 = reg_info.readRegister(k,"key2",True)
                value = reg_size.readRegister(k)
                key = "src:" + hex_to_ip(key1) + "dst:" + hex_to_ip(key2)
                data.append({"count":value,"flow":key})
        return data
        
    def run_test(self):
        ''' complete the test code using bfrt API to debug p4 program'''
        # registers = []
        # for i in self.commands:
        #     j = i.split('\t')
        #     print(j)
        #     if(j[0]=="read_register"):
        #         registers.append([j[0],j[1],j[2]])
        #         self.title1.append(j[1])
        #     if(j[0]=="read_register_bf"):
        #         registers.append([j[0],j[1],j[2]])
        #         self.title2.append(j[1])
        #     elif(j[0] == "read_register_sketch"):
        #         registers.append([j[0],j[1],j[2]])
        #     elif(j[0] == "duration"):
        #         self.duration = int(j[1])
        #     elif(j[0] == "window"):
        #         self.window = int(j[1])
        #     else:
        #         print("no match registers and control cmd!")

        print(len(self.registers))
        print(self.registers)

        print("Register:", self.title1)
        print("Register_bf:", self.title2)
        self.read_res_with_clear()
        # self.read_res()

    def read_res(self):
        for i in self.registers:
            if(i[0]=="read_register"):
                reg = Table(self.target, gc, self.bfrt_info, i[1])
                reg.writeRegister(int(i[2]),0)
        data_file = open("./plot/mawi_data3_1y.txt","w")
        for i in self.title1:
            data_file.write(i + ',')
        for i in self.title2:
            data_file.write(i + ',')
        data_file.write('\n')

        for j in range(self.duration):
            data = []
            print("-------------------------------")
            t1 = time.time()
            # Read data from Register
            for i in self.registers:
                if(i[0]=="read_register" or i[0]=="read_register_bf"):
                    reg = Table(self.target, gc, self.bfrt_info, i[1])
                    data.append(reg.readRegister(int(i[2])))
                    # print(data)
                    print()
                    # return data
                elif(i[0] == "read_register_sketch" and i[1] == "top_flow_info"):
                    threthold = Table(self.target, gc, self.bfrt_info, "sketch_reg_threshold")
                    reg_info = Table(self.target, gc, self.bfrt_info, "top_flow_info")
                    reg_size = Table(self.target, gc, self.bfrt_info, "top_flow_size")
                    th = threthold.readRegister(0)
                    print("\n-----------------------------------")
                    print("Threshold: ",th)
                    print("-----------------------------------")
                    print("sip\t\tdip\t\tpkt")
                    print("-----------------------------------")

                    for k in range(int(i[2])):

                        key1 = hex_to_ip(reg_info.readRegister(k,"key1"))
                        if(key1 == "0.0.0.0"):
                            print(key1,end = '\t\t')
                            # pass
                        else:
                            print(key1,end = '\t')
                        key2 = hex_to_ip(reg_info.readRegister(k,"key2"))
                        if(key2 == "0.0.0.0"):
                            print(key2,end = '\t\t')
                            # pass
                        else:
                            print(key2,end = '\t')
                        value = reg_size.readRegister(k)
                        if(value==0):
                            print(value)
                            # pass
                        else:
                            print(value+th)
                    # pass
            print(self.title1)
            print(self.title2)
            print(data)
            for d in data:
                data_file.write(str(d)+',')
            data_file.write('\n')
            time.sleep(self.window)
        data_file.close()

    def read_res_with_clear(self): 
        for i in self.registers:
            if(i[0]=="read_register"):
                reg = Table(self.target, gc, self.bfrt_info, i[1])
                reg.writeRegister(int(i[2]),0)
        data_file = open("./plot/mawi_data3_1y_plus.txt","w")
        for i in self.title1:
            data_file.write(i + ',')
        for i in self.title2:
            data_file.write(i + ',')
        data_file.write('\n')

        switch = 0
        for j in range(self.duration):
            data = []
            print("-------------------------------")
            t1 = time.time()
            # Read data from Register
            for i in self.registers:
                if(i[0]=="read_register" or i[0]=="read_register_bf"):
                    reg = Table(self.target, gc, self.bfrt_info, i[1])
                    data.append(reg.readRegister(int(i[2])))
                    # print(data)
                    print()
                    # return data
                elif(i[0] == "read_register_sketch" and i[1] == "top_flow_info"):
                    threthold = Table(self.target, gc, self.bfrt_info, "sketch_reg_threshold")
                    reg_info = Table(self.target, gc, self.bfrt_info, "top_flow_info")
                    reg_size = Table(self.target, gc, self.bfrt_info, "top_flow_size")
                    th = threthold.readRegister(0)
                    print("\n-----------------------------------")
                    print("Threshold: ",th)
                    print("-----------------------------------")
                    print("sip\t\tdip\t\tpkt")
                    print("-----------------------------------")
                    topk_sum_value = 0 
                    topk_flow_num = 0
                    for k in range(int(i[2])):

                        key1 = hex_to_ip(reg_info.readRegister(k,"key1"))
                        if(key1 == "0.0.0.0"):
                            print(key1,end = '\t\t')
                            # pass
                        else:
                            print(key1,end = '\t')
                        key2 = hex_to_ip(reg_info.readRegister(k,"key2"))
                        if(key2 == "0.0.0.0"):
                            print(key2,end = '\t\t')
                            # pass
                        else:
                            print(key2,end = '\t')
                        value = reg_size.readRegister(k)
                        if(value==0):
                            print(value)
                            # pass
                        else:
                            print(value+th)
                            topk_sum_value = topk_sum_value + value + th
                            topk_flow_num += 1
                    # pass
            print(self.title1)
            print(self.title2)
            print(data)
            print(topk_sum_value)
            print(topk_flow_num)
            for d in data:
                data_file.write(str(d)+',')
            data_file.write(str(topk_sum_value) + ',')
            data_file.write(str(topk_flow_num) + ',')
            data_file.write('\n')

            t2 = time.time()
            # Switch to new Register and Clear the old Register
            # Switch: use switch reg
            # Clear: use clearEntry
            for i in self.registers:
                if(i[0]=="read_register"):
                    reg = Table(self.target, gc, self.bfrt_info, i[1])
                    reg.writeRegister(int(i[2]),0)
                elif(i[0]=="read_register_bf"): # clear the bloomfilter using switch
                    # switch to new bloomfilter
                    flag = Table(self.target, gc, self.bfrt_info, "bf_switch_reg")
                    flag.writeRegister(0,1-switch)
                    # clear old bloomfilter
                    if(switch==0):
                        bf = Table(self.target, gc, self.bfrt_info, "bf")
                    else:
                        bf = Table(self.target, gc, self.bfrt_info, "bf_shadow")
                    bf.clearEntry()
                    # clear flow num
                    flow_num = Table(self.target, gc, self.bfrt_info, i[1])
                    flow_num.writeRegister(int(i[2]),0)
                elif(i[0] == "read_register_sketch" and i[1] == "top_flow_info"):
                    # switch to new sketch
                    flag = Table(self.target, gc, self.bfrt_info, "sketch_switch_reg")
                    flag.writeRegister(0,1-switch)
                    # clear old sketch
                    if(switch==0):
                        sketch1 = Table(self.target, gc, self.bfrt_info, "sketch_reg1")
                        sketch2 = Table(self.target, gc, self.bfrt_info, "sketch_reg2")
                        sketch3 = Table(self.target, gc, self.bfrt_info, "sketch_reg3")
                        sketch4 = Table(self.target, gc, self.bfrt_info, "sketch_reg4")
                    else:
                        sketch1 = Table(self.target, gc, self.bfrt_info, "sketch_reg1_shadow")
                        sketch2 = Table(self.target, gc, self.bfrt_info, "sketch_reg2_shadow")
                        sketch3 = Table(self.target, gc, self.bfrt_info, "sketch_reg3_shadow")
                        sketch4 = Table(self.target, gc, self.bfrt_info, "sketch_reg4_shadow")
                    sketch1.clearEntry()
                    sketch2.clearEntry()
                    sketch3.clearEntry()
                    sketch4.clearEntry()
                    # clear topk register
                    reg_info = Table(self.target, gc, self.bfrt_info, "top_flow_info")
                    reg_size = Table(self.target, gc, self.bfrt_info, "top_flow_size")
                    reg_info.initRegister(0,"key1")
                    reg_info.initRegister(0,"key2")
                    reg_size.clearEntry()
            t3 = time.time()
            time.sleep(self.window)
            # print("read time\tclear time")
            # print(t2-t1,t3-t2)
            switch = 1 - switch

        data_file.close()



if __name__ == '__main__':

    argparser = argparse.ArgumentParser(description='Lemon controller.')
    argparser.add_argument('--p4_name',
                           type=str,
                           default='leilei_lemon',
                           help='P4 program name. Default: leilei_lemon')

    args = argparser.parse_args()
    # args.p4_name = "ict_demo3"
    ctrl = Lemon(args.p4_name)
    ctrl.setup()
    ctrl.add_entry()
    ctrl.run_test()