from socket import socket
from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO, send, emit
import random
import os
import time
import threading
import json
import multiprocessing
import subprocess

from runtime.lemon import Lemon
from runtime.preset_code import *

app = Flask(__name__)
CORS(app, cors_allowed_origins="*")
socketio = SocketIO(app, async_handlers=True, pingTimeout = 9000, cors_allowed_origins='*')
thread_switch=None
thread_flowsize=None
thread_flowcount=None
thread_flowcoord=None

chart_name=[]

def compile_lemon():
    # cmd_str = "python ./test_echo.py"
    flag = -1
    t1 = time.time()
    cmd_str = "python ./lemon-p4c.py -u lemon_demox"
    flag = os.system(cmd_str)
    t2 = time.time()
    if(flag == 0):
        print("Compile lemon to p4 Down!")
        print("\n\tCompile lemon to p4 Down! use %s s\n" % (t2-t1))
    else:
        print("Compile lemon to p4 Failed!")
    return flag

def switchd_b():
    cmd_str = "xterm -e $SDE/my_p4_16_switch.sh -b --lemon lemon_demox"
    flag = os.system(cmd_str)
"""
    switch = threading.Thread(target=switchd_b, args=())
    switch.start()
"""
def compile_p4():
    # cmd_str = "$SDE/../lemon/test_echo.sh"
    print("!!!!!!!!!!!!!!!!!!start")
    cmd_str = "xterm -e '$SDE/my_p4_16_switch.sh -b --lemon lemon_demox'"
    flag = os.system(cmd_str)
    print("!!!!!!!!!!!!!!!!!!end")


def run_switch():
    # cmd_str = "xterm -e '$SDE/my_p4_16_switch.sh -p lemon_demox;exec bash'" #保留xterm窗口
    # cmd_str = "xterm -e '$SDE/my_p4_16_switch.sh -p lemon_demox'"  #进程结束后退出xterm窗口
    # flag = os.system(cmd_str)

    bash_cmd = ["xterm","-e","$SDE/my_p4_16_switch.sh -p lemon_demox"]
    p4_switch = subprocess.Popen(bash_cmd, stdout=subprocess.PIPE)
    print(f"Process {p4_switch.pid}-p4_switch running...")

    # os.system(f"kill {p4_switch.pid}")

def stop_switch():
    cmd_str = "ps aux|grep /root/bf-sde-9.6.0/my_p4_16_switch.sh|grep -v grep|cut -c 9-16|xargs kill -9"
    flag = os.system(cmd_str)
    print("xterm(run_switch.sh) Exit!")

def run_p4i():
    cmd_str1 = "xterm -e 'su zhangleilei -c 'xvfb-run -a /root/bf-sde-9.6.0/install/bin/p4i -o /root/bf-sde-9.6.0/build/p4-build/lemon_demox/tofino/lemon_demox/manifest.json''"
    cmd_str2 = "su zhangleilei -c 'xvfb-run -a /root/bf-sde-9.6.0/install/bin/p4i -o /root/bf-sde-9.6.0/build/p4-build/lemon_demox/tofino/lemon_demox/manifest.json'"
    bash_cmd = ["xterm","-e","su zhangleilei -c 'xvfb-run -a /root/bf-sde-9.6.0/install/bin/p4i -o /root/bf-sde-9.6.0/build/p4-build/lemon_demox/tofino/lemon_demox/manifest.json'"]
    bash_cmd2 = ["xterm","-e" ,"python -m http.server"]
    p4_insight = subprocess.Popen(bash_cmd, stdout=subprocess.PIPE)
    time.sleep(10)
    print(f"Process {p4_insight.pid}-p4_insight running...")
    # os.system(f"kill {p4_insight.pid}")
    # flag = os.system(cmd_str2)


def bfruntime():
    print("init Lemon")
    ctrl = Lemon("lemon_demox")
    ctrl.setup()
    print("setup down")
    ctrl.add_entry()
    chart_name = ctrl.title
    print(ctrl.title)
    socketio.emit("updateChartName",{"chart_name":chart_name})
    while(True):
        time.sleep(2)
        result = ctrl.get_data()
        print(result)

def generate_lemon(para_dict):
    # ["ethernet.ether_type", "ipv4.src_addr", "ipv4.dst_addr", "ipv4.protocol", "tcp.flags", "tcp.src_port", "tcp.dst_port", "udp.src_port", "udp.dst_port"]
    count_type = ["SYN_flood","ACK_flood","RST_flood","FIN_flood","DNS_request_flood","DNS_response_flood","NTP_response_flood"]
    

    if(para_dict["task"] == "flow_size"):
        match_key = []
        for i in para_dict.keys():
            if(i == "eth_type"): match_key.append("ethernet.ether_type == %s" % para_dict["eth_type"])
            elif(i == "src_ip"): match_key.append("ipv4.src_addr == %s" % para_dict["src_ip"])
            elif(i == "dst_ip"): match_key.append("ipv4.dst_addr == %s" % para_dict["dst_ip"])
            elif(i == "ip_protocol"): match_key.append("ipv4.protocol == %s" % para_dict["ip_protocol"])
            elif(i == "src_port"): src_port = para_dict["src_port"]
            elif(i == "dst_port"): dst_port = para_dict["dst_port"]
            elif(i == "tcp_flags"): tcp_flags = para_dict["tcp_flags"]
            # else: print("task flow_size with error feild!")
        if("ip_protocol" in para_dict and para_dict["ip_protocol"] == "0x06"):
            if("src_port" in locals().keys()):
                match_key.append("tcp.src_port == %s" % src_port)
            if("dst_port" in locals().keys()):
                match_key.append("tcp.dst_port == %s" % dst_port)
            if("tcp_flags" in locals().keys()):
                match_key.append("tcp.flags == %s" % tcp_flags)
        if("ip_protocol" in para_dict and para_dict["ip_protocol"] == "0x11"):
            if("src_port" in locals().keys()):
                match_key.append("udp.src_port == %s" % src_port)
            if("dst_port" in locals().keys()):
                match_key.append("udp.dst_port == %s" % dst_port)
        match_key = " && ".join(match_key)
        lemon_code = lemon_count_code % match_key
    elif(para_dict["task"] == "SYN_flood"):
        match_key = "tcp.flags == 0x02 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]
        lemon_code = lemon_count_code % match_key
    elif(para_dict["task"] == "ACK_flood"):
        match_key = "tcp.flags == 0x10 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]
        lemon_code = lemon_count_code % match_key
    elif(para_dict["task"] == "RST_flood"):
        match_key = "tcp.flags == 0x11 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]
        lemon_code = lemon_count_code % match_key
    elif(para_dict["task"] == "FIN_flood"):
        match_key = "tcp.flags == 0x04 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]  
        lemon_code = lemon_count_code % match_key  
    elif(para_dict["task"] == "DNS_request_flood"):
        match_key = "udp.dst_port == 53 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]  
        lemon_code = lemon_count_code % match_key 
    elif(para_dict["task"] == "DNS_response_flood"):
        match_key = "udp.src_port == 53 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]  
        lemon_code = lemon_count_code % match_key
    elif(para_dict["task"] == "NTP_response_flood"):
        match_key = "udp.src_port == 123 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]   
        lemon_code = lemon_count_code % match_key         
    elif(para_dict["task"] == "SNMP_response_flood"):
        match_key = "udp.src_port == 161 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]  
        lemon_code = lemon_count_code % match_key
    elif(para_dict["task"] == "SSDP_response_flood"):
        match_key = "udp.src_port == 1900 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]  
        lemon_code = lemon_count_code % match_key
    elif(para_dict["task"] == "ICMP_response_flood"):
        match_key = "ipv4.protocol == 0x01 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"]  
        lemon_code = lemon_count_code % match_key     
    elif(para_dict["task"] == "HTTP_flood"):
        match_key = "tcp.flags == 0x02 && " + \
                    "tcp.dst_port == 80 &&" + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"] 
        lemon_code = lemon_count_code % match_key      
    
    elif(para_dict["task"] == "tcp_connection"):
        match_key = "ipv4.protocol == 0x06 && " + \
                    "ipv4.dst_addr == %s" % para_dict["dst_ip"] 
        hash_key = "{ipv4.src_addr}"
        lemon_code = lemon_reduce_code % (match_key, hash_key)
    elif(para_dict["task"] == "port_scan"):
        match_key = "ipv4.dst_addr == %s" % para_dict["dst_ip"] 
        hash_key = "{tcp.dst_port}"
        lemon_code = lemon_reduce_code % (match_key, hash_key)
    elif(para_dict["task"] == "super_spreader"):
        match_key = "ipv4.src_addr == %s" % para_dict["src_ip"] 
        hash_key = "{ipv4.dst_addr}"
        lemon_code = lemon_reduce_code % (match_key, hash_key)

    elif(para_dict["task"] == "heavy_hitter"):
        match_key = "ipv4.protocol == 0x06" 
        hash_key = "{ipv4.src_addr, ipv4.dst_addr}"
        lemon_code = lemon_sketch_code % (match_key, hash_key)

    else:
        print("No such task.")
        lemon_code = "error!"
    
    if("duration" in para_dict):
        duration = para_dict["duration"]
    else:
        duration = "60"
    if("window" in para_dict):
        window = para_dict["window"]
    else:
        window = "5"
    
    lemon_code += control_code % (duration,window)
    print(lemon_code)
    return lemon_code



def start_switch():
    # 启动p4-insight资源可视化工具
    bash_cmd1 = ["xterm","-e","su zhangleilei -c 'xvfb-run -a /root/bf-sde-9.6.0/install/bin/p4i -o /root/bf-sde-9.6.0/build/p4-build/lemon_demox/tofino/lemon_demox/manifest.json'"]
    p4_insight = subprocess.Popen(bash_cmd1, stdout=subprocess.PIPE)
    print(f"Process: {p4_insight.pid}(p4_insight) running...")
    
    # 启动交换机
    bash_cmd2 = ["xterm","-e","$SDE/my_p4_16_switch.sh -p lemon_demox"]
    p4_switch = subprocess.Popen(bash_cmd2, stdout=subprocess.PIPE)
    print(f"Process: {p4_switch.pid}(p4_switch) running...")

    # 启动监控程序
    time.sleep(15)
    ctrl = Lemon("lemon_demox")
    ctrl.setup()
    ctrl.add_entry()
    window = ctrl.window
    duration = ctrl.duration

    chart_name = [ctrl.title1, ctrl.title2, ctrl.topk]
    print(f"chart_name: {chart_name}")
    size_length = len(chart_name[0])
    socketio.emit("updateChartName", chart_name)
    new_data = ctrl.get_data()[0]
    for i in range(duration):
        old_data = new_data
        time.sleep(window)
        new_data = ctrl.get_data()[0]
        diff_data = [new_data[i]-old_data[i] for i in range(size_length)]

        
        chart_data = ctrl.get_data()
        chart_data[0] = diff_data  #汇报差值而不是累计值
        print(chart_data)
        socketio.emit('updateChartData', chart_data)
    
    # 关闭switch，p4i
    os.system(f"kill {p4_insight.pid}")
    print(f"Process: {p4_insight.pid}(p4_insight) stop!")
    os.system(f"kill {p4_switch.pid}")
    print(f"Process: {p4_switch.pid}(p4_switch) stop!")
    global thread_switch
    thread_switch = None


@socketio.on('connect')
def handle_message():
    print("连接成功！！！")

@socketio.on('disconnect', namespace='/chat')
def test_disconnect():
    print('Client disconnected')
    

@socketio.on('run_switch')
def deal_with_run_switch():
    print("服务器端 启动交换机！")
    global thread_switch
    if thread_switch is None:
        thread_switch = socketio.start_background_task(target=start_switch)


@socketio.on('pre-set') # submit-choice
def preset_task(var):
    para_dict = json.loads(var)
    print("Get measurement task from web:")
    print(para_dict)

    lemon_code = generate_lemon(para_dict)
    socketio.emit("updatePrimitive",lemon_code)
    print("Translated to lemon code as:\n" + lemon_code)

    with open("/root/lemon/tasks/lemon_demox.py",'w') as f:
        f.write(lemon_code)
    
    compile_lemon()

    # # 启动P4编译器
    # P4_compile_cmd = ["xterm","-e","$SDE/my_p4_16_switch.sh -b --lemon lemon_demox"]
    # p4_compile = subprocess.Popen(P4_compile_cmd, stdout=subprocess.PIPE)
    # print(f"Process: {p4_compile.pid}(P4_compile) running...")
    start_time = time.time()
    print("P4 is compiling...")
    p4_compile = multiprocessing.Process(target=compile_p4)
    p4_compile.start()
    # p4_compile.join()
    while(1):
        print(p4_compile.is_alive())
        if(p4_compile.is_alive()):
            print("Compiling...")
            time.sleep(2)
        else:
            print("Compile Done")
            socketio.emit('p4_compile_done')
            break
    end_time = time.time()
    print(f"P4-compile Done! Last {end_time-start_time}s")

@socketio.on('command') # submit-txt
def process_command(val):
    print("Get lemon code from web:\n" + val)
    with open("/root/lemon/tasks/lemon_demox.py",'w') as f:
        f.write(val)
    
    compile_lemon()
    p4_compile = multiprocessing.Process(target=compile_p4)
    start_time = time.time()
    print("P4 is compiling...")
    p4_compile.start()
    # p4_compile.join()
    while(1):
        print(p4_compile.is_alive())
        if(p4_compile.is_alive()):
            print("Compiling...")
            time.sleep(2)
        else:
            print("Compile Done")
            socketio.emit('p4_compile_done')
            break
    end_time = time.time()
    print(f"P4-compile Done! Last {end_time-start_time}s")


if __name__ == '__main__':

    socketio.run(app, debug=True, host="0.0.0.0", port=5000)

    # flow_size_all = {"task":"flow_size", "eth_type": "0x0800", "src_ip":"10.22.0.200", "dst_ip":"10.22.0.201", "ip_protocol":"0x06", "tcp_flags":"0x02","src_port":"111","dst_port":"222"}
    # flow_size = {"task":"flow_size", "eth_type": "0x0800","src_ip":"10.22.0.200"}
    # syn_flood = {"task":"SYN_flood","dst_ip":"10.22.0.201"}
    # ack_flood = {"task":"ACK_flood","dst_ip":"10.22.0.201"}

    # generate_lemon(flow_size)
    # generate_lemon(syn_flood)
    # generate_lemon(ack_flood)
    # start_switch()

