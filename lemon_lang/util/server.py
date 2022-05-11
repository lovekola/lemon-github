from socket import socket
from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO, send, emit
import random


app = Flask(__name__)
CORS(app, cors_allowed_origins="*")
socketio = SocketIO(app, cors_allowed_origins='*')
thread_flowsize=None
thread_flowcount=None
thread_flowcoord=None
chart_name=[]

def process():
    data=[]
    for _ in range(7):
        data.append(round(random.random(),2))
    return data

def get_rank():
    data=[]
    for i in range(10):
        data.append({
            "count":round(random.random(),2),
            "flow":"src:xxx     dest:xxx    {0}".format(i)
        })
    # data.sort(reverse=True)
    return data

def update_flow_size():
    while True:
        socketio.sleep(1)
        result = process()
        socketio.emit('updateFlowSize', {'flow_size': result})

def update_flow_count():
    while True:
        socketio.sleep(1)
        result=process()
        socketio.emit('updateFlowCount',{'flow_count':result})

def update_flow_coord():
    while True:
        socketio.sleep(1)
        result=get_rank()
        socketio.emit('updateFlowCoord',{'rank':result})

@socketio.on('connect')
def handle_message():
    print("连接成功！！！")

@socketio.on('disconnect', namespace='/chat')
def test_disconnect():
    print('Client disconnected')
    

@socketio.on('flowsize')
def measure_flow_size():
    print("服务器端 flowsize")
    global thread_flowsize
    if thread_flowsize is None:
        thread_flowsize = socketio.start_background_task(target=update_flow_size)

@socketio.on('flowcount')
def measure_flow_count():
    print("服务器端 flowcount")
    global thread_flowcount
    if thread_flowcount is None:
        thread_flowcount=socketio.start_background_task(target=update_flow_count)

@socketio.on('flowcoord')
def measure_flow_coord():
    print("服务器端 flowcoord")
    global thread_flowcoord
    if not thread_flowcoord:
        thread_flowcoord=socketio.start_background_task(target=update_flow_coord)

@socketio.on('command')
def process_command(val):
    print("服务器端command:"+val)
    # 保存测量任务
    with open("./tasks/lemon_demox.py",'w') as f:
        f.write(val)
    global chart_name
    chart_name=[]   #清空之前提交的chartname
    random_name="chart"+str(random.randint(1,10))
    chart_name.append(random_name)   #保存此次提交需要绘制的chartname
    
    # chart_name.append("chart_my")
    print(chart_name)
    socketio.emit("updateChartName",{"chart_name":chart_name})

if __name__ == '__main__':
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)








