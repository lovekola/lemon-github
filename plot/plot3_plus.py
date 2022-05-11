import os
from matplotlib import pyplot as plt
plt.rcParams["font.sans-serif"]=["SimHei"] #设置字体
plt.rcParams["axes.unicode_minus"]=False #正常显示负号

data_tcp = []
data_topk = []
data_flow = []

with open('./mawi_data3_1y_plus.txt','r') as f:
    line = f.readline().split(',')
    print(line)
    while True:
        if not line:
            break
        line = f.readline()
        data = line.split(',')
        if(len(data)<3):break
        data_tcp.append(int(data[1]))
        data_topk.append(int(data[2]))
        data_flow.append(int(data[3]))
        print(data)

x = range(len(data_tcp))
# x = range(300)
# plt.plot(x, # x轴数据
#          data_all, # y轴数据
#          linestyle = '-', # 折线类型
#          linewidth = 2, # 折线宽度
#          color = 'black', # 折线颜色
#          marker = 'o', # 点的形状
#          markersize = 1, # 点的大小
#          markeredgecolor='black', # 点的边框色
#          markerfacecolor='steelblue', # 点的填充色
#          label = 'all') # 添加标签
plt.subplot(2,1,1)
plt.plot(x, # x轴数据
         data_tcp, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
         color = 'red', # 折线颜色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999', # 点的填充色
         label = 'tcp') # 添加标签
plt.plot(x, # x轴数据
         data_topk, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
        #  color = '#fff888', # 折线颜色
         color = 'green', # 折线颜色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999',
        label = 'topk') # 添加标签
plt.xlabel("时间")
plt.ylabel("数据包个数")
plt.legend(prop={'size':18})
plt.grid()
plt.title("TCP流量与TopK流量实时折线图")

plt.subplot(2,1,2)
plt.plot(x, # x轴数据
         data_flow, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
        #  color = '#fff888', # 折线颜色
         color = 'black', # 折线颜色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999') # 添加标签
        
plt.title("TopK流(数据包数超过10000的流)个数实时折线图")
plt.xlabel("时间")
plt.ylabel("TopK流个数")
plt.grid()


plt.show()