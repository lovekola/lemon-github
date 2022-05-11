import os
from matplotlib import pyplot as plt
plt.rcParams["font.sans-serif"]=["SimHei"] #设置字体
plt.rcParams["axes.unicode_minus"]=False #正常显示负号

data_all = []
data_tcp = []
data_flow = []

with open('./mawi_data2_1y.txt','r') as f:
    line = f.readline().split(',')
    print(line)
    while True:
        if not line:
            break
        line = f.readline()
        data = line.split(',')
        if(len(data)<3):break
        data_all.append(int(data[0]))
        data_tcp.append(int(data[1]))
        data_flow.append(int(data[2]))
        print("1")
        print(data)

diff_data_all = []
diff_data_tcp = []
diff_data_flow = []

for i in range(len(data_all)-1):
# for i in range(300):
    diff_data_all.append(data_all[i+1]-data_all[i])
    diff_data_tcp.append(data_tcp[i+1]-data_tcp[i])
    diff_data_flow.append(data_flow[i+1]-data_flow[i])

x = range(len(data_all))
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

# plt.plot(x, # x轴数据
#          data_tcp, # y轴数据
#          linestyle = '-', # 折线类型
#          linewidth = 2, # 折线宽度
#          color = 'red', # 折线颜色
#          marker = 'o', # 点的形状
#          markersize = 1, # 点的大小
#          markeredgecolor='black', # 点的边框色
#          markerfacecolor='#ff9999', # 点的填充色
#          label = 'tcp') # 添加标签
plt.plot(x, # x轴数据
         data_flow, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
        #  color = '#fff888', # 折线颜色
         color = 'green', # 折线颜色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999') # 添加标签

        
plt.title("IP对连接数统计折线图")
plt.xlabel("时间")
plt.ylabel("IP对个数")
plt.grid()
# plt.legend(prop={'size':18})
plt.show()