import os
from matplotlib import pyplot as plt
plt.rcParams["font.sans-serif"]=["SimHei"] #设置字体
plt.rcParams["axes.unicode_minus"]=False #正常显示负号

data_all = []
data_ipv4 = []
data_ipv6 = []
data_arp = []
data_tcp = []
data_udp = []
data_icmp = []


with open('./mawi_data1_1y.txt','r') as f:
    line = f.readline().split(',')
    print(line)
    while True:
        if not line:
            break
        line = f.readline()
        data = line.split(',')
        if(len(data)<5):break
        data_all.append(int(data[0]))
        data_ipv4.append(int(data[1]))
        data_ipv6.append(int(data[2]))
        data_arp.append(int(data[3]))
        data_tcp.append(int(data[4]))
        data_udp.append(int(data[5]))
        data_icmp.append(int(data[6]))

        # print(data)
diff_data_all = []
diff_data_ipv4 = []
diff_data_ipv6 = []
diff_data_arp = []
diff_data_tcp = []
diff_data_udp = []
diff_data_icmp = []

for i in range(len(data_all)-1):
# for i in range(300):
    diff_data_all.append(data_all[i+1]-data_all[i])
    diff_data_ipv4.append(data_ipv4[i+1]-data_ipv4[i])
    diff_data_ipv6.append(data_ipv6[i+1]-data_ipv6[i])
    diff_data_arp.append(data_arp[i+1]-data_arp[i])
    diff_data_tcp.append(data_tcp[i+1]-data_tcp[i])
    diff_data_udp.append(data_udp[i+1]-data_udp[i])
    diff_data_icmp.append(data_icmp[i+1]-data_icmp[i])

x = range(len(data_all)-1)
# x = range(300)
plt.plot(x, # x轴数据
         diff_data_all, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
         color = 'black', # 折线颜色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='steelblue', # 点的填充色
         label = 'all') # 添加标签

plt.plot(x, # x轴数据
         diff_data_ipv4, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
         color = 'red', # 折线颜色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999', # 点的填充色
         label = 'ipv4') # 添加标签
plt.plot(x, # x轴数据
         diff_data_ipv6, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
        #  color = '#fff888', # 折线颜色
         color = 'yellow', # 折线颜色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999', # 点的填充色
         label = 'ipv6') # 添加标签
plt.plot(x, # x轴数据
         diff_data_arp, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
         color = 'cyan', # 蓝绿色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999', # 点的填充色
         label = 'arp') # 添加标签
plt.plot(x, # x轴数据
         diff_data_tcp, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
         color = 'green', # 
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999', # 点的填充色
         label = 'tcp') # 添加标签
plt.plot(x, # x轴数据
         diff_data_udp, # y轴数据
         linestyle = '-', # 折线类型
         linewidth = 2, # 折线宽度
         color = 'magenta', # 粉紫色
         marker = 'o', # 点的形状
         markersize = 1, # 点的大小
         markeredgecolor='black', # 点的边框色
         markerfacecolor='#ff9999', # 点的填充色
         label = 'udp') # 添加标签
        
plt.title("流量协议分布统计折线图")
plt.xlabel("时间")
plt.ylabel("数据包个数")
plt.grid()
plt.legend(prop={'size':18})
plt.show()