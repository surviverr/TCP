from scapy.all import *
import matplotlib.pyplot as plt
import pdb
import socket
import sys



FILE_TO_READ = '/home/vagrant/server.pcap'
if len(sys.argv)>=2:
	FILE_TO_READ = sys.argv[1]
print("正在使用 %s 抓包结果绘图"%FILE_TO_READ)

packets = rdpcap(FILE_TO_READ)
seq_list = []
times = []
base_time = 0
server_port = 20218
num_packets = 0

i = 0
for packet in packets:
	payload = packet[Raw].load

	if(IP in packet and packet[IP].dport == server_port):
		num_packets = num_packets + 1

		seq_num = int.from_bytes(payload[4:8], byteorder='big')
		pkt_len = int.from_bytes(payload[14:16], byteorder='big')
		if pkt_len <= 20:
			continue
		
		packet_time = packet.time
		if base_time == 0:
			base_time = packet_time

		seq_list.append(seq_num)
		times.append(packet_time - base_time)
	else:
		print("Catch")

	i += 1
	if i == 200:
		break


plt.plot(times, seq_list)
plt.xlabel('Time (s)', fontdict={'size':24})
plt.ylabel('Sequence Number', fontdict={'size':24})
plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig('/vagrant/tju_tcp/test/SeqNum_VS_Time.png', dpi=600)
print("绘制成功, 图像位于/vagrant/tju_tcp/test/SeqNum_VS_Time.png")
