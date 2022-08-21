from scapy.all import *
from scapy.layers import http
import atexit 
import matplotlib.pyplot as plt
import subprocess


def scan_network(IPAddr):
	jadu=[]
	jadu.append(IPAddr.split('.'))
	subnet_IP= jadu[0][0]+"."+jadu[0][1] +"."+jadu[0][2]+"."+"0/24"
	subprocess.call("nmap -sn "+ subnet_IP, shell="True")


def pkt_count():
		
	global udp_count, icmp_count,tcp_count,http_count
	topic = ['UDP', 'ICMP', 'TCP', 'HTTP', 'ATTACK']
	Postive_percentage = []
	Postive_percentage.append(udp_count)
	Postive_percentage.append(icmp_count)
	Postive_percentage.append(tcp_count)
	Postive_percentage.append(http_count)
	Postive_percentage.append(0)
	sizes = Postive_percentage
	print(sizes)
	labels = list(topic)
	# makeitastring = ''.join(map(str, labels))
	print(labels)
	colors = ['yellowgreen', 'lightgreen', 'darkgreen', 'gold', 'red']
	plt.pie(sizes, explode=None, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=90)   #line 240
	#plt.pie(sizes, labels, colors)
	plt.axis('equal')
	plt.legend()
	plt.show()


def network_monitoring_for_visualization_version(pkt):
	if pkt.haslayer(UDP):
		global udp_count
		udp_count=udp_count+1
		try:
			print("--------------UDP PACKET----------------")
			print("UDP PKT FROM SRC >>", pkt[IP].src + " TO dst >>"+ pkt[IP].dst)
			try:
				print("----------DATA--------------")
				print(pkt[Raw].load)
			except IndexError:
				print("NONE")
		except IndexError:
			print("--------------UDP PACKET----------------")
			print("UDP PKT FROM SRC >>", pkt[IPv6].src + " TO dst >>"+ pkt[IPv6].dst)
			try:
				print("----------DATA---------------")
				print(pkt[Raw].load)
			except IndexError:
				print("NONE")	

	if pkt.haslayer(ICMP) and str(pkt.getlayer(ICMP).type)=="8":
		global icmp_count
		icmp_count=icmp_count+1
		print("--------------ICMP PACKET----------------")
		print("ICMP REQUEST FROM SRC >>", (pkt[IP].src) ," TO DESTINATION >> ", pkt[IP].dst)


	if pkt.haslayer(TCP):
		global tcp_count
		tcp_count= tcp_count+1
		try:
			print("--------------TCP PACKET----------------")
			print("TCP PKT FROM SRC >> ", pkt[IP].src + " TO dst >> "+ pkt[IP].dst)
			print()
			try:
				print("-------DATA IN TCP PACKET -------")
				#print(pkt[Raw])
			except IndexError:
				print("None")
		except IndexError:
			print("--------------TCP PACKET----------------")
			print("TCP PKT FROM SRC >>", pkt[IPv6].src + "TO dst >>"+ pkt[IPv6].dst)
			print()
			try:
				print("------DATA IN TCP PACKET ---------")
				#print(pkt[Raw])
			except IndexError:
				print("None")

	if pkt.haslayer(http.HTTPRequest):
		global http_count
		http_count=http_count+1
		print("--------------HTTP PACKET----------------")
		print("HTTP Request >>", pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path)
		try:
			print(pkt[Raw].load)
		except IndexError:
			print("None")



if __name__ == '__main__':
	udp_count=0
	icmp_count=0
	tcp_count=0
	http_count=0
	#IPAddr=raw_input("enter IP of machine >> ")
	#scan_network(IPAddr)
	try :	
		sniff(prn=network_monitoring_for_visualization_version)	
		atexit.register(pkt_count)
	except KeyboardInterrupt:
		print("Exiting.......")
