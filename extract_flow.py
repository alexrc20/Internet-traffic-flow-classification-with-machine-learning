import argparse , sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import datetime
import socket 
from decimal import Decimal

class clase:
	def __init__(self, ipsrc,ipdest,srcport,dstport, count, lenght,active,urgf,ackf,pshf,rstf,synf,finf, app):
         self.ipsrc = ipsrc
         self.ipdest = ipdest
         self.srcport = srcport
         self.dstport = dstport
         self.count = count
         self.lenght = lenght
         self.active = active
         self.urgf = urgf
         self.ackf = ackf
         self.pshf = pshf
         self.rstf = rstf
         self.synf = synf
         self.finf = finf
         self.app = app



count = 0
lenght = 0
old_time =0
lista = [99]

flag_urg =0
flag_ack =0
flag_psh =0
flag_rst =0
flag_syn =0
flag_fin =0	

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80



pkts = rdpcap("/Users/alejandroromerodelcampo/Documents/uni/TFG/malware/conversion_flujos/trafico_uam_hackado.pcap")

for pkt in pkts:
	if pkt.haslayer(IP):
		if pkt.haslayer(TCP):

			F = pkt[TCP].flags    # this should give you an integer

			if F & URG:
				flag_urg=1
    		# FIN flag activated
			if F & ACK:
				flag_ack=1
    		# SYN flag activated
			# rest of the flags here
			if F & PSH:
				flag_psh=1

			if F & RST:
				flag_rst=1

			if F & SYN:
				flag_syn=1

			if F & FIN:
				flag_fin=1


			coincidencias = 0
			if count == 0:
				if pkt[TCP].dport == 80 or pkt[TCP].dport == 22:
					lista[count] = clase(pkt[IP].src, pkt[IP].dst , pkt[TCP].sport, pkt[TCP].dport,0, 0,0, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, socket.getservbyport(pkt[TCP].dport))
				else :
					lista[count] = clase(pkt[IP].src, pkt[IP].dst , pkt[TCP].sport, pkt[TCP].dport,0, 0,0, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, "unknown")
				count +=1
				lenght +=len(pkt)
				coincidencias = 0


			for i in range(count):
				if ((pkt[IP].src==lista[i].ipsrc) and (pkt[IP].dst==lista[i].ipdest) and (pkt[TCP].sport==lista[i].srcport) and (pkt[TCP].dport==lista[i].dstport)):
					lista[i].count+=1
					lista[i].lenght+=len(pkt)
					lista[i].active += ((datetime.datetime.utcfromtimestamp(pkt.time)-datetime.datetime.utcfromtimestamp(old_time)).microseconds)
					coincidencias=1


			if coincidencias==0:
				if pkt[TCP].dport == 80 or pkt[TCP].dport == 22:
					lista.append(clase(pkt[IP].src,pkt[IP].dst ,pkt[TCP].sport, pkt[TCP].dport,1,len(pkt),((datetime.datetime.utcfromtimestamp(pkt.time)-datetime.datetime.utcfromtimestamp(old_time)).microseconds) , flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, socket.getservbyport(pkt[TCP].dport)))
				else: 
					lista.append(clase(pkt[IP].src,pkt[IP].dst ,pkt[TCP].sport, pkt[TCP].dport,1,len(pkt),((datetime.datetime.utcfromtimestamp(pkt.time)-datetime.datetime.utcfromtimestamp(old_time)).microseconds) , flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, "unknown"))
				count+=1
			old_time = pkt.time

for i in range(count):
	print "6," + str(lista[i].srcport) + ',' + str(lista[i].dstport) + ',' + str(lista[i].count) + "," + str(lista[i].lenght) + "," + str(Decimal((lista[i].active)/1000000.0)) + "," + str(lista[i].urgf) + "," + str(lista[i].ackf) + "," + str(lista[i].pshf) + "," + str(lista[i].rstf) + "," + str(lista[i].synf) + "," + str(lista[i].finf) +  "," + str(lista[i].app) + "," + "nmap-tcp"


			







	

