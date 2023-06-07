#!/usr/bin/python3

# This program is developed by Mr.Laxmikant Yadav under guidance from Prof Dylan Smith, incase any support needed do contact me at laxmikant.yadav@mycit.ie 
# For the devlopment of this programm, I referred https://scapy.readthedocs.io/en/latest/usage.html#advanced-sniffing-sniffing-sessions as well as from https://stackoverflow.com/

# This program is based on four functions: Main Function, Help Function, active_scan and passive_scan
#Note, Sniff function of scappy is used in the Passive Scan, while active scan is mainly based on the outcome of ans variable.
#       Once run it will display a welocme message and  Programm to be initaited by Main function, Help function will provide the support to user for using the tool. 
#       Active scan will scan and display all the live IP address in the IP adress user want to scan, user require to provide the ip Subnet or ip address as a input to the tool once asked for.Active scan will list the IP's as a output if any Ip will rechable in ICMP ping else it will show an empty table and quit the program.





# Main Coding for this tool will satrt from this section onwards:

from scapy.all import *
import sys
import os

#Help Function, will help user to understand the working of tool. It will guide user about the functions available, the arguments and information needed to run the Tool.
def help():
	print("\nThis tool to be used for Network Reconnaissance, it can be used for:\n1. Active Mode Scanning\n2. Passive Mode Scanning")
	print("\nRefer below information for more details:","\n1. For Active scan, pass an argument either '-a' or '--active'","\n2. For Passive scan,pass an argument either '-p' or'--Passive' ","\n3. Specify, Inteface details by sending argument either '-i' or '--iface'\n")
	print("\nSample Cli:\nFor active Mode 'net_recon.py -i enp0s3 -a'\nFor Passive Mode net_recon.py -i enp0s3 -p\n")
 

#passive_scan, this function of tool will scan  monitor the ARP traffic on the interface provided
def passive_scan(iface):
	list=[]
	host_activity={}
	def sniffing(iface):
		sniff(iface=iface,prn=process_sniffed_packet,filter='arp')
	def process_sniffed_packet(Packet):
		for i in Packet[ARP]:
			if(i.op==2):
				if [i.hwsrc,i.psrc] not in list:
					list.append([i.hwsrc,i.psrc])
				if i.psrc in host_activity:
					host_activity[i.psrc] = host_activity[i.psrc]+1
				else:
					host_activity[i.psrc] = 1
				os.system('clear')
				print("Interface:",iface,"\t\t\tMode: Passive","\t\t\t Found:",len(list)," Hosts")
				print("-" *90,'\n'"MAC Address","\t\t\t\t","IP Address","\t\t\t","Host Activity"'\n',"-"*90)
				for i in list:
					print(i[0],"\t\t\t",i[1],"\t\t\t",host_activity[i[1]])
				
	sniffing(iface)
	
#active_scan, this function of tool will scan monitor the ARPffic on the active ports in network
def active_recon(iface,IPinterface):
	ans,unans= sr(IP(dst=IPinterface)/ICMP(),timeout=1,verbose=0)
	for i in ans:
		print(i[1].src)

	
#Main Function of tool
def main():
	print("\n\nWelcome to Network Reconnaissance tool !!!\n")
	iface=str(input("Mention Interface: "))
	print("\nSelect from below options to move forward:\n - Active Scan >> '-a' or '--active'\n - Passive Scan >> '-p' or '--passive'\n - Help >> 'Help'\n")
	choice=str(input("Option Choosed: "))
	if choice.lower()== '-a' or choice.lower()=='--active':
			print("\nProvide valid IP address to be scanned in next step.\nUse format IP Network/Subnet Mask (e.g. 192.168.0.1/24) or mention IP Address (192.168.0.1)\n")
			IPinterface=str(input("Enter the IP Address: "))
			print('\n',"-"*25,"Active Network Scan Mode Output","-"*25,'\n')
			print("Interface:",iface,"\t\t\tMode: Active")
			print("-" *90,'\n'"IP Address"'\n',"-"*90)
			active_recon(iface,IPinterface)
			
	elif choice.lower()== '-p' or choice.lower()=='--passive':
			print('\n',"-" * 25,"Passive Network Scan Mode Output","-" * 25,'\n')
			passive_scan(iface)
	else:
			help()
main ()
