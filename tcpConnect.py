###########################################################################
#
# Need Python version 2.x, scapy, and python module sys installed on system
#
# Usage: python tcpConnect.py [hostname] [port]
#
# For example:   python tcpConnect.py google.com 80
#
###########################################################################


from socket import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL) #Supress scapy info level messages
from scapy.all import *
import sys

def tcp_connect(host, port):
    print "[+] Performing TCP Connect Scan against " + str(host) +" on port "+ str(port) + "\n";
    try:
        dst_ip = host
        src_port = random.randint(1,65535)
        dst_port = port

        tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport = src_port,dport = dst_port,flags="S"),timeout=10)
        if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):

            print("[+] Port " + str(dst_port) + " is open.")

        elif(tcp_connect_scan_resp.haslayer(TCP)):
            if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
                print("[+] Port" + str(dst_port) + " is open.")

            elif(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                print("[+] Port" + str(dst_port) + " is closed.")

    except IOError as e:
        print(e)

if __name__=="__main__":
    if len(sys.argv) < 2:
        print "Usage: python tcpConnect.py [hostname] [port]"
    else:
        hostname = str(sys.argv[1])
        portnum = int(sys.argv[2])
        tcp_connect(hostname, portnum)
