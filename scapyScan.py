#!/usr/bin/env python3

from socket import *
from optparse import OptionParser
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

"""
Actual port scanner.
Takes four arguments host, port, timeout, and protocol.
Returns 1024 bits of data grabbed from socket conenct as banner.
"""

def tcp_connect(host, port, timeout):
    print "[+] Performing TCP Connect Scan." + "\n";
    try:
        dst_ip = host
        src_port = RandShort()
        dst_port = port
        #timeoutx=timeout

        tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport = src_port,dport = dst_port,flags="S"),timeout=10)
        if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
            print "[+] Port" + str(dst_port) + " is open."

        elif(tcp_connect_scan_resp.haslayer(TCP)):
            if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
                print "[+] Port" + str(dst_port) + " open"

            elif(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                print "[+] Port" + str(dst_port) + " closed"

    except IOError as e:
        print(e)

if __name__=="__main__":

#Defining our OptionsParser.

    parser = OptionParser()
    parser.add_option("-t", "--target", dest="host", type="string", metavar="target.com")
    parser.add_option("-p", "--ports", dest="ports", type="string", help="Ports separated by commas.")
    parser.add_option("-s", "--timeout", dest="timeoutx", type="int", metavar="[timeout in seconds]")
    parser.add_option("-S", "--scantype", dest="scantype", type="string", metavar="TCP Connect, TCP Stealth, XMAS, or FIN scan.", default="TCP Connect")
    #parser.add_option("-T", "--TCP", dest="stream", metavar="TCP", action = "store_true", default=True)
    #parser.add_option("-U", "--UDP", dest="datagram", metavar="UDP", action = "store_true", default=False)
    (options, args) = parser.parse_args()

    if options.host == None or options.ports == None:
            parser.print_help()
    else:
            host = options.host
            ports = (options.ports).split(",")
            #timeout = options.timeout

           # if options.timeout == None:
            #    timeout = 10    #Our default timeout will be at 10 sec.
            #else:
             #   timeout = options.timeout
            #let's perform a portscan.
            for port in ports:
                print("[+] Scanning port " + port)
                tcp_connect(host, int(port), timeout)

