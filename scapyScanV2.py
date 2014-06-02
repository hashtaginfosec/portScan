#!/usr/bin/env python

from socket import *
from optparse import OptionParser
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from array import array

"""
Actual port scanner.
Takes four arguments host, port, timeout, and protocol.
Returns 1024 bits of data grabbed from socket conenct as banner.
"""

#TCP Connect Scan

def tcp_connect(host, port, timeout, results):
    print "[+] Performing TCP Connect Scan." + "\n";
    try:
        dst_ip = host
        src_port = random.randint(1,65535)
        dst_port = port
        #timeoutx=timeout

        tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport = src_port,dport = dst_port,flags="S"),timeout=10)
        if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
            print "[+] Port open."
            results.append("[+] Port " + str(dst_port) + " is open.")

        elif(tcp_connect_scan_resp.haslayer(TCP)):
            if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
                print "[+] Port open"
                results.append("[+] Port" + str(dst_port) + " is open.")

            elif(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                print "[-] Port closed"
                results.append("[+] Port" + str(dst_port) + " is closed.")

    except IOError as e:
        print(e)

# TCP Stealth Scan


def tcp_stealth(host, port, timeout, results):
    print "[+] Performing TCP Stealth Scan." + "\n";
    try:
        dst_ip = host
        src_port = random.randint(1,65535)
        dst_port = port

        stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
        if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
            print "[+] Port filtered."
            results.append("[+] Port " + str(dst_port) + " is filtered.")

        elif(stealth_scan_resp.haslayer(TCP)):
            if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
                print "[+] Port open."
                results.append("[+] Port " + str(dst_port) + " is open.")

            elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                print "[+] Port closed."
                results.append("[+] Port " + str(dst_port) + " is closed.")

            elif(stealth_scan_resp.haslayer(ICMP)):
                if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    print "[+] Port filtered."
                    results.append("[+] Port " + str(dst_port) + " is filtered.")

    except IOError as e:
        print(e)



#TCP XMAS scan

def tcp_xmas(host, port, timeout, results):
    print "[+] Performing TCP XMAS Scan." + "\n";
    try:
        dst_ip = host
        src_port = random.randint(1,65535)
        dst_port = port
        #timeoutx=timeout

        xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=10)
        if(str(type(xmas_scan_resp))=="<type 'NoneType'>"):
            print "[+] Port open or filtered."
            results.append("[+] Port " + str(dst_port) + " is open/filtered.")

        elif(tcp_connect_scan_resp.haslayer(TCP)):
            if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                print "[-] Port closed"
                results.append("[+] Port" + str(dst_port) + " is closed.")
            elif(xmas_scan_resp.haslayer(ICMP)):
                if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    print "Port filtered"
                    results.append("[+] Port" + str(dst_port) + " is filtered.")


    except IOError as e:
        print(e)


#TCP FIN scan

def tcp_fin(host, port, timeout, results):
    print "[+] Performing TCP FIN Scan." + "\n";
    try:
        dst_ip = host
        src_port = random.randint(1,65535)
        dst_port = port

        fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=10)
        if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
            print "Port open or filtered"
            results.append("[+] Port" + str(dst_port) + " is open/filtered.")

        elif(fin_scan_resp.haslayer(TCP)):
            if(fin_scan_resp.getlayer(TCP).flags == 0x14):
                print "Closed"
            else:
                print "Port in unkown state"
                results.append("[+] Port" + str(dst_port) + " is unkown in state.")
    
        elif(fin_scan_resp.haslayer(ICMP)):
            if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                print "port filtered"
                results.append("[+] Port" + str(dst_port) + " is filtered.")
            else:
                print "Port in unkown state"
                results.append("[+] Port" + str(dst_port) + " is unkown in state.")

    except IOError as e:
        print(e)



if __name__=="__main__":

#Global list named results.
    #resutls=[]

#Defining our OptionsParser.

    parser = OptionParser()
    parser.add_option("-t", "--target", dest="host", type="string", metavar="target.com")
    parser.add_option("-p", "--ports", dest="ports", type="string", help="Ports separated by commas and no spaces.")
    parser.add_option("-s", "--timeout", dest="timeoutx", type="int", metavar="[timeout in seconds]")
    parser.add_option("-S", "--scantype", dest="scantype", type="string", metavar="(c) TCP Connect, TCP (s) Stealth, (x)XMAS, or (f) FIN scan.", default="TCP Connect")
    
    (options, args) = parser.parse_args()

    if options.host == None or options.ports == None:
            parser.print_help()
    else:
            host = options.host
            ports = (options.ports).split(",")
            results = []
            
#            print "You asked to perfrom " + scantype + "\n"
            for port in ports:
                print("[+] Scanning port " + port)
                if options.scantype=="c":
                    tcp_connect(host, int(port), timeout, results)
                if options.scantype=="s":
                    tcp_stealth(host, int(port), timeout, results)
                if options.scantype=="x":
                    tcp_xmas(host, int(port), timeout, results)
                if options.scantype=="f":
                    tcp_fin(host, int(port), timeout, results)
    
            for each_result in results:
                print "\n" + each_result
     
                

