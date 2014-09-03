from socket import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL) #Supress scapy info level messages
from scapy.all import *

def tcp_connect(host, port):
    print "[+] Performing TCP Connect Scan." + "\n";
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
    tcp_connect("192.168.0.1", 80)



