#!/usr/bin/env python3

from socket import *
from optparse import OptionParser


"""
Actual port scanner.
Takes four arguments host, port, timeout, and protocol. 
Returns 1024 bits of data grabbed from socket conenct as banner.
"""
def scanner(host, port, timeout):
    try:
        if options.stream:
            sock=socket(AF_INET, SOCK_STREAM) #Doing a TCP connect
        if options.datagram:
            sock=socket(AF_INET, SOCK_DGRAM) #Doing a UDP connect
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(2024)
        print(banner)
    except IOError as e:
        print(e)

if __name__=="__main__":

#Defining our OptionsParser.

    parser = OptionParser()
    parser.add_option("-t", "--target", dest="host", type="string", metavar="target.com")
    parser.add_option("-p", "--port", dest="port", type="int", metavar="PORT")
    parser.add_option("-s", "--timeout", dest="timeout", type="int", metavar="[timeout in seconds]")
    parser.add_option("-T", "--TCP", dest="stream", metavar="TCP", action = "store_true", default=True)
    parser.add_option("-U", "--UDP", dest="datagram", metavar="UDP", action = "store_true", default=False)
    (options, args) = parser.parse_args()

    if options.host == None or options.port == None:
	    parser.print_help()
    else:
	    host = options.host
	    port = options.port
	    timeout = options.timeout
            
	    if options.timeout == None:
            	timeout = 10    #Our default timeout will be at 10 sec.
	    else:
	     	timeout = options.timeout

            #let's perform a portscan.
	    scanner(host, port, timeout)
