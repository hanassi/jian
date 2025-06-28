#!/usr/bin/python

from socket import *
import optparse
from threading import *


#2020626 udemy
def connscan(tgt_host, tgt_port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((tgt_host, tgt_port))
        print(f"[+] {tgt_port}/tcp Open")
    except:
        print(f"[-] {tgt_port}/tcp Closed")

def portscan(tgt_host, tgt_ports):
        try:
                tgt_ip = gethostbyname(tgt_host)
        except:
                print(f"Unknown Host {tgt_host}")
        try:
                tgt_name = gethostbyaddr(tgt_ip)
                print(f"[+] Scan Results for : {tgt_name[0]}")
        except:
               print(f"[+] Scan Results for : {tgt_ip}")
        setdefaulttimeout(1)
        for tgt_port in tgt_ports:
            t = Thread(target=connscan, args=(tgt_host, int(tgt_port)))
            t.start()


def main():
        parser = optparse.OptionParser('Usage of program: ' + '-H <target host> -p <target port>')
        parser.add_option('-H', dest='tgt_host', type='string', help='specify target host')
        parser.add_option('-p', dest='tgt_port', type='string', help='specify target ports seperated by comma')
        (options, args) = parser.parse_args()
        tgt_host = options.tgt_host
        tgt_ports = str(options.tgt_port).split(',')
        if (tgt_host is None) | (tgt_ports[0] is None):
                print(parser.usage)
                exit(0)
        portscan(tgt_host, tgt_ports)

if __name__ == '__main__':
        main()
