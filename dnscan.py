#!/usr/bin/env python3
"""dnscan.py - Domain Name scanner

Usage:
    dnscan.py check <domain>
"""
import gzip
import socket

import docopt
import dns


__version__ = '20.06.12'

#class HostCache():
#    def __init__(self):
#        # ensure 'hosts.gz' file exists
#        open('hosts.gz', 'a').close()
#
#        self.cache = {}
#        with gzip.open('hosts.gz') as fin: 
#            for ip_host in fin.readlines():
#                ip, host = ip_host.decode().strip().split('\t')
#                self.cache[host] = ip
#
#        self.fw = gzip.open('hosts.gz', 'a')
#
#    def __del__(self):
#        self.fw.close()
#
#    def exist(self, host):
#        return host in self.cache
#
#    def add(self, host, ip):
#        self.fw.write(f'{ip}\t{host}\n'.encode())
#
#
#def hosts_to_scan():
#    for n in range(99999999):
#        host = str(n)+'.com'
#        yield host
#
#
#def cmd_scan(args):
#    cache = HostCache()
#    # scan
#    for host in hosts_to_scan():
#        if cache.exist(host):
#            continue
#        ip = get_dns_record(host) or 'none'
#        cache.add(host, ip)
#        print(f'{ip}\t{host}')



def get_dns_record(host):
    "Return IP of the host or None"
    try:
        ip = socket.gethostbyname(host)
        return ['A', ip]
    except socket.gaierror:
        pass


def cmd_check(domain):
    rec = get_dns_record(domain)
    print(f"DNS A-record for '{domain}': {rec}")

def main(args):
    if args['check']:
        return cmd_check(args['<domain>'])
    else:
        raise NotImplementedError()

if __name__ == '__main__':
    args = docopt.docopt(__doc__, version = "dnscan.py "+__version__)
    main(args)
