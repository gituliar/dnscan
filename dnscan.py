#!/usr/bin/env python3
"""dnscan.py - Domain Name scanner

Usage:
    dnscan.py check <domain>
"""
import gzip
import socket
import sys

try:
    import docopt
    import dns.resolver
except ModuleNotFoundError as err:
    print(f'Error: {err}.')
    print('Hint: Resolve with')
    print('    $ pip install dnspython docopt\n')
    exit(1)

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



def get_dns_records(host):
    "Return list of DNS (A/MX) records"
    recs = []

    # A-record
#    try:
#        ip = socket.gethostbyname(host)
#        recs += [('A', ip)]
#    except socket.gaierror:
#        pass

    a_resp = []
    try:
        a_resp = dns.resolver.query(host, 'A')
    except dns.resolver.NXDOMAIN as err:
        # No A-record exists
        pass
    for a_rec in a_resp:
        recs += [('A', a_rec.address)]

    # MX-record
    mx_resp = []
    try:
        mx_resp = dns.resolver.query(host, 'MX')
    except dns.resolver.NXDOMAIN as err:
        # No MX-record exists
        pass
    for mx_rec in mx_resp:
        recs += [('MX', str(mx_rec.exchange), mx_rec.preference)]

    return recs


def get_whois_record(host):
    "Return WHOIS record for the host"
    HOST, PORT = 'whois.verisign-grs.com', 43

    if not host.endswith('.com'):
        print('Warning: only .COM domains has WHOIS support')
        return None
    
    s = None
    for res in socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except OSError as msg:
            s = None
            continue
        try:
            s.connect(sa)
        except OSError as msg:
            s.close()
            s = None
            continue
        break
    if s is None:
        return None
    with s:
        s.sendall(bytes(host+'\r\n', 'utf-8'))
        data = s.recv(1024)
    rec = data.decode('utf-8')

    if rec.startswith('No match'):
        return None

    def val(rec, field):
        for r in rec.split('\r\n'):
            r = r.strip()
            if r.startswith(field):
                _, value = r.split(':', 1)
                return value.strip()

    rec = {
        'create': val(rec, 'Creation Date'),
        'expiry': val(rec, 'Registry Expiry Date'),
    }

    return rec


def cmd_check(domain):
    dns_rec = get_dns_records(domain)
    print(f"DNS records (A/MX) for '{domain}': {dns_rec}")
    whois_rec = get_whois_record(domain)
    print(f"WHOIS record for '{domain}': {whois_rec}")

def main(args):
    if args['check']:
        return cmd_check(args['<domain>'])
    else:
        raise NotImplementedError()

if __name__ == '__main__':
    args = docopt.docopt(__doc__, version = "dnscan.py "+__version__)
    main(args)
