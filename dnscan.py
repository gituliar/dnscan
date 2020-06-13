#!/usr/bin/env python3
"""dnscan.py - Domain Name scanner

Usage:
    dnscan.py check <domain>
    dnscan.py scan
"""
import gzip
import os
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


class ZoneFile():
    def __init__(self, path):
        self.zonefile = open(path, 'r')

    def __del__(self):
        if hasattr(self, 'zf') and self.zonefile:
            self.zonefile.close()

    def find(self, domain):
        dns_records = []
        for rec in self.zonefile:
            rec = rec.strip()
            if rec.startswith(domain):
                dns_records.append(rec)
        return dns_records

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

def open_zonefile(filename):
    "Helper to open Zone Files relative to the current module"
    return ZoneFile(os.path.join(MODULE_DIR, filename))

ZONE_NET = open_zonefile('zone/net')

def get_dns_record(domain):
    return (get_dns_record_a(domain) or []) + (get_dns_record_mx(domain) or []) + (get_dns_record_ns(domain) or [])

def get_dns_record_a(domain):
    "Return list of domain's DNS A-records"
    try:
        ip = socket.gethostbyname(domain)
        print(f'{domain} = {ip}')
        return [('A', ip)]
    except socket.gaierror:
        return []
    except Exception as err:
        print(f'ERROR: {err}')
        return None

    resp = dns_query(domain, 'A')
    if resp is not None:
        return [('A', a_rec.address) for a_rec in resp]

def get_dns_record_mx(domain):
    "Return list of domain's DNS MX-records"
    resp = dns_query(domain, 'MX')
    if resp is not None:
        return [('MX', str(mx_rec.exchange), mx_rec.preference) for mx_rec in resp]

def get_dns_record_ns(domain):
    "Return list of domain's DNS NS-records"
    if not domain.endswith('.net'):
        print('Warning: DNS Zone File lookup works with .NET domains only')
        return []
    dns_records = []
    for rec in ZONE_NET.find(domain):
        v = rec.split('\t')
        dns_records += [(v[-2].upper(), v[-1])]
    return dns_records

def dns_query(domain, rdtype):
    "Wrapper for dnspython's query logic"
    try:
        a_resp = dns.resolver.query(domain, rdtype)
    except dns.resolver.NXDOMAIN as err:
        a_resp = [] # No records
    except Exception as err:
        print(f"ERROR: {err}")
        return None


def get_whois_record(domain):
    "Return domain's WHOIS record"
    HOST, PORT = 'whois.verisign-grs.com', 43

    if not domain.endswith('.com'):
        print('Warning: WHOIS lookup works with .COM domains only')
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
        s.sendall(bytes(domain+'\r\n', 'utf-8'))
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
    dns_rec = get_dns_record(domain)
    print(f"DNS records (A/MX/NS) for '{domain}': {dns_rec}")
    whois_rec = get_whois_record(domain)
    print(f"WHOIS record for '{domain}': {whois_rec}")


def int_com():
    for n in range(99999999):
        host = str(n)+'.com'
        yield host

def cmd_scan(domains_to_scan=int_com()):
    cache_filename = os.path.join(MODULE_DIR, 'dnscan.cache')

    try:
        with open(cache_filename, 'r') as fr:
            cache = [domain.strip() for domain in fr.readlines()]
    except FileNotFoundError:
        cache = []

    print('Available domains:')
    with open(cache_filename, 'a') as fw:
        for domain in domains_to_scan:
            if domain in cache:
                continue
            print(domain)
            #if get_dns_record_a(domain) or get_dns_record_mx(domain) or get_whois_record(domain):
            if get_whois_record(domain):
                fw.write(domain+'\n')
                continue
            # Found free domain
            print(f'{d}')
            break


def main(args):
    if args['check']:
        return cmd_check(args['<domain>'])
    elif args['scan']:
        return cmd_scan()
    else:
        raise NotImplementedError()

if __name__ == '__main__':
    args = docopt.docopt(__doc__, version = "dnscan.py "+__version__)
    main(args)
