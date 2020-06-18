#!/usr/bin/env python3
"""dnscan.py - Domain Name scanner

Usage:
    dnscan.py check <domain>
    dnscan.py [-v] min <tld>
"""
import gzip
import os
import socket
import sys

try:
    import dns.resolver
    import docopt
except ModuleNotFoundError as err:
    print(f'Error: {err}.')
    print('Hint: Resolve with')
    print('$ pip3 install dnspython docopt\n')
    exit(1)

__version__ = '20.06.18'


class ZoneFile():
    def __init__(self, path):
        try:
            self.zonefile = open(path, 'r')
        except FileNotFoundError:
            self.zonefile = []

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

    root_domain = domain.split('.')[-1]
    if root_domain not in ('com', 'net'):
        print('Warning: WHOIS lookup works with .COM or .NET domains only')
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


def int_tld(tld):
    for n in range(99999999):
        host = str(n)+'.'+tld
        yield host

def cmd_min(tld, verbose=False):
    prnt = print if verbose else lambda msg: None
    domains_to_scan = int_tld(tld)

    cache_filename = os.path.join(MODULE_DIR, f'dnscan.cache.{tld}.gz')
    try:
        with gzip.open(cache_filename, 'r') as fr:
            prnt(f"Read cache at {cache_filename}")
            # get only domains
            cache = set([rec.decode().strip().split('\t', 1)[0] for rec in fr.readlines()])
    except FileNotFoundError:
        prnt(f"No cache at '{cache_filename}'")
        cache = []

    prnt('Start WHOIS scanning')
    with gzip.open(cache_filename, 'a') as fw:
        for domain in domains_to_scan:
            if domain in cache:
                continue
            whois_rec = get_whois_record(domain)
            if whois_rec:
                rec = ';'.join(f"{key}={val}" for key,val in whois_rec.items())
                fw.write(f"{domain}\tWHOIS\t{rec}\n".encode())
                continue
            # Found free domain
            print(f'{domain}')
            break


def main(args):
    #print(f"dnscan.py v{__version__}")
    if args['check']:
        return cmd_check(args['<domain>'])
    elif args['min']:
        return cmd_min(args['<tld>'], args['-v'])
    else:
        raise NotImplementedError()

if __name__ == '__main__':
    args = docopt.docopt(__doc__)
    try:
        main(args)
    except KeyboardInterrupt:
        pass
