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
import time

try:
    import dns.resolver
    import docopt
except ModuleNotFoundError as err:
    print(f'Error: {err}.')
    print('Hint: Resolve with')
    print('$ pip3 install dnspython docopt\n')
    exit(1)

__version__ = '20.06.23'

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


class WhoisRecordError(Exception):
    def __init__(self, key, domain, record):
        self.key = key
        self.domain = domain
        self.record = record

    def __str__(self):
        return f"No key '{self.key}' in WHOIS record for '{self.domain}'"



def cmd_check(domain):
    subdomain, tld = domain.split('.', 1)

    dns_rec = DnsClient().get_record(domain)
    print(f"DNS records (A/MX) for '{domain}': {dns_rec}")

    whois_rec = WhoisClient(tld).get_record(domain)
    print(f"WHOIS record for '{domain}': {whois_rec}")


def int_tld(tld):
    for n in range(99999999):
        host = str(n)+'.'+tld
        yield host

class CacheFile():
    def __init__(self, path):
        try:
            with gzip.open(path, 'r') as fr:
                print(f"Read cache at {path}")
                # get only domains
                self.keys = set([rec.decode().strip().split('\t', 1)[0] for rec in fr.readlines()])
        except FileNotFoundError:
            print(f"No cache at '{path}'")
            self.keys = set()
        except OSError as err:
            print('ERROR: {err}')
            self.keys = set()

        self.fw = gzip.open(path, 'a')

    def __del__(self):
        if self.fw:
            self.fw.close()

    def exist(self, key):
        return key in self.keys

    def put(self, key, val):
        self.keys.add(key)
        self.fw.write(f'{key}\t{val}\n'.encode())
        

class DnsClient():
    def __init__(self):
        pass

    def get_record(self, domain):
        return (self.get_dns_record_a(domain) or []) + (self.get_dns_record_mx(domain) or [])

    def get_dns_record_a(self, domain):
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
    
        resp = self.dns_query(domain, 'A')
        if resp is not None:
            return [('A', a_rec.address) for a_rec in resp]
    
    def get_dns_record_mx(self, domain):
        "Return list of domain's DNS MX-records"
        resp = self.dns_query(domain, 'MX')
        if resp is not None:
            return [('MX', str(mx_rec.exchange), mx_rec.preference) for mx_rec in resp]
    
    def dns_query(self, domain, rdtype):
        "Wrapper for dnspython's query logic"
        try:
            a_resp = dns.resolver.query(domain, rdtype)
        except dns.resolver.NXDOMAIN as err:
            a_resp = [] # No records
        except Exception as err:
            print(f"ERROR: {err}")
            return None
    

class WhoisClient():
    HOST = {
        'com': {'host': 'whois.verisign-grs.com', 'limit': None},
        'net': {'host': 'whois.verisign-grs.com', 'limit': None},
        'io': {'host': 'whois.nic.io', 'limit': 30}
    }

    def __init__(self, tld):
        if tld not in self.HOST:
            raise Exception(f"WHOIS lookup does not work for '{tld}', supported domains are {self.HOST.keys()}")

        self.host = self.HOST[tld]['host']
        self.limit = self.HOST[tld]['limit']
        self.tld = tld

    def get_record(self, domain):
        "Return domain's WHOIS record"
        host, port = self.host, 43
        
        s = None
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
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

        if self.limit is not None:
            time.sleep(60/self.limit)
        with s:
            s.sendall(bytes(domain+'\r\n', 'utf-8'))
            data = s.recv(1024).decode('utf-8')

        # Parse WHOIS data
    
        def val(data, key):
            for r in data.split('\r\n'):
                r = r.strip()
                if r.startswith(key):
                    _, value = r.split(':', 1)
                    return value.strip()
            raise WhoisRecordError(key, domain, data)

        error = None

        # Option 1
        if data.startswith('No match'):
            return None
    
        # Option 2
        try:
            rec = {
                'create': val(data, 'Creation Date'),
                'expiry': val(data, 'Registry Expiry Date'),
            }
        except WhoisRecordError as err:
            error = err

        # Option 3
        if data.find('Reserved by the registry') >= 0:
            return {'status': 'reserved'}

        # Finalize
        if error:
            raise error

    
        return rec

class DomainResolver():
    obj = None

    @classmethod
    def instance(cls):
        if cls.obj is None:
            cls.obj = DomainResolver()
        return cls.obj

    def __init__(self):
        self.cache = {}

    def get_cache(self, tld, label):
        key = tld + '.' + label
        if key not in self.cache:
            self.cache[key] = CacheFile(os.path.join(MODULE_DIR, f'cache/{tld}.{label}.gz'))
        return self.cache[key]

    def exist(self, subdomain, tld):
        domain = subdomain + '.' + tld

        cache_dns = self.get_cache(tld, 'dns')
        if cache_dns.exist(domain):
            return True
        cache_whois = self.get_cache(tld, 'whois')
        if cache_whois.exist(domain):
            return True


        whois = WhoisClient(tld)
        whois_rec = whois.get_record(domain)
        print(f'{domain} :: {whois_rec}')
        if whois_rec:
            rec = ';'.join(f"{key}={val}" for key,val in whois_rec.items())
            cache_whois.put(domain, rec)
            return True

        return False

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
    r = DomainResolver.instance()

    for domain in domains_to_scan:
        subdomain = domain[:-len(tld)-1]
        try:
            domain_exist = r.exist(subdomain, tld)
        except WhoisRecordError as err:
            print(err)
            print(err.record)
            return

        if not domain_exist:
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
