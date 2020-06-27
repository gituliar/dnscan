#!/usr/bin/env python3
"""dnscan.py - Domain Name scanner

Usage:
    dnscan.py check <domain>
    dnscan.py [-v | -d] [-n <num>] min <tld>

Options:
    -n <num>    Show n smallest domains [default: 1]
"""
import gzip
import logging
import os
import socket
import sys
import time

log = logging.getLogger('dnsmin')

try:
    import dns.resolver
    import docopt
except ModuleNotFoundError as err:
    log.error(f'Error: {err}.')
    log.error('Hint: Resolve with')
    log.error('$ pip3 install dnspython docopt\n')
    exit(1)

__version__ = '20.06.27'

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


class WhoisParseError(Exception):
    def __init__(self, domain=None, whois_record=None):
        self.domain = domain
        self.whois_record = whois_record

    def __str__(self):
        if self.domain:
            return f'Failed to parse WHOIS data from {self.domain}'
        return f'Failed to parse WHOIS data'


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
                log.info(f"Read cache at {path}")
                # get only domains
                self.keys = set([rec.decode().strip().split('\t', 1)[0] for rec in fr.readlines()])
        except FileNotFoundError:
            log.warning(f"No cache at '{path}'")
            self.keys = set()
        except OSError as err:
            log.error('\n{err}')
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
            log.info(f'{domain} = {ip}')
            return [('A', ip)]
        except socket.gaierror:
            return []
        except Exception as err:
            log.error(f'\n{err}')
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
            log.error(f"\n{err}")
            return None
    

class WhoisClient():
    HOST = {
        #'ac': {'host': 'whois.nic.ac', 'limit': 30},
        #'ad': {'host': 'whois.ripe.net', 'limit': None},
        #'ae': {'host': 'whois.aeda.net.ae', 'limit': None},
        #'aero': {'host': 'whois.aero', 'limit': None},
        #'af': {'host': 'whois.nic.af', 'limit': None},
        #'ag': {'host': 'whois.nic.ag', 'limit': None},
        #'ai': {'host': 'whois.ai', 'limit': None},
        #'al': {'host': 'whois.ripe.net', 'limit': None},
        #'am': {'host': 'whois.amnic.net', 'limit': None},
        #'as': {'host': 'whois.nic.as', 'limit': None},
        #'asia': {'host': 'whois.nic.asia', 'limit': None},
        #'at': {'host': 'whois.nic.at', 'limit': None},
        #'au': {'host': 'whois.aunic.net', 'limit': None},
        #'aw': {'host': 'whois.nic.aw', 'limit': None},
        #'ax': {'host': 'whois.ax', 'limit': None},
        #'az': {'host': 'whois.ripe.net', 'limit': None},
        #'ba': {'host': 'whois.ripe.net', 'limit': None},
        #'bar': {'host': 'whois.nic.bar', 'limit': None},
        #'be': {'host': 'whois.dns.be', 'limit': None},
        #'berlin': {'host': 'whois.nic.berlin', 'limit': None},
        #'best': {'host': 'whois.nic.best', 'limit': None},
        #'bg': {'host': 'whois.register.bg', 'limit': None},
        #'bi': {'host': 'whois.nic.bi', 'limit': None},
        'biz': {'host': 'whois.neulevel.biz', 'limit': None},
        #'bj': {'host': 'www.nic.bj', 'limit': None},
        #'bo': {'host': 'whois.nic.bo', 'limit': None},
        #'br': {'host': 'whois.nic.br', 'limit': None},
        #'br.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'bt': {'host': 'whois.netnames.net', 'limit': None},
        #'bw': {'host': 'whois.nic.net.bw', 'limit': None},
        #'by': {'host': 'whois.cctld.by', 'limit': None},
        #'bz': {'host': 'whois.belizenic.bz', 'limit': None},
        #'bzh': {'host': 'whois-bzh.nic.fr', 'limit': None},
        #'ca': {'host': 'whois.cira.ca', 'limit': None},
        #'cat': {'host': 'whois.cat', 'limit': None},
        #'cc': {'host': 'whois.nic.cc', 'limit': None},
        #'cd': {'host': 'whois.nic.cd', 'limit': None},
        #'ceo': {'host': 'whois.nic.ceo', 'limit': None},
        #'cf': {'host': 'whois.dot.cf', 'limit': None},
        #'ch': {'host': 'whois.nic.ch', 'limit': None},
        #'ci': {'host': 'whois.nic.ci', 'limit': None},
        #'ck': {'host': 'whois.nic.ck', 'limit': None},
        #'cl': {'host': 'whois.nic.cl', 'limit': None},
        'cloud': {'host': 'whois.nic.cloud', 'limit': None},
        #'club': {'host': 'whois.nic.club', 'limit': None},
        #'cn': {'host': 'whois.cnnic.net.cn', 'limit': None},
        #'cn.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'co': {'host': 'whois.nic.co', 'limit': None},
        #'co.nl': {'host': 'whois.co.nl', 'limit': None},
        'com': {'host': 'whois.verisign-grs.com', 'limit': None},
        #'coop': {'host': 'whois.nic.coop', 'limit': None},
        #'cx': {'host': 'whois.nic.cx', 'limit': None},
        #'cy': {'host': 'whois.ripe.net', 'limit': None},
        #'cz': {'host': 'whois.nic.cz', 'limit': None},
        #'de': {'host': 'whois.denic.de', 'limit': None},
        #'dk': {'host': 'whois.dk-hostmaster.dk', 'limit': None},
        #'dm': {'host': 'whois.nic.cx', 'limit': None},
        #'dz': {'host': 'whois.nic.dz', 'limit': None},
        #'ec': {'host': 'whois.nic.ec', 'limit': None},
        #'edu': {'host': 'whois.educause.net', 'limit': None},
        ##'ee': {'host': 'whois.tld.ee', 'limit': None},
        #'eg': {'host': 'whois.ripe.net', 'limit': None},
        #'es': {'host': 'whois.nic.es', 'limit': None},
        #'eu': {'host': 'whois.eu', 'limit': None},
        #'eu.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'eus': {'host': 'whois.nic.eus', 'limit': None},
        #'fi': {'host': 'whois.fi', 'limit': None},
        #'fo': {'host': 'whois.nic.fo', 'limit': None},
        #'fr': {'host': 'whois.nic.fr', 'limit': None},
        #'gb': {'host': 'whois.ripe.net', 'limit': None},
        #'gb.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'gb.net': {'host': 'whois.centralnic.com', 'limit': None},
        #'qc.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'ge': {'host': 'whois.ripe.net', 'limit': None},
        #'gg': {'host': 'whois.gg', 'limit': None},
        #'gi': {'host': 'whois2.afilias-grs.net', 'limit': None},
        #'gl': {'host': 'whois.nic.gl', 'limit': None},
        #'gm': {'host': 'whois.ripe.net', 'limit': None},
        #'gov': {'host': 'whois.nic.gov', 'limit': None},
        #'gr': {'host': 'whois.ripe.net', 'limit': None},
        #'gs': {'host': 'whois.nic.gs', 'limit': None},
        #'gy': {'host': 'whois.registry.gy', 'limit': None},
        #'hamburg': {'host': 'whois.nic.hamburg', 'limit': None},
        #'hiphop': {'host': 'whois.uniregistry.net', 'limit': None},
        #'hk': {'host': 'whois.hknic.net.hk', 'limit': None},
        #'hm': {'host': 'whois.registry.hm', 'limit': None},
        #'hn': {'host': 'whois2.afilias-grs.net', 'limit': None},
        #'host': {'host': 'whois.nic.host', 'limit': None},
        #'hr': {'host': 'whois.dns.hr', 'limit': None},
        #'ht': {'host': 'whois.nic.ht', 'limit': None},
        #'hu': {'host': 'whois.nic.hu', 'limit': None},
        #'hu.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'id': {'host': 'whois.pandi.or.id', 'limit': None},
        #'ie': {'host': 'whois.domainregistry.ie', 'limit': None},
        #'il': {'host': 'whois.isoc.org.il', 'limit': None},
        #'im': {'host': 'whois.nic.im', 'limit': None},
        #'in': {'host': 'whois.inregistry.net', 'limit': None},
        #'info': {'host': 'whois.afilias.info', 'limit': None},
        #'ing': {'host': 'domain-registry-whois.l.google.com', 'limit': None},
        #'ink': {'host': 'whois.centralnic.com', 'limit': None},
        #'int': {'host': 'whois.isi.edu', 'limit': None},
        'io': {'host': 'whois.nic.io', 'limit': 30},
        #'iq': {'host': 'whois.cmc.iq', 'limit': None},
        #'ir': {'host': 'whois.nic.ir', 'limit': None},
        #'is': {'host': 'whois.isnic.is', 'limit': None},
        #'it': {'host': 'whois.nic.it', 'limit': None},
        #'je': {'host': 'whois.je', 'limit': None},
        #'jobs': {'host': 'jobswhois.verisign-grs.com', 'limit': None},
        #'jp': {'host': 'whois.jprs.jp', 'limit': None},
        #'ke': {'host': 'whois.kenic.or.ke', 'limit': None},
        #'kg': {'host': 'whois.domain.kg', 'limit': None},
        #'ki': {'host': 'whois.nic.ki', 'limit': None},
        #'kr': {'host': 'whois.kr', 'limit': None},
        #'kz': {'host': 'whois.nic.kz', 'limit': None},
        #'la': {'host': 'whois2.afilias-grs.net', 'limit': None},
        #'li': {'host': 'whois.nic.li', 'limit': None},
        #'london': {'host': 'whois.nic.london', 'limit': None},
        #'lt': {'host': 'whois.domreg.lt', 'limit': None},
        #'lu': {'host': 'whois.restena.lu', 'limit': None},
        #'lv': {'host': 'whois.nic.lv', 'limit': None},
        #'ly': {'host': 'whois.lydomains.com', 'limit': None},
        #'ma': {'host': 'whois.iam.net.ma', 'limit': None},
        #'mc': {'host': 'whois.ripe.net', 'limit': None},
        #'md': {'host': 'whois.nic.md', 'limit': None},
        #'me': {'host': 'whois.nic.me', 'limit': None},
        #'mg': {'host': 'whois.nic.mg', 'limit': None},
        #'mil': {'host': 'whois.nic.mil', 'limit': None},
        #'mk': {'host': 'whois.ripe.net', 'limit': None},
        #'ml': {'host': 'whois.dot.ml', 'limit': None},
        #'mo': {'host': 'whois.monic.mo', 'limit': None},
        #'mobi': {'host': 'whois.dotmobiregistry.net', 'limit': None},
        #'ms': {'host': 'whois.nic.ms', 'limit': None},
        #'mt': {'host': 'whois.ripe.net', 'limit': None},
        #'mu': {'host': 'whois.nic.mu', 'limit': None},
        #'museum': {'host': 'whois.museum', 'limit': None},
        #'mx': {'host': 'whois.nic.mx', 'limit': None},
        #'my': {'host': 'whois.mynic.net.my', 'limit': None},
        #'mz': {'host': 'whois.nic.mz', 'limit': None},
        #'na': {'host': 'whois.na-nic.com.na', 'limit': None},
        #'name': {'host': 'whois.nic.name', 'limit': None},
        #'nc': {'host': 'whois.nc', 'limit': None},
        'net': {'host': 'whois.verisign-grs.com', 'limit': 30},
        #'nf': {'host': 'whois.nic.cx', 'limit': None},
        #'ng': {'host': 'whois.nic.net.ng', 'limit': None},
        #'nl': {'host': 'whois.domain-registry.nl', 'limit': None},
        #'no': {'host': 'whois.norid.no', 'limit': None},
        #'no.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'nu': {'host': 'whois.nic.nu', 'limit': None},
        #'nz': {'host': 'whois.srs.net.nz', 'limit': None},
        #'om': {'host': 'whois.registry.om', 'limit': None},
        #'ong': {'host': 'whois.publicinterestregistry.net', 'limit': None},
        #'ooo': {'host': 'whois.nic.ooo', 'limit': None},
        'org': {'host': 'whois.pir.org', 'limit': 30},
        #'paris': {'host': 'whois-paris.nic.fr', 'limit': None},
        #'pe': {'host': 'kero.yachay.pe', 'limit': None},
        #'pf': {'host': 'whois.registry.pf', 'limit': None},
        #'pics': {'host': 'whois.uniregistry.net', 'limit': None},
        #'pl': {'host': 'whois.dns.pl', 'limit': None},
        #'pm': {'host': 'whois.nic.pm', 'limit': None},
        #'pr': {'host': 'whois.nic.pr', 'limit': None},
        #'press': {'host': 'whois.nic.press', 'limit': None},
        #'pro': {'host': 'whois.registrypro.pro', 'limit': None},
        #'pt': {'host': 'whois.dns.pt', 'limit': None},
        #'pub': {'host': 'whois.unitedtld.com', 'limit': None},
        #'pw': {'host': 'whois.nic.pw', 'limit': None},
        #'qa': {'host': 'whois.registry.qa', 'limit': None},
        #'re': {'host': 'whois.nic.re', 'limit': None},
        #'ro': {'host': 'whois.rotld.ro', 'limit': None},
        #'rs': {'host': 'whois.rnids.rs', 'limit': None},
        #'ru': {'host': 'whois.tcinet.ru', 'limit': None},
        #'sa': {'host': 'saudinic.net.sa', 'limit': None},
        #'sa.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'sb': {'host': 'whois.nic.net.sb', 'limit': None},
        #'sc': {'host': 'whois2.afilias-grs.net', 'limit': None},
        #'se': {'host': 'whois.nic-se.se', 'limit': None},
        #'se.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'se.net': {'host': 'whois.centralnic.com', 'limit': None},
        #'sg': {'host': 'whois.nic.net.sg', 'limit': None},
        #'sh': {'host': 'whois.nic.sh', 'limit': None},
        #'si': {'host': 'whois.arnes.si', 'limit': None},
        #'sk': {'host': 'whois.sk-nic.sk', 'limit': None},
        #'sm': {'host': 'whois.nic.sm', 'limit': None},
        #'st': {'host': 'whois.nic.st', 'limit': None},
        #'so': {'host': 'whois.nic.so', 'limit': None},
        #'su': {'host': 'whois.tcinet.ru', 'limit': None},
        #'sx': {'host': 'whois.sx', 'limit': None},
        #'sy': {'host': 'whois.tld.sy', 'limit': None},
        #'tc': {'host': 'whois.adamsnames.tc', 'limit': None},
        #'tel': {'host': 'whois.nic.tel', 'limit': None},
        #'tf': {'host': 'whois.nic.tf', 'limit': None},
        #'th': {'host': 'whois.thnic.net', 'limit': None},
        #'tj': {'host': 'whois.nic.tj', 'limit': None},
        #'tk': {'host': 'whois.nic.tk', 'limit': None},
        #'tl': {'host': 'whois.domains.tl', 'limit': None},
        #'tm': {'host': 'whois.nic.tm', 'limit': None},
        #'tn': {'host': 'whois.ati.tn', 'limit': None},
        #'to': {'host': 'whois.tonic.to', 'limit': None},
        #'top': {'host': 'whois.nic.top', 'limit': None},
        #'tp': {'host': 'whois.domains.tl', 'limit': None},
        #'tr': {'host': 'whois.nic.tr', 'limit': None},
        #'travel': {'host': 'whois.nic.travel', 'limit': None},
        #'tw': {'host': 'whois.twnic.net.tw', 'limit': None},
        #'tv': {'host': 'whois.nic.tv', 'limit': None},
        #'tz': {'host': 'whois.tznic.or.tz', 'limit': None},
        #'ua': {'host': 'whois.ua', 'limit': None},
        #'ug': {'host': 'whois.co.ug', 'limit': None},
        'uk': {'host': 'whois.nic.uk', 'limit': None},
        #'uk.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'uk.net': {'host': 'whois.centralnic.com', 'limit': None},
        #'ac.uk': {'host': 'whois.ja.net', 'limit': None},
        #'gov.uk': {'host': 'whois.ja.net', 'limit': None},
        #'us': {'host': 'whois.nic.us', 'limit': None},
        #'us.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'uy': {'host': 'nic.uy', 'limit': None},
        #'uy.com': {'host': 'whois.centralnic.com', 'limit': None},
        #'uz': {'host': 'whois.cctld.uz', 'limit': None},
        #'va': {'host': 'whois.ripe.net', 'limit': None},
        #'vc': {'host': 'whois2.afilias-grs.net', 'limit': None},
        #'ve': {'host': 'whois.nic.ve', 'limit': None},
        #'vg': {'host': 'ccwhois.ksregistry.net', 'limit': None},
        #'vu': {'host': 'vunic.vu', 'limit': None},
        #'wang': {'host': 'whois.nic.wang', 'limit': None},
        'wf': {'host': 'whois.nic.wf', 'limit': None},
        'wiki': {'host': 'whois.nic.wiki', 'limit': None},
        'ws': {'host': 'whois.website.ws', 'limit': None},
        'xxx': {'host': 'whois.nic.xxx', 'limit': None},
        'xyz': {'host': 'whois.nic.xyz', 'limit': None},
        #'yu': {'host': 'whois.ripe.net', 'limit': None},
        'za.com': {'host': 'whois.centralnic.com', 'limit': None},
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
            data = s.recv(2048).decode('utf-8')

        # Parse WHOIS data
    
        def val(data, key):
            for r in data.split('\r\n'):
                r = r.strip()
                if r.startswith(key):
                    _, value = r.split(':', 1)
                    return value.strip()
            raise WhoisParseError()

        error = False

        # Option 1
        patterns = [
            'NOT FOUND',
            'No match',
            'No Data Found',
            'The queried object does not exist',
        ]
        for p in patterns:
            if data.startswith(p):
                log.debug(f"Match on '{p}'")
                return None

        patterns = [
            f'Domain {domain} is available for registration',
            'DOMAIN NOT FOUND',
            'previous registration',
            'This domain name has not been registered',
        ]
        for p in patterns:
            if data.find(p) >= 0:
                log.debug(f"Match on '{p}'")
                return None

        # Option 2
        if (data.find('Reserved by the registry') >= 0
                or data.startswith('Reserved Domain Name')
                or data.find('>>> Registry Reserved') >= 0 ):
            return {'status': 'reserved'}

        # Option 3
        try:
            rec = {
                'create': val(data, 'Creation Date'),
                'expiry': val(data, 'Registry Expiry Date'),
            }
            return rec
        except WhoisParseError as err:
            error = True

        try:
            rec = {
                'create': val(data, 'Registered on'),
                'expiry': val(data, 'Expiry date'),
            }
            return rec
        except WhoisParseError as err:
            error = True

        # Finalize
        if error:
            raise WhoisParseError(domain, data)
    
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
        log.info(f'{domain} :: {whois_rec}')
        if whois_rec:
            rec = ';'.join(f"{key}={val}" for key,val in whois_rec.items())
            cache_whois.put(domain, rec)
            return True

        return False

def cmd_min(tld, n, verbose=False):
    domains_to_scan = int_tld(tld)

    log.info('Start WHOIS scanning')
    r = DomainResolver.instance()

    for domain in domains_to_scan:
        subdomain = domain[:-len(tld)-1]
        try:
            domain_exist = r.exist(subdomain, tld)
        except WhoisParseError as err:
            log.error(err)
            log.error(f'\n{err.whois_record}')
            return

        if not domain_exist:
            print(f'{domain}')
            n -= 1
            if n == 0:
                break


def main(args):
    #print(f"dnscan.py v{__version__}")

    logging.basicConfig(format='%(asctime)s :: %(name)s :: %(levelname)s :: %(message)s')
    log.setLevel(logging.WARNING)
    if args['-v']:
        log.setLevel(logging.INFO)
    if args['-d']:
        log.setLevel(logging.DEBUG)

    if args['check']:
        return cmd_check(args['<domain>'])
    elif args['min']:
        return cmd_min(args['<tld>'], int(args['-n']), args['-v'])
    else:
        raise NotImplementedError()

if __name__ == '__main__':
    args = docopt.docopt(__doc__)
    try:
        main(args)
    except KeyboardInterrupt:
        pass
