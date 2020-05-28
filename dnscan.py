import gzip
import socket

class HostCache():
    def __init__(self):
        # ensure 'hosts.gz' file exists
        open('hosts.gz', 'a').close()

        self.cache = {}
        with gzip.open('hosts.gz') as fin: 
            for ip_host in fin.readlines():
                ip, host = ip_host.decode().strip().split('\t')
                self.cache[host] = ip

        self.fw = gzip.open('hosts.gz', 'a')

    def __del__(self):
        self.fw.close()

    def exist(self, host):
        return host in self.cache

    def add(self, host, ip):
        self.fw.write(f'{ip}\t{host}\n'.encode())


def gethostbyname(host):
    "Return IP of the host or None"
    try:
        addr = socket.gethostbyname(host)
        return addr
    except socket.gaierror:
        pass

def hosts_to_scan():
    for n in range(99999999):
        host = str(n)+'.com'
        yield host

def main():
    cache = HostCache()

    # scan
    for host in hosts_to_scan():
        if cache.exist(host):
            continue
        ip = gethostbyname(host) or 'none'
        cache.add(host, ip)
        print(f'{ip}\t{host}')

if __name__ == '__main__':
    main()
