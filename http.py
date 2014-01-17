import socket

import dpkt


class HTTPReader(object):
    def __init__(self, pcap):
        self.pcap = pcap
        self.buffers = {}
        self.requests = {}
        self.timers = {}

    def __iter__(self):
        for ts, buf in self.pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            if (tcp.dport == 80 or tcp.sport == 80) and len(tcp.data) > 0:
                bk = (ip.src, tcp.sport, ip.dst, tcp.dport)
                if bk not in self.buffers:
                    self.buffers[bk] = tcp.data
                else:
                    self.buffers[bk] += tcp.data
                if bk not in self.timers:
                    self.timers[bk] = ts
                try:
                    if tcp.dport == 80:
                        http = dpkt.http.Request(self.buffers[bk])
                    if tcp.sport == 80:
                        http = dpkt.http.Response(self.buffers[bk])
                except dpkt.dpkt.UnpackError:
                    pass
                else:
                    del self.buffers[bk]
                    if tcp.dport == 80:
                        self.requests[(ip.src, tcp.sport,
                                       ip.dst, tcp.dport)] = http
                    else:
                        rk = (ip.dst, tcp.dport, ip.src, tcp.sport)
                        if rk in self.requests:
                            yield (socket.inet_ntoa(ip.dst), tcp.dport,
                                   socket.inet_ntoa(ip.src), tcp.sport
                                   ), (self.timers[bk], self.timers[rk], ts
                                       ), self.requests[rk], http

if __name__ == '__main__':
    import sys

    f = open(sys.argv[1], 'r')
    pcap = dpkt.pcap.Reader(f)
    for source_destination, timers, request, response in HTTPReader(pcap):
        print request.headers
        print response.headers
