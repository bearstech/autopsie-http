import socket

import dpkt


class HTTPReader(object):
    """
    Iterate over a dpkt pcap reader.

    Request and its response are grouped.
    Yield lots of informations :
        * source_destination: source ip and ort, destination ip and port
        * timers: starting request, starting response, ending response
        * request
        * response
    """

    def __init__(self, pcap, port=80):
        self.pcap = pcap
        self.port = port
        self.buffers = {}
        self.requests = {}
        self.timers = {}

    def __iter__(self):
        for ts, buf in self.pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                # I want IP
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                # I want TCP
                continue
            tcp = ip.data
            if (tcp.dport == self.port or
                    tcp.sport == self.port) and len(tcp.data) > 0:
                # Not empty packet, on the right port
                is_request = tcp.dport == self.port
                bk = (ip.src, tcp.sport, ip.dst, tcp.dport)  # Buffer key
                if bk not in self.buffers:
                    self.buffers[bk] = tcp.data
                else:
                    self.buffers[bk] += tcp.data
                if bk not in self.timers:
                    self.timers[bk] = ts
                try:
                    if is_request:
                        http = dpkt.http.Request(self.buffers[bk])
                    else:
                        http = dpkt.http.Response(self.buffers[bk])
                except dpkt.dpkt.UnpackError:
                    # buffer is too short, append stuff and try later
                    pass
                else:
                    del self.buffers[bk]
                    if is_request:
                        self.requests[(ip.src, tcp.sport,
                                       ip.dst, tcp.dport)] = http
                    else:
                        # request key
                        rk = (ip.dst, tcp.dport, ip.src, tcp.sport)
                        if rk in self.requests:
                            yield (socket.inet_ntoa(ip.src), tcp.sport,
                                   socket.inet_ntoa(ip.dst), tcp.dport
                                   ), (self.timers[bk], self.timers[rk], ts
                                       ), self.requests[rk], http

if __name__ == '__main__':
    import sys

    f = open(sys.argv[1], 'r')
    pcap = dpkt.pcap.Reader(f)
    for source_destination, timers, request, response in HTTPReader(pcap):
        print request.headers
        print response.headers
