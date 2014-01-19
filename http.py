import socket

import dpkt


class HTTPReader(object):
    """
    Iterate over a dpkt pcap reader.

    Request and its response are grouped.
    Yield lots of informations :
        * source_destination: source ip and port, destination ip and port
        * timers: starting request, starting response, ending response
        * request
        * response
    """

    def __init__(self, pcap, port=80):
        self.pcap = pcap
        self.port = port
        self.buffers = {}
        self.requests = {}
        self.request_timers = {}
        self.request_end_timers = {}
        self.response_timers = {}

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
                # request key
                rk = (ip.dst, tcp.dport, ip.src, tcp.sport)
                if bk not in self.buffers:
                    self.buffers[bk] = tcp.data
                else:
                    self.buffers[bk] += tcp.data
                if is_request:
                    if bk not in self.request_timers:
                        self.request_timers[bk] = ts
                else:
                    if bk not in self.response_timers:
                        self.response_timers[bk] = ts
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
                        self.requests[bk] = http
                        self.request_end_timers[bk] = ts
                    else:
                        if rk in self.requests:
                            assert self.request_timers[rk] <= self.response_timers[bk]
                            assert self.response_timers[bk] <= ts
                            request_start = self.request_timers[rk]
                            request_end = self.request_end_timers[rk]
                            response_start = self.response_timers[bk]
                            del self.request_timers[rk]
                            del self.request_end_timers[rk]
                            del self.response_timers[bk]
                            yield (socket.inet_ntoa(ip.src), tcp.sport,
                                   socket.inet_ntoa(ip.dst), tcp.dport
                                   ), (request_start, request_end,
                                       response_start, ts
                                       ), self.requests[rk], http

if __name__ == '__main__':
    import sys

    f = open(sys.argv[1], 'r')
    pcap = dpkt.pcap.Reader(f)
    for source_destination, timers, request, response in HTTPReader(pcap):
        print request.headers
        print response.headers
