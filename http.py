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
        self.request_start_timers = {}
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
                rk = (ip.dst, tcp.dport, ip.src, tcp.sport)  # reverse key
                if bk not in self.buffers:
                    self.buffers[bk] = tcp.data
                else:
                    self.buffers[bk] += tcp.data

                if is_request:
                    if bk not in self.request_start_timers:
                        self.request_start_timers[bk] = ts
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
                        assert bk in self.request_start_timers
                    else:
                        if rk in self.requests:
                            #assert self.request_timers[rk] <= self.response_timers[bk]
                            #assert self.response_timers[bk] <= ts
                            request_start = self.request_start_timers[rk]
                            request_end = self.request_end_timers[rk]
                            response_start = self.response_timers[bk]
                            del self.request_start_timers[rk]
                            del self.request_end_timers[rk]
                            del self.response_timers[bk]
                            yield (socket.inet_ntoa(ip.src), tcp.sport,
                                   socket.inet_ntoa(ip.dst), tcp.dport
                                   ), (request_start, request_end,
                                       response_start, ts
                                       ), self.requests[rk], http

if __name__ == '__main__':
    import sys
    import os

    # Don't buffer on STDOUT
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

    if sys.argv[1] == '-i':
        import pcap as _pcap
        pcap = _pcap.pcap(sys.argv[2])
        if len(sys.argv) > 3:
            pcap.setfilter(' '.join(sys.argv[3:]))
        print("listening on %s" % sys.argv[2])
    else:
        f = open(sys.argv[1], 'r')
        pcap = dpkt.pcap.Reader(f)
    for source_destination, timers, request, response in HTTPReader(pcap):
        sys.stdout.write("\n")
        print((timers[3] - timers[0]) * 1000)
        print(request.headers)
        print(response.headers)
        #sys.stdout.flush()
