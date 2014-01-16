import sys
import socket

import dpkt


f = open(sys.argv[1], 'r')
pcap = dpkt.pcap.Reader(f)
buffers = {}
requests = {}


for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        continue
    ip = eth.data
    if not isinstance(ip.data, dpkt.tcp.TCP):
        continue
    tcp = ip.data
    if (tcp.dport == 80 or tcp.sport == 80) and len(tcp.data) > 0:
        bk = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if bk not in buffers:
            buffers[bk] = tcp.data
        else:
            buffers[bk] += tcp.data
        try:
            if tcp.dport == 80:
                http = dpkt.http.Request(buffers[bk])
            if tcp.sport == 80:
                http = dpkt.http.Response(buffers[bk])
        except dpkt.dpkt.UnpackError:
            pass
        else:
            del buffers[bk]
            if tcp.dport == 80:
                requests[(ip.src, tcp.sport, ip.dst, tcp.dport)] = http
            else:
                rk = (ip.dst, tcp.dport, ip.src, tcp.sport)
                if rk in requests:
                    print "%s:%i -> %s:%i" % (socket.inet_ntoa(ip.dst),
                                              tcp.dport,
                                              socket.inet_ntoa(ip.src),
                                              tcp.sport)
                    print "http://%s/%s" % (requests[rk].headers['host'],
                                            requests[rk].uri)
                    print "\t", requests[rk].headers
                    print
                    print "\t", http.headers
                    print
                    print
