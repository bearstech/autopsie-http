import sys
import socket

import dpkt


f = open(sys.argv[1], 'r')
pcap = dpkt.pcap.Reader(f)
buffers = {}


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
            print(socket.inet_ntoa(ip.src), tcp.sport,
                  socket.inet_ntoa(ip.dst), tcp.dport)
            print http.headers
            print "------------------------------------"
    #print ts
