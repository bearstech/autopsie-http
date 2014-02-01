#!/usr/bin/env python -u
# -*- coding: utf8 -*-
import socket
import json

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

    def __init__(self, pcap, port=[80]):
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
            if (tcp.dport in self.port or
                    tcp.sport in self.port) and len(tcp.data) > 0:
                # Not empty packet, on the right port
                is_request = tcp.dport in self.port
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
                            request = self.requests[rk]
                            del self.requests[rk]
                            yield (socket.inet_ntoa(ip.dst), tcp.dport,
                                   socket.inet_ntoa(ip.src), tcp.sport), (
                                       request_start, request_end,
                                       response_start, ts
                                       ), request, http


class Filter(object):
    def __init__(self, raw):
        key, predicat = args.filter.split('=')
        self.key = key.strip()
        self.predicat = predicat.strip()

    def __call__(self, request_header, response_header):
        return (self.key in request_header and
                request_header[self.key] == self.predicat) or (
                    self.key in response_header and
                    response_header[self.key] == self.predicat)


def Yes(request_header, response_header):
    return True


if __name__ == '__main__':
    import sys
    import os
    import argparse

    # Don't buffer on STDOUT
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-i', '--interface', dest='interface', default=None)
    parser.add_argument('-p', '--port', dest='port', default=[80],
                        type=int, nargs='+')
    parser.add_argument('-f', '--file', dest='file', default=None,
                        help="A tcpdump exported file.")
    parser.add_argument('-F', '--filter', dest='filter', default=None,
                        help="A filter on headers")
    parser.add_argument('-l', '--logstash', dest='logstash', default=None,
                        help="A logstash server")
    args = parser.parse_args()
    print args

    pcap = None
    if args.interface is not None:
        if args.file is not None:
            raise Exception("Choose file or live, but not both.")
        import pcap as _pcap
        pcap = _pcap.pcap(args.interface, immediate=True)
        #if len(sys.argv) > 3:
            #pcap.setfilter(' '.join(sys.argv[3:]))
        print("listening on %s" % args.interface)

    if args.file is not None:
        f = open(args.file, 'r')
        pcap = dpkt.pcap.Reader(f)

    if pcap is None:
        raise Exception("Choose a tcpdump file or listen an interface.")

    if args.filter is None:
        _filter = Yes
    else:
        _filter = Filter(args.filter)

    logstash = None

    for source_destination, timers, request, response in HTTPReader(pcap, args.port):
        source, sport, destination, dport = source_destination
        if _filter(request.headers, response.headers):
            timer = int((timers[3] - timers[0]) * 1000)
            if args.logstash is None:
                sys.stdout.write("\n")

                print("%s:%i → %s:%i" % (source, sport, destination, dport))
                print("[%s] %s http://%s%s %i ms" % (response.status, request.method, request.headers['host'],
                                                request.uri, timer))
                print(request.headers)
                print(response.headers)
            else:
                if logstash is None:
                    logstash = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    logstash.connect((args.logstash, 4807))
                logstash.sendall(json.dumps(dict(
                    ip=dict(
                        source=source,
                        sport=sport,
                        destination=destination,
                        dport=dport),
                    http=dict(
                        request=dict(
                            method=request.method,
                            host=request.headers['host'],
                            uri=request.uri,
                            headers=request.headers,
                        ),
                        response=dict(
                            status=response.status,
                            timer=timer,
                            headers=response.headers,
                        )
                    )
                )) + "\n")

