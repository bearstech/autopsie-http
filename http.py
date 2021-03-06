#!/usr/bin/env python
# -*- coding: utf8 -*-
import socket
import json
from datetime import datetime
from Cookie import SimpleCookie, CookieError

import dpkt

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser


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
        self.readers = {}
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
                if not is_request and rk not in self.readers:  # response without it request
                    continue
                if is_request:
                    kind = 0
                else:
                    kind = 1
                if bk not in self.readers:
                    self.readers[bk] = HttpParser(kind=kind, decompress=True)
                size = len(tcp.data)
                nparsed = self.readers[bk].execute(tcp.data, size)
                #assert nparsed == size
                # I should try to read the body, now, here

                if is_request:
                    if bk not in self.request_start_timers:
                        self.request_start_timers[bk] = ts
                else:
                    if bk not in self.response_timers:
                        self.response_timers[bk] = ts

                if is_request and self.readers[bk].is_message_complete():
                    self.request_end_timers[bk] = ts
                    assert bk in self.request_start_timers

                if not is_request and self.readers[bk].is_message_complete():
                    request_start = self.request_start_timers[rk]
                    response_start = self.response_timers[bk]
                    if rk in self.request_end_timers:
                        request_end = self.request_end_timers[rk]
                    else:
                        request_end = response_start
                    response = self.readers[bk]
                    request = self.readers[rk]
                    del self.request_start_timers[rk]
                    if rk in self.request_end_timers:
                        del self.request_end_timers[rk]
                    del self.response_timers[bk]
                    del self.readers[rk]
                    del self.readers[bk]
                    yield (socket.inet_ntoa(ip.dst), tcp.dport,
                            socket.inet_ntoa(ip.src), tcp.sport), (
                                request_start, request_end,
                                response_start, ts
                                ), request, response


class Filter(object):
    def __init__(self, raw):
        if args.filter.find('!=') != -1:
            self.comp = '!='
            key, predicat = args.filter.split('!=')
        else:
            self.comp = '='
            key, predicat = args.filter.split('=')
        self.key = key.strip()
        self.predicat = predicat.strip()

    def __call__(self, request_header, response_header):
        if self.comp == '!=':
            return (self.key in request_header and
                    request_header[self.key] != self.predicat) or (
                        self.key in response_header and
                        response_header[self.key] != self.predicat)
        else:
            return (self.key in request_header and
                    request_header[self.key] == self.predicat) or (
                        self.key in response_header and
                        response_header[self.key] == self.predicat)


def Yes(request_header, response_header):
    return True


def normalize_dict(dico):
    return dict([(k.lower(), v) for (k, v) in dico.items()])


def args_and_weight(txt):
    return [arg.split(';')[0].strip() for arg in txt.split(',')]


def flat_dict(d, writer):
    for k, v in d.items():
        writer.write("{%s: %s} " % (k, v))


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
        if _filter(request.get_headers(), response.get_headers()):
            timer = int((timers[3] - timers[0]) * 1000)
            if args.logstash is None:
                sys.stdout.write("\n")

                print("%s:%i → %s:%i" % (source, sport, destination, dport))
                print("[%s] %s http://%s%s %i ms" % (response.get_status_code(), request.get_method(), request.get_headers()['host'],
                                                request.get_url(), timer))
                w = sys.stdout
                flat_dict(request.get_headers(), w)
                w.write('\n')
                print(request.recv_body())
                flat_dict(response.get_headers(), w)
                if response.get_headers().get('content-type',
                                              '').split(';')[0].strip() == "application/json":
                    body = response.recv_body()
                    print body
                    try:
                        json.loads(body)
                        print "JSON is parsable."
                    except Exception:
                        pass
            else:
                try:
                    if logstash is None:
                        logstash = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        logstash.connect((args.logstash, 4807))
                    event = {
                        'timestamp': int(timers[-1]),
                        'ip': dict(
                            source=source,
                            sport=sport,
                            destination=destination,
                            dport=dport),
                        'http': dict(
                            request=dict(
                                method=request.get_method(),
                                uri=request.get_url(),
                                headers=normalize_dict(request.get_headers()),
                            ),
                            response=dict(
                                status=response.get_status_code(),
                                timer=timer,
                                headers=normalize_dict(response.get_headers()),
                            )
                        )
                    }
                    if 'host' in request.get_headers():
                        event['http']['request']['host'] = request.get_headers()['host']
                    else:
                        event['http']['request']['host'] = destination
                    req_headers = event['http']['request']['headers']
                    res_headers = event['http']['response']['headers']
                    if 'content-type' in res_headers:
                        if ';' in res_headers['content-type']:
                            ct, other = res_headers['content-type'].split(';')
                            res_headers['content-type'] = ct
                        event['http']['response']['content-type-family'] = res_headers['content-type'].split('/')[0]
                    if 'server' in res_headers:
                        event['http']['response']['server-family'] = res_headers['server'].split('/')[0]
                    if 'accept-encoding' in req_headers:
                        req_headers['accept-encoding'] = args_and_weight(req_headers['accept-encoding'])
                    if 'accept-charset' in req_headers:
                        req_headers['accept-charset'] = args_and_weight(req_headers['accept-charset'])
                    if 'accept-language' in req_headers:
                        req_headers['accept-language'] = args_and_weight(req_headers['accept-language'])
                    if 'accept' in req_headers:
                        req_headers['accept'] = args_and_weight(req_headers['accept'])
                    if 'content-length' in req_headers:
                        req_headers['content-length'] = int(req_headers['content-length'])
                    if 'content-length' in res_headers:
                        try:
                            res_headers['content-length'] = int(res_headers['content-length'])
                        except ValueError as e:
                            print "content length is rotten:", e
                    if 'cookie' in req_headers:
                        cookie = SimpleCookie()
                        try:
                            cookie.load(req_headers['cookie'])
                            event['http']['request']['cookie'] = dict([(k, cookie[k].value) for k in cookie.keys()])
                        except CookieError as e:
                            print "oups' cookie: ", e
                    event['http']['request']['headers'] = req_headers
                    event['http']['response']['headers'] = res_headers

                    logstash.sendall(json.dumps(event, separators=(',', ':')) + "\n")
                except socket.error as e:
                    print "Oups", e
                    logstash = None
