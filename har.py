import json
import codecs
from datetime import datetime

import dpkt

from http import HTTPReader


class HARWriter(object):
    def __init__(self, reader):
        self.reader = reader

    def build(self):
        har = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Autopsie",
                    "version": "0.1"
                },
                "entries": [],
                "pages": []
            }
        }
        for source_destination, timers, request, response in self.reader:
            source_ip, source_port, destination_ip, destination_port = source_destination
            ts_request, ts_response, te_response = timers
            print response.headers
            startedDateTime = datetime.fromtimestamp(ts_request).isoformat() + "+01:00"
            if len(har['log']['pages']) == 0:
                page = {
                    "startedDateTime": startedDateTime,
                    "id": "plop",
                    "title": "plop",
                    "pageTimings": {
                        "onContentLoad": 445,
                        "onLoad": 846
                    }
                }
                har['log']['pages'].append(page)
            entry = {
                # FIXME handles TZ
                "startedDateTime": datetime.fromtimestamp(ts_request).isoformat() + "+01:00",
                "time": int((te_response - ts_request) * 1000),  # ms
                "pageref": "plop",
                "request": {
                    "method": request.method,
                    "url": "http://%s%s" % (request.headers['host'], request.uri),
                    "httpVersion": "HTTP/%s" % request.version,
                    "cookies": [],
                    "headers": [],
                    "queryString": [],
                    #"postData":
                    "headersSize": 42,
                    "bodySize": len(request.body)
                },
                "response": {
                    "status": int(response.status),
                    "statusText": response.reason,
                    "httpVersion":"HTTP/%s" % response.version,
                    "cookies": [],
                    "headers": [],
                    "content": {
                        "size": int(response.headers['content-length']),
                        "mimeType": response.headers['content-type'],
                        "text": ""
                    },
                    "redirectURL": "",
                    "headersSize": 42,
                    "bodySize": len(response.body)
                },
                "cache": {
                },
                "timings": {
                    "send": te_response - ts_response,
                    "receive": te_response - ts_request,
                    "wait": -1,
                },
                "serverIPAddress": destination_ip,
                "connection": "%s:%i" % (source_ip, source_port),
            }
            har['log']['entries'].append(entry)
        return har

    def write_to(self, path):
        har = self.build()
        #print har
        json.dump(har, codecs.open(path, 'w', 'utf8'))


if __name__ == '__main__':
    import sys

    f = open(sys.argv[1], 'r')
    pcap = dpkt.pcap.Reader(f)
    har = HARWriter(HTTPReader(pcap))
    har.write_to("toto.har")

