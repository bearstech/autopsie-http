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
        first_ts = None
        for source_destination, timers, request, response in self.reader:
            source_ip, source_port, destination_ip, destination_port = source_destination
            ts_request, te_request, ts_response, te_response = timers
            startedDateTime = datetime.fromtimestamp(ts_request).isoformat() + "+01:00"
            if len(har['log']['pages']) == 0:
                page = {
                    "startedDateTime": startedDateTime,
                    "id": "plop",
                    "title": "plop",
                    "pageTimings": {
                        "onLoad": -1
                    }
                }
                first_ts = ts_request
                har['log']['pages'].append(page)
            entry = {
                # FIXME handles TZ
                "startedDateTime": datetime.fromtimestamp(ts_request).isoformat() + "Z",
                "pageref": "plop",
                "request": {
                    "method": request.method,
                    "url": "http://%s%s" % (request.headers['host'], request.uri),
                    "httpVersion": "HTTP/%s" % request.version,
                    "cookies": [],
                    "headers": [],
                    "queryString": [],
                    #"postData":
                    "headersSize": len(request.headers),
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
                    "headersSize": len(response.headers),
                    "bodySize": len(response.body)
                },
                "cache": {
                },
                "timings": {
                    "blocked": -1,
                    "dns": -1,
                    "connect": -1,
                    "send": int((ts_request - te_request) * 1000),
                    "wait": int((ts_response - te_request) * 1000),
                    "receive": int((te_response - ts_response) * 1000),
                    "ssl": -1

                },
                "serverIPAddress": destination_ip,
                "connection": "%s:%i" % (source_ip, source_port),
            }
            entry['time'] = entry['timings']['send'] + entry['timings']['wait'] + entry['timings']['receive']
            har['log']['entries'].append(entry)
            har['log']['pages'][0]['pageTimings']['onContentLoad'] = int((te_response - first_ts) * 1000)
            har['log']['pages'][0]['pageTimings']['onLoad'] = har['log']['pages'][0]['pageTimings']['onContentLoad']
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

