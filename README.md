Autopsie, the http part
=======================

Autopsie means autopsy, in fench, easy, no?

Autopsie-http is part of a larger project, _autopsie_ unreleased now.

Autopsie helps you to find informations from wired http flow.
For debugging purpose.

Install it
----------

### Debian or Ubuntu

    apt-get install python-dpkt python-pypcap python-http-parser

Use it
------

### Input
#### Cold analysis

Extract HTTP information from a tcpdump.

    sudo tcpdump -i eth0 -w toto.cap -c 1000 'host toto.com'

Dump 1000 packets on interface eth0 to file toto.cap, where host is toto.com.

Enjoy the power of [pcap filter](http://wiki.wireshark.org/CaptureFilters)

Analyse it on place, or on a different computer

    ./http.py toto.cap

#### Live analysis

    ./http.py -i eth0

### Output

#### Console

The default view is a simple console view. Useful for debugging RPC or Proxy.

#### Logstash analysis

Sometime, watching logs like the good guys in Matrix is not enough.

Kibana is a nice log drilling tool (with Logstash and Elasticsearch).

Autopsie can send data to Logstash, throught a socket.
If the logstash server is behind a NAT, configuration will be painful, VPN is the best solution.

Logstash provides a 'all in one' packet, embedding Elasticsearch and Kibana.

The used protocol is dummy, you can test it with netcat :

    nc -l 4807

Logstash configuration is easy to read, check provided example, and launch it :

    java -jar logstash-1.3.3-flatjar.jar agent -f logstash.conf -- web


Licence
-------

3 terms BSD Licence © 2014 Mathieu Lecarme.
