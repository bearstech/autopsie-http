Autopsie, the http part
=======================

Autopsie means autopsy, in fench, easy, no?

Autopsie-http is part of a larger project, _autopsie_ unreleased now.

Autopsie helps you to find informations from wired http flow.
For debugging purpose.

Install it
----------

### Debian or Ubuntu

    apt-get install python-dpkt python-pypcap

Use it
------

### Cold analysis

Extract HTTP information from a tcpdump.

    sudo tcpdump -i eth0 -w toto.cap -c 1000 'host toto.com'

Dump 1000 packets on interface eth0 to file toto.cap, where host is toto.com.

Enjoy the power of [pcap filter](http://wiki.wireshark.org/CaptureFilters)

Analyse it on place, or on a different computer

    ./http.py toto.cap

### Live analysis

    ./http.py -i eth0

Licence
-------

3 terms BSD Licence © 2014 Mathieu Lecarme.
