Autopsie, the http part
=======================

Extract HTTP information from a tcpdump.

    sudo tcpdump -i eth0 -w toto.cap -c 1000 'host toto.com'

Dump 1000 packets on interface eth0 to file toto.cap, where host is toto.com.

Enjoy the power of [pcap filter](http://wiki.wireshark.org/CaptureFilters)

Analyse it on place, or on a different computer

    ./bin/pyton http.py toto.cap
