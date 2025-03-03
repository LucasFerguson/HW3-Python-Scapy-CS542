
from scapy.all import *

# send(IP(src="192.168.1.103", dst="192.168.1.1")/ICMP()/"Hello World")

send(IPv6(src="fe80::1017:f9ff:fef9:19a", dst="fe80::4d3:1aff:fe9e:1504")/ICMP()/"Hello World")
# - This worked!! I was able to capture the packet using tcpdump on the other vm
