from scapy.all import *

# Recreateing the packets from lferguson.pcap

# Packet 1

	# Internet Protocol Version 6, Src: 2001:aea7:6bda:21f4:de29:d524:90db:2492, Dst: 2001:9d49:2b39:210f:1527:7693:9014:71fe
	# 	0110 .... = Version: 6
	# 	.... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00 (DSCP: CS0, ECN: Not-ECT)
	# 	.... 0000 0000 0000 0000 0000 = Flow Label: 0x00000
	# 	Payload Length: 22
	# 	Next Header: UDP (17)
	# 	Hop Limit: 64
	# 	Source Address: 2001:aea7:6bda:21f4:de29:d524:90db:2492
	# 	Destination Address: 2001:9d49:2b39:210f:1527:7693:9014:71fe
	# 	[Stream index: 0]

	# User Datagram Protocol, Src Port: 29780, Dst Port: 6217
	# 	Source Port: 29780
	# 	Destination Port: 6217
	# 	Length: 22
	# 	Checksum: 0x1d35 [unverified]
	# 	[Checksum Status: Unverified]
	# 	[Stream index: 0]
	# 	[Stream Packet Number: 1]
	# 	[Timestamps]
	# 	UDP payload (14 bytes)

	# Data (14 bytes)
	# 	Data: 6165393862626261356332633234
	# 	[Length: 14]
p1 = Ether(src="68:c7:b9:69:0e:a7", dst="00:d6:f9:f4:99:78")/IPv6(src="2001:aea7:6bda:21f4:de29:d524:90db:2492", dst="2001:9d49:2b39:210f:1527:7693:9014:71fe")/UDP(sport=29780, dport=6217)/int("6165393862626261356332633234", 16).to_bytes(14, byteorder='big')

# sleep for 0.004353 seconds
time.sleep(0.004353)

# Packet 2
p2 = Ether(src="00:d6:f9:f4:99:78", dst="68:c7:b9:69:0e:a7")/IPv6(src="2001:9d49:2b39:210f:1527:7693:9014:71fe", dst="2001:aea7:6bda:21f4:de29:d524:90db:2492")/UDP(sport=27192, dport=32489)/int("32383031333932383938636239633631373462", 16).to_bytes(19, byteorder='big')

# Packet 3
# checksum: 0x6d33 [correct]
p3 = Ether(src="68:c7:b9:69:0e:a7", dst="00:57:3a:e9:03:a2")/IPv6(src="2001:aea7:6bda:21f4:de29:d524:90db:2492", dst="2001:9d49:2b39:210f:790e:acc:3af:4b52")/ICMPv6TimeExceeded(code=0, cksum=0x6d33)/int("054220eb0012000065666665643365343263", 16).to_bytes(18, byteorder='big')

# Packet 4
p4 = Ether(src="68:c7:b9:69:0e:a7", dst="00:d6:f9:f4:99:78")/IPv6(src="2001:aea7:6bda:21f4:de29:d524:90db:2492", dst="2001:9d49:2b39:210f:1527:7693:9014:71fe")/UDP(sport=59908, dport=63031)/int("3731623237323838323638633730", 16).to_bytes(14, byteorder='big')

# Packet 5
p5 = Ether(src="68:c7:b9:69:0e:a7", dst="00:57:3a:e9:03:a2")/IPv6(src="2001:aea7:6bda:21f4:de29:d524:90db:2492", dst="2001:9d49:2b39:210f:790e:acc:3af:4b52")/UDP(sport=51999, dport=3172)/int("35616537373430373337623734373362653838646635653266353536646361", 16).to_bytes(31, byteorder='big')

# Packet 6
p6 = Ether(src="e4:e3:29:49:80:f9", dst="68:c7:b9:69:0e:a7")/IPv6(src="2001:9d49:2b39:210f:cc51:56ae:fa7d:9e82", dst="2001:aea7:6bda:21f4:de29:d524:90db:2492")/UDP(sport=65212, dport=37299)/int("64363761393364666236656162343533376139613236623533313634666139", 16).to_bytes(31, byteorder='big')

# Packet 7
p7 = Ether(src="68:c7:b9:69:0e:a7", dst="e4:e3:29:49:80:f9")/IPv6(src="2001:aea7:6bda:21f4:de29:d524:90db:2492", dst="2001:9d49:2b39:210f:cc51:56ae:fa7d:9e82")/UDP(sport=38176, dport=35156)/int("35376538306431326661656332626334346638", 16).to_bytes(19, byteorder='big')

# Packet 8

# Flags: 0x002 (SYN)
# Window: 8192
p8 = Ether(src="68:c7:b9:69:0e:a7", dst="e4:e3:29:49:80:f9")/IPv6(src="2001:aea7:6bda:21f4:de29:d524:90db:2492", dst="2001:9d49:2b39:210f:cc51:56ae:fa7d:9e82")/TCP(sport=53, dport=4467, seq=0, flags=0x002, window=8192, chksum=0xa8d3)/int("002100000100000100000000000003777777076578616d706c6503636f6d0000010001", 16).to_bytes(35, byteorder='big')

# Packet 9
p9 = Ether(src="00:57:3a:e9:03:a2", dst="e4:e3:29:49:80:f9")/IPv6(src="2001:9d49:2b39:210f:790e:acc:3af:4b52", dst="2001:9d49:2b39:210f:cc51:56ae:fa7d:9e82")/ICMPv6EchoRequest(type=128, code=0, id=0x0000, seq=0, cksum=0xddba)

# Packet 10
# Type: Echo (ping) reply (129)
# Code: 0
# Checksum: 0xdcba [correct]
p10 = Ether(src="e4:e3:29:49:80:f9", dst="00:57:3a:e9:03:a2")/IPv6(src="2001:9d49:2b39:210f:cc51:56ae:fa7d:9e82", dst="2001:9d49:2b39:210f:790e:acc:3af:4b52")/ICMPv6EchoReply(type=129, code=0, id=0x0000, seq=0, cksum=0xdcba)

# Packet 11
p11 = Ether(src="68:c7:b9:69:0e:a7", dst="00:57:3a:e9:03:a2")/IPv6(src="2001:aea7:6bda:21f4:de29:d524:90db:2492", dst="2001:9d49:2b39:210f:790e:acc:3af:4b52")/UDP(sport=46166, dport=12081, chksum=0x0dd3)/int("666633323764363230343566", 16).to_bytes(12, byteorder='big')

# Packet 12
p12 = Ether(src="00:57:3a:e9:03:a2", dst="68:c7:b9:69:0e:a7")/IPv6(src="2001:9d49:2b39:210f:790e:acc:3af:4b52", dst="2001:aea7:6bda:21f4:de29:d524:90db:2492")/TCP(sport=60061, dport=11345, seq=0, flags=0x002, window=8192, chksum=0xce48)/int("3966633334363831", 16).to_bytes(8, byteorder='big')


p3.show()

# create pcap file
wrpcap("lferguson.pcap", [p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12])
