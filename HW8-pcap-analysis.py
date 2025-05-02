from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS

# Initialize analysis containers
packet_count = 0
ip_addresses = set()
tcp_connections = set()
layer4_flows = set()
protocol_counts = {
    'TCP': 0,
    'ICMP': 0,
    'LLDP': 0,
    'ARP': 0,
    'DNS': 0,
    'FTP': 0
}

def process_packet(packet):
    global packet_count, ip_addresses, tcp_connections, layer4_flows, protocol_counts
    packet_count += 1
    
    # IP Address Collection (Handles both IPv4 and IPv6)
    if packet.haslayer(IP):
        ip_layer = IP
    elif packet.haslayer(scapy.layers.inet6.IPv6):
        ip_layer = scapy.layers.inet6.IPv6
    else:
        ip_layer = None
        
    if ip_layer:
        ip_addresses.add(packet[ip_layer].src)
        ip_addresses.add(packet[ip_layer].dst)
    
    # TCP Connection Tracking
    if packet.haslayer(TCP):
        protocol_counts['TCP'] += 1
        if ip_layer:
            conn_tuple = (packet[ip_layer].src, packet[TCP].sport,
                          packet[ip_layer].dst, packet[TCP].dport)
            tcp_connections.add(conn_tuple)
            layer4_flows.add(conn_tuple + ('TCP',))
    
    # UDP Flow Tracking
    if packet.haslayer(UDP):
        if ip_layer:
            flow_tuple = (packet[ip_layer].src, packet[UDP].sport,
                          packet[ip_layer].dst, packet[UDP].dport)
            layer4_flows.add(flow_tuple + ('UDP',))
    
    # Protocol Detection
    for proto in ['ICMP', 'ARP', 'DNS']:
        if packet.haslayer(eval(proto)):
            protocol_counts[proto] += 1
    
    # LLDP Detection (Layer 2 protocol)
    if packet.haslayer(Ether) and packet[Ether].type == 0x88cc:
        protocol_counts['LLDP'] += 1
    
    # FTP Detection (Port-based heuristic)
    if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
        protocol_counts['FTP'] += 1

# Process PCAP efficiently using generator
sniff(offline='05_02_2025_04_17_38-1.pcap', prn=process_packet, store=0)

# Calculate results
present_protocols = [k for k,v in protocol_counts.items() if v > 0]

print(f"""Analysis Results:
1. Total packets: {packet_count}
2. Unique IP addresses: {len(ip_addresses)} {ip_addresses}
3. TCP connections: {len(tcp_connections)}	{tcp_connections}
4. Layer-4 flows: {len(layer4_flows)} {layer4_flows}
5. Present protocols: {', '.join(present_protocols)}""")



# not (ip.addr == 10.134.148.2 or ip.addr == 10.139.134.2)

# Analysis Results:
# 1. Total packets: 139726
# 2. Unique IP addresses: 4 {'10.139.134.2', 'ff02::1', '10.134.148.2', 'fe80::be2c:e6ff:feb3:d12e'}
# 3. TCP connections: 4   {('10.134.148.2', 34588, '10.139.134.2', 5201), ('10.134.148.2', 34604, '10.139.134.2', 5201), ('10.139.134.2', 5201, '10.134.148.2', 34604), ('10.139.134.2', 5201, '10.134.148.2', 34588)}
# 4. Layer-4 flows: 4 {('10.134.148.2', 34588, '10.139.134.2', 5201, 'TCP'), ('10.139.134.2', 5201, '10.134.148.2', 34588, 'TCP'), ('10.139.134.2', 5201, '10.134.148.2', 34604, 'TCP'), ('10.134.148.2', 34604, '10.139.134.2', 5201, 'TCP')}
# 5. Present protocols: TCP, ICMP, LLDP, ARP
