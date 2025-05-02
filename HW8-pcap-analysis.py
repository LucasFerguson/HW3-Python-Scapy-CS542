from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS

def normalize_conn(src_ip, sport, dst_ip, dport):
    """Normalize connection direction for consistent flow tracking"""
    # Convert IP addresses to comparable format
    src_ip = str(src_ip)
    dst_ip = str(dst_ip)
    
    # Sort connection endpoints using tuple comparison
    if (src_ip, sport) > (dst_ip, dport):
        return (dst_ip, dport, src_ip, sport)
    return (src_ip, sport, dst_ip, dport)

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
    
    # IP Address Handling (IPv4/IPv6)
    ip_layer = None
    for layer in [IP, scapy.layers.inet6.IPv6]:
        if packet.haslayer(layer):
            ip_layer = layer
            break
            
    if ip_layer:
        ip_addresses.add(packet[ip_layer].src)
        ip_addresses.add(packet[ip_layer].dst)
    
    # TCP Connection Tracking with Normalization
    if packet.haslayer(TCP):
        protocol_counts['TCP'] += 1
        if ip_layer:
            conn = normalize_conn(
                packet[ip_layer].src, packet[TCP].sport,
                packet[ip_layer].dst, packet[TCP].dport
            )
            tcp_connections.add(conn)
            layer4_flows.add(conn + ('TCP',))
    
    # UDP Flow Tracking with Normalization
    if packet.haslayer(UDP):
        if ip_layer:
            flow = normalize_conn(
                packet[ip_layer].src, packet[UDP].sport,
                packet[ip_layer].dst, packet[UDP].dport
            )
            layer4_flows.add(flow + ('UDP',))
    
    # Protocol Detection
    for proto in ['ICMP', 'ARP', 'DNS']:
        if packet.haslayer(eval(proto)):
            protocol_counts[proto] += 1
    
    # LLDP Detection
    if packet.haslayer(Ether) and packet[Ether].type == 0x88cc:
        protocol_counts['LLDP'] += 1
    
    # FTP Detection
    if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
        protocol_counts['FTP'] += 1

# Process PCAP
sniff(offline='05_02_2025_04_17_38-1.pcap', prn=process_packet, store=0)

# Prepare results
present_protocols = [k for k,v in protocol_counts.items() if v > 0]

print(f"""Analysis Results:
1. Total packets: {packet_count}
2. Unique IP addresses: {len(ip_addresses)} {ip_addresses}
3. TCP connections: {len(tcp_connections)}\t{tcp_connections}
4. Layer-4 flows: {len(layer4_flows)}\t{layer4_flows}
5. Present protocols: {', '.join(present_protocols)}""")
