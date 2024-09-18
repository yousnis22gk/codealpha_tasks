from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        
        if TCP in packet:
            print(f"TCP Packet: {ip_src} -> {ip_dst} | Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        
        
        elif UDP in packet:
            print(f"UDP Packet: {ip_src} -> {ip_dst} | Port: {packet[UDP].sport} -> {packet[UDP].dport}")
        
        
        else:
            print(f"IP Packet: {ip_src} -> {ip_dst}")


print("Starting the network sniffer...")
sniff(filter="ip", prn=packet_callback, store=0, iface="Intel(R) Wi-Fi 6 AX201 160MHz")  