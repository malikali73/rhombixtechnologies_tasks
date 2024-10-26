# Import necessary libraries
import socket
from scapy.all import *

# Function to analyze cap1tured packets
def analyze_packet(packet):
    print(f"\nCaptured Packet: {packet.summary()}")
    
    # Extract IP layer information
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} --> {ip_layer.dst}")
    
    # Extract TCP layer information
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"TCP Packet: {tcp_layer.sport} --> {tcp_layer.dport}")
        print(f"Flags: {tcp_layer.flags}")
    
    # Extract UDP layer information
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"UDP Packet: {udp_layer.sport} --> {udp_layer.dport}")
    
    # Extract Raw Data (Payload)
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        print(f"Raw Payload: {raw_data}")

# Function to sniff network packets
def sniff_packets():
    # Use scapy's sniff function to capture packets
    print("Starting packet capture...")
    sniff(prn=analyze_packet, filter="ip", count=0)

# Function to filter specific traffic (like HTTP, HTTPS)
def filter_traffic():
    def analyze(packet):
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            print(f"\nIP Packet: {ip_layer.src} --> {ip_layer.dst}")
        
            # Only capture HTTP traffic (port 80)
            if packet.haslayer(TCP) and packet[TCP].dport == 80:
                print("HTTP traffic detected!")
            elif packet.haslayer(TCP) and packet[TCP].dport == 443:
                print("HTTPS traffic detected!")
            elif packet.haslayer(UDP):
                print("UDP traffic detected!")

    print("Starting packet capture with filter...")
    sniff(prn=analyze, filter="tcp or udp", count=0)

# Main execution
if __name__ == "__main__":
    choice = input("Choose an option:\n1. Capture all packets\n2. Filter specific traffic (HTTP/HTTPS)\nEnter choice: ")
    if choice == '1':
        sniff_packets()
    elif choice == '2':
        filter_traffic()
    else:
        print("Invalid choice. Exiting...")
