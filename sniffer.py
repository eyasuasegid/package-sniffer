
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Packet processing function
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print(f"[+] {ip_layer.src} --> {ip_layer.dst} | Protocol: {protocol}")

# Start sniffing (sniff 100 packets or press Ctrl+C to stop)
print("[*] Starting Packet Sniffer...")
sniff(prn=process_packet, count=100, store=False)
