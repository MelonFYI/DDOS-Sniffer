from scapy.all import *
from win10toast import ToastNotifier

# Create a ToastNotifier object
toaster = ToastNotifier()

# Define the callback function to process sniffed packets
def packet_callback(packet):
    # Check if the packet matches the criteria for a potential DDoS attack
    # You can customize this logic based on your specific requirements
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # Check for suspicious traffic patterns, such as a high number of packets from a single source
            if packet[IP].ttl < 64 and packet[IP].len > 1500:
                # Display a toast notification
                toaster.show_toast("Potential DDoS Attack Detected", f"Source IP: {src_ip}\nDestination IP: {dst_ip}\nSource Port: {src_port}\nDestination Port: {dst_port}", duration=10)

# Sniff packets on the network interface
sniff(prn=packet_callback, filter="ip")

# Run the program indefinitely
while True:
    pass
ddos_sniffer.py
