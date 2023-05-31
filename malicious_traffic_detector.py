from scapy.all import *
from win10toast import ToastNotifier

# Create a ToastNotifier object
toaster = ToastNotifier()

# Define the callback function to process sniffed packets
def packet_callback(packet):
    # Check if the packet contains malicious traffic based on your criteria
    if packet.haslayer(TCP) and packet[TCP].flags == 2:
        # Display a toast notification
        toaster.show_toast("Malicious Traffic Detected", "Your PC received a malicious TCP packet!", duration=10)

# Sniff packets on the network interface
sniff(prn=packet_callback, filter="tcp")

# Run the program indefinitely
while True:
    pass
