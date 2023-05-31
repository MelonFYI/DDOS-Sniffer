import subprocess
from scapy.all import *
from tkinter import *
from win10toast import ToastNotifier

# Create a ToastNotifier object
toaster = ToastNotifier()

# Create the GUI window
window = Tk()
window.title("Malicious Traffic Detector")
window.geometry("400x200")

# Create a label for displaying notifications
label = Label(window, text="No malicious traffic detected.", font=("Arial", 12))
label.pack(pady=20)

# Define a dictionary to store IP address and packet count
ip_packet_count = {}

# Define the maximum allowed packet count per IP address
MAX_PACKET_COUNT = 100

# Define the rate limit per IP address (in packets per second)
RATE_LIMIT = 10

# Define the threshold for anomaly detection
ANOMALY_THRESHOLD = 1000

# Define the callback function to process sniffed packets
def packet_callback(packet):
    # Check if the packet contains malicious traffic based on your criteria
    if packet.haslayer(TCP) and packet[TCP].flags == 2:
        # Extract relevant information from the packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Prepare the notification message
        message = f"Malicious Traffic Detected!\n\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nSource Port: {src_port}\nDestination Port: {dst_port}"

        # Display a toast notification
        toaster.show_toast("Security Alert", message, duration=10)

        # Update the label with the notification message
        label.config(text=message)

        # Apply rate limiting
        if not is_rate_limited(src_ip):
            increment_packet_count(src_ip)
            # Apply traffic filtering
            if is_suspicious_traffic(packet):
                drop_packet(packet)

        # Apply anomaly detection
        if is_anomalous_traffic(src_ip):
            raise_anomaly_alert(src_ip)

# Method to check if an IP address is rate limited
def is_rate_limited(ip):
    current_time = time.time()
    if ip in ip_packet_count:
        count, last_time = ip_packet_count[ip]
        if count >= MAX_PACKET_COUNT and current_time - last_time < 1:
            return True
    return False

# Method to increment packet count for an IP address
def increment_packet_count(ip):
    current_time = time.time()
    if ip in ip_packet_count:
        count, last_time = ip_packet_count[ip]
        if current_time - last_time >= 1:
            ip_packet_count[ip] = (1, current_time)
        else:
            ip_packet_count[ip] = (count + 1, last_time)
    else:
        ip_packet_count[ip] = (1, current_time)

# Method to check if traffic is suspicious
def is_suspicious_traffic(packet):
    # TODO: Implement traffic filtering rules here
    # Analyze packet characteristics and return True if it's suspicious, otherwise False

    # Example implementation: Consider traffic with a large number of packets per second as suspicious
    if packet.haslayer(IP):
        return packet[IP].src == "x.x.x.x" and packet[IP].len > 1000
    return False

# Method to check if traffic is anomalous
def is_anomalous_traffic(ip):
    # TODO: Implement anomaly detection logic here
    # Analyze traffic patterns for the given IP and return True if it's anomalous, otherwise False

    # Example implementation: Check if the packet count for the IP exceeds the threshold
    if ip in ip_packet_count:
        count, _ = ip_packet_count[ip]
        return count > ANOMALY_THRESHOLD
    return False

# Method to raise an anomaly alert
def raise_anomaly_alert(ip):
    # TODO: Implement actions to be taken when an anomaly is detected

    # Notify administrators, log the event, or take other appropriate measures

    # Example implementation: Display a toast notification for the anomaly alert
    message = f"Anomalous Traffic Detected from IP: {ip}"
    toaster.show_toast("Anomaly Alert", message, duration=10)

# Method to drop a packet
def drop_packet(packet):
    # TODO: Implement packet dropping logic here
    # Drop or block the packet to prevent it from reaching the target

    # Example implementation using `iptables` command in Linux:
    drop_packet_cmd = "iptables -A INPUT -p tcp --dport 80 -j DROP"
    subprocess.run(drop_packet_cmd, shell=True)

# Sniff packets on the network interface
sniff(prn=packet_callback, filter="tcp")

# Run the GUI main loop
window.mainloop()
