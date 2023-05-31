import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from win10toast import ToastNotifier
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import time


class MaliciousTrafficDetector:
    def __init__(self):
        self.interface = "eth0"  # Default interface, can be changed by the user
        self.alert_threshold = 10  # Default alert threshold, can be changed by the user
        self.detected_ips = set()
        self.lock = threading.Lock()

    def sniff_packets(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.process_packet)

    def process_packet(self, packet):
        if packet.haslayer(ARP):
            # Process ARP packets
            source_ip = packet[ARP].psrc
            source_mac = packet[ARP].hwsrc
            print(f"[ARP] Source IP: {source_ip} Source MAC: {source_mac}")
        elif packet.haslayer(IP):
            if packet.haslayer(TCP):
                # Process TCP packets
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                print(f"[TCP] Source IP: {source_ip}:{source_port} --> Destination IP: {destination_ip}:{destination_port}")
                self.check_for_malicious_traffic(source_ip)
            elif packet.haslayer(UDP):
                # Process UDP packets
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport
                print(f"[UDP] Source IP: {source_ip}:{source_port} --> Destination IP: {destination_ip}:{destination_port}")
                self.check_for_malicious_traffic(source_ip)
            elif packet.haslayer(http.HTTPRequest):
                # Process HTTP packets
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                method = packet[http.HTTPRequest].Method.decode()
                path = packet[http.HTTPRequest].Path.decode()
                print(f"[HTTP] Source IP: {source_ip} --> Destination IP: {destination_ip} {method} {path}")
                if path.lower() == "/malicious":
                    self.check_for_malicious_traffic(source_ip)

    def check_for_malicious_traffic(self, ip):
        with self.lock:
            if ip in self.detected_ips:
                return

            self.detected_ips.add(ip)
            if len(self.detected_ips) > self.alert_threshold:
                self.displimport scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from win10toast import ToastNotifier
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import time


class MaliciousTrafficDetector:
    def __init__(self):
        self.interface = "eth0"  # Default interface, can be changed by the user
        self.alert_threshold = 10  # Default alert threshold, can be changed by the user
        self.anomaly_threshold = 50  # Default anomaly threshold, can be changed by the user
        self.detected_ips = set()
        self.detected_anomalies = {}
        self.lock = threading.Lock()

    def sniff_packets(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.process_packet)

    def process_packet(self, packet):
        if packet.haslayer(ARP):
            # Process ARP packets
            source_ip = packet[ARP].psrc
            source_mac = packet[ARP].hwsrc
            print(f"[ARP] Source IP: {source_ip} Source MAC: {source_mac}")
        elif packet.haslayer(IP):
            if packet.haslayer(TCP):
                # Process TCP packets
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                print(f"[TCP] Source IP: {source_ip}:{source_port} --> Destination IP: {destination_ip}:{destination_port}")
                self.check_for_malicious_traffic(source_ip)
                self.detect_anomaly(source_ip)
            elif packet.haslayer(UDP):
                # Process UDP packets
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport
                print(f"[UDP] Source IP: {source_ip}:{source_port} --> Destination IP: {destination_ip}:{destination_port}")
                self.check_for_malicious_traffic(source_ip)
                self.detect_anomaly(source_ip)
            elif packet.haslayer(http.HTTPRequest):
                # Process HTTP packets
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                method = packet[http.HTTPRequest].Method.decode()
                path = packet[http.HTTPRequest].Path.decode()
                print(f"[HTTP] Source IP: {source_ip} --> Destination IP: {destination_ip} {method} {path}")
                if path.lower() == "/malicious":
                    self.check_for_malicious_traffic(source_ip)
                    self.detect_anomaly(source_ip)

    def check_for_malicious_traffic(self, ip):
        with self.lock:
            if ip in self.detected_ips:
                return

            self.detected_ips.add(ip)
            if len(self.detected_ips) > self.alert_threshold:
                self.display_toast_notification("Malicious traffic detected: Alert Threshold Exceeded")
                self.send_notification_email()
                self.log_malicious_traffic()

    def detect_anomaly(self, ip):
        with self.lock:
            if ip in self.detected_anomalies:
                self.detected_anomalies[ip] += 1
            else:
                self.detected_anomalies[ip] = 1

            if self.detected_anomalies[ip] > self.anomaly_threshold:
                self.display_toast_notification(f"Anomaly detected for IP: {ip}")
                self.block_ip(ip)

    def display_toast_notification(self, message):
        toaster = ToastNotifier()
        toaster.show_toast("Malicious Traffic Detected", message, duration=5)

    def send_notification_email(self):
        # TODO: Implement email notification logic
        pass

    def log_malicious_traffic(self):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open("malicious_traffic.log", "a") as f:
            for ip in self.detected_ips:
                f.write(f"[{current_time}] Malicious traffic detected from IP: {ip}\n")

    def block_ip(self, ip):
        # TODO: Implement IP blocking
        pass

    def start_sniffing(self):
        threading.Thread(target=self.sniff_packets).start()

    def change_dynamic_ip(self):
        # TODO: Implement method to change dynamic IP
        pass

    def handle_start_button(self):
        self.interface = self.interface_var.get()
        self.alert_threshold = int(self.alert_threshold_var.get())
        self.anomaly_threshold = int(self.anomaly_threshold_var.get())
        self.start_sniffing()

    def create_gui(self):
        root = tk.Tk()
        root.title("Malicious Traffic Detector")

        # Interface Selection
        interface_frame = ttk.Frame(root, padding="20")
        interface_frame.pack()
        ttk.Label(interface_frame, text="Interface:").pack(side="left")
        self.interface_var = tk.StringVar()
        interface_combobox = ttk.Combobox(interface_frame, textvariable=self.interface_var)
        interface_combobox['values'] = ["eth0", "eth1", "wlan0", "wlan1"]
        interface_combobox.current(0)
        interface_combobox.pack(side="left")

        # Alert Threshold
        threshold_frame = ttk.Frame(root, padding="20")
        threshold_frame.pack()
        ttk.Label(threshold_frame, text="Alert Threshold:").pack(side="left")
        self.alert_threshold_var = tk.StringVar()
        threshold_entry = ttk.Entry(threshold_frame, textvariable=self.alert_threshold_var)
        threshold_entry.pack(side="left")

        # Anomaly Threshold
        anomaly_frame = ttk.Frame(root, padding="20")
        anomaly_frame.pack()
        ttk.Label(anomaly_frame, text="Anomaly Threshold:").pack(side="left")
        self.anomaly_threshold_var = tk.StringVar()
        anomaly_entry = ttk.Entry(anomaly_frame, textvariable=self.anomaly_threshold_var)
        anomaly_entry.pack(side="left")

        # Start Button
        start_button = ttk.Button(root, text="Start", command=self.handle_start_button)
        start_button.pack(pady=10)

        root.mainloop()


def main():
    detector = MaliciousTrafficDetector()
    detector.create_gui()


if __name__ == "__main__":
    main()
ay_toast_notification("Malicious traffic detected: Alert Threshold Exceeded")
                self.send_notification_email()
                self.log_malicious_traffic()

    def display_toast_notification(self, message):
        toaster = ToastNotifier()
        toaster.show_toast("Malicious Traffic Detected", message, duration=5)

    def send_notification_email(self):
        # TODO: Implement email notification logic
        pass

    def log_malicious_traffic(self):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open("malicious_traffic.log", "a") as f:
            for ip in self.detected_ips:
                f.write(f"[{current_time}] Malicious traffic detected from IP: {ip}\n")

    def start_sniffing(self):
        threading.Thread(target=self.sniff_packets).start()

    def change_dynamic_ip(self):
        # TODO: Implement method to change dynamic IP
        pass

    def detect_anomaly(self):
        # TODO: Implement anomaly detection
        pass

    def block_ip(self, ip):
        # TODO: Implement IP blocking
        pass

    def handle_start_button(self):
        self.interface = self.interface_var.get()
        self.alert_threshold = int(self.alert_threshold_var.get())
        self.start_sniffing()

    def create_gui(self):
        root = tk.Tk()
        root.title("Malicious Traffic Detector")

        # Interface Selection
        interface_frame = ttk.Frame(root, padding="20")
        interface_frame.pack()
        ttk.Label(interface_frame, text="Interface:").pack(side="left")
        self.interface_var = tk.StringVar()
        interface_combobox = ttk.Combobox(interface_frame, textvariable=self.interface_var)
        interface_combobox['values'] = ["eth0", "eth1", "wlan0", "wlan1"]
        interface_combobox.current(0)
        interface_combobox.pack(side="left")

        # Alert Threshold
        threshold_frame = ttk.Frame(root, padding="20")
        threshold_frame.pack()
        ttk.Label(threshold_frame, text="Alert Threshold:").pack(side="left")
        self.alert_threshold_var = tk.StringVar()
        threshold_entry = ttk.Entry(threshold_frame, textvariable=self.alert_threshold_var)
        threshold_entry.pack(side="left")

        # Start Button
        start_button = ttk.Button(root, text="Start", command=self.handle_start_button)
        start_button.pack(pady=10)

        root.mainloop()


def main():
    detector = MaliciousTrafficDetector()
    detector.create_gui()


if __name__ == "__main__":
    main()
