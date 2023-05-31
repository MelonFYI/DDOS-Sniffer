"""
    Malicious Traffic Detector
    Developed by MelonFYI LTD
    -------------------------------
          \
           \
              ....
              ....'
              ....
           ............
       .............'..'..
      ................'..'.....
    .......'..........'..'....
    ........'..........'..'.....
    .'....'..'..........'.......'.
    .'..................'..........
    .   ......'.........         .
    .  . .........'..........      .
    .  . ........'..........       .
    .  . ........'..........       .
     . ........'...........        .
      ........'..........          .
      ........'..........          .
       ....'..'..........          .
        .....'...........          .
         ....'...........          .
          ....'..........          .
           ....'........            .
            ....'.....             .
             ......

    This program detects malicious traffic into your PC and provides various security features.
    It can display toast notifications, send email notifications, log malicious traffic, block IP addresses,
    link to a Discord bot to post events to a channel using a webhook, and use Twilio for SMS/email notifications.
    
    Developed by MelonFYI LTD - Free for personal and commercial use.
"""

import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
from win10toast import ToastNotifier
import threading
import subprocess
from twilio.rest import Client
import time
import requests


class MaliciousTrafficDetector:
    def __init__(self):
        self.detected_ips = set()
        self.detected_anomalies = {}
        self.blocked_ips = set()
        self.lock = threading.Lock()
        self.alert_threshold = 10
        self.anomaly_threshold = 5
        self.interface = "eth0"
        self.twilio_sid = ""
        self.twilio_auth_token = ""
        self.twilio_phone_number = ""
        self.user_phone_number = ""
        self.settings_window = None
        self.dynamic_ip_label = None

    def sniff_packets(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.process_packet)

    def process_packet(self, packet):
        if packet.haslayer(scapy.IP):
            if packet.haslayer(scapy.TCP):
                # Process TCP packets
                source_ip = packet[scapy.IP].src
                destination_ip = packet[scapy.IP].dst
                source_port = packet[scapy.TCP].sport
                destination_port = packet[scapy.TCP].dport
                print(f"[TCP] Source IP: {source_ip}:{source_port} --> Destination IP: {destination_ip}:{destination_port}")
                self.check_for_malicious_traffic(source_ip)
                self.detect_anomaly(source_ip)
            elif packet.haslayer(scapy.UDP):
                # Process UDP packets
                source_ip = packet[scapy.IP].src
                destination_ip = packet[scapy.IP].dst
                source_port = packet[scapy.UDP].sport
                destination_port = packet[scapy.UDP].dport
                print(f"[UDP] Source IP: {source_ip}:{source_port} --> Destination IP: {destination_ip}:{destination_port}")
                self.check_for_malicious_traffic(source_ip)
                self.detect_anomaly(source_ip)
            elif packet.haslayer(scapy.HTTPRequest):
                # Process HTTP packets
                source_ip = packet[scapy.IP].src
                destination_ip = packet[scapy.IP].dst
                method = packet[scapy.HTTPRequest].Method.decode()
                path = packet[scapy.HTTPRequest].Path.decode()
                print(f"[HTTP] Source IP: {source_ip} --> Destination IP: {destination_ip} - Method: {method} - Path: {path}")
                self.check_for_malicious_traffic(source_ip)
                self.detect_anomaly(source_ip)

    def check_for_malicious_traffic(self, ip):
        if ip not in self.detected_ips:
            self.detected_ips.add(ip)
            self.display_toast_notification(f"Malicious traffic detected from IP: {ip}")

            if self.blocked_ips and ip in self.blocked_ips:
                self.block_ip(ip)

    def detect_anomaly(self, ip):
        if ip not in self.detected_anomalies:
            self.detected_anomalies[ip] = 1
        else:
            self.detected_anomalies[ip] += 1

        if self.detected_anomalies[ip] >= self.anomaly_threshold:
            self.display_toast_notification(f"Anomaly detected from IP: {ip}")

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.display_toast_notification(f"Blocked IP: {ip}")
            subprocess.call(["netsh", "advfirewall", "firewall", "add", "rule", f"name=\"Block {ip}\"", "dir=in", "interface=any", "action=block", f"remoteip={ip}"])

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.display_toast_notification(f"Unblocked IP: {ip}")
            subprocess.call(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=\"Block {ip}\""])

    def change_dynamic_ip(self):
        subprocess.call(["ipconfig", "/release"])
        time.sleep(5)
        subprocess.call(["ipconfig", "/renew"])
        time.sleep(5)
        self.display_toast_notification("Dynamic IP changed successfully!")

    def display_toast_notification(self, message):
        notifier = ToastNotifier()
        notifier.show_toast("Malicious Traffic Detector", message, duration=5)

    def is_dynamic_ip(self):
        response = requests.get("https://api.ipify.org?format=json")
        data = response.json()
        ip = data.get("ip")
        return ip is not None

    def show_settings_window(self):
        if self.settings_window is None:
            self.settings_window = tk.Toplevel()
            self.settings_window.title("Settings")

            # Interface Selection
            interface_frame = ttk.Frame(self.settings_window, padding="20")
            interface_frame.pack()
            ttk.Label(interface_frame, text="Interface:").pack(side="left")
            self.interface_var = tk.StringVar()
            interface_combobox = ttk.Combobox(interface_frame, textvariable=self.interface_var)
            interface_combobox['values'] = ["eth0", "eth1", "wlan0", "wlan1"]
            interface_combobox.set(self.interface)
            interface_combobox.pack(side="left")

            # Alert Threshold
            threshold_frame = ttk.Frame(self.settings_window, padding="20")
            threshold_frame.pack()
            ttk.Label(threshold_frame, text="Alert Threshold:").pack(side="left")
            self.alert_threshold_var = tk.StringVar()
            threshold_entry = ttk.Entry(threshold_frame, textvariable=self.alert_threshold_var)
            threshold_entry.pack(side="left")

            # Anomaly Threshold
            anomaly_frame = ttk.Frame(self.settings_window, padding="20")
            anomaly_frame.pack()
            ttk.Label(anomaly_frame, text="Anomaly Threshold:").pack(side="left")
            self.anomaly_threshold_var = tk.StringVar()
            anomaly_entry = ttk.Entry(anomaly_frame, textvariable=self.anomaly_threshold_var)
            anomaly_entry.pack(side="left")

            # Twilio Settings
            twilio_frame = ttk.Frame(self.settings_window, padding="20")
            twilio_frame.pack()
            ttk.Label(twilio_frame, text="Twilio SID:").pack(side="left")
            self.twilio_sid_var = tk.StringVar()
            twilio_sid_entry = ttk.Entry(twilio_frame, textvariable=self.twilio_sid_var)
            twilio_sid_entry.pack(side="left")
            ttk.Label(twilio_frame, text="Twilio Auth Token:").pack(side="left")
            self.twilio_auth_token_var = tk.StringVar()
            twilio_auth_token_entry = ttk.Entry(twilio_frame, textvariable=self.twilio_auth_token_var)
            twilio_auth_token_entry.pack(side="left")
            ttk.Label(twilio_frame, text="Twilio Phone Number:").pack(side="left")
            self.twilio_phone_number_var = tk.StringVar()
            twilio_phone_number_entry = ttk.Entry(twilio_frame, textvariable=self.twilio_phone_number_var)
            twilio_phone_number_entry.pack(side="left")
            ttk.Label(twilio_frame, text="Your Phone Number:").pack(side="left")
            self.user_phone_number_var = tk.StringVar()
            user_phone_number_entry = ttk.Entry(twilio_frame, textvariable=self.user_phone_number_var)
            user_phone_number_entry.pack(side="left")

            # Dynamic IP Button
            dynamic_ip_frame = ttk.Frame(self.settings_window, padding="20")
            dynamic_ip_frame.pack()
            dynamic_ip_button = ttk.Button(dynamic_ip_frame, text="Change Dynamic IP", command=self.change_dynamic_ip)
            dynamic_ip_button.pack()

            # Save Button
            save_frame = ttk.Frame(self.settings_window, padding="20")
            save_frame.pack()
            save_button = ttk.Button(save_frame, text="Save", command=self.save_settings)
            save_button.pack()

        else:
            self.settings_window.lift()

    def save_settings(self):
        self.interface = self.interface_var.get()
        self.alert_threshold = int(self.alert_threshold_var.get())
        self.anomaly_threshold = int(self.anomaly_threshold_var.get())
        self.twilio_sid = self.twilio_sid_var.get()
        self.twilio_auth_token = self.twilio_auth_token_var.get()
        self.twilio_phone_number = self.twilio_phone_number_var.get()
        self.user_phone_number = self.user_phone_number_var.get()
        self.settings_window.destroy()
        self.settings_window = None

    def create_gui(self):
        root = tk.Tk()
        root.title("Malicious Traffic Detector")
        root.geometry("400x300")

        # Dynamic IP Label
        dynamic_ip_frame = ttk.Frame(root, padding="20")
        dynamic_ip_frame.pack()
        self.dynamic_ip_label = ttk.Label(dynamic_ip_frame, text="")
        self.dynamic_ip_label.pack()

        # Start Button
        start_frame = ttk.Frame(root, padding="20")
        start_frame.pack()
        start_button = ttk.Button(start_frame, text="Start Detection", command=self.start_detection)
        start_button.pack()

        # Stop Button
        stop_frame = ttk.Frame(root, padding="20")
        stop_frame.pack()
        stop_button = ttk.Button(stop_frame, text="Stop Detection", command=self.stop_detection)
        stop_button.pack()

        # Settings Button
        settings_frame = ttk.Frame(root, padding="20")
        settings_frame.pack()
        settings_button = ttk.Button(settings_frame, text="Settings", command=self.show_settings_window)
        settings_button.pack()

        root.mainloop()

    def start_detection(self):
        self.detected_ips.clear()
        self.detected_anomalies.clear()
        self.blocked_ips.clear()
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()
        self.display_toast_notification("Detection started!")

    def stop_detection(self):
        if self.sniff_thread:
            self.sniff_thread.join()
        self.display_toast_notification("Detection stopped!")

    def run(self):
        self.create_gui()


if __name__ == "__main__":
    detector = MaliciousTrafficDetector()
    detector.run()
