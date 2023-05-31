import subprocess
import curses
from scapy.all import *
from win10toast import ToastNotifier

# Create a ToastNotifier object
toaster = ToastNotifier()

# Initialize curses
stdscr = curses.initscr()
curses.noecho()
curses.cbreak()
stdscr.keypad(True)

# Define colors for the console interface
curses.start_color()
curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)

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

        # Ask the user if they want to change their IP address
        stdscr.addstr("\nDo you want to attempt changing your IP address? (y/n): ", curses.color_pair(1))
        stdscr.refresh()
        change_ip = stdscr.getkey()
        if change_ip.lower() == "y":
            # Attempt to release and renew the IP address
            release_ip_cmd = "ipconfig /release"
            renew_ip_cmd = "ipconfig /renew"

            # Execute the commands using subprocess
            subprocess.run(release_ip_cmd, shell=True)
            subprocess.run(renew_ip_cmd, shell=True)
            stdscr.addstr("\nIP address changed successfully.", curses.color_pair(2))
            stdscr.refresh()

# Sniff packets on the network interface
sniff(prn=packet_callback, filter="tcp")

# Exit curses mode
curses.nocbreak()
stdscr.keypad(False)
curses.echo()
curses.endwin()
