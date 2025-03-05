import argparse
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

# Lists for blocked IPs and traffic monitoring
blocked_ips = set()
suspicious_ips = {}  # {IP: packet_count}
SUSPICIOUS_THRESHOLD = 20  # Flag if an IP sends more than 20 packets in a session


# Function to log suspicious activity
def log_suspicious_activity(logfile, message):
    with open(logfile, "a") as log:
        log.write(message + "\n")


# Function to process captured packets
def packet_callback(packet):
    # Extract relevant details
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
    proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"

    # Check if source IP is blocked
    if src_ip in blocked_ips:
        print(f"[BLOCKED] Packet from {src_ip} → {dst_ip} ({proto}) at {timestamp}")
        return

    # Monitor for suspicious activity    suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1
    if suspicious_ips[src_ip] > SUSPICIOUS_THRESHOLD:
        alert_msg = f"[ALERT] Suspicious activity detected from {src_ip} ({suspicious_ips[src_ip]} packets)"
        print(alert_msg)
        if args.logfile:
            log_suspicious_activity(args.logfile, alert_msg)

        # Extract ports if TCP/UDP
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        proto = "TCP"
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        proto = "UDP"
    else:
        src_port = dst_port = "N/A"
        proto = "Other"

        # Print the captured packet details
    print(f"[{timestamp}] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})")


# Main function to handle arguments
def main():
    global args  # Needed for accessing args inside packet_callback
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer with Firewall & Logging Features")

    # Define command-line arguments
    parser.add_argument("-s", "--sniff", action="store_true", help="Sniff packets and print in terminal")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    parser.add_argument("-f", "--filter", type=str, help="Protocol filter (e.g., tcp, udp, icmp)")
    parser.add_argument("-o", "--output", type=str, help="Save captured packets to a file (.pcap)")
    parser.add_argument("-b", "--block", type=str, help="Block packets from a specific IP")
    parser.add_argument("-l", "--logfile", type=str, help="Log suspicious packets to a file")

    args = parser.parse_args()

    # Set protocol filter if provided
    filter_protocol = args.filter if args.filter else None

    # Block a specific IP
    if args.block:
        blocked_ips.add(args.block)
        print(f"[*] Blocking traffic from {args.block}")

    # Sniff and print packets
    if args.sniff:
        print("[*] Sniffing packets...")
        sniff(filter=filter_protocol, prn=packet_callback, store=False)

    # Capture specific number of packets
    elif args.count:
        print(f"[*] Capturing {args.count} packets...")
        packets = sniff(filter=filter_protocol, count=args.count, prn=packet_callback)

        # Save to a file if output is specified
        if args.output:
            wrpcap(args.output, packets)
            print(f"[*] Packets saved to {args.output}")

    else:
        print("[!] No valid argument provided. Use -h for help.")


if __name__ == "__main__":
    main()
