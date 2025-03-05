# Advanced Packet Sniffer with Firewall & Logging

## Overview
This is an **Advanced Packet Sniffer** with built-in **firewall and logging** capabilities. It allows you to:
- **Sniff and display network packets** in real time.
- **Filter packets** by protocol (TCP, UDP, ICMP, etc.).
- **Capture a specific number of packets** and save them to a `.pcap` file.
- **Block packets from specific IPs**.
- **Log suspicious activity** when an IP exceeds a threshold number of packets.

---

## Features
✅ **Packet Sniffing**: Capture and display real-time network traffic.
✅ **Packet Filtering**: Filter packets based on protocol (e.g., TCP, UDP, ICMP).
✅ **Packet Capturing**: Capture a specific number of packets and save to a file.
✅ **Firewall Feature**: Block packets from specific IPs.
✅ **Suspicious Activity Monitoring**: Detects when an IP sends too many packets.
✅ **Logging**: Saves alerts to a log file.

---

## Installation
### Prerequisites
- Python 3.7+
- **Scapy** library (for packet sniffing)
- Administrator/root privileges (required for sniffing network traffic)

### Install Required Packages
```bash
pip install scapy
```

---

## Usage
Run the script with the desired options:

### **1️⃣ Sniff packets and print to terminal**
```bash
python packet_sniffer.py -s
```

### **2️⃣ Capture a specific number of packets**
```bash
python packet_sniffer.py -c 10
```
This captures **10 packets** and prints them in the terminal.

### **3️⃣ Filter packets by protocol**
```bash
python packet_sniffer.py -s -f tcp
```
This captures **only TCP packets**.

### **4️⃣ Save captured packets to a file**
```bash
python packet_sniffer.py -c 50 -o captured_traffic.pcap
```
This captures **50 packets** and saves them to `captured_traffic.pcap`.

### **5️⃣ Block traffic from a specific IP**
```bash
python packet_sniffer.py -s -b 192.168.1.10
```
This blocks packets from `192.168.1.10`.

### **6️⃣ Log suspicious activity to a file**
```bash
python packet_sniffer.py -s -l suspicious.log
```
This logs any **suspicious activity** (IP sending too many packets) to `suspicious.log`.

---

## Code Explanation
### **Packet Processing (`packet_callback`)**
- Extracts **source/destination IP** and **protocol**.
- Checks if an IP is **blocked** and ignores its packets.
- Tracks **packet count per IP** and detects suspicious activity.
- Logs suspicious activity to a file if enabled.

### **Main Function (`main()`)**
- Parses **command-line arguments**.
- Sets up **filters and options**.
- Calls **sniff()** to start capturing packets.

---

## Example Output
```
[*] Sniffing packets...
[2025-03-05 12:30:10] 192.168.1.100 → 192.168.1.50 (TCP)
[2025-03-05 12:30:11] 10.10.10.5 → 8.8.8.8 (UDP)
[ALERT] Suspicious activity detected from 192.168.1.100 (21 packets)
```

---

## Notes
- **Root/Administrator privileges required** to capture network traffic.
- The **suspicious activity threshold** is set to `20` packets.
- Supports **TCP, UDP, and ICMP filtering**.

---

## License
This project is open-source and available under the MIT License.

---

## Author
Developed by **[Your Name]** 🚀

