# Pyshark PCAP Inspector

A beginner-friendly Python script for inspecting DNS traffic in `.pcap` files using the PyShark library.

This tool performs:
-  DNS query volume analysis (per source IP)
-  Suspicious long subdomain detection (potential tunneling)
-  Logging of findings to a report file

---

## Features

- **Parse PCAP files** with Wireshark-style filtering (`display_filter='dns'`)
- **Count DNS queries** by IP address
- **Detect long DNS queries** (length > 50 characters)
- **Log flagged traffic** to a report file: `dns_report.log`

---

## Project Structure

