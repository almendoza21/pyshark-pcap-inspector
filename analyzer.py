import pyshark
from collections import defaultdict

# --- Load PCAP File ---
cap = pyshark.FileCapture('test.pcap', display_filter='dns')

# --- Setup ---
dns_counter = defaultdict(int)
long_queries = []

print("Analyzing DNS traffic...\n")

# --- Packet Processing ---
for pkt in cap:
    try:
        ip = pkt.ip.src
        domain = pkt.dns.qry_name

        # Count by IP
        dns_counter[ip] += 1

        # Check for long subdomain
        if len(domain) > 50:
            long_queries.append((ip, domain))
            print(f"[!] Long query: {domain} (from {ip}, length={len(domain)})")

    except AttributeError:
        continue

cap.close()

# --- Print Summary ---
print("\n Top DNS Query Sources:")
for ip, count in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip}: {count} queries")

# --- Log to File ---
with open("dns_report.log", "w") as f:
    f.write("DNS Analysis Report\n")
    f.write("=======================\n\n")

    f.write("Top DNS Requesters:\n")
    for ip, count in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True):
        if count > 5:
            f.write(f"{ip}: {count} queries\n")

    f.write("\nSuspicious Long Domains:\n")
    for ip, domain in long_queries:
        f.write(f"{ip} queried: {domain} (length={len(domain)})\n")

print("\n Report saved to dns_report.log")

