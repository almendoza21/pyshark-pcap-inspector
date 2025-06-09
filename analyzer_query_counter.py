import pyshark
from collections import defaultdict

cap = pyshark.FileCapture('test.pcap', display_filter='dns')

dns_counter = defaultdict(int)

print("Counting DNS queries by IP...\n")

for pkt in cap:
    try:
        src_ip = pkt.ip.src
        dns_counter[src_ip] += 1
    except AttributeError:
        continue

for ip, count in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip}: {count} DNS queries")

cap.close()
