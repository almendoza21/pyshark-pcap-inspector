import pyshark
from collections import defaultdict

cap = pyshark.FileCapture('test.pcap', display_filter='dns')
dns_counter = defaultdict(int)

for pkt in cap:
    try:
        ip = pkt.ip.src
        dns_counter[ip] += 1
    except AttributeError:
        continue

# Write to log file
with open("dns_report.log", "w") as log:
    log.write("DNS Query Report\n")
    log.write("=================\n")
    for ip, count in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True):
        if count > 5:
            log.write(f"{ip}: {count} queries\n")

print("✅ Report written to dns_report.log")

cap.close()
