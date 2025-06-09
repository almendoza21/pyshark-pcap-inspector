import pyshark

cap = pyshark.FileCapture('test.pcap', display_filter='dns')

print("Flagging long DNS queries...\n")

for pkt in cap:
    try:
        domain = pkt.dns.qry_name
        if len(domain) > 50:
            print(f"[!] Suspicious long domain: {domain} (length: {len(domain)})")
    except AttributeError:
        continue

cap.close()
