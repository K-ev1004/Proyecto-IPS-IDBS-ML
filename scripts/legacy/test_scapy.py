import scapy.all as scapy
from scapy.all import get_if_list, sniff

print("Interfaces detected by Scapy:")
try:
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
except Exception as e:
    print(f"Error listing interfaces: {e}")

print("\nAttempting to sniff 5 packets...")
try:
    packets = sniff(count=5, timeout=10)
    print(f"Captured {len(packets)} packets.")
    for p in packets:
        print(p.summary())
except Exception as e:
    print(f"Error sniffing: {e}")
