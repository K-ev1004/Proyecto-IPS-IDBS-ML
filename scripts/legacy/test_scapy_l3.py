from scapy.all import conf, L3RawSocket, sniff
import sys

print("Testing L3 Sniffing on Windows...")
try:
    # Attempt to use L3RawSocket which is native to Windows (needs Admin)
    conf.L3socket = L3RawSocket
    print(f"Current L3socket: {conf.L3socket}")
    
    def pkt_callback(pkt):
        print(f"Captured: {pkt.summary()}")
        
    print("Sniffing 2 packets at L3...")
    sniff(count=2, prn=pkt_callback, timeout=10)
    print("Test finished.")
except Exception as e:
    print(f"L3 Sniffing failed: {e}")
    sys.exit(1)
