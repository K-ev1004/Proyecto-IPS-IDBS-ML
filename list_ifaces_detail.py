from scapy.arch.windows import get_windows_if_list
import pprint

print("Windows interfaces details:")
try:
    ifaces = get_windows_if_list()
    pprint.pprint(ifaces)
except Exception as e:
    print(f"Error: {e}")
