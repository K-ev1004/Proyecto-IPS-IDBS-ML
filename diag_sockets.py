import scapy.all as scapy
import scapy.config
import pprint

print(f"Scapy version: {scapy.__version__}")
print("Available sockets in conf:")
pprint.pprint(scapy.config.conf.L2listen)
pprint.pprint(scapy.config.conf.L3socket)

try:
    from scapy.arch.windows import get_windows_if_list
    print("Interfaces:")
    pprint.pprint(get_windows_if_list())
except Exception as e:
    print(f"Error listing interfaces: {e}")

try:
    from scapy.arch.windows.native import NativeWindowsSocket
    print("Found NativeWindowsSocket")
except ImportError:
    print("NativeWindowsSocket not found")
