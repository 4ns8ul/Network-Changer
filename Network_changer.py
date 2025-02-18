import argparse
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

def parsed():
    parser = argparse.ArgumentParser(description="ARP Scanner")
    parser.add_argument("-t", "--target", dest="ip_addr", required=True, help="Specify IP range to scan")
    args = parser.parse_args()
    return args

def scan(ip_addr):
    print(f"Scanning IP Address {ip_addr}")
    
    arp_request = ARP(pdst=ip_addr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for elem in answered_list:
        client_dict = {"ip": elem[1].psrc, "MAC": elem[1].hwsrc}
        client_list.append(client_dict)

    if not client_list:
        print("No devices found.")
        return

    print("_______________________\nIP ADDRESS\t\tMAC ADDRESS\n_______________________")
    for client in client_list:
        print(client["ip"] + "\t\t" + client["MAC"])

options = parsed()
scan(options.ip_addr)
