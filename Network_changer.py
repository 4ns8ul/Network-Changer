import optparse
import scapy.all as scapy

def parsed():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip_addr", help="Use -t or --target to add IP Address")
    (option, args) = parser.parse_args()
    print (f"Debug: option.ip_addr = {option.ip_addr}")
    return option

def scan (ip_addr) :
    print(f"Scanning IP Address {ip_addr}")
    arp_request = scapy.ARP(pdst=ip_addr)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []

    for elem in answered_list:
        client_dict = {"ip":elem[0].pdst, "MAC":elem[1].hwdst}
        client_list.append(client_dict)

    def printList():
        print("_______________________\nIP ADDRESS\t\tMAC ADDRESS\n_______________________")
        for i in range(len(client_list)):
                print(client_list[0]["ip"] + "\t\t" + client_list[1]["MAC"])

    printList ()

options = parsed()
if options.ip_addr:
    scan(options.ip_addr)
else:
    print("[-] Invalid Usage. Please use --help")