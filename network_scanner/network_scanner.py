#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")

    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP or IP range, use --help for more info.")

    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    boardcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_boardcast = boardcast/arp_request
    answered_list = scapy.srp(arp_request_boardcast, timeout=1, verbose=False)[0]

    client_list = []
    for elements in answered_list:
        clint_dist = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        client_list.append(clint_dist)
    return client_list

def print_result(result_list):
    print("IP Address\t\t\tMAC Address\n----------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t\t\t" + client["mac"])


options = get_arguments()
scan_result= scan(options.target)
print_result(scan_result)







