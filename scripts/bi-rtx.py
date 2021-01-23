#!/usr/bin/env python3
from scapy.all import *
import pyshark

""" Script bi-rtx.py:
Function:
- Pcap file, source and destination IP addresses as inputs
- Calculate amount of total packets between given IPs
- Calculate amount of re-transmission packets between given IPs
- Calculate percentage of re-transmission packets between given IPs
- Calculate amount of total packets in given pcap file
"""

## Input variables
## TODO:
## Change vars to input arguments
pcap_file = 'pcap-captures/mycap2.pcap'
src_ip = "23.56.172.136"
dst_ip = "190.57.158.174"

## Print IPs for Analysis
print('####################################################################')
print(f'Analysis between src IP: "{src_ip}" && dst IP: "{dst_ip}"')
print('####################################################################\n')

## Read pcap files using Scapy
total_pcap_pkts = rdpcap(pcap_file)

## Calculate total packets in pcap file
total_pkts_count = len(total_pcap_pkts)

## Filter packets based on src and dst ip
pkt_counter = 0
filtered_ip_pkts = []
for pkt in total_pcap_pkts:
    if pkt[IP].src == src_ip and pkt[IP].dst == dst_ip:
        filtered_ip_pkts.append(pkt)
        pkt_counter +=1

## Filter packets to obtain only retransmissions
re_tx_filter = 'tcp.analysis.retransmission && ip.src=='+ src_ip + ' && ip.dst==' + dst_ip
re_tx_total_pkts = pyshark.FileCapture(pcap_file, display_filter=re_tx_filter)
re_tx_counter = 0
for re_tx_pkt in re_tx_total_pkts:
    re_tx_counter +=1

print('####################################################################')
print('between given IPs:')
print(f'total pkts: {pkt_counter}')
print(f're-tx pkts: "{re_tx_counter}" - percentage: "{round((re_tx_counter*100)/pkt_counter,2)}%"')

print('####################################################################\n')
print('####################################################################')
print(f'Total pkts in pcap file: {total_pkts_count}')
print('####################################################################\n')
