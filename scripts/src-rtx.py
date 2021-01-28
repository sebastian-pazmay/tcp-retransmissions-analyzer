#!/usr/bin/env python3
from scapy.all import *
import pyshark

""" Script src-rtx.py:
Function:
- Pcap file and source IP address as inputs
- Calculate amount of total packets for given IP
- Calculate amount of re-transmission packets for given IP
- Calculate percentage of re-transmission packets for given IP
- Calculate amount of total packets in given pcap file
"""

pcap_file = 'sample-captures/tcp.pcap'
src_ip = '10.10.10.1'

## Print IPs for Analysis
print('####################################################################')
print(f'Analysis for src IP: "{src_ip}"')
print('####################################################################\n')

## Read pcap files using Scapy
total_pcap_pkts = rdpcap(pcap_file)

## Calculate total packets in pcap file
total_pkts_count = len(total_pcap_pkts)

## Filter packets based on src ip
pkt_counter = 0
filtered_ip_pkts = []
for pkt in total_pcap_pkts:
    if pkt[IP].src == src_ip:
        filtered_ip_pkts.append(pkt)
        pkt_counter +=1

## Filter packets to obtain only retransmissions
re_tx_filter = 'tcp.analysis.retransmission && ip.src=='+ src_ip
re_tx_total_pkts = pyshark.FileCapture(pcap_file, display_filter=re_tx_filter)
re_tx_counter = 0
for re_tx_pkt in re_tx_total_pkts:
    re_tx_counter +=1

print('####################################################################')
print('for given src IP:')
print(f'total pkts: {pkt_counter}')
print(f're-tx pkts: "{re_tx_counter}" - percentage: "{round((re_tx_counter*100)/pkt_counter,2)}%"')

print('####################################################################\n')
print('####################################################################')
print(f'Total pkts in pcap file: {total_pkts_count}')
print('####################################################################\n')
