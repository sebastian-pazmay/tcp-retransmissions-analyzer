#!/usr/bin/env python3
from scapy.all import *
import pyshark

""" Script net-src-rtx.py:
Function:
- Pcap file and source network as inputs
- Calculate amount of total packets for given network
- Calculate amount of re-transmission packets for given network
- Calculate percentage of re-transmission packets for given network
- Calculate amount of total packets in given pcap file
"""

pcap_file = 'sample-captures/tcp.pcap'
src_net = '10.10.10.0/24'

## Print IPs for Analysis
print('####################################################################')
print(f'Analysis for src network: "{src_net}"')
print('####################################################################\n')

## Read pcap files using Scapy
total_pcap_pkts = rdpcap(pcap_file)

## Calculate total packets in pcap file
total_pkts_count = len(total_pcap_pkts)

## Filter packets based on src network
src_net_filter = 'ip.src=='+ src_net
src_net_total_pkts = pyshark.FileCapture(pcap_file, display_filter=src_net_filter)
src_net_counter = 0
for src_net_pkt in src_net_total_pkts:
    src_net_counter +=1

## Filter packets to obtain only retransmissions
re_tx_filter = 'tcp.analysis.retransmission && ip.src=='+ src_net
re_tx_total_pkts = pyshark.FileCapture(pcap_file, display_filter=re_tx_filter)
re_tx_counter = 0
for re_tx_pkt in re_tx_total_pkts:
    re_tx_counter +=1

print('####################################################################')
print('for given src network:')
print(f'total pkts: {src_net_counter}')
print(f're-tx pkts: "{re_tx_counter}" - percentage: "{round((re_tx_counter*100)/src_net_counter,2)}%"')

print('####################################################################\n')
print('####################################################################')
print(f'Total pkts in pcap file: {total_pkts_count}')
print('####################################################################\n')
