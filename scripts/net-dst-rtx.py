#!/usr/bin/env python3
from scapy.all import *
import pyshark

## Input variables
## TODO:
## Change vars to input arguments
pcap_file = 'pcap-captures/mycap2.pcap'
dst_net = "190.57.158.0/24"

## Print IPs for Analysis
print('####################################################################')
print(f'Analysis for dst network: "{dst_net}"')
print('####################################################################\n')

## Read pcap files using Scapy
total_pcap_pkts = rdpcap(pcap_file)

## Calculate total packets in pcap file
total_pkts_count = len(total_pcap_pkts)

## Filter packets based on dst network
dst_net_filter = 'ip.dst=='+ dst_net
dst_net_total_pkts = pyshark.FileCapture(pcap_file, display_filter=dst_net_filter)
dst_net_counter = 0
for dst_net_pkt in dst_net_total_pkts:
    dst_net_counter +=1

## Filter packets to obtain only retransmissions
re_tx_filter = 'tcp.analysis.retransmission && ip.dst=='+ dst_net
re_tx_total_pkts = pyshark.FileCapture(pcap_file, display_filter=re_tx_filter)
re_tx_counter = 0
for re_tx_pkt in re_tx_total_pkts:
    re_tx_counter +=1

print('####################################################################')
print('for given dst network:')
print(f'total pkts: {dst_net_counter}')
print(f're-tx pkts: "{re_tx_counter}" - percentage: "{round((re_tx_counter*100)/dst_net_counter,2)}%"')

print('####################################################################\n')
print('####################################################################')
print(f'Total pkts in pcap file: {total_pkts_count}')
print('####################################################################\n')
