#!/usr/bin/env python3
from scapy.all import *
import pyshark

""" Script net-bi-rtx.py:
Function:
- Pcap file, source and destination networks as inputs
- Calculate amount of total packets between given networks
- Calculate amount of re-transmission packets between given networks
- Calculate percentage of re-transmission packets between given networks
- Calculate amount of total packets in given pcap file
"""
## Input variables
## TODO:
## Change vars to input arguments
pcap_file = 'sample-captures/tcp.pcap'
src_net = "23.56.172.0/24"
dst_net = "190.57.158.0/24"

## Print IPs for Analysis
print('####################################################################')
print(f'Analysis between src network: "{src_net}" && dst network: "{dst_net}"')
print('####################################################################\n')

## Read pcap files using Scapy
total_pcap_pkts = rdpcap(pcap_file)

## Calculate total packets in pcap file
total_pkts_count = len(total_pcap_pkts)

## Filter packets based on src && dst network
bi_net_filter = 'ip.src=='+ src_net + ' && ip.dst==' + dst_net
bi_net_total_pkts = pyshark.FileCapture(pcap_file, display_filter=bi_net_filter)
bi_net_counter = 0
for bi_net_pkt in bi_net_total_pkts:
    bi_net_counter +=1

## Filter packets to obtain only retransmissions
re_tx_filter = 'tcp.analysis.retransmission && ip.src=='+ src_net + ' && ip.dst==' + dst_net
re_tx_total_pkts = pyshark.FileCapture(pcap_file, display_filter=re_tx_filter)
re_tx_counter = 0
for re_tx_pkt in re_tx_total_pkts:
    re_tx_counter +=1

print('####################################################################')
print('between given networks:')
print(f'total pkts: {bi_net_counter}')
print(f're-tx pkts: "{re_tx_counter}" - percentage: "{round((re_tx_counter*100)/bi_net_counter,2)}%"')

print('####################################################################\n')
print('####################################################################')
print(f'Total pkts in pcap file: {total_pkts_count}')
print('####################################################################\n')
