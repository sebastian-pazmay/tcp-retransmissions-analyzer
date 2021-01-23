from scapy.all import *
import pyshark

## Input variables
## TODO:
## Change vars to input arguments
pcap_file = '../pcap-captures/mycap2.pcap'

## Required filter example:
## tcp.analysis.retransmission && ip.src == 190.57.158.160/27
# src_ip = "23.56.172.136"
# dst_ip = "190.57.158.174"

src_network = "190.57.158.160/27"
# dst_network = "190.57.158.174"

# ## Read pcap files using Scapy
# total_pcap_pkts = rdpcap(pcap_file)

# ## Calculate total packets in pcap file
# total_pkts_count = len(total_pcap_pkts)
# print('Total packets found in pcap file: "{}"'.format(total_pkts_count))

######filtered_ip_pkts = []
######for pkt in total_pcap_pkts:
######    if pkt[IP].src == src_ip or pkt[IP].dst == dst_ip:
######        filtered_ip_pkts.append(pkt)
######print('Total packets found for src IP "{}" and dst IP "{}" in pcap file: "{}"'.format(src_ip,dst_ip))


###  When only src_network is given:
## Filter packets based on src_network

# filter = "tcp and src='192.168.2.0/24'"
#           tcp and src='190.57.158.160/27'
re_tx_filter = "src='"+src_network+"'"
total_pcap_pkts=sniff(offline=pcap_file, filter=re_tx_filter)
re_tx_counter = 0
for pkt in total_pcap_pkts:
    re_tx_counter +=1
print('Total re-transmission packets found for src IP "{}" in pcap file: "{}"'.format(src_ip,re_tx_counter))




# ###  When src_ip and dst_ip are given:
# ## Filter packets based on src and dst ip
# filtered_ip_pkts = []
# for pkt in total_pcap_pkts:
#     if pkt[IP].src == src_ip or pkt[IP].dst == dst_ip:
#         filtered_ip_pkts.append(pkt)
# print('Total packets found for src IP "{}" and dst IP "{}" in pcap file: "{}"'.format(src_ip,dst_ip))

# ## Filter packets to obtain only retransmissions
# re_tx_filter = 'tcp.analysis.retransmission && ip.src=='+ src_ip + ' && ip.dst==' + dst_ip
# re_tx_total_pkts = pyshark.FileCapture(pcap_file, display_filter=re_tx_filter)
# re_tx_counter = 0
# for re_tx_pkt in re_tx_total_pkts:
#     re_tx_counter +=1
# print('Total re-transmission packets found for src IP "{}" and dst IP "{}" in pcap file: "{}"'.format(src_ip,dst_ip,re_tx_counter))
