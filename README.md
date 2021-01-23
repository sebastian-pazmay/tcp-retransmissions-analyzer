# tcp-retransmissions-analyzer

At the moment this project only contains scripts to analyze tcp re-transmissions given a pcap file.

## Scripts

This directory contains different scripts to display tcp re-transmissions. Each script contains documentation about its purpose. In order to execute the scripts: 

```sh
$ python3 scripts/src-dst-rtx.py
```

## Requirements for Linux

Requirements to be installed before running scripts

```sh
$ apt-get install -y tshark
$ pip3 install -r requirements.txt
```