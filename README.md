# tcp-retransmissions-analyzer

At the moment this project only contains scripts to analyze tcp re-transmissions given a pcap file.

## Scripts

This directory contains different scripts to display tcp re-transmissions. Each script contains documentation about its purpose. A sample capture is provided to test the scripts. In order to execute the scripts: 

```sh
$ python3 scripts/src-dst-rtx.py
```

**Required libraries**

Requirements to be installed before running scripts:

```sh
$ apt install -y tshark
$ pip3 install -r requirements.txt
```

### Dockerfile

In order to test the scripts, a Dockerfile is provided. The following commands allow you to build an image from the Dockerfile and run the container from the created image.

```sh
$ docker build -t bi_rtx -f Dockerfile --build-arg SCRIPT=bi_rtx .
$ docker run bi_rtx:latest
```
