#!/bin/bash

sudo apt install iperf3 netperf clang libbpf-dev llvm linux-headers-`uname -r` -y

curl https://mise.run | sh
