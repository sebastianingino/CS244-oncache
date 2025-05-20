#!/bin/bash

sudo apt install iperf3 netperf clang libbpf-dev llvm make -y

sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

curl https://mise.run | sh
