#!/bin/sh

sudo apt install linux-headers-`uname -r`
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

sudo apt install libbpf-dev

rustup install stable
rustup toolchain install nightly --component rust-src

cargo install bpf-linker

