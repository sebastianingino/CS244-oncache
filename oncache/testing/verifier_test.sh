sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo tc qdisc add dev dummy0 clsact
sudo tc filter add dev dummy0 egress bpf da obj ./ebpf_plugin.o sec egress_init
sudo tc filter add dev dummy0 egress bpf da obj ./ebpf_plugin.o sec egress 
sudo tc filter add dev dummy0 ingress bpf da obj ./ebpf_plugin.o sec ingress_init
sudo tc filter add dev dummy0 ingress bpf da obj ./ebpf_plugin.o sec ingress
sudo tc qdisc del dev dummy0 clsact
sudo ip link del dummy0
