# Helpful notes for testing eBPF

## Setup

We first want to set up an environment for testing. While we could do this the SMART way and use a VM, we will instead directly attach to the host kernel using a dummy interface.

If you want to check what interfaces are available, you can use the following command:

```bash
ip addr
```

### Create a dummy interface
We can create a dummy interface using the following command:

```bash
sudo ip link add dummy0 type dummy
```

We need to bring up the dummy interface using the following command:

```bash
sudo ip link set dummy0 up
```

### Remove the dummy interface
To remove the dummy interface, we can use the following command:

```bash
sudo ip link del dummy0
```

### Add a qdisc to the dummy interface

First, we add a qdisc (queueing discipline) to the dummy interface. This will allow us to test our eBPF program without needing to set up a VM or a container. We can use the following command to add a qdisc to the dummy interface:

```bash
sudo tc qdisc add dev dummy0 clsact
```

We can list the qdiscs on the dummy interface using the following command:

```bash
tc qdisc show dev dummy0
```

You should see something like this:

```bash
qdisc clsact ffff: parent ffff:fff1
```

To remove the qdisc, we can use the following command:

```bash
sudo tc qdisc del dev dummy0 clsact
```

## Load the eBPF program
We can load the eBPF program using the following command:

```bash
sudo tc filter add dev dummy0 egress bpf da obj ./ebpf_plugin.o sec egress_init
```

To show the filters, we can use the following command:

```bash
tc filter show dev dummy0 egress
```

To remove the filter, we can use the following command:

```bash
sudo tc filter del dev dummy0 egress
```

### Logs

You can read the log pipe with the following command:

```bash
sudo cat  /sys/kernel/debug/tracing/trace_pipe
```

### Print maps

You can print the pinned eBPF maps using the following command:

```bash
sudo bpftool map dump pinned /sys/fs/bpf/ebpf_plugin/ebpf_plugin/maps
```
