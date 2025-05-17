# Helpful notes for testing eBPF

## Setup

We first want to set up an environment for testing. While we could do this the SMART way and use a VM, we will instead directly attach to the host kernel using the loopback interface. 

If you want to check what interfaces are available, you can use the following command:

```bash
ip addr
```

First, we add a qdisc (queueing discipline) to the loopback interface. This will allow us to test our eBPF program without needing to set up a VM or a container. We can use the following command to add a qdisc to the loopback interface:

```bash
sudo tc qdisc add dev lo clsact
```

We can list the qdiscs on the loopback interface using the following command:

```bash
tc qdisc show dev lo
```

You should see something like this:

```bash
qdisc clsact ffff: parent ffff:fff1
```

## Load the eBPF program
We can load the eBPF program using the following command:

```bash
sudo tc filter add dev lo egress bpf da obj ./ebpf_plugin.o sec egress_init
```

To show the filters, we can use the following command:

```bash
tc filter show dev lo egress
```

To remove the filter, we can use the following command:

```bash
sudo tc filter del dev lo egress
```
