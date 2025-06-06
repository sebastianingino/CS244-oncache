# CS244 Replication of "ONCache: A Cache-Based Low-Overhead Container Overlay Network"

## Setup Instructions

As specified in the original paper, this code (and associated scripts) is designed to run on Ubuntu 20.04 LTS with Linux kernel 5.14.

1. **Clone the repository**:

   ```bash
   git clone https://github.com/sebastianingino/CS244-oncache.git
   cd CS244-oncache
   ```

2. **Update the kernel** (if necessary):

   Note: Ubuntu 20.04 LTS comes with Linux kernel 5.4 by default. You will need to update it to version 5.14.

   ```bash
   scripts/kernel_upgrade.sh
   ```

   After updating the kernel, some packages may be installed with broken dependencies. If you encounter issues, you can try to fix them by running:

   ```bash
   sudo apt install -f
   ```

3. **Run the setup script**:

   ```bash
   source scripts/setup.sh
   ```

## Kubernetes Setup

1. **Install Kubernetes**:

   On all nodes:

   ```bash
   scripts/k8s_install.sh
   ```

2. **Configure control plane**:

   On the control plane node:

   ```bash
   scripts/k8s_setup_cp_generic.sh
   ```

   If you are using Cilium as the kube-proxy, you should instead run:

   ```bash
   scripts/k8s_setup_cp_noproxy.sh
   ```

3. **Configure worker nodes**:

   On each worker node, run:

   ```bash
   LOCAL_IP=<your_local_ip>; echo "KUBELET_EXTRA_ARGS=--node-ip=$LOCAL_IP" | sudo tee /etc/default/kubelet
   ```

   You should then run the `kubeadm join` command that was outputted when you set up the control plane.

   Lastly, label the nodes as either `bench-role=client` or `bench-role=server` depending on their role in the benchmark:

   ```bash
   kubectl label node <node_name> bench-role=client
   kubectl label node <node_name> bench-role=server
   ```

## Build the Project

After running the setup script, you can build the project using:

```bash
(cd oncache; make all)
```

## Running ONCache

To run ONCache, you should use run it via the user-space manager. This is done by running the following command:

```bash
(cd oncache/user; sudo ./user)
```

### ONCache Configuration

The ONCache manager has some configuration options that can be set via flags. You can see the available flags by running:

```bash
(cd oncache/user; sudo ./user --help)
```

You will likely want to set the following flags:

- `--hostNetdev`: The name of the host network device (e.g., `eth0`).
- `--hostname`: The _Kubernetes_ hostname of the node (e.g., `node1`).

## Running Benchmarks

To run the benchmarks, you can use the provided `benchmark.py` script.

### Benchmark Configuration

The benchmark script uses configuration file `config/benchmark.toml`. You can modify this file to change the benchmark parameters, such as the number of requests, the request size, and the duration of the benchmark.

### Bare Metal Benchmark

The bare metal benchmark requires some additional setup. You will likely need to adjust the server IP address in the `config/baremetal.toml` file to match your setup.

To run the bare metal benchmark, execute the following command on the server node first:

```bash
python3 benchmark.py baremetal -r server
```

Then, on the client node, run:

```bash
python3 benchmark.py baremetal -r client
```

You will need to interact with the benchmark process on both the server and client nodes to complete the test.

### Kubernetes Benchmark

To run the Kubernetes benchmark, you can use the same `benchmark.py` script with the `k8s` argument and specify the overlay name you want to test (this only affects the output file name).

```bash
python3 benchmark.py k8s -o <overlay_name>
```

Note that this script relies on the Kubernetes cluster being set up correctly and the appropriate nodes being labeled as `bench-role=client` and `bench-role=server`.

The benchmark script will automatically deploy the necessary pods and services in the Kubernetes cluster and run the benchmark tests.
