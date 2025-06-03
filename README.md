# CS244 Replication of "ONCache: A Cache-Based Low-Overhead Container Overlay Network"

## Setup Instructions

As specified in the original paper, this code (and associated scripts) is designed to run on Ubuntu 20.04 LTS with Linux kernel 5.14.

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/sebastianingino/CS244-oncache.git
   cd CS244-oncache
   ```

2. **Update the Kernel**

   Note: Ubuntu 20.04 LTS comes with Linux kernel 5.4 by default. You will need to update it to version 5.14.

   ```bash
   scripts/kernel_update.sh
   ```

3. **Remove bad packages**:

   Some packages may be installed with broken dependencies. If you encounter issues, you can try to fix them by running:

   ```bash
   sudo apt install -f
   ```

4. **Run the setup script**:

   ```bash
   source scripts/setup.sh
   ```

## Kubernetes Setup

1. **Install Kubernetes**:

   On all nodes:

   ```bash
   scripts/k8s_install.sh
   ```

2. **Configure Control Plane**:

   On the control plane node:

   ```bash
   scripts/k8s_setup_cp_generic.sh
   ```

   If you are using Cilium as the kube-proxy, you should instead run:

   ```bash
   scripts/k8s_setup_cp_noproxy.sh
   ```

3. **Configure Worker Nodes**:

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
