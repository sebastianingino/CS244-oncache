#!/bin/bash

# Based on https://medium.com/@priyantha.getc/step-by-step-guide-to-creating-a-kubernetes-cluster-on-ubuntu-22-04-using-containerd-runtime-0ead53a8d273

sudo apt update
sudo apt install systemd-timesyncd
sudo timedatectl set-ntp true

sudo swapoff -a
sudo sed -i.bak -r 's/(.+ swap .+)/#\1/' /etc/fstab
free -m # Check no swap is enabled

# Load kernel modules
echo "overlay" | sudo tee -a /etc/modules-load.d/k8s.conf
echo "br_netfilter" | sudo tee -a /etc/modules-load.d/k8s.conf

sudo modprobe overlay
sudo modprobe br_netfilter

# Configure networking
echo "net.bridge.bridge-nf-call-ip6tables = 1" | sudo tee -a /etc/sysctl.d/k8s.conf
echo "net.bridge.bridge-nf-call-iptables = 1" | sudo tee -a /etc/sysctl.d/k8s.conf
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.d/k8s.conf

sudo sysctl --system

# Install tools
sudo apt-get install -y apt-transport-https ca-certificates curl gpg gnupg2 software-properties-common

# Install kubeadm, kubelet and kubectl
# based on https://v1-32.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Install containerd
# based on https://www.hostafrica.com/blog/kubernetes/kubernetes-ubuntu-20-containerd/
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

sudo apt update -y 
sudo apt install -y containerd.io

sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml

# Change the cgroup driver to systemd
# TODO
sudo systemctl restart containerd
sudo systemctl enable containerd

# Install cri-tools
sudo apt install cri-tools
echo "runtime-endpoint: unix:///run/containerd/containerd.sock" | sudo tee -a /etc/crictl.yaml
echo "image-endpoint: unix:///run/containerd/containerd.sock" | sudo tee -a /etc/crictl.yaml
echo "timeout: 2" | sudo tee -a /etc/crictl.yaml
echo "debug: false" | sudo tee -a /etc/crictl.yaml
echo "pull-image-on-create: false" | sudo tee -a /etc/crictl.yaml

# Enable kubelet service
sudo systemctl enable kubelet
