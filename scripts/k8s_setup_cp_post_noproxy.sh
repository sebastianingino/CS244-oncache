#!/bin/bash

LOCAL_IP=10.10.1.1
CIDR=10.244.0.0/16

# Control plane setup script for Kubernetes
# based on https://medium.com/@priyantha.getc/step-by-step-guide-to-creating-a-kubernetes-cluster-on-ubuntu-22-04-using-containerd-runtime-0ead53a8d273
# sudo kubeadm config images pull --cri-socket unix:///var/run/containerd/containerd.sock
echo "KUBELET_EXTRA_ARGS=--node-ip=$LOCAL_IP" | sudo tee /etc/default/kubelet
sudo systemctl restart kubelet.service

sudo kubeadm init \
  --pod-network-cidr=$CIDR \
  --cri-socket unix:///var/run/containerd/containerd.sock \
  --apiserver-advertise-address $LOCAL_IP \
  --skip-phases=addon/kube-proxy \
  --v=5

# Set up kubeconfig for user
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config


