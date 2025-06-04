#!/bin/bash

# Install helm
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm

# Install cilium
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium --version 1.12.4 \
--namespace kube-system \
--set kubeProxyReplacement=enabled \
--set k8sServiceHost="10.10.1.1" \
--set k8sServicePort=6443 \
--set routingMode=native \
--set bpf.masquerade=true \
--set ipv4.enabled=true \
--set enableIPv4BIGTCP=true \
--set ipv4NativeRoutingCIDR="10.244.0.0/16" \
--set autoDirectNodeRoutes=true \
--set installNoConntrackIptablesRules=true \
--set hubble.enabled=false \
--set bpfClockProbe=true \
--set tunnel=disabled
