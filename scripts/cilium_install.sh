#!/bin/bash

# Install helm
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm

# Install cilium
helm install cilium cilium/cilium --version 1.17.4 \
--namespace kube-system \
--set routingMode=native \
--set bpf.masquerade=true \
--set ipv4.enabled=true \
--set enableIPv4BIGTCP=true \
--set installNoConntrackIptablesRules=true \
--set kubeProxyReplacement=true \
--set ipv4NativeRoutingCIDR="10.244.0.0/16" \
--set bpf.distributedLRU.enabled=true 
