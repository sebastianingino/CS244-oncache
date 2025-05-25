#!/bin/bash

LOCAL_IP=10.10.1.2
echo "KUBELET_EXTRA_ARGS=--node-ip=$LOCAL_IP" | sudo tee /etc/default/kubelet
sudo systemctl restart kubelet.service
