sudo rm -f /etc/containerd/config.toml; sudo systemctl restart containerd.service
sudo systemctl restart kubelet.service
sudo kubeadm reset -f; rm $HOME/.kube/config -f
