sudo rm -f /etc/containerd/config.toml
sudo kubeadm reset -f; rm $HOME/.kube/config -f
sudo rm -rf /etc/cni/net.d
sudo ipvsadm --clear
sudo rm -rf /var/lib/etcd
sudo rm -rf /var/lib/cni
sudo rm -rf /var/lib/kubelet

sudo systemctl restart containerd.service
sudo systemctl restart kubelet.service
