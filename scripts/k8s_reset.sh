sudo rm -f /etc/containerd/config.toml
sudo kubeadm reset -f; rm $HOME/.kube/config -f
sudo rm -rf /etc/cni/net.d
sudo ipvsadm --clear

sudo rm -rf /var/lib/etcd
sudo rm -rf /var/lib/cni
sudo rm -rf /var/lib/kubelet
sudo rm -rf /var/lib/containerd
sudo rm -rf /var/run/kubernetes
sudo rm -rf /var/run/cni

sudo containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i -e 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd

sudo systemctl restart kubelet.service
