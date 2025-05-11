cilium uninstall

# Note run below on all nodes
sudo rm /etc/cni/net.d/05-cilium.conflist
sudo rm -rf /opt/cni/bin/cilium-cni
