# Remove taint
kubectl taint nodes node0 node-role.kubernetes.io/control-plane:NoSchedule- | true

# Add roles
kubectl label nodes node0 bench-role=client
kubectl label nodes node1 bench-role=server
