# Remove taint
kubectl taint nodes node0.ingino-258380.cs244-oncache-pg0.utah.cloudlab.us node-role.kubernetes.io/control-plane:NoSchedule- | true

# Add roles
kubectl label nodes node0.ingino-258380.cs244-oncache-pg0.utah.cloudlab.us bench-role=client
kubectl label nodes node1.ingino-258380.cs244-oncache-pg0.utah.cloudlab.us bench-role=server
