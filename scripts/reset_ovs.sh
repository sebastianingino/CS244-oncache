pod=s$(kubectl get pods -n kube-system -l app=antrea,component=antrea-agent -o name | cut -d '/' -f 2)
for pod in $pods
do
  cmd="kubectl exec -n kube-system $pod -c antrea-ovs -- ovs-ofctl mod-flows br-int"
  $cmd "table=ConntrackState, priority=200,ct_state=-new+trk,ct_mark=0x10/0x10,ip actions=load:0x1->NXM_NX_REG0[9],resubmit(,AntreaPolicyEgressRule)"
  $cmd "table=ConntrackState, priority=190,ct_state=-new+trk,ip actions=resubmit(,AntreaPolicyEgressRule)"
done
