#!/usr/bin/env bash
set -euo pipefail
PROJECT=$(gcloud config get-value project)
ZONE="us-central1-a"
CLUSTER="oncache-bench"
IMAGE="us-central1-docker.pkg.dev/${PROJECT}/bench/oncache:latest"

# enable APIs once
gcloud services enable container.googleapis.com \
                         artifactregistry.googleapis.com \
                         cloudbuild.googleapis.com

# create or get cluster
if ! gcloud container clusters describe $CLUSTER --zone $ZONE &>/dev/null; then
  gcloud container clusters create $CLUSTER \
        --zone $ZONE --num-nodes 3 --machine-type n2-standard-8 \
        --enable-ip-alias --release-channel regular
fi
gcloud container clusters get-credentials $CLUSTER --zone $ZONE

# build and push test image
gcloud builds submit --tag $IMAGE .

# install CNI plugins
# Antrea (default), Cilium, ONCache‑Antrea?
kubectl apply -f https://github.com/antrea-io/antrea/releases/latest/download/antrea.yml
kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/v1.15/install/kubernetes/quick-install.yaml
# kubectl apply -f https://raw.githubusercontent.com/nothepeople/ONCache/main/deploy/antrea_oncache.yml

# wait for nodes to be ready under ONCache
kubectl rollout status daemonset/antrea-agent -n kube-system
kubectl rollout status daemonset/oncache-agent -n kube-system || true

# deploy server DaemonSet + headless service
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata: {name: netbench}
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: bench-srv, namespace: netbench}
spec:
  selector: {matchLabels: {app: bench-srv}}
  template:
    metadata: {labels: {app: bench-srv}}
    spec:
      hostNetwork: true
      containers:
      - name: srv
        image: $IMAGE
        env: [{name: ROLE, value: "server"}]
        volumeMounts: [{name: logs, mountPath: /logs}]
      volumes: [{name: logs, emptyDir: {}}]
---
apiVersion: v1
kind: Service
metadata: {name: srv-headless, namespace: netbench}
spec: {clusterIP: None, selector: {app: bench-srv}, ports: [{port: 5200}]}
EOF

DEST=$(kubectl get pod -n netbench -l app=bench-srv \
        -o jsonpath='{.items[0].status.podIP}')

# launch one shot client job
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: bench-cli-$(date +%s), namespace: netbench}
spec:
  template:
    spec:
      hostNetwork: true
      restartPolicy: Never
      containers:
      - name: cli
        image: $IMAGE
        env:
        - {name: ROLE,    value: "client"}
        - {name: DEST_IP, value: "$DEST"}
        volumeMounts: [{name: logs, mountPath: /logs}]
      volumes: [{name: logs, emptyDir: {}}]
  backoffLimit: 0
EOF

kubectl wait -n netbench --for=condition=complete \
        job -l job-name --timeout=20m

# copy logs locally
POD=$(kubectl get pod -n netbench -l job-name -o name)
mkdir -p results
kubectl cp "netbench/${POD#/}:/logs/." results
echo "✅  JSON logs saved to ./results/"

# delete cluster to stop spending
gcloud container clusters delete $CLUSTER --zone $ZONE -q
