# ONCache Kubernetes Benchmark
This repo runs automated benchmarks for ONCache, Antrea, and Cilium using iperf3 and netperf in a GKE Kubernetes cluster

## Reqs
- gcp 
- [gcloud SDK](https://cloud.google.com/sdk/docs/install) with kubectl (gcloud init)
- Or use [Google Cloud Shell](https://shell.cloud.google.com/)

## Use
```bash
chmod +x bench.sh
./bench.sh
