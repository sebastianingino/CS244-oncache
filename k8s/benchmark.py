from kubernetes import client, config
import subprocess
from typing import List, TypedDict

from shared.config import TCPBenchmarkConfig, get_benchmark_config
from shared.util import exp_range

IPERF_SERVER_DEPLOYMENT = "k8s/deployments/server_iperf.yaml"
IPERF_CLIENT_DEPLOYMENT = "k8s/deployments/client_iperf.yaml"

NETPERF_SERVER_DEPLOYMENT = "k8s/deployments/server_netperf.yaml"
NETPERF_CLIENT_DEPLOYMENT = "k8s/deployments/client_netperf.yaml"


def load_kube_config():
    try:
        config.load_kube_config()
    except Exception as e:
        print(f"Error loading kube config: {e}")
        raise


PodConfig = TypedDict(
    "PodConfig",
    {
        "name": str,
        "ip": str,
    },
)

Pods = TypedDict(
    "Pods",
    {
        "clients": List[PodConfig],
        "servers": List[PodConfig],
    },
)

def k8s_startup(name: str, server_deployment: str, client_deployment: str) -> Pods:
    subprocess.run(["kubectl", "apply", "-f", server_deployment])
    subprocess.run(["kubectl", "apply", "-f", client_deployment])

    # Wait for all pods to be ready
    subprocess.run(
        [
            "kubectl",
            "wait",
            "--for=condition=Ready",
            "pods",
            "--all",
            "--timeout=60s",
            "-n",
            "default",
        ]
    )

    v1 = client.CoreV1Api()
    # Get all client pods
    pods = v1.list_namespaced_pod(
        namespace="default", label_selector=f"app=client-{name}"
    )
    client_pods: List[PodConfig] = []
    for pod in pods.items:
        if pod.status.phase != "Running":
            print(f"Pod {pod.metadata.name} is not running, status: {pod.status.phase}")
            continue
        client_pods.append(
            {
                "name": pod.metadata.name,
                "ip": pod.status.pod_ip,
            }
        )

    # Get all server pods
    pods = v1.list_namespaced_pod(
        namespace="default", label_selector=f"app=server-{name}"
    )
    server_pods: List[PodConfig] = []
    for pod in pods.items:
        if pod.status.phase != "Running":
            print(f"Pod {pod.metadata.name} is not running, status: {pod.status.phase}")
            continue
        server_pods.append(
            {
                "name": pod.metadata.name,
                "ip": pod.status.pod_ip,
            }
        )

    return {
        "clients": client_pods,
        "servers": server_pods,
    }


def k8s_teardown(server_deployment: str, client_deployment: str):
    subprocess.run(["kubectl", "delete", "-f", server_deployment])
    subprocess.run(["kubectl", "delete", "-f", client_deployment])
    subprocess.run(["kubectl", "wait", "--for=delete", "-f", server_deployment])
    subprocess.run(["kubectl", "wait", "--for=delete", "-f", client_deployment])


def run_iperf3_benchmark(benchmark_config: TCPBenchmarkConfig, pods: Pods):
    print("Running iperf3 benchmark...")
    pairs = list(zip(pods["clients"], pods["servers"]))
    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        print(f"Running iperf3 for {n_flows} flows...")
        processes = []
        for client, server in pairs[:n_flows]:
            cmd = [
                "kubectl",
                "exec",
                client["name"],
                "--",
                "iperf3",
                "-c",
                server["ip"],
                "-t",  # Test type
                str(benchmark_config["duration"]),
                "--json",
            ]

            processes.append(
                subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            )

        for i, p in enumerate(processes):
            p.wait()
            if p.returncode != 0:
                print(
                    f"Error in iperf3 for {n_flows} flows: {p.stderr.read().decode()}"
                )
            else:
                # Export the output to a file
                with open(
                    f"logs/k8s/client_log_throughput_{n_flows}_flows_{i}.json",
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write(p.stdout.read().decode())

    print("iperf3 throughput benchmark completed for all flows.")


def run_netperf_benchmark(benchmark_config: TCPBenchmarkConfig, pods: Pods):
    print("Running netperf benchmark...")
    pairs = list(zip(pods["clients"], pods["servers"]))
    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        print(f"Running netperf for {n_flows} flows...")
        processes = []
        for client, server in pairs[:n_flows]:
            cmd = [
                "kubectl",
                "exec",
                client["name"],
                "--",
                "netperf",
                "-H",
                server["ip"],
                "-t",  # Test type
                "TCP_STREAM",  # TCP stream test
                "-C",  # Report remote CPU utilization
                "-i",  # number of iterations
                str(benchmark_config["iterations"]),
            ]

            processes.append(
                subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            )

        for i, p in enumerate(processes):
            p.wait()
            if p.returncode != 0:
                print(
                    f"Error in netperf for {n_flows} flows: {p.stderr.read().decode()}"
                )
            else:
                # Export the output to a file
                with open(
                    f"logs/k8s/client_log_netperf_{n_flows}_flows_{i}.txt",
                    "w",
                    encoding="utf-8",
                ) as f:
                    f.write(p.stdout.read().decode())

    print("netperf benchmark completed for all flows.")

def run_benchmark():
    benchmark_config = get_benchmark_config()["tcp"]
    load_kube_config()

    # Clear logs
    subprocess.run(["mkdir", "-p", "logs/k8s"], check=True)
    subprocess.run(["find", "logs/k8s", "-name", "*.json", "-delete"], check=True)
    subprocess.run(["find", "logs/k8s", "-name", "*.txt", "-delete"], check=True)

    # Run iperf3 benchmark
    pods = k8s_startup("iperf", IPERF_SERVER_DEPLOYMENT, IPERF_CLIENT_DEPLOYMENT)
    run_iperf3_benchmark(benchmark_config, pods)
    k8s_teardown(IPERF_SERVER_DEPLOYMENT, IPERF_CLIENT_DEPLOYMENT)

    # Run netperf benchmark
    pods = k8s_startup("netperf", NETPERF_SERVER_DEPLOYMENT, NETPERF_CLIENT_DEPLOYMENT)
    run_netperf_benchmark(benchmark_config, pods)
    k8s_teardown(NETPERF_SERVER_DEPLOYMENT, NETPERF_CLIENT_DEPLOYMENT)
