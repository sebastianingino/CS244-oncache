import subprocess
from typing import Union

from shared.config import (UDPBenchmarkConfig, TCPBenchmarkConfig, get_benchmark_config, load_config)
from shared.setup import get_role
from shared.util import exp_range


def range_from_config(benchmark_config: Union[UDPBenchmarkConfig, TCPBenchmarkConfig]):
    return exp_range(benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2)


def run_parallel_netperf(cmd: list[str], n_flows: int, file: str):
    processes = []
    for _ in range(n_flows):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(p)
    for p in processes:
        p.wait()
        if p.returncode != 0:
            print(f"Error in netperf for {n_flows} flows: {p.stderr.read().decode()}")
    for i, p in enumerate(processes):
        # Export the output to a file
        with open(file, "a") as f:
            f.write(f"Output for flow {i + 1}:\n")
            f.write(p.stdout.read().decode())


def run_client_udp(benchmark_config: UDPBenchmarkConfig, destination: str):
    # IPerf Throughput benchmark
    print("Running iperf3 UDP throughput benchmark (Client)")
    for n_flows in range_from_config(benchmark_config):
        cmd = [
            "iperf3",
            "-b", benchmark_config["bandwidth"],
            "-c", destination,
            "-u",
            "-p", str(benchmark_config["port_start"]),
            "-t", str(benchmark_config["duration"]),
            "-P", str(n_flows),
            "--logfile", f"logs/baremetal/client_log_udp_throughput_{n_flows}_flows.json",
            "--json"
        ]
        subprocess.run(cmd, check=True)
    print("iperf3 UDP throughput benchmark completed for all flows.")
    input("Press Enter to continue to the next benchmark")

    # Netperf RR benchmark
    print("Running netperf UDP RR benchmark (Client)")
    for n_flows in range_from_config(benchmark_config):
        cmd = [
            "netperf",
            "-H", destination,
            "-p", str(benchmark_config["port_start"]),
            "-t", "UDP_RR",
            "-C",
            "-i", str(benchmark_config["iterations"]),
        ]
        run_parallel_netperf(cmd, n_flows, f"logs/baremetal/client_log_udp_rr_{n_flows}_flows.txt")
        print(f"Netperf completed successfully for {n_flows} flows.")
    print("netperf UDP RR benchmark completed for all flows.")


def run_client_tcp(benchmark_config: TCPBenchmarkConfig, destination: str):
    # IPerf Throughput Benchmark
    print("Running iperf3 TCP benchmark (Client)")
    for n_flows in range_from_config(benchmark_config):
        cmd = [
            "iperf3",
            "-c",
            destination,
            "-p",  # Port number to connect to the server
            str(benchmark_config["port_start"]),
            "-t",  # Duration of the test in seconds
            str(benchmark_config["duration"]),
            "-P",  # Number of parallel client streams
            str(n_flows),
            "--logfile",
            f"logs/baremetal/client_log_throughput_{n_flows}_flows.json",
            "--json",  # Output in JSON format for easier parsing
        ]
        subprocess.run(cmd, check=True)
    print("iperf3 TCP throughput benchmark completed for all flows.")
    input("Press Enter to continue to the next benchmark...")

    # Netperf RR Benchmark
    print("Running netperf TCP RR benchmark (Client)")
    for n_flows in range_from_config(benchmark_config):
        cmd = [
            "netperf",
            "-H",
            destination,
            "-p",  # Port number to connect to the server
            str(benchmark_config["port_start"]),
            "-t",  # Test type
            "TCP_RR",  # TCP request/response test
            "-C",  # Report remote CPU utilization
            "-i",  # number of iterations
            str(benchmark_config["iterations"]),
        ]

        run_parallel_netperf(cmd, n_flows, f"logs/baremetal/client_log_rr_{n_flows}_flows.txt")
        print(f"Netperf completed successfully for {n_flows} flows.")
    print("netperf TCP RR benchmark completed for all flows.")


def run_server(benchmark_config: TCPBenchmarkConfig, iperf_log: str):
    # iperf3 throughput benchmark
    cmd = [
        "iperf3",
        "-s",
        "-p",
        str(benchmark_config["port_start"]),
        "--logfile",
        iperf_log,
        "--json",  # Output in JSON format for easier parsing
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    input("Press Enter when finished with iperf...")
    p.terminate()
    p.wait()
    # Check if the process is still running and terminate it
    if p.poll() is None:
        p.terminate()
        p.wait()
    print("iperf3 server terminated successfully.")

    # netperf rr benchmark
    cmd = [
        "netserver",
        "-p",
        str(benchmark_config["port_start"]),
        "-D",  # Run NOT as a daemon
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    input("Press Enter when finished with netperf...")
    p.terminate()
    p.wait()
    # Check if the process is still running and terminate it
    if p.poll() is None:
        p.terminate()
        p.wait()
    print("netserver terminated successfully.")


def run_benchmark():
    general_config = get_benchmark_config()
    spec_config = load_config("config/baremetal.toml")
    role = get_role()

    # Clear logs
    subprocess.run(["mkdir", "-p", "logs/baremetal"], check=True)
    subprocess.run(["find", "logs/baremetal", "-name", "*.json", "-delete"], check=True)
    subprocess.run(["find", "logs/baremetal", "-name", "*.txt", "-delete"], check=True)

    # TCP roles
    if role == "primary":
        destination = spec_config["node"]["secondary"]["ip"]
        run_client_tcp(general_config["tcp"], destination)
    elif role == "secondary":
        run_server(general_config["tcp"], iperf_log="logs/baremetal/server_log_throughput_flows.json")
    # UDP roles
    elif role == "primary_udp":
        destination = spec_config["node"]["secondary"]["ip"]
        run_client_udp(general_config["udp"], destination)
    elif role == "secondary_udp":
        run_server(general_config()["udp"], iperf_log="logs/baremteal/server_log_udp_throughput_flows.json")
    # Fallthrough case
    else:
        raise ValueError(f"Unknown role: {role}. Expected 'primary', 'secondary', 'primary_udp', or 'secondary_udp'.")
