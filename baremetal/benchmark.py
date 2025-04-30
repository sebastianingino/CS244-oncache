import os
import subprocess

from shared.config import TCPBenchmarkConfig, get_benchmark_config, load_config
from shared.setup import get_role
from shared.util import exp_range


def run_client(benchmark_config: TCPBenchmarkConfig, destination: str):
    # IPerf Throughput Benchmark
    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
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


def run_server(benchmark_config: TCPBenchmarkConfig):
    # iperf3 throughput benchmark
    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        cmd = [
            "iperf3",
            "-s",
            "-p",
            str(benchmark_config["port_start"]),
            "-1",  # Run in one-off mode
            "-D",  # Run in daemon mode
            "--logfile",
            f"logs/baremetal/server_log_throughput_{n_flows}_flows.json",
            "--json",  # Output in JSON format for easier parsing
        ]
        subprocess.run(cmd, check=True)

    # netperf latency benchmark
    cmd = [
        "netserver",
        "-p", 
        str(benchmark_config["port_start"]),
        "-D",  # Run NOT as a daemon
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # Run the netserver for the specified duration
        p.wait(benchmark_config["duration"] + 10)
        if p.returncode != 0:
            raise subprocess.CalledProcessError(p.returncode, cmd)
        print("netserver started successfully.")
        # If the process is still running, terminate it
        if p.poll() is None:
            p.terminate()
            p.wait()
        print("netserver terminated successfully.")
    except subprocess.TimeoutExpired:
        print("netserver started successfully.")
    except Exception as e:
        print(f"Error starting netserver: {e}")
        return



def run_benchmark():
    general_config = get_benchmark_config()["tcp"]
    spec_config = load_config("config/baremetal.toml")
    role = get_role()

    # Clear logs
    subprocess.run(["mkdir", "-p", "logs/baremetal"], check=True)
    subprocess.run(["find", "logs/baremetal", "--name", "*.json", "-delete"], check=True)

    if role == "primary":
        destination = spec_config["node"]["secondary"]["ip"]
        run_client(general_config, destination)
    elif role == "secondary":
        run_server(general_config)
    else:
        raise ValueError(f"Unknown role: {role}. Expected 'primary' or 'secondary'.")
