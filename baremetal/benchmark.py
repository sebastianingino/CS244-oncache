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
    print("iperf3 throughput benchmark completed for all flows.")

    # Netperf Latency Benchmark
    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        cmd = [
            "netperf",
            "-H",
            destination,
            "-p",  # Port number to connect to the server
            str(benchmark_config["port_start"]),
            "-t",  # Test type
            "TCP_RR",  # TCP request/response test
            "-C"  # Report remote CPU utilization
            "-i",  # number of iterations
            str(benchmark_config["iterations"]),
        ]

        processes = []
        for _ in range(n_flows):
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(p)
        for p in processes:
            p.wait()
            if p.returncode != 0:
                print(
                    f"Error in netperf for {n_flows} flows: {p.stderr.read().decode()}"
                )
            else:
                print(f"Netperf completed successfully for {n_flows} flows.")
        for i, p in enumerate(processes):
            # Export the output to a file
            with open(
                f"logs/baremetal/client_log_latency_{n_flows}_flows.json", "a"
            ) as f:
                f.write(f"Output for flow {i + 1}:\n")
                f.write(p.stdout.read().decode())
    print("netperf latency benchmark completed for all flows.")


def run_server(benchmark_config: TCPBenchmarkConfig):
    # iperf3 throughput benchmark
    cmd = [
        "iperf3",
        "-s",
        "-p",
        str(benchmark_config["port_start"]),
        "--logfile",
        f"logs/baremetal/server_log_throughput_flows.json",
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

    # netperf latency benchmark
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
    general_config = get_benchmark_config()["tcp"]
    spec_config = load_config("config/baremetal.toml")
    role = get_role()

    # Clear logs
    subprocess.run(["mkdir", "-p", "logs/baremetal"], check=True)
    subprocess.run(["find", "logs/baremetal", "-name", "*.json", "-delete"], check=True)

    if role == "primary":
        destination = spec_config["node"]["secondary"]["ip"]
        run_client(general_config, destination)
    elif role == "secondary":
        run_server(general_config)
    else:
        raise ValueError(f"Unknown role: {role}. Expected 'primary' or 'secondary'.")
