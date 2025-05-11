import subprocess
from typing import Optional

from shared.config import BenchType, BenchmarkConfig, get_benchmark_config, load_config
from shared.setup import get_role
from shared.util import exp_range


def run_client(
    benchmark_config: BenchmarkConfig, destination: str, bench_type: BenchType
):
    # IPerf Throughput Benchmark
    print("Running iperf3 benchmark (client)")
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
            f"logs/baremetal/{bench_type.value.lower()}/client_log_throughput_{n_flows}_flows.json",
            "--json",  # Output in JSON format for easier parsing
        ]
        if bench_type == BenchType.UDP:
            cmd.append("-u")  # UDP test
        subprocess.run(cmd, check=True)
    print(f"iperf3 {bench_type.value} throughput benchmark completed for all flows.")
    input("Press Enter to continue to the next benchmark...")

    # Netperf RR Benchmark
    print("Running netperf benchmark (client)")
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
            f"{bench_type.value}_RR",  # RR test
            "-C",  # Report remote CPU utilization
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
        print(f"Netperf completed successfully for {n_flows} flows.")
        for i, p in enumerate(processes):
            # Export the output to a file
            with open(
                f"logs/baremetal/{bench_type.value.lower()}/client_log_rr_{n_flows}_flows.txt",
                "a",
            ) as f:
                f.write(f"Output for flow {i + 1}:\n")
                f.write(p.stdout.read().decode())
    print(f"netperf {bench_type.value} RR benchmark completed for all flows.")


def run_server(benchmark_config: BenchmarkConfig):
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


def run_benchmark_type(
    bench_type: BenchType, general_config: BenchmarkConfig, spec_config: dict
):
    role = get_role()
    if role == "primary":
        destination = spec_config["node"]["secondary"]["ip"]
        run_client(general_config, destination, bench_type)
    elif role == "secondary":
        run_server(general_config)
    else:
        raise ValueError(f"Unknown role: {role}. Expected 'primary' or 'secondary'.")


def run_benchmark(bench_type: Optional[BenchType] = None):
    general_config = get_benchmark_config()
    spec_config = load_config("config/baremetal.toml")

    # Clear logs
    for bench_type in BenchType:
        subprocess.run(
            ["mkdir", "-p", f"logs/baremetal/{bench_type.value.lower()}"],
            check=True,
        )
        subprocess.run(
            [
                "find",
                f"logs/baremetal/{bench_type.value.lower()}",
                "-name",
                "*.json",
                "-delete",
            ],
            check=True,
        )
        subprocess.run(
            [
                "find",
                f"logs/baremetal/{bench_type.value.lower()}",
                "-name",
                "*.txt",
                "-delete",
            ],
            check=True,
        )

    if bench_type is None:
        for bench_type in BenchType:
            print(f"Running benchmark for {bench_type.value}...")
            run_benchmark_type(bench_type, general_config, spec_config)
    else:
        print(f"Running benchmark for {bench_type.value}...")
        run_benchmark_type(bench_type, general_config, spec_config)
    print("Benchmark completed.")
