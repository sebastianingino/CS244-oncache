import subprocess
from typing import Optional

from shared.config import BenchType, BenchmarkConfig, get_benchmark_config, load_config
from shared.setup import get_role
from shared.util import exp_range


def run_client_iperf(
    benchmark_config: BenchmarkConfig, destination: str, bench_type: BenchType
):
    print(f"Running iperf3 benchmark for {bench_type.value} (client)")
    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        procs = []
        for i in range(n_flows):
            cmd = [
                "iperf3",
                "-c",
                destination,
                "-p",  # Port number to connect to the server
                str(benchmark_config["port_start"] + i),
                "-t",  # Duration of the test in seconds
                str(benchmark_config["duration"]),
                "--logfile",
                f"logs/baremetal/{bench_type.value.lower()}/client_log_throughput_{n_flows}_flows_{i}.json",
                "--json",  # Output in JSON format for easier parsing
            ]
            if bench_type == BenchType.UDP:
                cmd.append("-u")  # UDP test
                cmd.append("-b")  # Bitrate limit
                cmd.append("0")  # No limit
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)
        for p in procs:
            p.wait()
            if p.returncode != 0:
                print(
                    f"Error in iperf3 for {n_flows} flows: {p.stderr.read().decode()}"
                )
        print(f"iperf3 completed successfully for {n_flows} flows.")
    print(f"iperf3 {bench_type.value} throughput benchmark completed for all flows.")


def run_client_netperf(
    benchmark_config: BenchmarkConfig, destination: str, bench_type: BenchType
):
    print(f"Running netperf benchmark for {bench_type.value} (client)")
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
        print(f"netperf completed successfully for {n_flows} flows.")
        for i, p in enumerate(processes):
            # Export the output to a file
            with open(
                f"logs/baremetal/{bench_type.value.lower()}/client_log_rr_{n_flows}_flows.txt",
                "a",
            ) as f:
                f.write(f"Output for flow {i + 1}:\n")
                f.write(p.stdout.read().decode())
    print(f"netperf {bench_type.value} RR benchmark completed for all flows.")


def run_client(
    benchmark_config: BenchmarkConfig,
    destination: str,
    bench_type: Optional[BenchType],
    test: Optional[str] = None,
):
    if test is None or test == "throughput":
        # iperf Throughput Benchmark
        if bench_type is None:
            for bt in BenchType:
                run_client_iperf(benchmark_config, destination, bt)
        else:
            run_client_iperf(benchmark_config, destination, bench_type)

    if test is None:
        input("Press Enter to continue to the next benchmark...")

    if test is None or test == "latency":
        # netperf Latency Benchmark
        if bench_type is None:
            for bt in BenchType:
                run_client_netperf(benchmark_config, destination, bt)
        else:
            run_client_netperf(benchmark_config, destination, bench_type)


def run_server_iperf(benchmark_config: BenchmarkConfig):
    print("Running iperf3 server")
    # iperf3 throughput benchmark
    procs = []
    for i in range(benchmark_config["max_flows"]):
        cmd = [
            "iperf3",
            "-s",
            "-p", # Port number to listen on
            str(benchmark_config["port_start"] + i),
            "--logfile",
            f"logs/baremetal/server_log_throughput_{i}_flows.json",
            "--json",  # Output in JSON format for easier parsing
        ]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        procs.append(p)
    input("Press Enter when finished with iperf...")
    for p in procs:
        p.terminate()
        p.wait()
        # Check if the process is still running and terminate it
        if p.poll() is None:
            p.terminate()
            p.wait()
    print("iperf3 server terminated successfully.")


def run_server_netperf(benchmark_config: BenchmarkConfig):
    print("Running netserver")
    # netperf rr benchmark
    cmd = [
        "netserver",
        "-p", # Port number to listen on
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


def run_server(benchmark_config: BenchmarkConfig, test: Optional[str] = None):
    if test is None:
        run_server_iperf(benchmark_config)
        run_server_netperf(benchmark_config)
    elif test == "latency":
        # netserver rr benchmark
        run_server_netperf(benchmark_config)
    elif test == "throughput":
        # iperf3 throughput benchmark
        run_server_iperf(benchmark_config)


def run_benchmark(bench_type: Optional[BenchType] = None, test: Optional[str] = None):
    general_config = get_benchmark_config()
    spec_config = load_config("config/baremetal.toml")

    # Clear logs
    for b in [bench_type] if bench_type else BenchType:
        for t in [test] if test else ["latency", "throughput"]:
            subprocess.run(
                ["mkdir", "-p", f"logs/baremetal/{b.value.lower()}"],
                check=True,
            )
            subprocess.run(
                [
                    "find",
                    f"logs/baremetal/{b.value.lower()}",
                    "-name",
                    f"*_{t}_*.json",
                    "-delete",
                ],
                check=True,
            )
            subprocess.run(
                [
                    "find",
                    f"logs/baremetal/{b.value.lower()}",
                    "-name",
                    f"*_{t}_*.txt",
                    "-delete",
                ],
                check=True,
            )

    role = get_role()
    if role == "primary":
        destination = spec_config["node"]["secondary"]["ip"]
        run_client(general_config, destination, bench_type, test)
    elif role == "secondary":
        run_server(general_config, test)
    else:
        raise ValueError(f"Unknown role: {role}. Expected 'primary' or 'secondary'.")

    print("Benchmark completed.")
