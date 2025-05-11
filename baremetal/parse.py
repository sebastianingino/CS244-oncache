import csv
import json
from typing import Dict, List

from shared.config import BenchType, BenchmarkConfig, get_benchmark_config
from shared.util import exp_range

BITS_TO_GBPS = 1_000_000_000
CSV_FIELDS = [
    "Flows",
    "Throughput",
    "Throughput CPU",
    "RR",
    "RR CPU",
]
THROUGHPUT_PATTERN = (
    "logs/baremetal/{bench_type}/client_log_throughput_{n_flows}_flows.json"
)
RR_PATTERN = "logs/baremetal/{bench_type}/client_log_rr_{n_flows}_flows.txt"


def parse_throughput_single(filename: str, bench_type: BenchType) -> Dict[str, float]:
    """
    Parse the throughput data from the iperf3 JSON output file.
    """
    with open(filename, "r") as f:
        data = json.load(f)
        if bench_type == BenchType.TCP:
            bits_per_second = float(data["end"]["sum_received"]["bits_per_second"])
        else:
            received_rate = 1 - float(data["end"]["sum"]["lost_percent"]) / 100
            bits_per_second = (
                float(data["end"]["sum"]["bits_per_second"]) * received_rate
            )
        cpu_utilization = float(data["end"]["cpu_utilization_percent"]["remote_total"])
        num_flows = int(data["start"]["test_start"]["num_streams"])

        return {
            "Throughput": bits_per_second / BITS_TO_GBPS / num_flows,
            "Throughput CPU": cpu_utilization / num_flows,
        }


def parse_rr_single(
    filename: str, num_flows: int, bench_type: BenchType
) -> Dict[str, float]:
    """
    Parse the RR data from the netperf output file.
    """
    with open(filename, "r") as f:
        lines = f.readlines()

        rates = []
        cpu_usages = []

        for i in range(len(lines)):
            if lines[i].startswith("Local /Remote"):
                data = lines[i + 5].split()
                rates.append(float(data[5]))
                cpu_usages.append(float(data[7]))
        average_rate = sum(rates) / len(rates)
        average_cpu_usage = sum(cpu_usages) / len(cpu_usages)
        return {
            "RR": average_rate,
            "RR CPU": average_cpu_usage
            / num_flows,  # avg cpu will read the same for all flows
        }


def parse_throughput_many(
    benchmark_config: BenchmarkConfig, bench_type: BenchType, pattern: str
) -> Dict[str, List[float]]:
    """
    Parse the throughput data from multiple iperf3 JSON output files.
    """

    results = {}

    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        result = parse_throughput_single(
            pattern.format(bench_type=bench_type.value.lower(), n_flows=n_flows),
            bench_type,
        )
        for field, item in result.items():
            if field not in results:
                results[field] = []
            results[field].append(item)
    return results


def parse_rr_many(
    benchmark_config: BenchmarkConfig, bench_type: BenchType, pattern: str
) -> Dict[str, List[float]]:
    """
    Parse the RR data from multiple netperf output files.
    """

    results = {}

    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        result = parse_rr_single(
            pattern.format(bench_type=bench_type.value.lower(), n_flows=n_flows),
            n_flows,
            bench_type,
        )
        for field, item in result.items():
            if field not in results:
                results[field] = []
            results[field].append(item)
    return results


def run_parse(output_file: str, bench_type: BenchType) -> None:
    """
    Run the parsing of the throughput and RR data and save it to a CSV file.
    """
    benchmark_config = get_benchmark_config()
    throughput_results = parse_throughput_many(
        benchmark_config, bench_type, THROUGHPUT_PATTERN
    )
    rr_results = parse_rr_many(benchmark_config, bench_type, RR_PATTERN)

    # Combine the results
    results = {}
    results["Flows"] = list(
        exp_range(
            benchmark_config["min_flows"],
            benchmark_config["max_flows"] + 1,
            2,
        )
    )

    for field in CSV_FIELDS:
        if field not in results:
            results[field] = []
        if field in throughput_results:
            results[field].extend(throughput_results[field])
        if field in rr_results:
            results[field].extend(rr_results[field])

    # Write the results to a CSV file
    with open(output_file, "w") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(
            [
                {field: results[field][i] for field in CSV_FIELDS}
                for i in range(len(results[CSV_FIELDS[0]]))
            ]
        )
    print(f"Results saved to {output_file}")
