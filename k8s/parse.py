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
THROUGHPUT_PATTERN = "logs/k8s/{overlay}/{bench_type}/client_log_throughput_{{n_flows}}_flows_{{flow_idx}}.json"
RR_PATTERN = "logs/k8s/{overlay}/{bench_type}/client_log_netperf_{{n_flows}}_flows_{{flow_idx}}.txt"


def parse_throughput_single(filename: str, bench_type: BenchType) -> Dict[str, float]:
    with open(filename, "r") as f:
        data = json.load(f)

        bits_per_second = float(data["end"]["sum_received"]["bits_per_second"])
        cpu_utilization = float(data["end"]["cpu_utilization_percent"]["remote_total"])
        num_flows = int(data["start"]["test_start"]["num_streams"])

        return {
            "Throughput": bits_per_second / BITS_TO_GBPS / num_flows,
            "Throughput CPU": cpu_utilization / num_flows,
        }


def parse_rr_single(
    filename: str, num_flows: int, bench_type: BenchType
) -> Dict[str, float]:
    with open(filename, "r") as f:
        lines = f.readlines()

        rates = []
        cpu_usages = []

        data = lines[-2].split()
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
    benchmark_config: BenchmarkConfig, pattern: str, bench_type: BenchType
) -> Dict[str, List[float]]:
    results = {}

    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        flow_result = {}
        for i in range(n_flows):
            filename = pattern.format(
                n_flows=n_flows,
                flow_idx=i,
            )
            try:
                single_result = parse_throughput_single(filename, bench_type)
                for key in single_result:
                    if key not in flow_result:
                        flow_result[key] = []
                    flow_result[key].append(single_result[key])
            except FileNotFoundError:
                print(f"File {filename} not found. Skipping.")
        for key in flow_result:
            flow_result[key] = sum(flow_result[key]) / len(flow_result[key])
            if key not in results:
                results[key] = []
            results[key].append(flow_result[key])
    return results


def parse_rr_many(
    benchmark_config: BenchmarkConfig, pattern: str, bench_type: BenchType
) -> Dict[str, List[float]]:
    results = {}

    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        flow_result = {}
        for i in range(n_flows):
            filename = pattern.format(
                n_flows=n_flows,
                flow_idx=i,
            )
            try:
                single_result = parse_rr_single(filename, n_flows, bench_type)
                for key in single_result:
                    if key not in flow_result:
                        flow_result[key] = []
                    flow_result[key].append(single_result[key])
            except FileNotFoundError:
                print(f"File {filename} not found. Skipping.")
        for key in flow_result:
            flow_result[key] = sum(flow_result[key]) / len(flow_result[key])
            if key not in results:
                results[key] = []
            results[key].append(flow_result[key])
    return results


def run_parse(output_file: str, bench_type: BenchType, overlay: str):
    """
    Run the parsing of the benchmark results and save them to a CSV file.
    """
    benchmark_config = get_benchmark_config()
    throughput_results = parse_throughput_many(
        benchmark_config,
        THROUGHPUT_PATTERN.format(overlay=overlay, bench_type=bench_type.value.lower()),
        bench_type,
    )
    rr_results = parse_rr_many(
        benchmark_config,
        RR_PATTERN.format(overlay=overlay, bench_type=bench_type.value.lower()),
        bench_type,
    )

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

    # Save to CSV
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
