import csv
import json
from typing import Dict, List

from shared.config import TCPBenchmarkConfig, get_benchmark_config
from shared.util import exp_range

BITS_TO_GBPS = 1_000_000_000
CSV_FIELDS = [
    "FLOWS",
    "TCP Throughput",
    "TCP Throughput CPU",
    "TCP RR",
    "TCP RR CPU",
]
THROUGHPUT_PATTERN = "logs/k8s/client_log_throughput_{}_flows_{}.json"
RR_PATTERN = "logs/k8s/client_log_netperf_{}_flows_{}.txt"

def parse_throughput_single(filename: str) -> Dict[str, float]:
    with open(filename, "r") as f:
        data = json.load(f)

        bits_per_second = float(data["end"]["sum_sent"]["bits_per_second"])
        cpu_utilization = float(
            data["end"]["cpu_utilization_percent"]["remote_total"]
        )
        num_flows = int(data["start"]["test_start"]["num_streams"])

        return {
            "TCP Throughput": bits_per_second / BITS_TO_GBPS / num_flows,
            "TCP Throughput CPU": cpu_utilization / num_flows,
        }

def parse_rr_single(filename: str, num_flows: int) -> Dict[str, float]:
    with open(filename, "r") as f:
        lines = f.readlines()
    
        rates = []
        cpu_usages = []
        
        data = lines[-1].split()
        rates.append(float(data[4]))
        cpu_usages.append(float(data[6]))

        average_rate = sum(rates) / len(rates)
        average_cpu_usage = sum(cpu_usages) / len(cpu_usages)
        return {
            "TCP RR": average_rate,
            "TCP RR CPU": average_cpu_usage / num_flows,  # avg cpu will read the same for all flows
        }

def parse_throughput_many(benchmark_config: TCPBenchmarkConfig, pattern: str) -> Dict[str, List[float]]:
    results = {}

    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        flow_result = {}
        for i in range(n_flows):
            filename = pattern.format(n_flows, i)
            try:
                single_result = parse_throughput_single(filename)
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

def parse_rr_many(benchmark_config: TCPBenchmarkConfig, pattern: str) -> Dict[str, List[float]]:
    results = {}

    for n_flows in exp_range(
        benchmark_config["min_flows"], benchmark_config["max_flows"] + 1, 2
    ):
        flow_result = {}
        for i in range(n_flows):
            filename = pattern.format(n_flows, i)
            try:
                single_result = parse_rr_single(filename, n_flows)
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

def run_parse(output_file: str):
    """
    Run the parsing of the benchmark results and save them to a CSV file.
    """
    benchmark_config = get_benchmark_config()["tcp"]
    throughput_results = parse_throughput_many(benchmark_config, THROUGHPUT_PATTERN)
    rr_results = parse_rr_many(benchmark_config, RR_PATTERN)

    # Combine the results
    results = {}
    results["FLOWS"] = list(
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
