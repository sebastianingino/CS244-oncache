import argparse
from baremetal.benchmark import run_benchmark as baremetal_benchmark
from baremetal.parse import run_parse as baremetal_parse
from k8s.benchmark import run_benchmark as k8s_benchmark
from k8s.parse import run_parse as k8s_parse
from shared.config import BenchType
from shared.setup import get_role

BAREMETAL_OUTPUT_FILE = "results/{bench_type}_baremetal_output.csv"
K8S_OUTPUT_FILE = "results/{bench_type}_k8s_output_{overlay}.csv"


def main():
    parser = argparse.ArgumentParser(description="Benchmarking script")
    parser.add_argument(
        "benchmark",
        type=str,
        help="The name of the benchmark to run",
        choices=["baremetal", "k8s"],
    )
    parser.add_argument(
        "-o",
        "--overlay",
        type=str,
        help="The overlay network to use for the benchmark",
        choices=["antrea", "cilium", "oncache"],
        default=None,
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        help="The mode of the benchmark to run",
        choices=["tcp", "udp"],
        default=None,
    )
    parser.add_argument(
        "-t",
        "--test",
        type=str,
        help="The test to run",
        choices=["throughput", "latency"],
        default=None,
    )
    parser.add_argument(
        "--parse-only",
        action="store_true",
        help="Only parse the results without running the benchmark",
    )

    args = parser.parse_args()
    if args.benchmark == "k8s" and args.overlay is None:
        print("Overlay network must be specified for Kubernetes benchmark.")
        return

    if args.parse_only:
        print("Parsing results only...")
        if args.benchmark == "baremetal":
            for bench_type in BenchType:
                baremetal_parse(
                    BAREMETAL_OUTPUT_FILE.format(bench_type=bench_type.value.lower()),
                    bench_type,
                )
        elif args.benchmark == "k8s":
            for bench_type in BenchType:
                k8s_parse(
                    K8S_OUTPUT_FILE.format(
                        bench_type=bench_type.value.lower(), overlay=args.overlay
                    ),
                    bench_type,
                    args.overlay,
                )
        return

    if args.benchmark == "baremetal":
        role = get_role()
        print("Running baremetal benchmark...")
        baremetal_benchmark(BenchType.into(args.mode), args.test)
        if role == "primary":
            for bench_type in BenchType:
                baremetal_parse(
                    BAREMETAL_OUTPUT_FILE.format(bench_type=bench_type.value.lower()),
                    bench_type,
                )
    elif args.benchmark == "k8s":
        print("Running Kubernetes benchmark...")
        k8s_benchmark(BenchType.into(args.mode), args.overlay, args.test)
        for bench_type in BenchType:
            k8s_parse(
                K8S_OUTPUT_FILE.format(
                    bench_type=bench_type.value.lower(), overlay=args.overlay
                ),
                bench_type,
                args.overlay,
            )


if __name__ == "__main__":
    main()
