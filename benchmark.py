import argparse
import os
from baremetal.benchmark import run_benchmark as baremetal_benchmark
from baremetal.parse import run_parse as baremetal_parse
from k8s.benchmark import run_benchmark as k8s_benchmark
from k8s.parse import run_parse as k8s_parse
from shared.config import BenchType

BAREMETAL_OUTPUT_FILE = "{dir}/{bench_type}_baremetal_output.csv"
K8S_OUTPUT_FILE = "{dir}/{bench_type}_k8s_output_{overlay}.csv"


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
        help="The overlay network name for the benchmark (k8s only)",
        default=None,
    )
    parser.add_argument(
        "-r",
        "--role",
        type=str,
        help="The role of the node in the benchmark (baremetal only)",
        choices=["client", "server"],
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
        "-d",
        "--dir",
        help="The output directory for the benchmark results",
        default="results",
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
    if args.benchmark == "baremetal" and args.role is None:
        print("Role must be specified for baremetal benchmark.")
        return

    # make output dir if it does not exist
    os.makedirs(args.dir, exist_ok=True)

    if args.parse_only:
        print("Parsing results only...")
        if args.benchmark == "baremetal":
            for bench_type in (
                BenchType if args.mode is None else [BenchType.into(args.mode)]
            ):
                if bench_type is not None:
                    baremetal_parse(
                        BAREMETAL_OUTPUT_FILE.format(
                            dir=args.dir, bench_type=bench_type.value.lower()
                        ),
                        bench_type,
                    )
        elif args.benchmark == "k8s":
            for bench_type in (
                BenchType if args.mode is None else [BenchType.into(args.mode)]
            ):
                if bench_type is not None:
                    k8s_parse(
                        K8S_OUTPUT_FILE.format(
                            dir=args.dir,
                            bench_type=bench_type.value.lower(),
                            overlay=args.overlay,
                        ),
                        bench_type,
                        args.overlay,
                    )
        return

    if args.benchmark == "baremetal":
        print("Running baremetal benchmark...")
        baremetal_benchmark(BenchType.into(args.mode), args.test, args.role)
        if args.role == "client":  # Only parse on client
            for bench_type in (
                BenchType if args.mode is None else [BenchType.into(args.mode)]
            ):
                if bench_type is not None:
                    baremetal_parse(
                        BAREMETAL_OUTPUT_FILE.format(
                            dir=args.dir, bench_type=bench_type.value.lower()
                        ),
                        bench_type,
                    )
    elif args.benchmark == "k8s":
        print("Running Kubernetes benchmark...")
        k8s_benchmark(BenchType.into(args.mode), args.overlay, args.test)
        for bench_type in (
            BenchType if args.mode is None else [BenchType.into(args.mode)]
        ):
            if bench_type is not None:
                k8s_parse(
                    K8S_OUTPUT_FILE.format(
                        dir=args.dir,
                        bench_type=bench_type.value.lower(),
                        overlay=args.overlay,
                    ),
                    bench_type,
                    args.overlay,
                )


if __name__ == "__main__":
    main()
