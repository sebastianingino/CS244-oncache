import argparse
from baremetal.benchmark import run_benchmark as baremetal_benchmark
from baremetal.parse import run_parse as baremetal_parse
from k8s.benchmark import run_benchmark as k8s_benchmark

BAREMETAL_OUTPUT_FILE = "results/baremetal_output.csv"


def main():
    parser = argparse.ArgumentParser(description="Benchmarking script")
    parser.add_argument(
        "benchmark",
        type=str,
        help="The name of the benchmark to run",
        choices=["baremetal", "k8s"],
    )
    parser.add_argument(
        "--parse-only",
        action="store_true",
        help="Only parse the results without running the benchmark",
    )

    args = parser.parse_args()
    if args.parse_only:
        print("Parsing results only...")
        if args.benchmark == "baremetal":
            baremetal_parse(BAREMETAL_OUTPUT_FILE)
        elif args.benchmark == "k8s":
            raise NotImplementedError(
                "Kubernetes benchmark parsing is not implemented yet."
            )
        return

    if args.benchmark == "baremetal":
        print("Running baremetal benchmark...")
        baremetal_benchmark()
        baremetal_parse(BAREMETAL_OUTPUT_FILE)
    elif args.benchmark == "k8s":
        print("Running Kubernetes benchmark...")
        k8s_benchmark()


if __name__ == "__main__":
    main()
