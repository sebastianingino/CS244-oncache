import argparse
from baremetal.benchmark import run_benchmark as baremetal_benchmark

def main():
    parser = argparse.ArgumentParser(description="Benchmarking script")
    parser.add_argument(
        "benchmark",
        type=str,
        help="The name of the benchmark to run",
        choices=["baremetal", "k8s"],
    )

    args = parser.parse_args()
    if args.benchmark == "baremetal":
        print("Running baremetal benchmark...")
        baremetal_benchmark()
    elif args.benchmark == "k8s":
        raise NotImplementedError("Kubernetes benchmark is not implemented yet.")

if __name__ == "__main__":
    main()
