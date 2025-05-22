import argparse
import os
from typing import Any, Callable, Dict, List, NotRequired, TypedDict
import pandas as pd
import matplotlib.pyplot as plt
from shared.config import BenchType

SCALE_KEY = "k8s-antrea"

DataConfig = TypedDict(
    "DataConfig",
    {"filename": str, "label": str, "color": str},
)

Graph = TypedDict(
    "Graph",
    {
        "title": str,
        "xlabel": str,
        "ylabel": str,
        "column": str,
        "map": NotRequired[Callable[[float, str, Dict[str, pd.DataFrame]], Any]],
    },
)

DATA_CONFIG: Dict[str, DataConfig] = {
    "baremetal": {
        "filename": "results/{}_baremetal_output.csv",
        "label": "Bare Metal",
        "color": "blue",
    },
    "k8s-antrea": {
        "filename": "results/{}_k8s_output_antrea.csv",
        "label": "Antrea",
        "color": "orange",
    },
    "k8s-cilium": {
        "filename": "results/{}_k8s_output_cilium.csv",
        "label": "Cilium",
        "color": "green",
    },
    "k8s-oncache": {
        "filename": "results/{}_k8s_output_oncache.csv",
        "label": "ONCache",
        "color": "red",
    }
}

GRAPHS: List[Graph] = [
    {
        "title": "{} Throughput",
        "xlabel": "Flows",
        "ylabel": "Gbps",
        "column": "Throughput",
    },
    {
        "title": "{} Throughput CPU",
        "xlabel": "Flows",
        "ylabel": "Virtual Cores",
        "column": "Throughput CPU",
        "map": lambda point, name, df: point
        / df[name]["Throughput"]
        * df[SCALE_KEY]["Throughput"]
        / 1e2,  # Percentage
    },
    {
        "title": "{} RR",
        "xlabel": "Flows",
        "ylabel": "kRequests/s",
        "column": "RR",
        "map": lambda point, name, df: point / 1e3,  # Convert to kRequests/s
    },
    {
        "title": "{} RR CPU",
        "xlabel": "Flows",
        "ylabel": "Virtual Cores",
        "column": "RR CPU",
        "map": lambda point, name, df: point
        / df[name]["RR"]
        * df[SCALE_KEY]["RR"]
        / 1e2,  # Percentage
    },
]


def load_data(bench_type: BenchType) -> Dict[str, pd.DataFrame]:
    """
    Load the data from the configuration.

    Returns:
        Dict[str, pd.DataFrame]: A dictionary containing DataFrames for each data source.
    """
    data = {}
    for name, config in DATA_CONFIG.items():
        filename = config["filename"].format(bench_type.value.lower())
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File {filename} does not exist.")
        df = pd.read_csv(filename)
        df.set_index("Flows", inplace=True)
        data[name] = df

    mapped_data = {}
    for name, config in DATA_CONFIG.items():
        df = data[name].copy()
        for graph in GRAPHS:
            if "map" in graph:
                # Apply the mapping function to the specified column
                df[graph["column"]] = graph["map"](
                    df[graph["column"]],
                    name,
                    data,
                )
        mapped_data[name] = df

    # Concatenate all DataFrames indexed by column name
    joined_data = {}
    for graph in GRAPHS:
        df = pd.concat(
            [df[graph["column"]] for df in mapped_data.values()],
            axis=1,
            keys=mapped_data.keys(),
        )
        joined_data[graph["column"]] = df

    return joined_data


def plot_data(
    data: Dict[str, pd.DataFrame], bench_type: BenchType, output: str, show: bool
) -> None:
    """
    Plot the data from the given configuration.

    Args:
        data (Dict[str, pd.DataFrame]): A dictionary containing DataFrames for each data source .
    """
    fig, plts = plt.subplots(1, len(GRAPHS), figsize=(20, 5))
    fig.subplots_adjust(hspace=0.4)
    for i, graph in enumerate(GRAPHS):
        ax = plts[i]
        for name, config in DATA_CONFIG.items():
            df = data[graph["column"]]
            ax.plot(
                list(range(len(df))),
                df[name],
                label=config["label"],
                color=config["color"],
                marker="o",
                markersize=5,
            )
            ax.set_xticks(range(len(df)))
            ax.set_xticklabels(df.index)
        ax.set_title(graph["title"].format(bench_type.value))
        ax.set_xlabel(graph["xlabel"])
        ax.set_ylabel(graph["ylabel"])

    handles, labels = plts[-1].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=len(DATA_CONFIG))

    plt.tight_layout()
    plt.subplots_adjust(top=0.85)
    if not os.path.exists(os.path.dirname(output)):
        os.makedirs(os.path.dirname(output))
    plt.savefig(output, dpi=300, bbox_inches="tight")
    if show:
        plt.show()
    else:
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Plot data from CSV files.")
    parser.add_argument(
        "--output",
        type=str,
        default="results/{}_plot.png",
        help="Output file for the plot.",
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
        "--show",
        action="store_true",
        help="Show the plot.",
    )
    args = parser.parse_args()

    bench_type = BenchType.into(args.mode)
    for b in [bench_type] if bench_type else BenchType:
        data = load_data(b)
        plot_data(data, b, args.output.format(b.value.lower()), args.show)


if __name__ == "__main__":
    main()
