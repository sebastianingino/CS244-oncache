import os
from typing import Callable, Dict, List, NotRequired, TypedDict
import pandas as pd
import matplotlib.pyplot as plt

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
        "map": NotRequired[Callable[[float, pd.DataFrame, pd.DataFrame], float]],
    },
)

DATA_CONFIG: Dict[str, DataConfig] = {
    "baremetal": {
        "filename": "results/baremetal_output.csv",
        "label": "Bare Metal",
        "color": "blue",
    },
    "k8s-antrea": {
        "filename": "results/k8s-antrea_output.csv",
        "label": "K8s Antrea",
        "color": "orange",
    },
    "k8s-cilium": {
        "filename": "results/k8s-cilium_output.csv",
        "label": "K8s Cilium",
        "color": "green",
    },
}

GRAPHS: List[Graph] = [
    {
        "title": "TCP Throughput",
        "xlabel": "Flows",
        "ylabel": "Gbps",
        "column": "TCP Throughput",
    },
    {
        "title": "TCP Throughput CPU",
        "xlabel": "Flows",
        "ylabel": "Virtual Cores",
        "column": "TCP Throughput CPU",
        "map": lambda point, df_self, df_total: point
        / df_total["TCP Throughput"]["Antrea"]
        * df_self["TCP Throughput"],
    },
    {
        "title": "TCP RR",
        "xlabel": "Flows",
        "ylabel": "kRequests/s",
        "column": "TCP RR",
        "map": lambda point, df_self, df_total: point / 1e3,
    },
    {
        "title": "TCP RR CPU",
        "xlabel": "Flows",
        "ylabel": "Virtual Cores",
        "column": "TCP RR CPU",
        "map": lambda point, df_self, df_total: point
        / df_total["TCP RR"]["Antrea"]
        * df_self["TCP RR"],
    },
]


def load_data() -> Dict[str, pd.DataFrame]:
    pass


def plot_data(data: Dict[str, pd.DataFrame]) -> None:
    """
    Plot the data from the given configuration.

    Args:
        data (Dict[str, pd.DataFrame]): A dictionary containing DataFrames for each data source .
    """
    fig, plts = plt.subplots(len(GRAPHS), figsize=(10, 8))


def main():
    data = load_data()
    plot_data(data)


if __name__ == "__main__":
    main()
