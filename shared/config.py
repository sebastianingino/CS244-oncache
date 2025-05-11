from enum import Enum
import tomllib
from typing import Any, Optional, TypedDict


class BenchType(Enum):
    TCP = "TCP"
    UDP = "UDP"

    @classmethod
    def into(cls, value: Any) -> Optional["BenchType"]:
        """
        Converts a string to a BenchType enum.
        :param value: The string to convert.
        :return: The corresponding BenchType enum.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            value = value.strip()
            if value.upper() == "TCP":
                return cls.TCP
            elif value.upper() == "UDP":
                return cls.UDP
            if value.isdigit():
                value = int(value)
        if isinstance(value, int):
            if value == 0:
                return cls.TCP
            elif value == 1:
                return cls.UDP
        return None


def load_config(path: str) -> dict:
    """
    Reads a configuration file in TOML format.
    :param path: Path to the configuration file.
    :return: A dictionary containing the configuration.
    """
    if not path.endswith(".toml"):
        raise ValueError("Configuration file must be a .toml file")
    if not path:
        raise ValueError("Configuration file path cannot be empty")
    with open(str(path), "rb") as f:
        config = tomllib.load(f)
    return config


BenchmarkConfig = TypedDict(
    "BenchmarkConfig",
    {
        "min_flows": int,
        "max_flows": int,
        "port_start": int,
        "duration": int,
        "iterations": int,
    },
)


def get_benchmark_config(path: str = "config/benchmark.toml") -> BenchmarkConfig:
    """
    Reads the benchmark configuration from a TOML file.

    :param path: Path to the benchmark configuration file.
    :return: A dictionary containing the benchmark configuration.
    """
    config = load_config(path)
    return BenchmarkConfig(**config)
