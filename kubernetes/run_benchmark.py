import os, subprocess, tomli, json, time, pathlib


def exp_range(start, stop, factor):
    n = start
    while n < stop:
        yield n
        n *= factor


def load_config(path):
    with open(path, "rb") as f:
        return tomli.load(f)


def run_client(cfg, dest):
    for n_flows in exp_range(cfg["min_flows"], cfg["max_flows"] + 1, 2):
        subprocess.run([
            "iperf3", "-c", dest,
            "-p", str(cfg["port_start"]),
            "-t", str(cfg["duration"]),
            "-P", str(n_flows),
            "--json",
            "--logfile", f"/logs/client_tput_{n_flows}.json"
        ], check=True)

        subprocess.run([
            "netperf", "-H", dest,
            "-p", str(cfg["port_start"]),
            "-l", str(cfg["duration"]),
            "-t", "TCP_RR",
            "--", "-o", "THROUGHPUT,MEAN_LATENCY"
        ], stdout=open(f"/logs/client_rr_{n_flows}.json", "w"),
           check=True)


def run_server(cfg):
    for n_flows in exp_range(cfg["min_flows"], cfg["max_flows"] + 1, 2):
        subprocess.Popen([
            "iperf3", "-s",
            "-p", str(cfg["port_start"]),
            "-1", "-D",
            "--json",
            "--logfile", f"/logs/server_tput_{n_flows}.json"
        ])
    subprocess.Popen(["netserver", "-p", str(cfg["port_start"])])


def main():
    role = os.environ.get("ROLE", "client")
    dest = os.environ.get("DEST_IP", "")
    cfg = load_config("/bench/config/k8s.toml")["tcp"]

    pathlib.Path("/logs").mkdir(exist_ok=True, parents=True)

    if role == "client":
        if not dest:
            raise RuntimeError("DEST_IP env missing for client")
        run_client(cfg, dest)
    else:
        run_server(cfg)


if __name__ == "__main__":
    main()
