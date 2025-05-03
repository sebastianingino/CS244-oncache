# min image: iperf3 + netperf + py harness
FROM alpine:3.20
RUN apk add --no-cache iperf3 netperf python3 py3-pip
COPY requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt
COPY . /bench
ENTRYPOINT ["python3", "/bench/run_benchmark.py"]
