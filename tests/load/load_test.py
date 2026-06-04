#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# NIST SP 800-53 Rev5: SA-11 (Developer Testing), CA-8 (Penetration Testing),
#   AU-12 (Audit Record Generation), SC-5 (DoS Protection Assessment),
#   SI-2 (Flaw Remediation), PM-14 (Testing, Training, and Monitoring)
"""TACACS+ non-TLS ASCII auth load test: throughput, latency, resource use.

Fires concurrent ASCII (interactive GETUSER/GETPASS) authentication requests
against a TACACS+ legacy (non-TLS) endpoint and records per-request latency.
Server CPU and RSS memory are sampled every second via psutil (local process)
or a Prometheus /metrics scrape.

Usage:
    python load_test.py --secret mysecret [options]

    # against Docker Compose E2E stack (tests/e2e/compose.yaml):
    python load_test.py --host 172.30.0.10 --secret e2e-shared-secret-k8s \\
        --workers 50 --duration 60

    # against local binary (see run_local.sh):
    python load_test.py --host 127.0.0.1 --port 4949 --secret loadtest \\
        --workers 100 --duration 60 --pid $(cat /tmp/tacacs-load.pid)

    # with Prometheus metrics endpoint:
    python load_test.py --secret loadtest \\
        --metrics-url http://127.0.0.1:9090/metrics

Requires:
    pip install tacacs_plus
    pip install psutil   # optional; enables --pid CPU/memory tracking
"""

import argparse
import socket
import statistics
import sys
import threading
import time
import struct
import urllib.error
import urllib.request
from typing import Optional

try:
    import psutil as _psutil_mod
    _PSUTIL = True
except ImportError:
    _psutil_mod = None  # type: ignore[assignment]
    _PSUTIL = False

from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import TAC_PLUS_AUTHEN_TYPE_ASCII

# ---------------------------------------------------------------------------
# Constants — fixed upper bounds (CLAUDE.md Rule 2)
# ---------------------------------------------------------------------------

_ERR_WORKERS = "workers must be >= 1"

MAX_WORKERS: int = 500           # hard cap on concurrency
MAX_DURATION_SECS: int = 3_600   # 1-hour ceiling
MAX_RESULTS: int = 5_000_000     # stored latency samples
MAX_MONITOR_TICKS: int = 3_600   # 1-hour of 1-second samples
CONNECT_RETRIES: int = 60        # readiness probe attempts
CONNECT_RETRY_DELAY: float = 1.0 # seconds between retries
MONITOR_INTERVAL: float = 1.0    # seconds between resource samples
REQUEST_TIMEOUT: int = 10        # per-request TCP timeout (seconds)

# macOS ephemeral ports: 49152-65535 = 16 384 total.  TCP TIME_WAIT is
# 2 × MSL = 30 s on macOS (net.inet.tcp.msl = 15 000 ms).  The sustainable
# connection rate without port exhaustion is 16 384 / 30 ≈ 546 conn/s.
# DEFAULT_INTER_REQUEST_MS caps per-worker rate so that N workers × (1 000 /
# ms) stays safely below that ceiling (target: ~400 conn/s total).
# Pass --inter-request-ms 0 to disable on Linux or against a remote host.
DEFAULT_INTER_REQUEST_MS: float = 50.0  # 25 workers × 20 req/s = 500 req/s < 546


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse CLI arguments and apply range constraints."""
    # AC-17: document non-TLS usage explicitly
    parser = argparse.ArgumentParser(
        description="TACACS+ non-TLS ASCII auth load test",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="TACACS+ server host")
    parser.add_argument("--port", type=int, default=49,
                        help="TACACS+ server port")
    parser.add_argument("--secret", required=True,
                        help="TACACS+ shared secret")
    parser.add_argument("--user", default="alice",
                        help="Username for ASCII authentication")
    parser.add_argument("--password", default="alice-secret",
                        help="Password for ASCII authentication")
    parser.add_argument("--workers", type=int, default=10,
                        help=f"Concurrent worker threads (max {MAX_WORKERS})")
    parser.add_argument("--duration", type=int, default=30,
                        help="Total test duration in seconds")
    parser.add_argument("--warmup", type=int, default=5,
                        help="Warmup period in seconds (excluded from stats)")
    parser.add_argument("--pid", type=int, default=None,
                        help="Server PID for psutil CPU/memory tracking")
    parser.add_argument("--metrics-url", default=None,
                        help="Prometheus /metrics URL for server resource tracking")
    parser.add_argument("--inter-request-ms", type=float,
                        default=DEFAULT_INTER_REQUEST_MS,
                        help="Sleep between requests per worker (ms). "
                             "Set 0 to disable. Default limits rate to avoid "
                             "macOS ephemeral-port exhaustion.")

    args = parser.parse_args()

    assert 1 <= args.workers <= MAX_WORKERS, \
        f"--workers must be 1-{MAX_WORKERS}, got {args.workers}"
    assert 1 <= args.duration <= MAX_DURATION_SECS, \
        f"--duration must be 1-{MAX_DURATION_SECS}, got {args.duration}"
    assert 0 <= args.warmup < args.duration, \
        f"--warmup must be 0-(duration-1), got {args.warmup}"
    assert 1 <= args.port <= 65535, \
        f"--port must be 1-65535, got {args.port}"
    assert args.inter_request_ms >= 0.0, \
        f"--inter-request-ms must be >= 0, got {args.inter_request_ms}"

    return args


# ---------------------------------------------------------------------------
# Server readiness probe
# ---------------------------------------------------------------------------

def wait_for_server(host: str, port: int) -> bool:
    """Block until TCP to host:port succeeds or CONNECT_RETRIES exhausted."""
    assert isinstance(host, str) and host, "host must be a non-empty string"
    assert 1 <= port <= 65535, f"port out of range: {port}"

    for attempt in range(CONNECT_RETRIES):
        try:
            with socket.create_connection((host, port), timeout=2.0):
                print(f"  server {host}:{port} ready (attempt {attempt + 1})")
                return True
        except OSError:
            if attempt < CONNECT_RETRIES - 1:
                time.sleep(CONNECT_RETRY_DELAY)

    print(f"  ERROR: {host}:{port} not reachable after {CONNECT_RETRIES} tries",
          file=sys.stderr)
    return False


# ---------------------------------------------------------------------------
# Single ASCII authentication
# ---------------------------------------------------------------------------

def send_ascii_auth(
    host: str, port: int, secret: str, user: str, password: str
) -> tuple[bool, float]:
    """Issue one ASCII (GETUSER/GETPASS) auth; return (success, latency_ms).

    Each call opens a fresh TCP connection and performs the full multi-step
    ASCII interactive exchange so the test exercises the complete auth path.
    """
    assert isinstance(secret, str) and secret, "secret must be non-empty"
    assert isinstance(user, str), "user must be a string"

    t0 = time.monotonic()
    try:
        client = TACACSClient(host, port, secret, timeout=REQUEST_TIMEOUT)
        reply = client.authenticate(
            user, password, authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII
        )
        latency_ms = (time.monotonic() - t0) * 1_000.0
        assert latency_ms >= 0.0, "latency cannot be negative"
        return reply.valid, latency_ms
    except (OSError, struct.error, ValueError, RuntimeError):
        latency_ms = (time.monotonic() - t0) * 1_000.0
        return False, latency_ms


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

def worker_fn(
    host: str,
    port: int,
    secret: str,
    user: str,
    password: str,
    inter_request_secs: float,
    results: list,
    lock: threading.Lock,
    stop_event: threading.Event,
    warmup_done: threading.Event,
) -> None:
    """Loop issuing ASCII auth requests; record results only after warmup."""
    assert host, "host must be non-empty"
    assert 1 <= port <= 65535, f"port out of range: {port}"

    for _ in range(MAX_RESULTS):  # fixed upper bound (Rule 2)
        if stop_event.is_set():
            break
        if inter_request_secs > 0.0:
            time.sleep(inter_request_secs)
        success, latency_ms = send_ascii_auth(host, port, secret, user, password)
        if not warmup_done.is_set():
            continue
        with lock:
            if len(results) < MAX_RESULTS:
                results.append((success, latency_ms))


# ---------------------------------------------------------------------------
# Resource monitoring — psutil path
# ---------------------------------------------------------------------------

def _find_process(pid: Optional[int]) -> Optional[object]:
    """Return psutil.Process by PID, or search by binary name; None on miss."""
    assert _PSUTIL and _psutil_mod is not None, "psutil must be installed"
    assert pid is None or pid > 0, f"invalid PID: {pid}"

    if pid is not None:
        try:
            proc = _psutil_mod.Process(pid)
            assert proc.is_running(), f"PID {pid} is not running"
            return proc
        except (_psutil_mod.NoSuchProcess, AssertionError):
            return None

    known_names = {"usg-tacacs-server", "usg-tacacs", "tacacs-server"}
    for proc in _psutil_mod.process_iter(["name"]):
        if proc.info.get("name") in known_names:
            return proc
    return None


def _sample_psutil(proc: object) -> tuple[Optional[float], Optional[float]]:
    """Return (cpu_pct, rss_mb) from a psutil Process; None on error."""
    assert proc is not None, "proc must not be None"
    assert _psutil_mod is not None, "psutil must be installed"

    try:
        cpu_pct = proc.cpu_percent(interval=None)  # type: ignore[union-attr]
        rss_mb = proc.memory_info().rss / (1024.0 * 1024.0)  # type: ignore
        assert cpu_pct >= 0.0, "CPU percent cannot be negative"
        assert rss_mb >= 0.0, "RSS cannot be negative"
        return cpu_pct, rss_mb
    except _psutil_mod.NoSuchProcess:
        return None, None


# ---------------------------------------------------------------------------
# Resource monitoring — Prometheus path
# ---------------------------------------------------------------------------

def _fetch_prometheus(url: str) -> tuple[Optional[float], Optional[float]]:
    """Fetch /metrics and return (process_cpu_seconds_total, rss_bytes)."""
    assert url.startswith("http"), f"metrics URL must start with http: {url}"
    assert len(url) < 2048, "URL length is unreasonably long"

    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            body = resp.read().decode("utf-8")
    except OSError:  # urllib.error.URLError is a subclass of OSError
        return None, None

    cpu_sec: Optional[float] = None
    rss_bytes: Optional[float] = None

    for line in body.splitlines():  # bounded by HTTP response size
        if line.startswith("process_cpu_seconds_total "):
            parts = line.split()
            if len(parts) >= 2:
                cpu_sec = float(parts[1])
        elif line.startswith("process_resident_memory_bytes "):
            parts = line.split()
            if len(parts) >= 2:
                rss_bytes = float(parts[1])

    assert cpu_sec is None or cpu_sec >= 0.0, "CPU seconds cannot be negative"
    return cpu_sec, rss_bytes


def _sample_prometheus(
    url: str, state: dict
) -> tuple[Optional[float], Optional[float]]:
    """Compute instantaneous CPU% from counter delta; return (cpu_pct, rss_mb)."""
    assert isinstance(state, dict), "state must be a dict"
    assert url, "url must not be empty"

    cpu_sec, rss_bytes = _fetch_prometheus(url)
    wall_now = time.monotonic()

    if cpu_sec is None or rss_bytes is None:
        return None, None

    cpu_pct: Optional[float] = None
    if "cpu_sec" in state and "wall" in state:
        delta_cpu = cpu_sec - state["cpu_sec"]
        delta_wall = wall_now - state["wall"]
        if delta_wall > 0.0:
            cpu_pct = (delta_cpu / delta_wall) * 100.0

    state["cpu_sec"] = cpu_sec
    state["wall"] = wall_now
    rss_mb = rss_bytes / (1024.0 * 1024.0)
    assert rss_mb >= 0.0, "RSS cannot be negative"
    return cpu_pct, rss_mb


# ---------------------------------------------------------------------------
# Monitor thread
# ---------------------------------------------------------------------------

def monitor_fn(
    pid: Optional[int],
    metrics_url: Optional[str],
    cpu_samples: list,
    mem_samples: list,
    lock: threading.Lock,
    stop_event: threading.Event,
) -> None:
    """Sample CPU% and RSS memory once per second until stop_event is set."""
    assert isinstance(cpu_samples, list), "cpu_samples must be a list"
    assert isinstance(mem_samples, list), "mem_samples must be a list"

    proc = _find_process(pid) if _PSUTIL else None
    if proc is not None:
        _sample_psutil(proc)  # prime CPU counter (first call always returns 0.0)

    prom_state: dict = {}

    for _ in range(MAX_MONITOR_TICKS):  # fixed upper bound (Rule 2)
        if stop_event.is_set():
            break
        time.sleep(MONITOR_INTERVAL)

        cpu_pct: Optional[float] = None
        rss_mb: Optional[float] = None

        if proc is not None:
            cpu_pct, rss_mb = _sample_psutil(proc)
        elif metrics_url is not None:
            cpu_pct, rss_mb = _sample_prometheus(metrics_url, prom_state)

        if cpu_pct is not None and rss_mb is not None:
            with lock:
                cpu_samples.append(cpu_pct)
                mem_samples.append(rss_mb)


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------

def percentile(sorted_vals: list, p: float) -> float:
    """Compute the p-th percentile of a pre-sorted list via linear interp."""
    assert sorted_vals, "sorted_vals must not be empty"
    assert 0.0 <= p <= 100.0, f"percentile must be 0-100, got {p}"

    n = len(sorted_vals)
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    result = sorted_vals[lo] * (1.0 - (idx - lo)) + sorted_vals[hi] * (idx - lo)

    assert sorted_vals[0] <= result <= sorted_vals[-1], \
        "percentile result must be within data range"
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_resource_summary(cpu_samples: list, mem_samples: list) -> None:
    """Print CPU and memory utilization from collected samples."""
    assert isinstance(cpu_samples, list), "cpu_samples must be a list"
    assert isinstance(mem_samples, list), "mem_samples must be a list"

    if not cpu_samples or not mem_samples:
        print("\n  Resource tracking: N/A")
        print("  Pass --pid <PID> or --metrics-url <URL> to enable.")
        return

    cpu_sorted = sorted(cpu_samples)
    print(f"\n  Resource samples : {len(cpu_samples)}")
    print(f"  CPU %  : avg={statistics.mean(cpu_samples):.1f}"
          f"  max={max(cpu_samples):.1f}"
          f"  p95={percentile(cpu_sorted, 95):.1f}")
    print(f"  RSS MB : avg={statistics.mean(mem_samples):.1f}"
          f"  max={max(mem_samples):.1f}"
          f"  min={min(mem_samples):.1f}")


def print_report(
    results: list,
    cpu_samples: list,
    mem_samples: list,
    elapsed_secs: float,
    workers: int,
) -> None:
    """Print load test summary: throughput, latency percentiles, resources."""
    assert results is not None, "results must not be None"
    assert elapsed_secs > 0.0, "elapsed must be positive"
    assert workers >= 1, _ERR_WORKERS

    total = len(results)
    print("\n" + "=" * 60)
    print("  TACACS+ ASCII Auth Load Test — Summary")
    print("=" * 60)
    print(f"  Duration  : {elapsed_secs:.1f}s   Workers: {workers}")

    if total == 0:
        print("  No requests recorded.")
        print("=" * 60)
        return

    failures = sum(1 for ok, _ in results if not ok)
    successes = total - failures
    print(f"  Requests  : {total:,}  "
          f"(ok={successes:,}  fail={failures:,}  "
          f"err={failures / total * 100:.1f}%)")
    print(f"  Throughput: {total / elapsed_secs:.1f} req/s")

    latencies = sorted(lat for _, lat in results)
    print(f"\n  Latency (ms) over {total:,} requests:")
    print(f"    min   : {latencies[0]:.1f}")
    print(f"    p50   : {percentile(latencies, 50):.1f}")
    print(f"    p95   : {percentile(latencies, 95):.1f}")
    print(f"    p99   : {percentile(latencies, 99):.1f}")
    print(f"    p99.9 : {percentile(latencies, 99.9):.1f}")
    print(f"    max   : {latencies[-1]:.1f}")
    if total > 1:
        print(f"    stdev : {statistics.stdev(latencies):.1f}")

    _print_resource_summary(cpu_samples, mem_samples)
    print("=" * 60)


# ---------------------------------------------------------------------------
# Orchestration helpers
# ---------------------------------------------------------------------------

def _launch_threads(
    args: argparse.Namespace,
    results: list,
    results_lock: threading.Lock,
    stop_event: threading.Event,
    warmup_done: threading.Event,
    cpu_samples: list,
    mem_samples: list,
    monitor_lock: threading.Lock,
) -> tuple[threading.Thread, list]:
    """Start the monitor thread and all worker threads; return them."""
    assert args.workers >= 1, _ERR_WORKERS
    assert isinstance(results, list), "results must be a list"

    inter_secs = args.inter_request_ms / 1_000.0

    monitor_t = threading.Thread(
        target=monitor_fn,
        args=(args.pid, args.metrics_url,
              cpu_samples, mem_samples, monitor_lock, stop_event),
        daemon=True, name="monitor",
    )
    monitor_t.start()

    worker_ts: list = []
    for i in range(args.workers):
        t = threading.Thread(
            target=worker_fn,
            args=(args.host, args.port, args.secret, args.user, args.password,
                  inter_secs, results, results_lock, stop_event, warmup_done),
            daemon=True, name=f"worker-{i}",
        )
        worker_ts.append(t)
        t.start()

    return monitor_t, worker_ts


def _measurement_loop(
    measurement: int, results: list, lock: threading.Lock
) -> float:
    """Drive the timed measurement window; return actual elapsed seconds."""
    assert measurement >= 1, "measurement window must be >= 1s"
    assert isinstance(results, list), "results must be a list"

    t_start = time.monotonic()
    for _tick in range(measurement):  # fixed upper bound (Rule 2)
        time.sleep(1.0)
        elapsed = time.monotonic() - t_start
        with lock:
            n = len(results)
        print(f"\r  {elapsed:5.0f}s  requests={n:,}  ", end="", flush=True)
        if elapsed >= float(measurement):
            break
    return time.monotonic() - t_start


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_load_test(args: argparse.Namespace) -> int:
    """Start workers and monitor threads, collect results, print report."""
    assert args.workers >= 1, _ERR_WORKERS
    assert args.duration >= 1, "duration must be >= 1"

    print("=" * 60)
    print("  TACACS+ Non-TLS ASCII Auth Load Test")
    print("=" * 60)
    print(f"  Target   : {args.host}:{args.port}")
    print(f"  Workers  : {args.workers}")
    rate_cap = (1_000.0 / args.inter_request_ms * args.workers
                if args.inter_request_ms > 0 else float("inf"))
    rate_str = (f"{rate_cap:.0f} req/s cap"
                if rate_cap != float("inf") else "unlimited")
    print(f"  Duration : {args.duration}s  Warmup: {args.warmup}s"
          f"  Rate: {rate_str}")
    if args.pid:
        monitor_desc = f"psutil PID {args.pid}"
    elif args.metrics_url:
        monitor_desc = args.metrics_url
    else:
        monitor_desc = "none (pass --pid or --metrics-url to enable)"
    print(f"  Monitor  : {monitor_desc}\n")

    if not wait_for_server(args.host, args.port):
        return 1

    results: list = []
    cpu_samples: list = []
    mem_samples: list = []
    results_lock = threading.Lock()
    monitor_lock = threading.Lock()
    stop_event = threading.Event()
    warmup_done = threading.Event()

    monitor_t, worker_ts = _launch_threads(
        args, results, results_lock, stop_event, warmup_done,
        cpu_samples, mem_samples, monitor_lock,
    )

    if args.warmup > 0:
        print(f"[warmup]  {args.warmup}s...", end=" ", flush=True)
        time.sleep(float(args.warmup))
        print("done")

    warmup_done.set()
    measurement = args.duration - args.warmup
    print(f"[running] {measurement}s measurement window...")
    elapsed = _measurement_loop(measurement, results, results_lock)

    print()
    stop_event.set()
    for t in worker_ts:
        t.join(timeout=5.0)
    monitor_t.join(timeout=3.0)

    print_report(
        list(results), list(cpu_samples), list(mem_samples),
        elapsed, args.workers,
    )

    if not results:
        return 1
    failures = sum(1 for ok, _ in results if not ok)
    return 0 if failures / len(results) < 0.05 else 1


def main() -> int:
    """Entry point."""
    args = parse_args()
    assert args is not None, "parse_args must return a valid namespace"
    return run_load_test(args)


if __name__ == "__main__":
    sys.exit(main())
