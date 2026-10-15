"""Fixture-only, fresh-process baseline/candidate benchmark; never opens raw data."""

import argparse
import hashlib
import importlib.util
import json
import platform
import resource
import subprocess
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from time import perf_counter

from ml.ctu13.flows import Flows
from ml.verified_producers.network import Packet
from ml.verified_producers.network_v1_1 import network_features

IDENTITY = "a" * 64


def packets(flow_count: int, rounds: int):
    for r in range(rounds):
        for flow in range(flow_count):
            # Generate unique owned metadata per observation, emulating header parsing.
            src = f"192.0.{flow // 250}.{flow % 250 + 1}"
            dst = "198.51.100." + str(flow % 250 + 1)
            a, b = (src, 1000 + flow), (dst, 80)
            if r % 2:
                a, b = b, a
            index = r * flow_count + flow
            yield Packet(
                f"fixture:{index}",
                IDENTITY,
                IDENTITY,
                index * 10000,
                a[0],
                b[0],
                a[1],
                b[1],
                "tcp",
                40 + index % 1460,
                18 if r % 2 else 2,
            )


def baseline_class():
    path = Path(__file__).parent / "fixtures/flows_8567c62.py"
    if (
        hashlib.sha256(path.read_bytes()).hexdigest()
        != "a83ded204fa6f9400fa51c831917558e3bb61f3cd4eed053662c5faba270e022"
    ):
        raise ValueError("BASELINE_CODE_TAMPERING")
    spec = importlib.util.spec_from_file_location("ctu_flow_baseline", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.Flows


def worker(
    mode: str, flow_count: int, rounds: int, max_buffered: int
) -> dict[str, object]:
    cls = baseline_class() if mode == "BASELINE" else Flows
    table = cls(max_active=20000, max_buffered=max_buffered)
    input_sha = hashlib.sha256()
    output_sha = hashlib.sha256()
    closed = Counter()
    incomplete = 0
    created = 0
    count = 0
    peak_packets = 0
    started = perf_counter()

    def consume(flow):
        nonlocal incomplete
        closed[flow.closure] += 1
        incomplete += flow.closure in {
            "RESOURCE_EVICTION",
            "PACKET_LIMIT",
            "INCOMPLETE_CAPTURE",
            "CAPTURE_GAP",
        }
        output_sha.update(
            json.dumps(
                {"ids": [p.event_id for p in flow.packets], "closure": flow.closure},
                sort_keys=True,
            ).encode()
        )
        if flow.closure not in {
            "RESOURCE_EVICTION",
            "PACKET_LIMIT",
            "INCOMPLETE_CAPTURE",
            "CAPTURE_GAP",
        }:
            vector = network_features(
                flow.packets, source_origin="FIXTURE", source_identity=IDENTITY
            )
            output_sha.update(vector.feature_digest.encode())

    for packet in packets(flow_count, rounds):
        key = (packet.transport, tuple(sorted(packet.endpoints)))
        created += key not in table.active
        input_sha.update(
            json.dumps(asdict(packet), sort_keys=True, separators=(",", ":")).encode()
        )
        for result in table.add(packet):
            consume(result)
        count += 1
        peak_packets = max(peak_packets, table.buffered)
    for result in table.finish(complete=True):
        consume(result)
    elapsed = perf_counter() - started
    total = sum(closed.values())
    return {
        "mode": mode,
        "input_origin": "FIXTURE",
        "fixture_id": "round-robin-packet-metadata:v1",
        "flow_count": flow_count,
        "rounds": rounds,
        "max_active": 20000,
        "max_buffered": max_buffered,
        "input_digest": input_sha.hexdigest(),
        "output_digest": output_sha.hexdigest(),
        "packets_processed": count,
        "flows_created": created,
        "flows_closed": total,
        "flows_completed": total - incomplete,
        "flows_evicted": closed["RESOURCE_EVICTION"],
        "flows_incomplete": incomplete,
        "flows_excluded": incomplete,
        "closure_reasons": dict(closed),
        "peak_buffered_packets": peak_packets,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "peak_state_charged_bytes": getattr(table, "peak_state_bytes", None),
        "processing_seconds": elapsed,
        "packets_per_second": count / elapsed,
        "flows_per_second": total / elapsed,
        "python": platform.python_version(),
        "machine": platform.machine(),
        "platform": platform.system(),
        "producer_version": "1.1.0",
        "inference": "BLOCKED",
        "write": "WRITE_DENIED",
    }


def run_pair(flow_count: int, rounds: int, max_buffered: int) -> dict[str, object]:
    results = []
    for mode in ("BASELINE", "CANDIDATE"):
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                mode,
                "--flows",
                str(flow_count),
                "--rounds",
                str(rounds),
                "--max-buffered",
                str(max_buffered),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        results.append(json.loads(completed.stdout))
    a, b = results
    for key in (
        "input_digest",
        "output_digest",
        "max_active",
        "max_buffered",
        "flow_count",
        "rounds",
        "python",
        "machine",
        "packets_processed",
        "closure_reasons",
    ):
        if a[key] != b[key]:
            raise ValueError("BENCHMARK_COMPARISON_MISMATCH:" + key)
    return {
        "baseline": a,
        "candidate": b,
        "reproducibility": "SAME_FIXTURE_BUDGET_OUTPUT_DIGEST",
        "memory_change_fraction": b["peak_rss_bytes"] / a["peak_rss_bytes"] - 1,
        "time_change_fraction": b["processing_seconds"] / a["processing_seconds"] - 1,
        "limitations": [
            "Single sequential run per variant, host scheduling/cache not controlled",
            "Fixture only; no real corpus throughput or loss improvement claim",
            "Additional candidate state accounting bound not hit in comparison; not a process RSS limiter",
        ],
    }


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--worker", choices=["BASELINE", "CANDIDATE"])
    cli.add_argument("--flows", type=int, default=500)
    cli.add_argument("--rounds", type=int, default=160)
    cli.add_argument("--max-buffered", type=int, default=100000)
    args = cli.parse_args()
    if (
        not 1 <= args.flows <= 2000
        or not 1 <= args.rounds <= 256
        or not 1 <= args.max_buffered <= 100000
    ):
        cli.error("fixture limits exceeded")
    print(
        json.dumps(
            worker(args.worker, args.flows, args.rounds, args.max_buffered)
            if args.worker
            else run_pair(args.flows, args.rounds, args.max_buffered),
            indent=2,
        )
    )
