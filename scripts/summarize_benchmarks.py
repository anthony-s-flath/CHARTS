#!/usr/bin/env python3

import re
import sys
from collections import defaultdict
from statistics import mean

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <benchmark-file>")
    sys.exit(1)

pattern = re.compile(
    r"^(Benchmark\S+)\s+\d+\s+(\d+)\s+ns/op\b"
)

results = defaultdict(list)

with open(sys.argv[1], "r") as f:
    for line in f:
        match = pattern.match(line)
        if not match:
            continue

        name = match.group(1)
        ns_per_op = int(match.group(2))
        results[name].append(ns_per_op)

for name, values in results.items():
    avg_ms = mean(values) / 1_000_000
    print(f"{name:<75} {avg_ms:10.2f} ms")
