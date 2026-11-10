#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Predict the original client's NAT policy from advertised DW_NAT_TYPE values."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from codstun.policy import NAMES, route


def nat(value):
    labels = {"open": 1, "moderate": 2, "strict": 3, "1": 1, "2": 2, "3": 3}
    try:
        return labels[value.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError("use Open/Moderate/Strict or 1/2/3")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--local-nat", required=True, type=nat)
parser.add_argument("--peer-nat", required=True, type=nat)
args = parser.parse_args()
result = route(args.local_nat, args.peer_nat)
print(f"Advertised {NAMES[args.local_nat]} -> {NAMES[args.peer_nat]}: {result}")
if result == "reject":
    print("After local discovery fails, the client rejects this pairing before sending a remote introduction.")
else:
    print("The client permits this attempt; packet filtering, mappings and later admission can still fail.")
print("Use the advertised DW_NAT_TYPE values. One-IP direct discovery cannot accurately measure every physical NAT.")
