# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""The original client's remote NAT policy (MP.BIN 0x003a4994).

Applies after local discovery has failed. A permitted path is not proof of
reachability. Relay mode presents Open virtual endpoints instead of classifying
the underlying physical NAT.
"""

NAMES = {1: "Open", 2: "Moderate", 3: "Strict"}
ROUTES = {
    1: {1: "direct", 2: "introducer", 3: "introducer"},
    2: {1: "direct", 2: "introducer", 3: "reject"},
    3: {1: "direct", 2: "reject", 3: "reject"},
}


def route(local_nat: int, peer_nat: int) -> str:
    if local_nat not in NAMES or peer_nat not in NAMES:
        raise ValueError("NAT values must be 1 (Open), 2 (Moderate), or 3 (Strict)")
    return ROUTES[local_nat][peer_nat]
