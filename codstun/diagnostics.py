# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Structured observations. These events never claim unobserved game admission."""

import json
import logging
import time

LOG = logging.getLogger("codstun.events")


class Events:
    def emit(self, event: str, **fields):
        LOG.info(json.dumps({"event": event, "time": round(time.time(), 3), **fields},
                            sort_keys=True, separators=(",", ":")))


def endpoint(address):
    return f"{address.ip}:{address.port}"
