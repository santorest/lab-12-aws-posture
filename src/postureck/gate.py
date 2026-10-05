"""Fail on an undetected planted flaw, a planted flaw not fixed, a regression or a dirty teardown."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def failures(results: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for item in results["items"]:
        if not item["detected"]:
            out.append(f"planted flaw not detected: {item['id']}")
        if item["after"] == "failing":
            out.append(f"planted flaw still failing after fix: {item['id']}")
        elif item["after"] == "unverified":
            out.append(f"planted flaw unverified after fix (detector silent): {item['id']}")
    for f in results["regressions"]:
        out.append(f"regression: {f['check_id']} on {f['resource']}")
    for resource in results["inventory_left"]:
        out.append(f"teardown left: {resource}")
    return out
