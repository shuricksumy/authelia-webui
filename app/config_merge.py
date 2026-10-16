"""Model of how Authelia combines multiple configuration files.

Authelia loads files in order with koanf (StrictMerge off): maps are merged
recursively, any other value (lists included) is replaced by the later file.
Verified against the pinned version in tests/integration/test_merge_behaviour.py;
see docs/merge-behaviour.md.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {k: copy.deepcopy(v) for k, v in base.items()}
    for key, value in override.items():
        current = result.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            result[key] = deep_merge(current, value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def merge_all(documents: Iterable[Mapping[str, Any] | None]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for doc in documents:
        if doc:
            merged = deep_merge(merged, doc)
    return merged
