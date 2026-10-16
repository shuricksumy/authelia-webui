"""Small persistent facts about the managed dir (.apply/state.json): the main config's hash at
the last apply, the last external change, the last version mismatch that was notified."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def path_of(managed_dir: Path) -> Path:
    return managed_dir / ".apply" / "state.json"


def load(managed_dir: Path) -> dict[str, Any]:
    try:
        data = json.loads(path_of(managed_dir).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def update(managed_dir: Path, **values: Any) -> dict[str, Any]:
    data = {**load(managed_dir), **values}
    target = path_of(managed_dir)
    target.parent.mkdir(mode=0o700, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle)
    os.replace(tmp, target)
    return data
